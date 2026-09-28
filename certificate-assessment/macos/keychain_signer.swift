// This helper exposes signing and public-key operations only. The private RSA key
// stays non-extractable in the login Keychain. This is software, not Secure Enclave.
import Foundation
import Security

func fail(_ message: String) -> Never {
  FileHandle.standardError.write(Data((message + "\n").utf8))
  exit(1)
}
func failCF(_ message: String, _ error: Unmanaged<CFError>?) -> Never {
  let code = error.map { CFErrorGetCode($0.takeRetainedValue()) } ?? 0
  fail("\(message) (code \(code)).")
}
let args = Array(CommandLine.arguments.dropFirst())
guard args.count >= 2 else {
  fail("Usage: keychain-signer create|check|public|sign|delete-test TAG [rs256|ps256]")
}
let command = args[0]
let tag = args[1]
guard
  tag.range(
    of: "^com\\.proaxiom\\.[A-Za-z0-9][A-Za-z0-9.-]{0,179}$",
    options: .regularExpression) != nil
else { fail("Invalid Proaxiom key tag.") }
guard ["create", "check", "public", "sign", "delete-test"].contains(command),
  args.count == (command == "sign" ? 3 : 2)
else { fail("Invalid command arguments.") }
let tagData = Data(tag.utf8)
var login: SecKeychain?
let openStatus = SecKeychainOpen(
  NSHomeDirectory() + "/Library/Keychains/login.keychain-db", &login)
guard openStatus == errSecSuccess, let login = login else {
  fail("Cannot open the login Keychain (status \(openStatus)).")
}
func query(privateOnly: Bool = true) -> [String: Any] {
  var result: [String: Any] = [
    kSecClass as String: kSecClassKey,
    kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
    kSecAttrApplicationTag as String: tagData,
    kSecMatchSearchList as String: [login],
  ]
  if privateOnly { result[kSecAttrKeyClass as String] = kSecAttrKeyClassPrivate }
  return result
}
func load() -> SecKey {
  var q = query()
  q[kSecReturnRef as String] = true
  var result: CFTypeRef?
  let status = SecItemCopyMatching(q as CFDictionary, &result)
  guard status == errSecSuccess, let result = result else {
    fail("Cannot read the requested Keychain key (status \(status)).")
  }
  return result as! SecKey
}
func valid(_ key: SecKey) -> Bool {
  guard let attrs = SecKeyCopyAttributes(key) as? [String: Any],
    let extractable = attrs[kSecAttrIsExtractable as String] as? Bool,
    extractable == false,
    let bits = attrs[kSecAttrKeySizeInBits as String] as? Int,
    bits == 2048
  else { return false }
  return SecKeyGetBlockSize(key) == 256
}
func requireValid(_ key: SecKey) {
  guard valid(key) else {
    fail("The Keychain did not confirm a non-extractable RSA-2048 key. Refusing use.")
  }
}
if command == "create" {
  var existing: CFTypeRef?
  let status = SecItemCopyMatching(query(privateOnly: false) as CFDictionary, &existing)
  guard status == errSecItemNotFound else {
    fail("Key already exists or lookup failed (status \(status)). No key was replaced.")
  }
  let options: [String: Any] = [
    kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
    kSecAttrKeySizeInBits as String: 2048,
    kSecUseKeychain as String: login,
    // macOS needs this at the top level. A private-attrs-only request was
    // ignored in native tests. Per-use flags also caused status -67731.
    kSecAttrIsExtractable as String: false,
    kSecPrivateKeyAttrs as String: [
      kSecAttrIsPermanent as String: true,
      kSecAttrApplicationTag as String: tagData,
      kSecAttrLabel as String: tag,
      kSecAttrIsExtractable as String: false,
      kSecAttrIsSensitive as String: true,
    ],
    kSecPublicKeyAttrs as String: [
      kSecAttrIsPermanent as String: false,
      kSecAttrApplicationTag as String: tagData,
      kSecAttrIsExtractable as String: true,
    ],
  ]
  var error: Unmanaged<CFError>?
  guard let key = SecKeyCreateRandomKey(options as CFDictionary, &error) else {
    failCF("Keychain key creation failed", error)
  }
  guard valid(key) else {
    // This can remove only the new, unregistered key from this operation.
    let cleanup = SecItemDelete(query(privateOnly: false) as CFDictionary)
    fail("Key attributes were not enforced; new-key cleanup status \(cleanup).")
  }
  requireValid(load())
  print("Created non-extractable RSA-2048 key in the login Keychain.")
} else if command == "delete-test" {
  guard tag.hasPrefix("com.proaxiom.assessment.test.") else {
    fail("Cleanup is restricted to this tool's test keys.")
  }
  // Delete each class explicitly. Legacy Keychain deletion can stop after
  // one matching item when a tag has both a public and a private key.
  for keyClass in [kSecAttrKeyClassPrivate, kSecAttrKeyClassPublic] {
    var cleanup = query(privateOnly: false)
    cleanup[kSecAttrKeyClass as String] = keyClass
    let status = SecItemDelete(cleanup as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else {
      fail("Test-key cleanup failed (status \(status)).")
    }
  }
  print("Test key removed.")
} else {
  let key = load()
  requireValid(key)
  if command == "check" {
    print(
      "{\"algorithm\":\"RSA\",\"bits\":2048,\"extractable\":false,\"storage\":\"macOS login Keychain\",\"hardware_backed\":false}"
    )
  } else if command == "public" {
    guard let pub = SecKeyCopyPublicKey(key) else { fail("Public-key lookup failed.") }
    var error: Unmanaged<CFError>?
    guard let bytes = SecKeyCopyExternalRepresentation(pub, &error) else {
      failCF("Public-key export failed", error)
    }
    FileHandle.standardOutput.write(bytes as Data)
  } else {
    let algorithm: SecKeyAlgorithm
    if args[2] == "rs256" {
      algorithm = .rsaSignatureMessagePKCS1v15SHA256
    } else if args[2] == "ps256" {
      algorithm = .rsaSignatureMessagePSSSHA256
    } else {
      fail("Unsupported signature algorithm.")
    }
    guard SecKeyIsAlgorithmSupported(key, .sign, algorithm) else {
      fail("Signature algorithm unsupported by this key.")
    }
    let message = FileHandle.standardInput.readDataToEndOfFile()
    guard !message.isEmpty && message.count <= 65536 else {
      fail("Signing message size rejected.")
    }
    var error: Unmanaged<CFError>?
    guard let signature = SecKeyCreateSignature(key, algorithm, message as CFData, &error) else {
      failCF("Signing failed", error)
    }
    FileHandle.standardOutput.write(signature as Data)
  }
}
