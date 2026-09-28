"""Mac certificate setup and in-memory Entra tokens for an Entra assessment.

The RSA key stays opaque in the software login Keychain. Only the public DER
certificate and nonsecret metadata are written. There is deliberately no token CLI.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID


class CertificateError(RuntimeError):
    """A safe diagnostic that never includes a credential or token response."""


TAG = re.compile(r"com\.proaxiom\.[A-Za-z0-9][A-Za-z0-9.-]{0,179}\Z")
DEFAULT_HELPER = (
    Path.home()
    / "Library"
    / "Application Support"
    / "Proaxiom"
    / "EntraAssessment"
    / "keychain-signer"
)
PUBLIC_FILE = "certificate.cer"
METADATA_FILE = "certificate-metadata.json"
UTC = timezone.utc


def _tag(value: str) -> str:
    if not isinstance(value, str) or not TAG.fullmatch(value):
        raise CertificateError("Invalid Proaxiom Keychain tag.")
    return value


def _source_digest() -> str:
    try:
        return hashlib.sha256(
            Path(__file__).with_name("keychain_signer.swift").read_bytes()
        ).hexdigest()
    except OSError:
        raise CertificateError("The native helper source could not be read.") from None


def _safe_file(path: Path) -> None:
    if path.is_symlink():
        raise CertificateError("Helper files must not be symbolic links.")
    info = path.stat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & 0o022
    ):
        raise CertificateError(
            "The signing helper has unsafe ownership or permissions."
        )


def build_helper(destination: Path | str | None = None) -> Path:
    """Build once; reject stale or unverifiable binaries without replacing them."""
    if sys.platform != "darwin":
        raise CertificateError("This helper requires macOS and the login Keychain.")
    path = Path(destination) if destination is not None else DEFAULT_HELPER
    metadata_path = path.with_name(path.name + ".build.json")
    source_hash = _source_digest()
    if path.exists() or path.is_symlink():
        try:
            _safe_file(path)
            if not os.access(path, os.X_OK):
                raise CertificateError("The signing helper is not executable.")
            _safe_file(metadata_path)
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise CertificateError(
                "Existing helper build metadata is unavailable or invalid. Choose a new stable helper path after review."
            ) from None
        if not isinstance(metadata, dict) or metadata.get("schema_version") != 1:
            raise CertificateError("Existing helper build metadata is invalid.")
        if metadata.get("source_sha256") != source_hash:
            raise CertificateError(
                "The helper source has changed. Choose a new stable helper path after review; the existing helper was not replaced."
            )
        if (
            metadata.get("binary_sha256")
            != hashlib.sha256(path.read_bytes()).hexdigest()
        ):
            raise CertificateError(
                "The helper binary does not match its build metadata."
            )
        return path
    if metadata_path.exists() or metadata_path.is_symlink():
        raise CertificateError(
            "Build metadata already exists without a helper. Choose a new stable helper path after review."
        )
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    source = Path(__file__).with_name("keychain_signer.swift")
    descriptor, temporary = tempfile.mkstemp(prefix=".signer-", dir=path.parent)
    os.close(descriptor)
    published = False
    try:
        result = subprocess.run(
            ["/usr/bin/swiftc", str(source), "-o", temporary],
            capture_output=True,
            timeout=60,
            check=False,
        )
        if result.returncode:
            raise CertificateError(
                f"Signing helper build failed (status {result.returncode})."
            )
        os.chmod(temporary, 0o700)
        metadata = {
            "schema_version": 1,
            "source_sha256": source_hash,
            "binary_sha256": hashlib.sha256(Path(temporary).read_bytes()).hexdigest(),
        }
        os.link(temporary, path)
        published = True
        with metadata_path.open("x", encoding="utf-8") as handle:
            json.dump(metadata, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.chmod(metadata_path, 0o600)
    except (OSError, subprocess.SubprocessError):
        if published:
            path.unlink(missing_ok=True)
        raise CertificateError(
            "The signing helper could not be built. No existing helper was replaced."
        ) from None
    finally:
        Path(temporary).unlink(missing_ok=True)
    return path


def _native(
    helper: Path,
    command: str,
    key_tag: str,
    data: bytes | None = None,
    algorithm: str | None = None,
) -> bytes:
    _tag(key_tag)
    arguments = [str(helper), command, key_tag]
    if algorithm is not None:
        arguments.append(algorithm)
    try:
        result = subprocess.run(
            arguments, input=data, capture_output=True, timeout=45, check=False
        )
    except (OSError, subprocess.SubprocessError):
        raise CertificateError(
            "The Keychain signing helper did not complete."
        ) from None
    if result.returncode:
        # Only numeric diagnostics may cross the subprocess error boundary.
        numbers = re.findall(rb"(?:code|status) (-?\d+)", result.stderr)
        suffix = f"; native status {int(numbers[-1])}" if numbers else ""
        raise CertificateError(f"Keychain operation {command} failed{suffix}.")
    return result.stdout


def _public_key(helper: Path, key_tag: str) -> rsa.RSAPublicKey:
    try:
        public = serialization.load_der_public_key(_native(helper, "public", key_tag))
    except (ValueError, TypeError):
        raise CertificateError("Keychain public-key format was invalid.") from None
    if not isinstance(public, rsa.RSAPublicKey) or public.key_size != 2048:
        raise CertificateError("A non-extractable RSA-2048 key is required.")
    return public


def _sign(
    helper: Path, key_tag: str, public: rsa.RSAPublicKey, data: bytes, algorithm: str
) -> bytes:
    if (
        algorithm not in {"rs256", "ps256"}
        or not isinstance(data, bytes)
        or not 0 < len(data) <= 65536
    ):
        raise CertificateError("Invalid signing algorithm or message length.")
    signature = _native(helper, "sign", key_tag, data, algorithm)
    scheme = (
        padding.PKCS1v15()
        if algorithm == "rs256"
        else padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
    )
    try:
        public.verify(signature, data, scheme, hashes.SHA256())
    except (InvalidSignature, ValueError):
        raise CertificateError("The Keychain signature did not verify.") from None
    return signature


class CertificateSigner:
    """An opaque Keychain signer matched to an existing public DER certificate.

    public_key() returns only an RSA public key. sign(data, algorithm) accepts
    'rs256' or 'ps256'. helper_path is optional; the stable default is built once.
    """

    def __init__(
        self,
        public_certificate_path: Path | str,
        key_tag: str,
        helper_path: Path | str | None = None,
    ):
        self.key_tag = _tag(key_tag)
        self.helper_path = build_helper(helper_path)
        try:
            raw = Path(public_certificate_path).read_bytes()
            if len(raw) > 65536:
                raise ValueError
            self.certificate = x509.load_der_x509_certificate(raw)
        except (OSError, ValueError):
            raise CertificateError(
                "The public DER certificate could not be read."
            ) from None
        self._public = _public_key(self.helper_path, self.key_tag)
        cert_public = self.certificate.public_key()
        if not isinstance(cert_public, rsa.RSAPublicKey) or (
            cert_public.public_numbers() != self._public.public_numbers()
        ):
            raise CertificateError(
                "The public certificate does not match the Keychain key."
            )
        self.check_validity()

    def check_validity(self) -> None:
        now = datetime.now(UTC)
        if (
            not self.certificate.not_valid_before_utc
            <= now
            < self.certificate.not_valid_after_utc
        ):
            raise CertificateError(
                "The public certificate is outside its validity period."
            )

    def public_key(self) -> rsa.RSAPublicKey:
        return self._public

    def sign(self, data: bytes, algorithm: str) -> bytes:
        return _sign(self.helper_path, self.key_tag, self._public, data, algorithm)


def _der(tag: int, value: bytes) -> bytes:
    size = len(value)
    length = (
        bytes([size])
        if size < 128
        else (
            bytes([0x80 | ((size.bit_length() + 7) // 8)])
            + size.to_bytes((size.bit_length() + 7) // 8, "big")
        )
    )
    return bytes([tag]) + length + value


def _certificate(
    helper: Path, key_tag: str, common_name: str, days: int
) -> x509.Certificate:
    public = _public_key(helper, key_tag)
    start = datetime.now(UTC).replace(microsecond=0) - timedelta(minutes=5)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(public)
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(start + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    # cryptography constructs the DER TBSCertificate with an in-memory temporary
    # key. That key is never serialized. Its throwaway signature is discarded.
    temporary = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    template = builder.sign(temporary, hashes.SHA256())
    del temporary
    tbs = template.tbs_certificate_bytes
    signature = _sign(helper, key_tag, public, tbs, "rs256")
    # sha256WithRSAEncryption AlgorithmIdentifier followed by the signature BIT STRING.
    algorithm = bytes.fromhex("300d06092a864886f70d01010b0500")
    certificate = x509.load_der_x509_certificate(
        _der(0x30, tbs + algorithm + _der(0x03, b"\x00" + signature))
    )
    try:
        public.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except InvalidSignature:
        raise CertificateError(
            "The public certificate signature did not verify."
        ) from None
    return certificate


def prepare(
    output_dir: Path | str,
    key_tag: str,
    days: int = 60,
    common_name: str = "Entra assessment",
    helper_path: Path | str | None = None,
    existing_key: bool = False,
) -> dict:
    """Create a key and public setup pack. existing_key reissues from a known opaque key."""
    _tag(key_tag)
    if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= 90:
        raise CertificateError("Certificate duration must be 1–90 days.")
    if (
        not isinstance(common_name, str)
        or not 1 <= len(common_name) <= 64
        or not all(32 <= ord(c) < 127 for c in common_name)
    ):
        raise CertificateError(
            "Certificate common name must be 1–64 printable ASCII characters."
        )
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    paths = [out / PUBLIC_FILE, out / METADATA_FILE]
    if any(path.exists() or path.is_symlink() for path in paths):
        raise CertificateError(
            "Public setup files already exist. Nothing was replaced."
        )
    helper = build_helper(helper_path)
    _native(helper, "check" if existing_key else "create", key_tag)
    certificate = _certificate(helper, key_tag, common_name, days)
    der = certificate.public_bytes(serialization.Encoding.DER)
    metadata = {
        "schema_version": 1,
        "public_certificate": PUBLIC_FILE,
        "key_tag": key_tag,
        "common_name": common_name,
        "algorithm": "RSA",
        "bits": 2048,
        "private_key_extractable": False,
        "storage": "macOS login Keychain",
        "hardware_backed": False,
        "valid_days": days,
        "not_before": certificate.not_valid_before_utc.isoformat(),
        "not_after": certificate.not_valid_after_utc.isoformat(),
        "certificate_sha256": hashlib.sha256(der).hexdigest(),
        "certificate_thumbprint_sha1": certificate.fingerprint(hashes.SHA1()).hex(),
        "assertion_algorithm": "PS256",
    }
    try:
        with paths[0].open("xb") as handle:
            handle.write(der)
        with paths[1].open("x", encoding="utf-8") as handle:
            json.dump(metadata, handle, indent=2, sort_keys=True)
            handle.write("\n")
    except OSError:
        raise CertificateError(
            "Public setup files could not be completed. The Keychain key was retained."
        ) from None
    return metadata


def _uuid(value: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, TypeError, AttributeError):
        raise CertificateError("Tenant and client IDs must be UUIDs.") from None
    if str(parsed) != value.lower():
        raise CertificateError("Tenant and client IDs must use canonical UUID format.")
    return str(parsed)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class CertificateTokenProvider:
    """In-memory tokens. access_token() refreshes within 90 seconds of expiry."""

    def __init__(
        self, tenant_id: str, client_id: str, signer: CertificateSigner, session=None
    ):
        self.tenant_id, self.client_id = _uuid(tenant_id), _uuid(client_id)
        self.signer = signer
        self._endpoint = (
            f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        )
        self._session = session if session is not None else requests.Session()
        self._session.trust_env = False
        self._token: str | None = None
        self._expires = 0.0

    def client_assertion(self) -> str:
        """Return a short-lived assertion to the caller's memory; never print it."""
        self.signer.check_validity()
        now = int(time.time())
        header = {
            "alg": "PS256",
            "typ": "JWT",
            "x5t#S256": _b64url(self.signer.certificate.fingerprint(hashes.SHA256())),
        }
        claims = {
            "aud": self._endpoint,
            "iss": self.client_id,
            "sub": self.client_id,
            "jti": str(uuid.uuid4()),
            "nbf": now,
            "iat": now,
            "exp": now + 300,
        }
        parts = [
            _b64url(json.dumps(item, separators=(",", ":")).encode("utf-8"))
            for item in (header, claims)
        ]
        message = ".".join(parts).encode("ascii")
        return (
            message.decode("ascii") + "." + _b64url(self.signer.sign(message, "ps256"))
        )

    def access_token(self) -> str:
        self.signer.check_validity()
        if self._token is not None and time.monotonic() < self._expires - 90:
            return self._token
        response = None
        assertion = self.client_assertion()
        started = time.monotonic()
        try:
            response = self._session.post(
                self._endpoint,
                data={
                    "client_id": self.client_id,
                    "grant_type": "client_credentials",
                    "scope": "https://graph.microsoft.com/.default",
                    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                    "client_assertion": assertion,
                },
                timeout=30,
                allow_redirects=False,
            )
            if response.status_code != 200:
                raise CertificateError(
                    f"Token request failed (HTTP {int(response.status_code)})."
                )
            body = response.json()
            token, expires = body.get("access_token"), body.get("expires_in")
            if (
                not isinstance(token, str)
                or not 1 <= len(token) <= 65536
                or isinstance(expires, bool)
                or not isinstance(expires, (int, float))
                or not 0 < expires <= 86400
                or body.get("token_type", "").lower() != "bearer"
            ):
                raise CertificateError(
                    "The token service returned an invalid response."
                )
            self._token, self._expires = token, started + expires
            return token
        except (requests.RequestException, ValueError, TypeError, AttributeError):
            raise CertificateError(
                "The token request could not be completed."
            ) from None
        finally:
            assertion = None
            if response is not None:
                response.close()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    setup = commands.add_parser(
        "prepare", help="Create a public certificate and nonsecret metadata"
    )
    setup.add_argument("--output-dir", required=True, type=Path)
    setup.add_argument("--key-tag", required=True)
    setup.add_argument("--days", type=int, default=60)
    setup.add_argument("--common-name", default="Entra assessment")
    setup.add_argument(
        "--helper", type=Path, help="An existing stable native helper path"
    )
    setup.add_argument(
        "--existing-key",
        action="store_true",
        help="Use an existing key; do not create or replace one",
    )
    args = parser.parse_args(argv)
    try:
        metadata = prepare(
            args.output_dir,
            args.key_tag,
            args.days,
            args.common_name,
            args.helper,
            args.existing_key,
        )
    except CertificateError as error:
        print(str(error), file=sys.stderr)
        return 1
    print(f"Public certificate ready: {args.output_dir / PUBLIC_FILE}")
    print(f"Public setup metadata: {args.output_dir / METADATA_FILE}")
    print(
        f"Expires: {metadata['not_after']}. Private key remains in the software login Keychain."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
