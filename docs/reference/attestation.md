# TPM key attestation reference

How the discovery tool's `-Attest` flag evidences that the signing key is TPM-bound,
what that evidence does and does **not** prove, and the higher-assurance alternative.

> **Attestation is assurance documentation only.** Microsoft Entra ID does **not**
> consume key-attestation claims — there is no way to make Entra *enforce* that an app
> credential's key lives in a TPM (see PRD §5 Non-Goals). The bundle this tool produces
> is for the engagement evidence pack: it gives the assessor and customer cryptographic
> evidence about where the key lives, independent of the cloud.

---

## What `-Attest` does

| Mode | Behaviour | FR |
|------|-----------|----|
| `GenerateLocal -Attest` | Creates a CNG **key-attestation claim** over the newly generated TPM key, gathers TPM Endorsement Key (EK) material, derives an honest assurance level, and writes a JSON **bundle** (default: `<thumbprint>.attestation.json`, or `-AttestationPath`). | FR 17 |
| `ImportCert -Attest -AttestationPath <file>` | **Verifies** a supplied bundle (`NCryptVerifyClaim`) and reports the result. | FR 18 |
| either, `-RequireHardwareRoot` | Opt-in **hard-fail** when the EK does not chain to a manufacturer root. Default is **report + warn** (no hard-fail). | OQ #1 |

Implementation: `src/Attestation.psm1`.

---

## The default route — CNG key-attestation claim (`NCryptCreateClaim`)

The tool uses the CNG claim API against the Microsoft Platform Crypto Provider (the TPM KSP):

- **API:** `NCryptCreateClaim` / `NCryptVerifyClaim` (P/Invoke `ncrypt.dll`), compiled with
  `Add-Type`. The subject key's `NCRYPT_KEY_HANDLE` comes from the certificate's
  `CngKey` (`RSACertificateExtensions::GetRSAPrivateKey($cert).Key.Handle`).
- **Claim type:** `NCRYPT_CLAIM_AUTHORITY_AND_SUBJECT` (`0x00000001`), with the subject
  and authority handle set to the **same** key — a **self-claim**. This is the supported
  TPM-KSP claim variant that does not require a separately provisioned authority /
  Attestation Identity Key (AIK). It cryptographically evidences that the named key is
  **resident in, and was created by, the platform TPM**.
- **Buffer pattern:** two-call sizing — call once with a NULL output buffer to learn the
  required length, then again to fill it.
- **Verification:** the bundle carries the subject key's public-key blob; verification
  re-imports it (`CngKey.Import`, `GenericPublicBlob`) and calls `NCryptVerifyClaim` with
  the same claim type. `VerifyResult = $true` only when the call returns
  `SECURITY_STATUS == 0`.

### What the self-claim proves — and what it does NOT

| Proves | Does NOT prove |
|--------|----------------|
| The key is TPM-resident and TPM-created (non-exportable, bound to *this* TPM). | That the TPM is a genuine hardware TPM with a manufacturer-rooted EK. |
| The claim verifies against the recorded public key. | Anything cloud-side — Entra ignores it. |

The "is this a real hardware TPM" question is answered **separately** by the EK check
below, and reported **independently** so the output never over-claims (FR 19).

---

## EK manufacturer-root determination (FR 19)

The tool calls **`Get-TpmEndorsementKeyInfo`** (TrustedPlatformModule module) and inspects:

- `ManufacturerCertificates` — manufacturer EK certs (typical of a **discrete** TPM);
- `AdditionalCertificates` — EK certs registered to the OS (typical of a **firmware /
  CPU-integrated** TPM, or enterprise-provisioned).

`EkChainedToManufacturerRoot` is `$true` **only when the EK certificate chains to a
TRUSTED hardware/cloud manufacturer root** — *not* merely when some EK cert is present.
Merely **having** an EK certificate is **not** evidence of a hardware root: a swtpm vTPM
presents a self-signed fake "IBM" EK certificate, so a cert can be present yet untrusted.
The honesty signal is computed conservatively (`Test-EkChainsToTrustedRoot`, fail-closed
to `$false`):

- `Confirm-CAEndorsementKeyInfo` is consulted when the SKU ships it (a clear `$false`
  forces untrusted); its absence is not fatal.
- Each EK certificate is then run through an `X509Chain` validated against the machine's
  trusted TPM-manufacturer roots (`Cert:\LocalMachine\TrustedTPM_RootCert` /
  `TrustedTPM_IntermediateCert` added as `ExtraStore`). A **self-signed** EK cert
  (issuer == subject) or any cert whose chain does not reach a trusted root is rejected.
- **Default is `$false`** on any failure or uncertainty — the tool never claims a
  hardware root it cannot positively prove (FR 19).

The resulting assurance levels:

| Condition | `AssuranceLevel` | `EkChainedToManufacturerRoot` / `HardwareRoot` |
|-----------|------------------|------------------------------------------------|
| No claim produced | `None` | `$false` |
| Claim produced, EK does **not** chain to a trusted root (no EK cert, **or** a self-signed/untrusted EK cert) | `TpmKeyAttestation-NoHardwareRoot` | `$false` |
| Claim produced **and** EK chains to a **trusted** manufacturer/cloud root | `TpmKeyAttestation-HardwareRoot` | `$true` |

---

## The vTPM EK-chain gap (per RFC-001)

The test lab runs on a **swtpm** (emulated) virtual TPM. A swtpm vTPM has **no
manufacturer EK certificate** — neither `ManufacturerCertificates` nor
`AdditionalCertificates` is populated. Therefore, on the lab VM (and on most customer
TPMs that do not expose an EK cert to the OS):

- the self-claim still **creates and verifies** successfully (the key really is in the
  vTPM), but
- `EkChainedToManufacturerRoot = $false` and the assurance level is
  `TpmKeyAttestation-NoHardwareRoot`.

The tool **must not** — and does not — report hardware-root assurance in this case
(FR 19). Full EK-chain-to-manufacturer validation requires **physical TPM hardware**
whose manufacturer EK certificate is visible to Windows.

> **`-RequireHardwareRoot` consequence:** because the lab vTPM cannot chain to a
> manufacturer root, `-RequireHardwareRoot` will **hard-fail** there by design. That is
> why the default is report + warn — so legitimate vTPM / no-EK-cert use is not blocked,
> while the strict switch remains available for engagements that mandate a hardware root.

---

## swtpm limitation and the deferral to a cloud vTPM (Azure-first)

> **Status:** the live key-attestation claim round-trip is **deferred to a cloud vTPM
> (Azure-first)** and is **not** validated on the swtpm (emulated) CI environment. The Tier-B
> create→verify tests **skip** on the swtpm and execute only on an attestable TPM.

Hardware-verified on the CI swtpm vTPM, two hard limits make a genuine attestation
impossible there:

1. **`NCryptCreateClaim` fails with `0x80290416`** = *"The TPM key usage policy is
   invalid."* The swtpm will not produce a key-attestation claim for our key — a deep
   emulator / key-policy limitation, not worth chasing on swtpm.
2. **The swtpm's single EK certificate is a self-signed FAKE "IBM" swtpm cert**, not a
   genuine hardware root. This is exactly why the FR-19 honesty rule treats
   *"an EK cert exists"* as **insufficient** — the cert must chain to a **trusted** root,
   which a self-signed swtpm cert does not. So even if the swtpm could produce a claim,
   it would (correctly) be reported `NoHardwareRoot`.

### Where genuine attestation gets validated — cloud vTPM, Azure-first

Genuine, hardware-rooted attestation is deferred to a **cloud vTPM**, validated by running
the attestation probe on a **real Azure VM**:

- **Open question — MAA vs CNG.** Azure's *idiomatic* attestation is **Microsoft Azure
  Attestation (MAA)**, which produces **boot-integrity quotes** for a VM. That is a
  **different mechanism** from this app's route — a CNG **`NCryptCreateClaim`** key claim
  whose hardware-root evidence is the **EK-certificate chain to a manufacturer root**.
  Whether the existing CNG/EK-chain route works **in-guest on an Azure Trusted Launch
  vTPM** (vs needing to adopt MAA) must be **confirmed by running the attestation probe on
  a real Azure VM**.
- **Azure Confidential VM vs plain Trusted Launch.** An **Azure Confidential VM** exposes
  an Attestation Key (AK) certificate signed by an **Azure CA** (hardware-backed), giving
  the clearest hardware-rooted key material. Plain **Trusted Launch** provides a vTPM but
  may not surface an equivalently strong, chainable EK/AK certificate — to be confirmed by
  the probe.
- **Trusted-root set must grow.** For `EkChainsToTrustedRoot` to resolve `$true` on cloud
  hardware, the relevant **Azure CA** (and potentially **AWS NitroTPM**) root/intermediate
  certificates must be added to the trusted-root set the chain build validates against.

---

## Higher-assurance alternative — AD CS TPM key attestation

For engagements that need a stronger, CA-anchored assurance than a TPM self-claim, the
standard route is **Active Directory Certificate Services (AD CS) TPM key attestation**:

- Enroll the key through a certificate template configured for **Key Attestation**
  (AD CS supports attestation anchored by EK certificate, EK public key, or a
  user-supplied hardware list).
- The CA validates the TPM's EK against a trusted manufacturer root (the manufacturer
  EK CA certificates must be installed in the CA's `TPM-EK` / intermediate stores), and
  issues the certificate **only** if attestation succeeds — so the issued cert itself
  becomes the evidence that the key is genuinely TPM-bound on validated hardware.

This binds the assurance to enterprise PKI and a manufacturer EK root, rather than to a
self-asserted CNG claim. It is **documented here as the higher-assurance path but is not
automated by this tool** (it requires AD CS infrastructure and per-template configuration
that is out of scope for the standalone provisioning script).

---

## Summary

- `-Attest` produces / verifies a TPM **self-claim** bundle: strong evidence the key is
  TPM-resident, weaker on "is the TPM a hardware root."
- EK manufacturer-root status is determined and reported **separately and honestly**;
  vTPMs (no EK cert) are reported `NoHardwareRoot` and never claimed as hardware-rooted.
- Default is report + warn; `-RequireHardwareRoot` is the opt-in strict gate.
- AD CS template-based attestation is the documented higher-assurance alternative.
- **Entra does not consume any of this** — it is assurance documentation only.
