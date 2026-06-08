<#
.SYNOPSIS
    TPM key-attestation (claim) generation and verification for the discovery app (FR 17-19).

.DESCRIPTION
    Implements the attestation functional requirements of the entraid-discovery-app
    PRD:

      * Add-AttestationInterop          - compile the ncrypt.dll P/Invoke signatures (Add-Type)
      * Get-AttestationEkInfo           - gather TPM Endorsement Key (EK) material (Windows)
      * Resolve-AttestationAssurance    - PURE: EK info -> assurance decision (FR 19)
      * Test-RequireHardwareRoot        - PURE: -RequireHardwareRoot enforcement decision
      * ConvertTo-AttestationBundle     - PURE: shape + JSON-serialise a bundle
      * ConvertFrom-AttestationBundle   - PURE: parse a serialised bundle back to an object
      * New-DiscoveryAttestation        - GenerateLocal: create a TPM claim + bundle (FR 17)
      * Test-DiscoveryAttestation       - ImportCert: verify a supplied bundle (FR 18)

    DESIGN — pure-vs-Windows split (testability):
      The pure functions (Resolve-AttestationAssurance, Test-RequireHardwareRoot,
      ConvertTo-/ConvertFrom-AttestationBundle) have NO OS dependency and are unit-
      tested on macOS in Tier A. The Windows/TPM P/Invoke surface
      (Add-AttestationInterop, Get-AttestationEkInfo, the NCryptCreateClaim /
      NCryptVerifyClaim calls inside New-/Test-DiscoveryAttestation) is gated behind
      Test-IsWindows and exercised only in Tier B on the CI vTPM runner. The module
      IMPORTS cleanly on macOS — Add-Type of the P/Invoke signatures is fine there;
      only the actual ncrypt calls require Windows + a TPM.

    ATTESTATION MODEL — what the claim proves, and what it does NOT:
      We use the CNG key-attestation claim NCRYPT_CLAIM_AUTHORITY_AND_SUBJECT (0x1)
      with hSubjectKey == hAuthorityKey (a self-claim over the generated key). This
      is the supported TPM KSP claim variant: it cryptographically evidences that the
      named key is resident in, and was created by, the platform TPM (Microsoft
      Platform Crypto Provider). It does NOT, on its own, chain the TPM's Endorsement
      Key to a manufacturer root — that is a SEPARATE check (Get-TpmEndorsementKeyInfo
      + manufacturer-cert inspection). The two are reported independently so the
      output never over-claims (FR 19).

      A higher-assurance alternative — using an AD CS / CA-issued Attestation Identity
      Key (AIK) as the authority and an AIK-anchored claim — is documented in
      docs/reference/attestation.md but NOT automated here.

    IMPORTANT (honesty / FR 19):
      Entra does NOT consume attestation. This bundle is assurance DOCUMENTATION for
      the engagement evidence pack only. A virtual / firmware TPM that lacks an EK
      certificate (e.g. the swtpm vTPM in the lab) will report
      EkChainedToManufacturerRoot = $false and an assurance level that is explicitly
      NOT hardware-rooted; the tool must never claim hardware-root for such a TPM.

    Cross-compatible with Windows PowerShell 5.1 (Desktop) and PowerShell 7.x (Core)
    on Windows (FR 21). Pure functions + module import work anywhere.
#>

Set-StrictMode -Version Latest

Import-Module "$PSScriptRoot/Common.psm1" -Force

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# CNG key-attestation claim types (ncrypt.h). For TPM key attestation against the
# Microsoft Platform Crypto Provider we use AUTHORITY_AND_SUBJECT with the SAME key
# as both subject and authority (a self-claim).
$script:NCRYPT_CLAIM_AUTHORITY_AND_SUBJECT = 0x00000001

# Schema version stamped into every bundle so a future format change is detectable.
$script:AttestationBundleVersion = '1.0'

# Assurance level vocabulary (string constants to avoid drift across functions).
$script:AssuranceTpmHardwareRoot  = 'TpmKeyAttestation-HardwareRoot'   # claim made AND EK chains to a TRUSTED manufacturer/cloud root
$script:AssuranceTpmNoHardwareRoot = 'TpmKeyAttestation-NoHardwareRoot' # claim made but EK does NOT chain to a trusted root (vTPM / self-signed EK)
$script:AssuranceNone              = 'None'                              # no usable claim produced

# ---------------------------------------------------------------------------
# P/Invoke interop (compiles anywhere; only CALLED on Windows)
# ---------------------------------------------------------------------------

function Add-AttestationInterop {
    <#
    .SYNOPSIS
        Compiles the ncrypt.dll NCryptCreateClaim / NCryptVerifyClaim P/Invoke signatures.

    .DESCRIPTION
        Adds (idempotently) a managed type 'Proaxiom.Attestation.NCryptInterop'
        exposing the two NCrypt claim entry points plus the minimal struct types
        needed to read the verify output. Compiling the signatures with Add-Type
        works on any platform (it is just IL generation); the methods are only
        ever INVOKED on Windows (the callers gate with Test-IsWindows).

        Signatures (ncrypt.h):

          SECURITY_STATUS NCryptCreateClaim(
            NCRYPT_KEY_HANDLE hSubjectKey, NCRYPT_KEY_HANDLE hAuthorityKey,
            DWORD dwClaimType, NCryptBufferDesc* pParameterList,
            PBYTE pbClaimBlob, DWORD cbClaimBlob, DWORD* pcbResult, DWORD dwFlags);

          SECURITY_STATUS NCryptVerifyClaim(
            NCRYPT_KEY_HANDLE hSubjectKey, NCRYPT_KEY_HANDLE hAuthorityKey,
            DWORD dwClaimType, NCryptBufferDesc* pParameterList,
            PBYTE pbClaimBlob, DWORD cbClaimBlob, NCryptBufferDesc* pOutput, DWORD dwFlags);

        NCRYPT_KEY_HANDLE is a pointer-sized handle (IntPtr). We do not parse the
        verify pOutput (we only care about the SECURITY_STATUS success/fail for a
        non-VBS claim), so pParameterList / pOutput are marshalled as IntPtr and
        passed IntPtr.Zero.

    .OUTPUTS
        None.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()

    if (-not ('Proaxiom.Attestation.NCryptInterop' -as [type])) {
        $cs = @'
using System;
using System.Runtime.InteropServices;

namespace Proaxiom.Attestation
{
    public static class NCryptInterop
    {
        // SECURITY_STATUS NCryptCreateClaim(...)
        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode, SetLastError = false)]
        public static extern int NCryptCreateClaim(
            IntPtr hSubjectKey,
            IntPtr hAuthorityKey,
            uint dwClaimType,
            IntPtr pParameterList,
            byte[] pbClaimBlob,
            uint cbClaimBlob,
            out uint pcbResult,
            uint dwFlags);

        // SECURITY_STATUS NCryptVerifyClaim(...)
        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode, SetLastError = false)]
        public static extern int NCryptVerifyClaim(
            IntPtr hSubjectKey,
            IntPtr hAuthorityKey,
            uint dwClaimType,
            IntPtr pParameterList,
            byte[] pbClaimBlob,
            uint cbClaimBlob,
            IntPtr pOutput,
            uint dwFlags);
    }
}
'@
        Add-Type -TypeDefinition $cs -ErrorAction Stop
    }
}

# ---------------------------------------------------------------------------
# Internal helper: get the raw NCRYPT_KEY_HANDLE for a certificate's CNG key
# ---------------------------------------------------------------------------

function Get-NCryptKeyHandle {
    <#
    .SYNOPSIS
        Returns the raw NCRYPT_KEY_HANDLE (IntPtr) for a certificate's CNG private key.

    .DESCRIPTION
        Windows-only. Reads the certificate's RSA private key as an RSACng, takes its
        CngKey, and returns the underlying SafeNCryptKeyHandle as an IntPtr suitable
        for the NCryptCreateClaim subject/authority parameters. Throws on a non-CNG
        key or off Windows. The caller is responsible for keeping the CngKey/cert
        alive for the duration of the native call (we return the handle value, not the
        SafeHandle, so the caller MUST hold a reference to the CngKey — see callers).

    .PARAMETER CngKey
        The live CngKey whose handle is required.

    .OUTPUTS
        System.IntPtr
    #>
    [CmdletBinding()]
    [OutputType([System.IntPtr])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [System.Security.Cryptography.CngKey]$CngKey
    )

    if (-not (Test-IsWindows)) {
        throw 'Get-NCryptKeyHandle is Windows-only (CNG key handles do not exist off Windows).'
    }

    # CngKey.Handle is a SafeNCryptKeyHandle; DangerousGetHandle() yields the raw
    # NCRYPT_KEY_HANDLE. The caller MUST keep $CngKey alive across the native call
    # (a SafeHandle freed mid-call would invalidate the raw handle).
    $safe = $CngKey.Handle
    $safe.DangerousGetHandle()
}

# ---------------------------------------------------------------------------
# PURE functions (OS-independent; unit-tested in Tier A on macOS)
# ---------------------------------------------------------------------------

function Resolve-AttestationAssurance {
    <#
    .SYNOPSIS
        PURE decision: given EK trust + whether a claim was produced, derive the assurance level (FR 19).

    .DESCRIPTION
        No OS calls. Encodes the honesty rule of FR 19:

          * If no usable claim was produced            -> assurance 'None', not hardware-rooted.
          * If a claim was produced but the EK does NOT chain to a TRUSTED hardware/cloud
            manufacturer root -> assurance 'TpmKeyAttestation-NoHardwareRoot',
            EkChainedToManufacturerRoot = $false. The tool MUST NOT claim hardware-root here.
            This is the case for a swtpm vTPM (no EK cert), AND for a TPM that presents an
            EK certificate which is self-signed or does NOT chain to a trusted root (e.g. the
            swtpm's fake "IBM" EK cert) — merely HAVING an EK cert is NOT sufficient.
          * If a claim was produced AND the EK chains to a TRUSTED manufacturer/cloud root
            -> assurance 'TpmKeyAttestation-HardwareRoot', EkChainedToManufacturerRoot = $true.

        FR-19 honesty: hardware-root is claimed ONLY when the EK genuinely chains to a
        trusted hardware/cloud manufacturer root — never merely because some EK certificate
        is present. The trusted-root set is intended to grow to include cloud CAs (Azure
        Trusted Launch / Confidential VM, and potentially AWS NitroTPM) — see
        docs/reference/attestation.md.

    .PARAMETER ClaimProduced
        Whether a TPM key-attestation claim blob was successfully produced.

    .PARAMETER EkChainsToTrustedRoot
        Whether the EK certificate chains to a TRUSTED hardware/cloud manufacturer root.
        This is the load-bearing honesty signal: it must be computed conservatively
        (fail-closed to $false). A swtpm vTPM with no EK cert, OR a TPM whose EK cert is
        self-signed / does not chain to a trusted root, is $false.

    .OUTPUTS
        PSCustomObject with: AssuranceLevel, EkChainedToManufacturerRoot (bool),
        HardwareRoot (bool), Rationale.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [bool]$ClaimProduced,

        [Parameter(Mandatory)]
        [bool]$EkChainsToTrustedRoot
    )

    if (-not $ClaimProduced) {
        return New-DiscoveryResult -Property @{
            AssuranceLevel               = $script:AssuranceNone
            EkChainedToManufacturerRoot  = $false
            HardwareRoot                 = $false
            Rationale                    = 'No TPM key-attestation claim was produced.'
        }
    }

    if ($EkChainsToTrustedRoot) {
        return New-DiscoveryResult -Property @{
            AssuranceLevel               = $script:AssuranceTpmHardwareRoot
            EkChainedToManufacturerRoot  = $true
            HardwareRoot                 = $true
            Rationale                    = 'TPM key-attestation claim produced and the Endorsement Key chains to a TRUSTED manufacturer/cloud root certificate.'
        }
    }

    # Claim produced but EK does NOT chain to a trusted root -> NOT hardware-rooted.
    # Do not over-claim: this covers both "no EK cert at all" (e.g. a bare vTPM) and
    # "an EK cert is present but it is self-signed / does not chain to a trusted root"
    # (e.g. the swtpm's fake "IBM" EK cert). FR 19 forbids claiming hardware-root here.
    New-DiscoveryResult -Property @{
        AssuranceLevel               = $script:AssuranceTpmNoHardwareRoot
        EkChainedToManufacturerRoot  = $false
        HardwareRoot                 = $false
        Rationale                    = 'TPM key-attestation claim produced, but the Endorsement Key does NOT chain to a TRUSTED manufacturer/cloud root (no EK certificate, or a self-signed/untrusted EK certificate — typical of a virtual/firmware TPM such as swtpm). Hardware-root assurance is NOT claimed.'
    }
}

function Test-RequireHardwareRoot {
    <#
    .SYNOPSIS
        PURE decision: should -RequireHardwareRoot hard-fail for this assurance? (Open Question #1).

    .DESCRIPTION
        No OS calls. Default behaviour is report-and-warn (do NOT hard-fail) when the
        EK does not chain to a manufacturer root. The opt-in -RequireHardwareRoot
        switch flips that: when set AND EkChainedToManufacturerRoot is $false, the
        caller MUST hard-fail. This helper isolates that decision so it is testable
        without any TPM.

    .PARAMETER RequireHardwareRoot
        Whether the operator passed -RequireHardwareRoot.

    .PARAMETER EkChainedToManufacturerRoot
        Whether the EK chained to a manufacturer root (from Resolve-AttestationAssurance).

    .OUTPUTS
        PSCustomObject with: ShouldFail (bool), Reason.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [bool]$RequireHardwareRoot,

        [Parameter(Mandatory)]
        [bool]$EkChainedToManufacturerRoot
    )

    if ($RequireHardwareRoot -and -not $EkChainedToManufacturerRoot) {
        return New-DiscoveryResult -Property @{
            ShouldFail = $true
            Reason     = '-RequireHardwareRoot was specified but the TPM Endorsement Key does not chain to a manufacturer root (no EK certificate). Refusing to continue.'
        }
    }

    New-DiscoveryResult -Property @{
        ShouldFail = $false
        Reason     = if ($RequireHardwareRoot) {
            'Hardware root required and satisfied.'
        }
        else {
            'Hardware root not required; reporting EK-chain status without hard-failing (default).'
        }
    }
}

function ConvertTo-AttestationBundle {
    <#
    .SYNOPSIS
        PURE: shapes the attestation fields into a serialisable bundle object + JSON string.

    .DESCRIPTION
        No OS calls. Produces the canonical bundle SHAPE and its JSON serialisation.
        The bundle carries everything a verifier needs: the schema version, the claim
        type, the base64 claim blob, the subject certificate thumbprint + x5t, the
        base64 subject public-key blob (so verification can import the key without the
        private key), the EK public-key hash (best-effort), and the assurance summary.

        Serialising the binary fields as base64 keeps the bundle a plain JSON document.

    .PARAMETER Thumbprint
        Subject certificate thumbprint (identifies which key the claim is over).

    .PARAMETER X5tBase64Url
        Subject certificate x5t (base64url SHA-1) — handy cross-reference to the cert.

    .PARAMETER ClaimType
        The numeric CNG claim type used (e.g. 1 for AUTHORITY_AND_SUBJECT).

    .PARAMETER ClaimBlobBase64
        Base64 of the NCryptCreateClaim output blob.

    .PARAMETER PublicKeyBlobBase64
        Base64 of the subject key's CNG public-key blob (for re-import at verify time).

    .PARAMETER EkPublicKeyHash
        Best-effort EK public-key hash (string) from Get-TpmEndorsementKeyInfo, or $null.

    .PARAMETER Assurance
        The assurance object from Resolve-AttestationAssurance.

    .OUTPUTS
        PSCustomObject with: Object (the bundle PSCustomObject) and Json (string).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Thumbprint,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$X5tBase64Url,

        [Parameter(Mandatory)]
        [int]$ClaimType,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ClaimBlobBase64,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$PublicKeyBlobBase64,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$EkPublicKeyHash,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [pscustomobject]$Assurance
    )

    $bundle = [pscustomobject][ordered]@{
        SchemaVersion               = $script:AttestationBundleVersion
        Kind                        = 'ProaxiomDiscoveryAttestationBundle'
        CreatedUtc                  = ([System.DateTime]::UtcNow.ToString('o'))
        Thumbprint                  = $Thumbprint
        X5tBase64Url                = $X5tBase64Url
        ClaimType                   = $ClaimType
        ClaimBlobBase64             = $ClaimBlobBase64
        PublicKeyBlobBase64         = $PublicKeyBlobBase64
        EkPublicKeyHash             = $EkPublicKeyHash
        AssuranceLevel              = $Assurance.AssuranceLevel
        EkChainedToManufacturerRoot = [bool]$Assurance.EkChainedToManufacturerRoot
        HardwareRoot                = [bool]$Assurance.HardwareRoot
        Rationale                   = $Assurance.Rationale
    }

    # Depth 5 is ample for this flat object; -Compress kept off for human readability.
    $json = $bundle | ConvertTo-Json -Depth 5

    New-DiscoveryResult -Property @{
        Object = $bundle
        Json   = $json
    }
}

function ConvertFrom-AttestationBundle {
    <#
    .SYNOPSIS
        PURE: parses a serialised attestation bundle (JSON) back to an object.

    .DESCRIPTION
        No OS calls. Inverse of ConvertTo-AttestationBundle. Validates the document
        is the expected Kind and carries the load-bearing fields (claim blob,
        thumbprint, claim type). Throws a clear error on a malformed bundle.

    .PARAMETER Json
        The JSON text of a bundle.

    .OUTPUTS
        PSCustomObject (the parsed bundle).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Json
    )

    try {
        $obj = $Json | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Attestation bundle is not valid JSON: $($_.Exception.Message)"
    }

    $kind = $null
    if ($obj.PSObject.Properties.Name -contains 'Kind') { $kind = [string]$obj.Kind }
    if ($kind -ne 'ProaxiomDiscoveryAttestationBundle') {
        throw "Not a Proaxiom discovery attestation bundle (Kind = '$kind')."
    }

    foreach ($required in @('Thumbprint', 'ClaimType', 'ClaimBlobBase64')) {
        if (($obj.PSObject.Properties.Name -notcontains $required) -or
            [string]::IsNullOrWhiteSpace([string]$obj.$required)) {
            throw "Attestation bundle is missing the required field '$required'."
        }
    }

    $obj
}

# ---------------------------------------------------------------------------
# Windows / TPM functions (gated; exercised in Tier B on the CI vTPM runner)
# ---------------------------------------------------------------------------

function Get-AttestationEkInfo {
    <#
    .SYNOPSIS
        Gathers TPM Endorsement Key (EK) material and the TRUSTED-root determination (FR 19).

    .DESCRIPTION
        Windows-only. Prefers Get-TpmEndorsementKeyInfo (TrustedPlatformModule).
        Inspects the returned EK certificate collections:

          * ManufacturerCertificates - manufacturer EK certs (discrete TPM)
          * AdditionalCertificates   - additional EK certs registered to the OS
                                       (e.g. firmware/CPU-integrated TPM, enterprise)

        EkCertificatePresent is $true if EITHER collection contains at least one
        certificate. NOTE (FR 19 honesty): EkCertificatePresent is NOT, on its own,
        evidence of a hardware root — a swtpm vTPM presents a self-signed FAKE "IBM"
        EK certificate, so a cert can be PRESENT yet UNTRUSTED.

        The load-bearing honesty signal is EkChainsToTrustedRoot: it is $true ONLY when
        the EK certificate chains to a TRUSTED hardware/cloud manufacturer root. It is
        computed CONSERVATIVELY (fail-closed to $false on any uncertainty/failure):

          1. If Confirm-CAEndorsementKeyInfo is available it is consulted; a clear
             $false from it forces EkChainsToTrustedRoot = $false. (Its absence is NOT
             fatal — we fall through to the chain build.)
          2. Otherwise / additionally, every EK certificate found is run through an
             X509Chain validated against the machine's trusted TPM-manufacturer roots
             (Cert:\LocalMachine\TrustedTPM_RootCert + intermediates, plus the standard
             machine root stores). A self-signed EK cert (issuer == subject) or any cert
             whose chain does not reach a trusted root is rejected.
          3. Default is $false: no EK cert, no Get-TpmEndorsementKeyInfo, any exception,
             or any ambiguity all yield EkChainsToTrustedRoot = $false. The tool never
             claims a hardware root it cannot positively prove.

        Never throws on a TPM with no EK info: returns a populated object with
        IsPresent/EkCertificatePresent/EkChainsToTrustedRoot = $false. Off Windows it
        fails closed (throws).

    .OUTPUTS
        PSCustomObject with: IsPresent (bool), EkCertificatePresent (bool),
        EkChainsToTrustedRoot (bool), EkPublicKeyHash (string|null),
        ManufacturerCertCount (int), AdditionalCertCount (int), Source (string).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    if (-not (Test-IsWindows)) {
        throw 'Get-AttestationEkInfo is Windows-only (TPM EK info requires Windows + a TPM).'
    }

    $isPresent             = $false
    $ekCertificatePresent  = $false
    $ekChainsToTrustedRoot = $false   # FAIL CLOSED by default (FR 19).
    $ekPublicKeyHash       = $null
    $manufacturerCount     = 0
    $additionalCount       = 0
    $source                = 'none'
    $ekCerts               = @()

    if (Get-Command -Name 'Get-TpmEndorsementKeyInfo' -ErrorAction SilentlyContinue) {
        try {
            # -Hash SHA256 yields a PublicKeyHash; harmless if the EK is absent.
            $ek = Get-TpmEndorsementKeyInfo -Hash 'Sha256' -ErrorAction Stop
            $source = 'Get-TpmEndorsementKeyInfo'

            if ($null -ne $ek) {
                try { $isPresent = [bool]$ek.IsPresent } catch { $isPresent = $false }
                try { $ekPublicKeyHash = [string]$ek.PublicKeyHash } catch { $ekPublicKeyHash = $null }

                try {
                    if ($null -ne $ek.ManufacturerCertificates) {
                        $mc = @($ek.ManufacturerCertificates)
                        $manufacturerCount = $mc.Count
                        $ekCerts += $mc
                    }
                }
                catch { $manufacturerCount = 0 }

                try {
                    if ($null -ne $ek.AdditionalCertificates) {
                        $ac = @($ek.AdditionalCertificates)
                        $additionalCount = $ac.Count
                        $ekCerts += $ac
                    }
                }
                catch { $additionalCount = 0 }

                $ekCertificatePresent = (($manufacturerCount -gt 0) -or ($additionalCount -gt 0))
            }
        }
        catch {
            # EK info unavailable (common on vTPMs). Fail closed on the EK chain
            # determination (EkChainsToTrustedRoot stays $false) but do not throw —
            # a missing EK cert is an expected, reportable state, not an error.
            $source = 'Get-TpmEndorsementKeyInfo (no EK info)'
        }
    }
    else {
        $source = 'Get-TpmEndorsementKeyInfo not available'
    }

    # --- TRUSTED-root determination (fail-closed; FR 19) -------------------
    # Only attempt to PROVE trust if at least one EK cert exists. No cert => $false.
    if ($ekCertificatePresent) {
        $ekChainsToTrustedRoot = Test-EkChainsToTrustedRoot -EkCertificates $ekCerts
    }

    New-DiscoveryResult -Property @{
        IsPresent             = $isPresent
        EkCertificatePresent  = $ekCertificatePresent
        EkChainsToTrustedRoot = $ekChainsToTrustedRoot
        EkPublicKeyHash       = $ekPublicKeyHash
        ManufacturerCertCount = $manufacturerCount
        AdditionalCertCount   = $additionalCount
        Source                = $source
    }
}

function Test-EkChainsToTrustedRoot {
    <#
    .SYNOPSIS
        Windows helper: does any supplied EK certificate chain to a TRUSTED root? (FR 19, fail-closed)

    .DESCRIPTION
        Windows-only. Conservatively determines whether at least one of the supplied EK
        certificates chains to a trusted hardware/cloud manufacturer root. Returns $false
        on ANY uncertainty (no certs, self-signed cert, broken chain, exception). This is
        the honesty gate that prevents a self-signed/untrusted EK cert (e.g. the swtpm's
        fake "IBM" cert) from being reported as a hardware root.

        Method:
          1. Best-effort consult Confirm-CAEndorsementKeyInfo when available; a clear
             $false short-circuits to $false. Its absence / errors are non-fatal.
          2. For each EK cert: reject self-signed (issuer == subject). Otherwise build an
             X509Chain with the machine's TrustedTPM_RootCert / TrustedTPM_IntermediateCert
             stores added as ExtraStore, RevocationMode = NoCheck (offline-tolerant), and
             require the chain to BUILD with no status flags other than offline-revocation.
          3. Any cert that validates => $true. Otherwise $false.

    .PARAMETER EkCertificates
        The EK X509Certificate2 objects gathered from Get-TpmEndorsementKeyInfo.

    .OUTPUTS
        System.Boolean
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        [AllowNull()]
        [object[]]$EkCertificates
    )

    if (-not (Test-IsWindows)) {
        # Defensive: should never be called off Windows. Fail closed.
        return $false
    }

    $certs = @($EkCertificates | Where-Object { $null -ne $_ })
    if ($certs.Count -eq 0) { return $false }

    # Best-effort negative signal from Confirm-CAEndorsementKeyInfo (some SKUs ship it).
    # We only ACT on a clear $false (forces untrusted); a $true or absence is NOT trusted
    # on its own — we still require the chain build below to positively prove trust.
    try {
        if (Get-Command -Name 'Confirm-CAEndorsementKeyInfo' -ErrorAction SilentlyContinue) {
            foreach ($c in $certs) {
                try {
                    $ck = Confirm-CAEndorsementKeyInfo -EndorsementKeyCertificate $c -ErrorAction Stop
                    if ($null -ne $ck -and ($ck -is [bool]) -and (-not $ck)) {
                        return $false
                    }
                }
                catch {
                    # non-fatal; fall through to the chain build.
                }
            }
        }
    }
    catch { }

    # Load the machine's trusted TPM-manufacturer roots/intermediates as ExtraStore so the
    # chain can terminate at a manufacturer root even if it is not in the default Root store.
    $extra = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
    foreach ($storePath in @('Cert:\LocalMachine\TrustedTPM_RootCert',
                             'Cert:\LocalMachine\TrustedTPM_IntermediateCert')) {
        try {
            if (Test-Path -LiteralPath $storePath) {
                Get-ChildItem -LiteralPath $storePath -ErrorAction SilentlyContinue |
                    ForEach-Object { $null = $extra.Add($_) }
            }
        }
        catch { }
    }

    foreach ($c in $certs) {
        try {
            # Reject a self-signed EK cert outright (issuer == subject) — the swtpm fake
            # "IBM" EK cert is self-signed; it must NEVER be treated as a trusted root.
            if ($c.Issuer -eq $c.Subject) { continue }

            $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
            $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
            $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot
            $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::IgnoreEndRevocationUnknown
            if ($extra.Count -gt 0) { $null = $chain.ChainPolicy.ExtraStore.AddRange($extra) }

            $built = $chain.Build($c)
            if (-not $built) { continue }

            # Accept only a chain that terminated at a root in a trusted store. Tolerate
            # offline-revocation status; reject anything else (UntrustedRoot, PartialChain…).
            $badFlags = $false
            foreach ($el in $chain.ChainElements) {
                foreach ($st in $el.ChainElementStatus) {
                    if ($st.Status -ne [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::NoError -and
                        $st.Status -ne [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::RevocationStatusUnknown -and
                        $st.Status -ne [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::OfflineRevocation) {
                        $badFlags = $true
                    }
                }
            }
            if (-not $badFlags) { return $true }
        }
        catch {
            # Any failure on this cert => skip it; do not let it produce a false positive.
            continue
        }
    }

    # Nothing positively chained to a trusted root => fail closed.
    return $false
}

function New-DiscoveryAttestation {
    <#
    .SYNOPSIS
        Produces a TPM key-attestation bundle for a generated key (GenerateLocal, FR 17).

    .DESCRIPTION
        Windows + TPM only. Creates a CNG key-attestation claim over the supplied
        certificate's TPM-resident key via NCryptCreateClaim
        (NCRYPT_CLAIM_AUTHORITY_AND_SUBJECT, subject == authority = a self-claim),
        gathers EK material (Get-AttestationEkInfo), derives the assurance level
        (Resolve-AttestationAssurance) and packages everything into a bundle
        (ConvertTo-AttestationBundle).

        Honesty: a vTPM with no EK certificate yields
        EkChainedToManufacturerRoot = $false and a NOT-hardware-rooted assurance
        level — hardware-root is never claimed in that case (FR 19).

        Two-call buffer-sizing pattern: NCryptCreateClaim is first called with a NULL
        output buffer to learn the required size, then again to fill the buffer.

        Fails closed off Windows (throws). The provider/TPM gate is the caller's
        responsibility (the entry script runs Test-PlatformCryptoProvider first).

    .PARAMETER Certificate
        The certificate whose TPM-resident private key is attested.

    .OUTPUTS
        PSCustomObject (the bundle object from ConvertTo-AttestationBundle .Object,
        with an added .Json property carrying the serialised form).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    if (-not (Test-IsWindows)) {
        throw 'New-DiscoveryAttestation is Windows-only: TPM key attestation requires Windows + a TPM (Microsoft Platform Crypto Provider).'
    }

    Add-AttestationInterop

    # --- Read the live CNG key (must be a TPM/MPCP key) --------------------
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    if ($null -eq $rsa) {
        throw 'Certificate has no readable RSA private key; cannot attest.'
    }
    $cngKey = $null
    try { $cngKey = $rsa.Key } catch { $cngKey = $null }
    if ($null -eq $cngKey) {
        throw 'Certificate private key is not a CNG key; TPM attestation requires a CNG (Platform Crypto Provider) key.'
    }

    # Capture the public-key blob now (for re-import at verify time) and the x5t.
    $pubBlobBase64 = $null
    try {
        $pubBlob = $cngKey.Export([System.Security.Cryptography.CngKeyBlobFormat]::GenericPublicBlob)
        $pubBlobBase64 = [System.Convert]::ToBase64String($pubBlob)
    }
    catch {
        # Public-blob export should not fail for a normal key; leave null if it does.
        $pubBlobBase64 = $null
    }

    $x5t = $null
    try {
        $hash = $Certificate.GetCertHash('SHA1')
        $x5t  = ([System.Convert]::ToBase64String($hash)).Replace('+', '-').Replace('/', '_').TrimEnd('=')
    }
    catch {
        try {
            $hash = $Certificate.GetCertHash()
            $x5t  = ([System.Convert]::ToBase64String($hash)).Replace('+', '-').Replace('/', '_').TrimEnd('=')
        }
        catch { $x5t = $null }
    }

    # --- Create the claim (NCryptCreateClaim) ------------------------------
    # Keep $cngKey alive across both native calls (the raw handle is derived from
    # its SafeNCryptKeyHandle).
    $hKey      = Get-NCryptKeyHandle -CngKey $cngKey
    $claimType = [uint32]$script:NCRYPT_CLAIM_AUTHORITY_AND_SUBJECT

    # 1. Size query: NULL output buffer.
    $cbResult = [uint32]0
    $status = [Proaxiom.Attestation.NCryptInterop]::NCryptCreateClaim(
        $hKey, $hKey, $claimType, [System.IntPtr]::Zero,
        $null, [uint32]0, [ref]$cbResult, [uint32]0)
    if ($status -ne 0) {
        throw ("NCryptCreateClaim (size query) failed with SECURITY_STATUS 0x{0:X8}. Claim type AUTHORITY_AND_SUBJECT may be unsupported by this TPM/KSP, or the key is not attestable." -f $status)
    }
    if ($cbResult -le 0) {
        throw 'NCryptCreateClaim reported a zero-length claim; cannot continue.'
    }

    # 2. Produce the claim into a sized buffer.
    $claimBlob = New-Object byte[] ([int]$cbResult)
    $written   = [uint32]0
    $status = [Proaxiom.Attestation.NCryptInterop]::NCryptCreateClaim(
        $hKey, $hKey, $claimType, [System.IntPtr]::Zero,
        $claimBlob, $cbResult, [ref]$written, [uint32]0)
    if ($status -ne 0) {
        throw ("NCryptCreateClaim (produce) failed with SECURITY_STATUS 0x{0:X8}." -f $status)
    }

    # Trim to the bytes actually written (defensive; usually equals $cbResult).
    if ($written -lt $claimBlob.Length) {
        $trimmed = New-Object byte[] ([int]$written)
        [System.Array]::Copy($claimBlob, $trimmed, [int]$written)
        $claimBlob = $trimmed
    }

    # Keep the key object referenced until here so the native handle stayed valid.
    $null = $cngKey

    $claimBase64 = [System.Convert]::ToBase64String($claimBlob)

    # --- EK material + assurance decision ----------------------------------
    $ek = Get-AttestationEkInfo
    $assurance = Resolve-AttestationAssurance `
        -ClaimProduced $true `
        -EkChainsToTrustedRoot ([bool]$ek.EkChainsToTrustedRoot)

    # --- Package the bundle ------------------------------------------------
    $bundleResult = ConvertTo-AttestationBundle `
        -Thumbprint $Certificate.Thumbprint `
        -X5tBase64Url $x5t `
        -ClaimType ([int]$claimType) `
        -ClaimBlobBase64 $claimBase64 `
        -PublicKeyBlobBase64 $pubBlobBase64 `
        -EkPublicKeyHash $ek.EkPublicKeyHash `
        -Assurance $assurance

    # Return the bundle object with the JSON attached for the writer.
    $out = $bundleResult.Object
    $out | Add-Member -NotePropertyName 'Json' -NotePropertyValue $bundleResult.Json -Force
    $out
}

function Test-DiscoveryAttestation {
    <#
    .SYNOPSIS
        Verifies a supplied attestation bundle (ImportCert, FR 18).

    .DESCRIPTION
        Windows + TPM only for the cryptographic verification step. Parses the bundle
        (ConvertFrom-AttestationBundle — pure), re-imports the subject public key from
        the bundle's PublicKeyBlobBase64 via CngKey.Import, then calls NCryptVerifyClaim
        with the SAME claim type the bundle records (AUTHORITY_AND_SUBJECT, subject ==
        authority). VerifyResult is $true only when NCryptVerifyClaim returns
        SECURITY_STATUS 0 (success).

        The result FAITHFULLY re-reports the bundle's recorded assurance (it does NOT
        upgrade it): EkChainedToManufacturerRoot and AssuranceLevel come straight from
        the bundle, so a vTPM bundle still reports NOT hardware-rooted after a
        successful verify (FR 19).

        Fails closed off Windows (throws) — verification needs the TPM KSP.

    .PARAMETER Path
        Path to the serialised attestation bundle (JSON).

    .OUTPUTS
        PSCustomObject with: VerifyResult (bool), Thumbprint, AssuranceLevel,
        EkChainedToManufacturerRoot (bool), HardwareRoot (bool), Reason, BundlePath.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Attestation bundle file not found: '$Path'."
    }

    $json   = Get-Content -LiteralPath $Path -Raw
    $bundle = ConvertFrom-AttestationBundle -Json $json

    if (-not (Test-IsWindows)) {
        throw 'Test-DiscoveryAttestation verification is Windows-only: NCryptVerifyClaim requires the Windows TPM KSP.'
    }

    Add-AttestationInterop

    $pubBlobB64 = $null
    if ($bundle.PSObject.Properties.Name -contains 'PublicKeyBlobBase64') {
        $pubBlobB64 = [string]$bundle.PublicKeyBlobBase64
    }
    if ([string]::IsNullOrWhiteSpace($pubBlobB64)) {
        throw 'Attestation bundle has no PublicKeyBlobBase64; cannot re-import the subject key for verification.'
    }

    $claimBlob = [System.Convert]::FromBase64String([string]$bundle.ClaimBlobBase64)
    $claimType = [uint32]([int]$bundle.ClaimType)

    # Re-import the subject public key into a CngKey so we have an NCRYPT_KEY_HANDLE.
    $pubBlob = [System.Convert]::FromBase64String($pubBlobB64)
    $importedKey = [System.Security.Cryptography.CngKey]::Import(
        $pubBlob,
        [System.Security.Cryptography.CngKeyBlobFormat]::GenericPublicBlob)

    $verifyResult = $false
    $reason       = $null
    try {
        $hKey = Get-NCryptKeyHandle -CngKey $importedKey
        # AUTHORITY_AND_SUBJECT self-claim: subject == authority handle.
        $status = [Proaxiom.Attestation.NCryptInterop]::NCryptVerifyClaim(
            $hKey, $hKey, $claimType, [System.IntPtr]::Zero,
            $claimBlob, [uint32]$claimBlob.Length, [System.IntPtr]::Zero, [uint32]0)

        $verifyResult = ($status -eq 0)
        $reason = if ($verifyResult) {
            'NCryptVerifyClaim succeeded: the claim is valid for the supplied key.'
        }
        else {
            ("NCryptVerifyClaim failed with SECURITY_STATUS 0x{0:X8}." -f $status)
        }

        # Keep the imported key alive across the native call.
        $null = $importedKey
    }
    finally {
        if ($null -ne $importedKey) {
            try { $importedKey.Dispose() } catch { }
        }
    }

    # Re-report the bundle's RECORDED assurance verbatim (do not upgrade — FR 19).
    $ekChained = $false
    if ($bundle.PSObject.Properties.Name -contains 'EkChainedToManufacturerRoot') {
        $ekChained = [bool]$bundle.EkChainedToManufacturerRoot
    }
    $hwRoot = $false
    if ($bundle.PSObject.Properties.Name -contains 'HardwareRoot') {
        $hwRoot = [bool]$bundle.HardwareRoot
    }
    $assuranceLevel = $null
    if ($bundle.PSObject.Properties.Name -contains 'AssuranceLevel') {
        $assuranceLevel = [string]$bundle.AssuranceLevel
    }

    New-DiscoveryResult -Property @{
        VerifyResult                = $verifyResult
        Thumbprint                  = [string]$bundle.Thumbprint
        AssuranceLevel              = $assuranceLevel
        EkChainedToManufacturerRoot = $ekChained
        HardwareRoot                = $hwRoot
        Reason                      = $reason
        BundlePath                  = $Path
    }
}

Export-ModuleMember -Function `
    Add-AttestationInterop, `
    Get-AttestationEkInfo, `
    Resolve-AttestationAssurance, `
    Test-RequireHardwareRoot, `
    ConvertTo-AttestationBundle, `
    ConvertFrom-AttestationBundle, `
    New-DiscoveryAttestation, `
    Test-DiscoveryAttestation
