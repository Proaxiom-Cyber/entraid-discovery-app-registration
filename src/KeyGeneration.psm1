<#
.SYNOPSIS
    TPM-backed key generation and certificate handling for the discovery app.

.DESCRIPTION
    Implements the credential / key-generation functional requirements (FR 6-11)
    of the entraid-discovery-app PRD:

      * Test-PlatformCryptoProvider       - probe for a usable TPM / MPCP (FR 7, 8)
      * New-DiscoveryTpmKey               - create a non-exportable RSA-2048 key in
                                            the Microsoft Platform Crypto Provider (FR 7)
      * Assert-KeyNonExportable           - prove the private key cannot be exported (FR 7)
      * Export-DiscoveryPublicCertificate - write the public .cer only (FR 10)
      * Import-DiscoveryPublicCertificate - accept a supplied public cert (FR 11)
      * Get-DiscoveryCertMetadata         - normalised metadata for downstream use
      * Format-DiscoveryKeyResult         - human-readable summary

    Cross-compatible with Windows PowerShell 5.1 (Desktop) and PowerShell 7.x (Core)
    on Windows (FR 21). The provider probe and import paths degrade gracefully on
    non-Windows hosts (returning populated objects rather than throwing) so the
    module can be parsed and unit-tested off-host.
#>

Set-StrictMode -Version Latest

Import-Module "$PSScriptRoot/Common.psm1" -Force

# Canonical provider name. Referenced everywhere a literal string would otherwise drift.
$script:MpcpName = 'Microsoft Platform Crypto Provider'

# ---------------------------------------------------------------------------
# Internal (non-exported) helpers
# ---------------------------------------------------------------------------

function Resolve-StorePath {
    <#
    .SYNOPSIS
        Maps a store-location keyword to a Cert:\ PSDrive path for the personal store.

    .DESCRIPTION
        'LocalMachine' -> 'Cert:\LocalMachine\My', 'CurrentUser' -> 'Cert:\CurrentUser\My'.
        Used as the -CertStoreLocation argument for New-SelfSignedCertificate and as the
        StorePath reported in metadata.

    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('LocalMachine', 'CurrentUser')]
        [string]$StoreLocation
    )

    "Cert:\$StoreLocation\My"
}

function Get-X5tThumbprint {
    <#
    .SYNOPSIS
        Computes the base64url (no padding) SHA-1 thumbprint of a certificate.

    .DESCRIPTION
        Entra / JWT client assertions identify the signing certificate via the
        "x5t" header: base64url of the raw SHA-1 hash BYTES of the certificate
        (not the hex thumbprint string). This helper produces exactly that value.

    .PARAMETER Certificate
        The certificate to fingerprint.

    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    # GetCertHash('SHA1') returns the raw 20-byte SHA-1 hash of the DER cert.
    # (Plain GetCertHash() is also SHA-1, but we pass the algorithm explicitly
    #  for clarity and forward-compat. The overload exists on .NET / PS 7; on
    #  5.1 fall back to the parameterless form which is SHA-1 by definition.)
    $hashBytes = $null
    try {
        $hashBytes = $Certificate.GetCertHash('SHA1')
    }
    catch {
        $hashBytes = $Certificate.GetCertHash()
    }

    $b64 = [System.Convert]::ToBase64String($hashBytes)
    # base64 -> base64url, strip padding.
    $b64.Replace('+', '-').Replace('/', '_').TrimEnd('=')
}

# ---------------------------------------------------------------------------
# Exported functions
# ---------------------------------------------------------------------------

function Get-DiscoveryExistingKeyMatch {
    <#
    .SYNOPSIS
        Returns the non-expired certificates in a set whose subject matches (FR 20).

    .DESCRIPTION
        Idempotency helper for the GenerateLocal path. Given a set of certificates
        (e.g. the contents of a Cert:\<loc>\My store) and a subject distinguished
        name, returns only those whose .Subject equals the supplied subject AND whose
        .NotAfter is in the future (not expired) as of -AsOf (default: now).

        PURE (no live store access — the caller supplies the certificate list), so it
        is Tier-A unit-testable without a real certificate store. The entry script
        uses it to WARN about pre-existing same-subject keys before generating a new
        one (rotation), rather than blocking or deleting.

        Subject comparison is case-insensitive exact (the distinguished name as the
        store reports it, e.g. 'CN=Proaxiom Discovery App').

    .PARAMETER Certificate
        The certificates to filter (e.g. Get-ChildItem Cert:\LocalMachine\My). May be
        $null / empty, in which case an empty result is returned.

    .PARAMETER Subject
        The subject distinguished name to match. Required.

    .PARAMETER AsOf
        The instant to evaluate expiry against. Defaults to (Get-Date). A certificate
        counts as non-expired when its NotAfter is strictly greater than AsOf.

    .OUTPUTS
        The matching certificate objects (zero or more). Returns nothing when none match.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [object[]]$Certificate,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Subject,

        [Parameter()]
        [datetime]$AsOf = (Get-Date)
    )

    if ($null -eq $Certificate) {
        return
    }

    $Certificate | Where-Object {
        $null -ne $_ -and
        $_.PSObject.Properties.Match('Subject').Count -gt 0 -and
        [string]$_.Subject -eq $Subject -and
        $_.PSObject.Properties.Match('NotAfter').Count -gt 0 -and
        [datetime]$_.NotAfter -gt $AsOf
    }
}

function Test-PlatformCryptoProvider {
    <#
    .SYNOPSIS
        Probes for a usable TPM and the Microsoft Platform Crypto Provider (FR 8).

    .DESCRIPTION
        FAIL-CLOSED gate. Defense in depth: TPM presence/readiness, the provider
        being listed by certutil, AND the provider actually opening via CNG must
        ALL succeed before Available is reported $true. Any failure (or any error
        reading TPM state) results in Available = $false so the caller never
        proceeds to software-key generation by accident.

        Never throws on a non-Windows host: returns a populated object with
        Available = $false and an explanatory Reason.

    .OUTPUTS
        PSCustomObject with: Available, TpmPresent, TpmReady, ProviderListed,
        ProviderOpens, Reason
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $tpmPresent     = $false
    $tpmReady       = $false
    $providerListed = $false
    $providerOpens  = $false
    $reason         = $null

    if (-not (Test-IsWindows)) {
        return New-DiscoveryResult -Property @{
            Available      = $false
            TpmPresent     = $false
            TpmReady       = $false
            ProviderListed = $false
            ProviderOpens  = $false
            Reason         = 'Not a Windows host'
        }
    }

    # --- 1. TPM presence / readiness ---------------------------------------
    # Prefer Get-Tpm (TrustedPlatformModule module). Fall back to WMI.
    $tpmQueried = $false
    try {
        if (Get-Command -Name 'Get-Tpm' -ErrorAction SilentlyContinue) {
            $tpm = Get-Tpm -ErrorAction Stop
            if ($null -ne $tpm) {
                $tpmQueried = $true
                # Properties are nullable booleans; coerce defensively.
                $tpmPresent = [bool]$tpm.TpmPresent
                $tpmReady   = [bool]$tpm.TpmReady
            }
        }
    }
    catch {
        # Get-Tpm can fail when not elevated or when the TBS service is unavailable.
        # Do not assume present; fall through to WMI.
        $tpmQueried = $false
    }

    if (-not $tpmQueried) {
        try {
            $wmiTpm = Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftTpm' `
                                      -ClassName 'Win32_Tpm' -ErrorAction Stop
            if ($null -ne $wmiTpm) {
                $tpmPresent = $true
                # IsEnabled_InitialValue + IsActivated_InitialValue approximate "ready".
                $enabled   = $false
                $activated = $false
                try { $enabled   = [bool]$wmiTpm.IsEnabled_InitialValue }   catch { $enabled   = $false }
                try { $activated = [bool]$wmiTpm.IsActivated_InitialValue } catch { $activated = $false }
                $tpmReady = ($enabled -and $activated)
            }
        }
        catch {
            # No instance, access denied, or namespace missing => fail closed.
            $tpmPresent = $false
            $tpmReady   = $false
        }
    }

    if (-not $tpmPresent) {
        $reason = 'TPM not present'
    }
    elseif (-not $tpmReady) {
        $reason = 'TPM present but not ready'
    }

    # --- 2. Provider listed by certutil ------------------------------------
    if ($null -eq $reason) {
        try {
            $cspList = & certutil -csplist 2>$null
            $cspText = ($cspList | Out-String)
            if ($cspText -match [regex]::Escape($script:MpcpName)) {
                $providerListed = $true
            }
        }
        catch {
            $providerListed = $false
        }

        if (-not $providerListed) {
            $reason = "'$script:MpcpName' not listed by certutil -csplist"
        }
    }

    # --- 3. Provider actually opens via CNG --------------------------------
    if ($null -eq $reason) {
        try {
            $cngProvider = [System.Security.Cryptography.CngProvider]::new($script:MpcpName)
            # Enumerating keys forces the provider to be opened (NCryptOpenStorageProvider
            # under the hood). An invalid / unavailable provider throws here.
            $null = [System.Security.Cryptography.CngKey]::GetCurrentUserKeyNames($cngProvider)
            $providerOpens = $true
        }
        catch {
            # GetCurrentUserKeyNames may not exist on Windows PowerShell 5.1's older
            # .NET surface. Fall back to a key-existence probe, which also opens the
            # provider. A "key not found" style failure still means the provider opened.
            try {
                $null = [System.Security.Cryptography.CngKey]::Exists(
                    '___proaxiom_probe_nonexistent___',
                    [System.Security.Cryptography.CngProvider]::new($script:MpcpName),
                    [System.Security.Cryptography.CngKeyOpenOptions]::None)
                $providerOpens = $true
            }
            catch {
                $providerOpens = $false
            }
        }

        if (-not $providerOpens) {
            $reason = "'$script:MpcpName' failed to open via CNG"
        }
    }

    $available = ($tpmPresent -and $tpmReady -and $providerListed -and $providerOpens)
    if ($available -and $null -eq $reason) {
        $reason = 'OK'
    }

    New-DiscoveryResult -Property @{
        Available      = $available
        TpmPresent     = $tpmPresent
        TpmReady       = $tpmReady
        ProviderListed = $providerListed
        ProviderOpens  = $providerOpens
        Reason         = $reason
    }
}

function New-DiscoveryTpmKey {
    <#
    .SYNOPSIS
        Creates a non-exportable RSA-2048 key in the Microsoft Platform Crypto Provider (FR 7, 9).

    .DESCRIPTION
        Generates a self-signed certificate whose private key lives in the TPM via
        the Microsoft Platform Crypto Provider, marked NonExportable and usable for
        signing (client assertions). The fail-closed provider gate is the caller's
        responsibility (the entry script runs Test-PlatformCryptoProvider first);
        this function may also be invoked directly in tests.

    .PARAMETER Subject
        Certificate subject distinguished name (e.g. 'CN=Proaxiom Discovery App').

    .PARAMETER ValidityMonths
        Certificate validity in months.

    .PARAMETER StoreLocation
        Certificate store location: 'LocalMachine' or 'CurrentUser'.

    .OUTPUTS
        PSCustomObject (certificate metadata from Get-DiscoveryCertMetadata).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Subject,

        [Parameter(Mandatory)]
        [ValidateRange(1, 120)]
        [int]$ValidityMonths,

        [Parameter(Mandatory)]
        [ValidateSet('LocalMachine', 'CurrentUser')]
        [string]$StoreLocation
    )

    $storePath = Resolve-StorePath -StoreLocation $StoreLocation

    $params = @{
        Subject           = $Subject
        Provider          = $script:MpcpName
        KeyAlgorithm      = 'RSA'
        KeyLength         = 2048
        KeyExportPolicy   = 'NonExportable'
        # NB: do NOT set -KeySpec here. The Microsoft Platform Crypto Provider is a
        # CNG-only (NCrypt) provider with no legacy CSP provider type, so passing
        # -KeySpec (Signature / KeyExchange) makes New-SelfSignedCertificate attempt
        # a legacy CSP mapping and fail with NTE_PROV_TYPE_NOT_DEF (0x80090017) on a
        # real TPM. Use -KeyUsage DigitalSignature to express the signing intent
        # instead; the CNG key is created without a legacy KeySpec.
        KeyUsage          = 'DigitalSignature'
        HashAlgorithm     = 'SHA256'
        NotAfter          = (Get-Date).AddMonths($ValidityMonths)
        CertStoreLocation = $storePath
    }

    $cert = New-SelfSignedCertificate @params

    Get-DiscoveryCertMetadata -Certificate $cert
}

function Assert-KeyNonExportable {
    <#
    .SYNOPSIS
        Proves the certificate's private key is non-exportable and TPM-resident (FR 8).

    .DESCRIPTION
        Verifies OUTCOME, not intent. Reads the live CngKey, requires the provider
        to be the Microsoft Platform Crypto Provider AND the CNG export policy to be
        None, then actively attempts a CNG private-key blob export (Pkcs8PrivateBlob)
        and requires it to THROW. NonExportable is true only if all three hold.

        WHY a CNG blob export (not X509Certificate2.Export('Pfx',...)): on .NET
        Framework (Windows PowerShell 5.1) a Pfx export attempt against a TPM/MPCP
        non-exportable key DOES throw, but it POISONS the underlying CNG key handle
        process-wide — afterwards GetRSAPrivateKey() fails with "Invalid flags
        specified" even on a fresh Get-Item reload of the cert, for the rest of the
        process. That makes the check non-idempotent. Exporting the CNG key's
        Pkcs8PrivateBlob is framework-consistent (throws on both 5.1 and 7 for a
        non-exportable key) and side-effect-free (does NOT poison the handle), so the
        function can be called repeatedly and sibling reads of the key still work.

    .PARAMETER Certificate
        The certificate (with private key) to inspect.

    .OUTPUTS
        PSCustomObject with: NonExportable, ProviderName, ExportPolicy, ExportAttemptThrew
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $providerName      = $null
    $exportPolicy      = $null
    $providerMatches   = $false
    $policyIsNone      = $false
    $exportAttemptThrew = $false
    $cngKey            = $null

    # --- Inspect the live CNG key ------------------------------------------
    try {
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
        if ($null -ne $rsa) {
            try {
                # RSACng exposes .Key (a CngKey). Guard in case of a non-CNG key.
                $cngKey = $rsa.Key
            }
            catch {
                $cngKey = $null
            }

            if ($null -ne $cngKey) {
                try { $providerName = $cngKey.Provider.Provider } catch { $providerName = $null }
                try { $exportPolicy = $cngKey.ExportPolicy.ToString() } catch { $exportPolicy = $null }

                $providerMatches = ($providerName -eq $script:MpcpName)
                $policyIsNone    = ($exportPolicy -eq 'None')
            }
        }
    }
    catch {
        # Could not read the CNG key at all -> treat as not-provably-non-exportable.
        $providerMatches = $false
        $policyIsNone    = $false
    }

    # --- Active export attempt (must throw) --------------------------------
    # Export the CNG key's Pkcs8PrivateBlob rather than X509Certificate2.Export('Pfx').
    # On .NET Framework (PS 5.1) a Pfx export poisons the CNG key handle process-wide
    # (see .DESCRIPTION); the CNG blob export throws for a non-exportable key on both
    # 5.1 and 7 WITHOUT poisoning the handle. If we couldn't read $cngKey, we cannot
    # prove the export threw -> leave $exportAttemptThrew = $false (fails closed;
    # providerMatches / policyIsNone are also false in that case).
    if ($null -ne $cngKey) {
        try {
            $null = $cngKey.Export([System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)
            # If we reach here the private key blob was exported => exportable => FAIL.
            $exportAttemptThrew = $false
        }
        catch {
            $exportAttemptThrew = $true
        }
    }
    else {
        $exportAttemptThrew = $false
    }

    $nonExportable = ($providerMatches -and $policyIsNone -and $exportAttemptThrew)

    New-DiscoveryResult -Property @{
        NonExportable      = $nonExportable
        ProviderName       = $providerName
        ExportPolicy       = $exportPolicy
        ExportAttemptThrew = $exportAttemptThrew
    }
}

function Export-DiscoveryPublicCertificate {
    <#
    .SYNOPSIS
        Exports only the public certificate (.cer, DER) for upload to Entra (FR 10).

    .DESCRIPTION
        Writes the PUBLIC certificate only -- never the private key. Uses
        Export-Certificate -Type CERT (DER encoding). Defaults the path to
        "<thumbprint>.cer" in the current directory when none is supplied, and
        refuses to overwrite an existing file unless -Force is given.

    .PARAMETER Certificate
        The certificate whose public portion is exported.

    .PARAMETER Path
        Destination path for the .cer file. Defaults to "$PWD/<thumbprint>.cer".

    .PARAMETER Force
        Overwrite an existing file at Path.

    .OUTPUTS
        PSCustomObject with: Path, Thumbprint, Format
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Path,

        [switch]$Force
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        $Path = Join-Path -Path (Get-Location).Path -ChildPath ("{0}.cer" -f $Certificate.Thumbprint)
    }

    if ((Test-Path -LiteralPath $Path) -and -not $Force) {
        throw "Destination '$Path' already exists. Use -Force to overwrite."
    }

    # Export-Certificate writes the public certificate only; -Type CERT => DER.
    $null = Export-Certificate -Cert $Certificate -FilePath $Path -Type CERT -Force:$Force

    New-DiscoveryResult -Property @{
        Path       = $Path
        Thumbprint = $Certificate.Thumbprint
        Format     = 'DER'
    }
}

function Import-DiscoveryPublicCertificate {
    <#
    .SYNOPSIS
        Imports a supplied public certificate without generating a key (FR 11).

    .DESCRIPTION
        Accepts a DER/PEM .cer/.crt file or a base64 text file. Generates NO key.
        Asserts the result is a PUBLIC certificate (HasPrivateKey is false).

    .PARAMETER Path
        Path to the supplied public certificate.

    .OUTPUTS
        PSCustomObject (certificate metadata from Get-DiscoveryCertMetadata).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Public certificate file not found: '$Path'."
    }

    $cert = $null

    # --- Attempt 1: let X509Certificate2 sniff the file (DER or PEM .cer) ---
    try {
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($Path)
    }
    catch {
        $cert = $null
    }

    # --- Attempt 2: treat as base64 (possibly PEM-armoured) text -----------
    if ($null -eq $cert) {
        $raw = Get-Content -LiteralPath $Path -Raw

        # Strip PEM armour if present (BEGIN/END CERTIFICATE lines and whitespace).
        $b64 = ($raw -replace '-----BEGIN [^-]+-----', '' `
                     -replace '-----END [^-]+-----', '')
        $b64 = ($b64 -replace '\s', '')

        if ([string]::IsNullOrWhiteSpace($b64)) {
            throw "Could not parse '$Path' as a certificate (empty after stripping armour)."
        }

        try {
            $bytes = [System.Convert]::FromBase64String($b64)
        }
        catch {
            throw "Could not parse '$Path' as a certificate (not valid DER and not valid base64)."
        }

        try {
            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes)
        }
        catch {
            throw "Could not parse '$Path' as a certificate (base64 bytes are not a valid X.509 certificate)."
        }
    }

    if ($null -eq $cert) {
        throw "Could not parse '$Path' as a certificate."
    }

    if ($cert.HasPrivateKey) {
        throw "Supplied file '$Path' contains a private key. A PUBLIC certificate is required."
    }

    Get-DiscoveryCertMetadata -Certificate $cert
}

function Get-DiscoveryCertMetadata {
    <#
    .SYNOPSIS
        Produces normalised metadata for a certificate (public or with private key).

    .DESCRIPTION
        Captures the inputs needed by the downstream auth / report flow (FR 15):
        thumbprint, subject, validity window, key algorithm/length, CNG provider
        name (best-effort), whether a private key is present, the base64url x5t
        value, and the Cert:\ store path the certificate resides in (best-effort).

    .PARAMETER Certificate
        The certificate to describe.

    .OUTPUTS
        PSCustomObject with: Thumbprint, Subject, NotBefore, NotAfter, KeyAlgorithm,
        KeyLength, ProviderName, HasPrivateKey, X5tBase64Url, StorePath
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $keyAlgorithm = $null
    $keyLength    = $null
    $providerName = $null
    $hasPrivate   = $false
    $storePath    = $null

    try { $hasPrivate = [bool]$Certificate.HasPrivateKey } catch { $hasPrivate = $false }

    # Public-key algorithm + length come from the public key regardless of private-key state.
    try {
        $pub = $Certificate.PublicKey
        if ($null -ne $pub -and $null -ne $pub.Oid) {
            $keyAlgorithm = $pub.Oid.FriendlyName
        }
    }
    catch {
        $keyAlgorithm = $null
    }

    try {
        $rsaPub = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($Certificate)
        if ($null -ne $rsaPub) {
            $keyLength = $rsaPub.KeySize
            if ([string]::IsNullOrWhiteSpace($keyAlgorithm)) { $keyAlgorithm = 'RSA' }
        }
    }
    catch {
        $keyLength = $null
    }

    # Provider name: best-effort, only meaningful when a private key is present.
    if ($hasPrivate) {
        try {
            $rsaPriv = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
            if ($null -ne $rsaPriv) {
                $cngKey = $null
                try { $cngKey = $rsaPriv.Key } catch { $cngKey = $null }
                if ($null -ne $cngKey) {
                    try { $providerName = $cngKey.Provider.Provider } catch { $providerName = $null }
                }
            }
        }
        catch {
            $providerName = $null
        }
    }

    # Store path: best-effort. The X509Certificate2 object does not carry its store,
    # so probe the standard personal stores for a matching thumbprint.
    try {
        foreach ($loc in @('CurrentUser', 'LocalMachine')) {
            $candidate = "Cert:\$loc\My\$($Certificate.Thumbprint)"
            if (Test-Path -LiteralPath $candidate -ErrorAction SilentlyContinue) {
                $storePath = "Cert:\$loc\My"
                break
            }
        }
    }
    catch {
        $storePath = $null
    }

    New-DiscoveryResult -Property @{
        Thumbprint    = $Certificate.Thumbprint
        Subject       = $Certificate.Subject
        NotBefore     = $Certificate.NotBefore
        NotAfter      = $Certificate.NotAfter
        KeyAlgorithm  = $keyAlgorithm
        KeyLength     = $keyLength
        ProviderName  = $providerName
        HasPrivateKey = $hasPrivate
        X5tBase64Url  = (Get-X5tThumbprint -Certificate $Certificate)
        StorePath     = $storePath
    }
}

function Format-DiscoveryKeyResult {
    <#
    .SYNOPSIS
        Writes a human-readable summary of the provisioning result to the host.

    .PARAMETER Metadata
        The certificate metadata object (from Get-DiscoveryCertMetadata).

    .OUTPUTS
        None. Writes to the host only.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [pscustomobject]$Metadata
    )

    $store = if ([string]::IsNullOrWhiteSpace([string]$Metadata.StorePath)) { '(not in a local store)' } else { $Metadata.StorePath }

    Write-Host ''
    Write-Host 'Discovery certificate provisioned' -ForegroundColor Green
    Write-Host '---------------------------------'
    Write-Host ("  Thumbprint : {0}" -f $Metadata.Thumbprint)
    Write-Host ("  Subject    : {0}" -f $Metadata.Subject)
    Write-Host ("  Store      : {0}" -f $store)
    Write-Host ("  Key        : {0} {1}-bit" -f $Metadata.KeyAlgorithm, $Metadata.KeyLength)
    Write-Host ("  Provider   : {0}" -f $(if ($null -eq $Metadata.ProviderName) { '(public cert / no private key)' } else { $Metadata.ProviderName }))
    Write-Host ("  Validity   : {0:yyyy-MM-dd} -> {1:yyyy-MM-dd}" -f $Metadata.NotBefore, $Metadata.NotAfter)
    Write-Host ("  x5t        : {0}" -f $Metadata.X5tBase64Url)
    Write-Host ''
    Write-Host 'Connect hint (fill in ClientId / TenantId once the app registration exists):' -ForegroundColor Cyan
    Write-Host ("  Connect-MgGraph -ClientId <appid> -TenantId <tid> -CertificateThumbprint {0}" -f $Metadata.Thumbprint)
    Write-Host ''
}

Export-ModuleMember -Function `
    Get-DiscoveryExistingKeyMatch, `
    Test-PlatformCryptoProvider, `
    New-DiscoveryTpmKey, `
    Assert-KeyNonExportable, `
    Export-DiscoveryPublicCertificate, `
    Import-DiscoveryPublicCertificate, `
    Get-DiscoveryCertMetadata, `
    Format-DiscoveryKeyResult
