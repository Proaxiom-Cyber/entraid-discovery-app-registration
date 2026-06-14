#Requires -Version 5.1

<#
.SYNOPSIS
    Provisions a least-privilege, TPM-bound certificate credential for the Proaxiom
    Phase 1 Entra ID discovery app registration.

.DESCRIPTION
    Thin entry point for the entraid-discovery-app tool. It selects one of five
    credential pathways via -CredentialMode (see docs/reference/credential-modes.md)
    and dispatches to the src/ modules. The pathways, highest assurance first:

      TpmBound (default)
        Generates a new RSA-2048 signing key inside the Microsoft Platform Crypto
        Provider (TPM), proves the private key is non-exportable, and exports only
        the public certificate (.cer) for upload to Entra. Fails closed if no
        usable TPM / Platform Crypto Provider is present. A plain -GenerateLocal
        run IS this pathway.

      ProviderHostedCert
        Imports a Proaxiom-provided public certificate (-CertPath) whose private
        key is TPM-bound on a Proaxiom-operated Azure VM, and (strongly
        recommended) verifies the supplied TPM attestation bundle
        (-AttestationPath) as evidence of that hardware binding.

      ImportPublicCert
        Accepts a supplied public certificate (.cer / PEM / base64) that was
        generated elsewhere, and produces its metadata. Generates no key. A plain
        -CertPath run IS this pathway (back-compatible).

      ImportPrivateKey (reduced assurance - acknowledgement required)
        Installs a supplied PFX/P12 (certificate + PRIVATE key, -PfxPath /
        -PfxPassword) into the certificate store. The store copy is installed
        non-exportable, but the source PFX file remains a portable private key.

      ClientSecret (lowest assurance - acknowledgement required)
        No certificate at all: adds a Graph-generated client secret to the app
        registration. The secret value is printed exactly once and never stored.

    Every run prints the selected pathway's security posture BEFORE any TPM probe,
    file write or tenant contact. The two reduced-assurance pathways
    (ImportPrivateKey, ClientSecret) additionally require an explicit operator
    acknowledgement (-AcknowledgeReducedAssurance, or an interactive yes) and FAIL
    CLOSED without one.

    This script is intentionally a thin dispatcher: all behaviour lives in the
    src/ modules. App-registration creation, cross-user grants and TPM attestation
    are layered on via the opt-in switches below.

.PARAMETER GenerateLocal
    Selects the GenerateLocal parameter set: generate a TPM-bound key on this
    endpoint (the TpmBound credential pathway). This is the default mode.

.PARAMETER Subject
    Certificate subject distinguished name. Default: 'CN=Proaxiom Discovery App'.
    (GenerateLocal only.)

.PARAMETER ValidityMonths
    Certificate validity in months (1-120). Default: 24. (GenerateLocal only.)

.PARAMETER PublicCertPath
    Optional path to write the exported public certificate (.cer). When omitted a
    default location is used ("<thumbprint>.cer" in the current directory). Used
    by the pathways that produce a public cert: TpmBound (the new TPM key's
    public cert) and ImportPrivateKey (the public half of the imported PFX).

.PARAMETER CertPath
    Path to a supplied public certificate to import (.cer / PEM / base64). Selects
    the ImportCert parameter set; without an explicit -CredentialMode this is the
    ImportPublicCert pathway, and with -CredentialMode ProviderHostedCert it is
    the Proaxiom-provided certificate.

.PARAMETER StoreLocation
    Certificate store location: 'LocalMachine' (default) or 'CurrentUser'.

.PARAMETER Force
    Overwrite an existing exported certificate file.

.PARAMETER CredentialMode
    The credential pathway to provision, highest assurance first: 'TpmBound'
    (default), 'ProviderHostedCert', 'ImportPublicCert', 'ImportPrivateKey',
    'ClientSecret'. When omitted, the mode is inferred for back-compatibility:
    -CertPath implies ImportPublicCert, -PfxPath implies ImportPrivateKey, and
    everything else is TpmBound. Each mode prints its security posture before
    anything is provisioned; ImportPrivateKey and ClientSecret additionally
    require -AcknowledgeReducedAssurance (or an interactive yes). See
    docs/reference/credential-modes.md.

.PARAMETER PfxPath
    Path to a PFX/P12 bundle (certificate + PRIVATE key) to install
    (ImportPrivateKey pathway only). The store copy is installed non-exportable;
    securely delete the source PFX (and every copy) after a successful import.

.PARAMETER PfxPassword
    Password for -PfxPath as a SecureString. Prompted interactively when omitted
    (press Enter at the prompt for a password-less PFX); in non-interactive
    sessions an omitted password is treated as a password-less PFX.

.PARAMETER AcknowledgeReducedAssurance
    Explicit operator acknowledgement that a REDUCED-ASSURANCE credential pathway
    (ImportPrivateKey or ClientSecret) is intended. Without it, an interactive
    session is prompted and a non-interactive session FAILS CLOSED.

.PARAMETER ForceNewApp
    Idempotency override (FR 20). By default -CreateAppRegistration refuses to create
    a new application when one of the same -DisplayName already exists in the tenant,
    throwing with the existing app's id and the ways forward (attach with -AppObjectId,
    pick a new -DisplayName, use -TestNaming, or pass -ForceNewApp). -ForceNewApp
    creates a deliberate duplicate instead.

.PARAMETER ConsentRedirectUri
    Optional HTTPS reply URL to register on the new app and include in the printed
    direct admin-consent URL. Use this with the Cloudflare Worker consent landing
    page to avoid Microsoft's AADSTS500113 "No reply address" page after Path A
    portal consent. Applies to -CreateAppRegistration only.

.EXAMPLE
    ./New-ProaxiomDiscoveryApp.ps1

    Generates a TPM-bound key (the default TpmBound pathway) with the default
    subject and 24-month validity in LocalMachine\My, and exports the public
    certificate.

.EXAMPLE
    ./New-ProaxiomDiscoveryApp.ps1 -GenerateLocal -Subject 'CN=Acme Discovery' -ValidityMonths 12 -PublicCertPath C:\temp\acme.cer -Force

    Generates a TPM-bound key with a custom subject and 12-month validity and writes
    the public certificate to the given path, overwriting if it exists.

.EXAMPLE
    ./New-ProaxiomDiscoveryApp.ps1 -CertPath C:\temp\supplied.cer

    Imports a public certificate generated elsewhere (the ImportPublicCert
    pathway, inferred from -CertPath) and reports its metadata.

.EXAMPLE
    ./New-ProaxiomDiscoveryApp.ps1 -CredentialMode ProviderHostedCert -CertPath C:\temp\proaxiom-provided.cer -AttestationPath C:\temp\bundle.json -CreateAppRegistration -DisplayName 'Contoso Discovery'

    ProviderHostedCert pathway: imports the Proaxiom-provided public certificate
    (private key TPM-bound on a Proaxiom-operated Azure VM), verifies the supplied
    TPM attestation bundle, and creates the app registration with that certificate.

.EXAMPLE
    ./New-ProaxiomDiscoveryApp.ps1 -CredentialMode ImportPublicCert -CertPath C:\temp\customer.cer -CreateAppRegistration -DisplayName 'Contoso Discovery'

    ImportPublicCert pathway (explicit): embeds the customer's own public
    certificate in a new app registration; the tool never sees the private key.

.EXAMPLE
    ./New-ProaxiomDiscoveryApp.ps1 -CredentialMode ImportPrivateKey -PfxPath C:\temp\supplied.pfx -PfxPassword $securePassword -CreateAppRegistration -DisplayName 'Contoso Discovery' -AcknowledgeReducedAssurance

    ImportPrivateKey pathway (reduced assurance, acknowledged): installs the
    supplied PFX into LocalMachine\My (store copy non-exportable), exports its
    public certificate and creates the app registration with it. -PfxPassword is
    prompted interactively when omitted; in non-interactive sessions an omitted
    password is treated as a password-less PFX. Securely delete the source PFX
    after the import.

.EXAMPLE
    ./New-ProaxiomDiscoveryApp.ps1 -CredentialMode ClientSecret -CreateAppRegistration -DisplayName 'Contoso Discovery' -AcknowledgeReducedAssurance

    ClientSecret pathway (lowest assurance, acknowledged): creates the app
    registration with NO certificate and adds a Graph-generated client secret.
    The secret value is printed exactly once with Proaxiom Pass handover
    instructions and is never stored by the tool.
#>

[CmdletBinding(DefaultParameterSetName = 'GenerateLocal', SupportsShouldProcess = $true)]
param(
    # --- GenerateLocal parameter set ---
    [Parameter(ParameterSetName = 'GenerateLocal')]
    [switch]$GenerateLocal,

    [Parameter(ParameterSetName = 'GenerateLocal')]
    [ValidateNotNullOrEmpty()]
    [string]$Subject = 'CN=Proaxiom Discovery App',

    [Parameter(ParameterSetName = 'GenerateLocal')]
    [ValidateRange(1, 120)]
    [int]$ValidityMonths = 24,

    # --- ImportCert parameter set ---
    [Parameter(ParameterSetName = 'ImportCert', Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$CertPath,

    # --- Shared parameters ---

    # Where to WRITE the exported public certificate (.cer). Shared (not
    # GenerateLocal-bound) so the ImportPrivateKey pathway can also export the
    # public half of an imported PFX; default behaviour when omitted is
    # unchanged ("<thumbprint>.cer" in the current directory).
    [string]$PublicCertPath,

    [ValidateSet('LocalMachine', 'CurrentUser')]
    [string]$StoreLocation = 'LocalMachine',

    [switch]$Force,

    # --- Credential pathway (Task 8.x) ---

    # The credential pathway to provision (assurance order; see
    # docs/reference/credential-modes.md). Explicit -CredentialMode always wins;
    # otherwise inferred: -CertPath => ImportPublicCert, -PfxPath =>
    # ImportPrivateKey, else TpmBound (back-compatible).
    [ValidateSet('TpmBound', 'ProviderHostedCert', 'ImportPublicCert', 'ImportPrivateKey', 'ClientSecret')]
    [string]$CredentialMode = 'TpmBound',

    # PFX/P12 bundle (certificate + PRIVATE key) for the ImportPrivateKey pathway.
    [ValidateNotNullOrEmpty()]
    [string]$PfxPath,

    # Password for -PfxPath. Prompted interactively when omitted (press Enter at
    # the prompt for a password-less PFX); in non-interactive sessions an omitted
    # password is treated as a password-less PFX.
    [securestring]$PfxPassword,

    # Explicit operator acknowledgement for the reduced-assurance pathways
    # (ImportPrivateKey, ClientSecret). Non-interactive runs without it FAIL CLOSED.
    [switch]$AcknowledgeReducedAssurance,

    # --- App registration (Task 3.0, FR 12-15) ---

    # Create a NEW application + service principal with the read-only permission manifest,
    # embedding the public cert as a keyCredential at creation (FR 12). Usable
    # after generating (GenerateLocal) or importing (ImportCert) a cert. In
    # ClientSecret mode the application is created with NO keyCredential and a
    # client secret is attached instead.
    [switch]$CreateAppRegistration,

    # Attach the public cert to an EXISTING app registration (object id) (FR 13).
    # Mutually exclusive with -CreateAppRegistration. In ClientSecret mode a
    # client secret is attached to the existing app instead of a certificate.
    [ValidateNotNullOrEmpty()]
    [string]$AppObjectId,

    # Grant tenant-wide admin consent (app-role assignments on the SP) (FR 14).
    # OPT-IN: without it, portal consent instructions are printed instead.
    [switch]$GrantConsent,

    # Application display name for -CreateAppRegistration. Defaults to the
    # production name; -TestNaming overrides with zzTEST-DiscoveryApp-<timestamp>.
    [ValidateNotNullOrEmpty()]
    [string]$DisplayName,

    # Use the integration-tier 'zzTEST-DiscoveryApp-<timestamp>' naming (Task 3.5).
    [switch]$TestNaming,

    # Idempotency override (FR 20). By default -CreateAppRegistration refuses to
    # create an app when one of the same -DisplayName already exists in the tenant
    # (it throws, naming the existing app and the ways forward). -ForceNewApp creates
    # a DELIBERATE duplicate anyway. Shared across both parameter sets.
    [switch]$ForceNewApp,

    # HTTPS reply URL for the Path A admin-consent completion page. Registered on
    # the new app and included as redirect_uri in the printed consent URL.
    [ValidatePattern('^https://')]
    [string]$ConsentRedirectUri,

    # Tenant id to connect to for the app-registration operations (optional).
    [ValidateNotNullOrEmpty()]
    [string]$TenantId,

    # --- Cross-user access (Task 4.0, FR 16) ---

    # Grant a non-admin operator account Read access to the LocalMachine key's
    # private-key ACL so it can sign without being a local admin (FR 16). Operates
    # on the key produced/targeted in this run. CurrentUser keys warn + no-op.
    [ValidateNotNullOrEmpty()]
    [string]$GrantUser,

    # Target an EXISTING key (by certificate thumbprint) for -GrantUser instead of
    # one generated/imported this run. Useful when ACLing a previously-provisioned
    # LocalMachine key.
    [ValidateNotNullOrEmpty()]
    [string]$GrantUserThumbprint,

    # --- Attestation (Task 5.0, FR 17-19) ---

    # Produce (TpmBound) or verify (ImportPublicCert / ProviderHostedCert) a TPM
    # key-attestation bundle. In TpmBound it creates a CNG key-attestation claim
    # over the new TPM key plus EK material and an honest assurance summary. In
    # the import modes it verifies a supplied bundle (NCryptVerifyClaim). Not
    # valid in ImportPrivateKey or ClientSecret mode (nothing attestable).
    [switch]$Attest,

    # Where to WRITE the attestation bundle (TpmBound) or READ it (import modes).
    # Defaults to "<thumbprint>.attestation.json" beside the public cert when omitted
    # (TpmBound); required content for verification. In ProviderHostedCert mode a
    # supplied bundle is verified automatically (no -Attest needed).
    [ValidateNotNullOrEmpty()]
    [string]$AttestationPath,

    # Opt-in: hard-fail when the TPM Endorsement Key does NOT chain to a manufacturer
    # root (no EK certificate -- e.g. a vTPM). Default behaviour reports + warns
    # WITHOUT hard-failing (Open Question #1 resolution). FR 19 is honoured either way.
    [switch]$RequireHardwareRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module "$PSScriptRoot/src/KeyGeneration.psm1" -Force
Import-Module "$PSScriptRoot/src/Manifest.psm1" -Force
Import-Module "$PSScriptRoot/src/AppRegistration.psm1" -Force
Import-Module "$PSScriptRoot/src/CrossUser.psm1" -Force
Import-Module "$PSScriptRoot/src/Output.psm1" -Force
Import-Module "$PSScriptRoot/src/Attestation.psm1" -Force
Import-Module "$PSScriptRoot/src/CredentialPosture.psm1" -Force
# Common.psm1 is imported LAST deliberately: several modules above re-import it
# internally with -Force, which removes its session-level exports and would leave
# this script unable to resolve Test-IsWindows / New-DiscoveryResult at script
# scope (see the import note in src/AppRegistration.psm1). Importing it after
# every other module guarantees its exports survive into the script body.
Import-Module "$PSScriptRoot/src/Common.psm1" -Force

# Shared bundle-verification routine (FR 18), used by BOTH the ProviderHostedCert
# auto-verify (in the dispatch below) and the explicit -Attest verify block at the
# bottom, so the verification logic exists exactly once. Read-only: it never
# writes to a store or the tenant.
function Invoke-DiscoveryAttestationVerify {
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory)]
        [bool]$RequireHardwareRoot
    )

    $result = Test-DiscoveryAttestation -Path $Path

    # -RequireHardwareRoot also gates verification: refuse to bless a non-hw-root bundle.
    $enforce = Test-RequireHardwareRoot `
        -RequireHardwareRoot $RequireHardwareRoot `
        -EkChainedToManufacturerRoot ([bool]$result.EkChainedToManufacturerRoot)
    if ($enforce.ShouldFail) {
        throw $enforce.Reason
    }
    if (-not [bool]$result.EkChainedToManufacturerRoot) {
        Write-Warning 'Attestation verify: the bundle is NOT hardware-rooted (EK does not chain to a manufacturer root).'
    }

    Write-Host ''
    Write-Host 'TPM attestation verification' -ForegroundColor Green
    Write-Host '----------------------------'
    Write-Host ("  Verify result    : {0}" -f $result.VerifyResult)
    Write-Host ("  Assurance        : {0}" -f $result.AssuranceLevel)
    Write-Host ("  Hardware root    : {0}" -f $result.EkChainedToManufacturerRoot)
    Write-Host ("  Reason           : {0}" -f $result.Reason)
    Write-Host ''

    $result
}

# --- Credential-pathway resolution (Task 8.4) --------------------------------
# An EXPLICIT -CredentialMode always wins; otherwise the mode is inferred for
# back-compatibility: -CertPath implies ImportPublicCert (the historical
# ImportCert shape), -PfxPath implies ImportPrivateKey, and everything else is
# the TpmBound default (-GenerateLocal was always the TPM pathway). Existing
# invocations therefore behave identically.
$modeExplicit  = $PSBoundParameters.ContainsKey('CredentialMode')
$certPathBound = $PSBoundParameters.ContainsKey('CertPath')
$pfxPathBound  = $PSBoundParameters.ContainsKey('PfxPath')

$effectiveMode = 'TpmBound'
if ($modeExplicit) {
    $effectiveMode = $CredentialMode
}
elseif ($certPathBound) {
    $effectiveMode = 'ImportPublicCert'
}
elseif ($pfxPathBound) {
    $effectiveMode = 'ImportPrivateKey'
}

# --- Credential-pathway consistency guards ------------------------------------
# ALL of these fire before any TPM probe, Graph/SDK import, tenant contact or
# file work, so an inconsistent invocation never gets near a side effect (and
# every guard is testable cross-platform).

if ($certPathBound -and $pfxPathBound) {
    throw 'Specify either -CertPath (a public certificate) or -PfxPath (a PFX private-key bundle), not both.'
}

if ($pfxPathBound -and $effectiveMode -ne 'ImportPrivateKey') {
    throw "-PfxPath applies only to the ImportPrivateKey pathway; it is not valid with -CredentialMode $effectiveMode."
}

switch ($effectiveMode) {
    'TpmBound' {
        if ($modeExplicit -and ($certPathBound -or $pfxPathBound)) {
            throw '-CredentialMode TpmBound generates a NEW key in this machine''s TPM; it does not accept -CertPath or -PfxPath. Omit them, or select ImportPublicCert / ImportPrivateKey.'
        }
    }
    'ProviderHostedCert' {
        if (-not $certPathBound) {
            throw '-CredentialMode ProviderHostedCert requires -CertPath (the Proaxiom-provided public certificate to import).'
        }
    }
    'ImportPublicCert' {
        if (-not $certPathBound) {
            throw '-CredentialMode ImportPublicCert requires -CertPath (the public certificate to import).'
        }
    }
    'ImportPrivateKey' {
        if (-not $pfxPathBound) {
            throw '-CredentialMode ImportPrivateKey requires -PfxPath (the PFX/P12 private-key bundle to import).'
        }
        if ($Attest) {
            throw '-Attest is not valid with -CredentialMode ImportPrivateKey: attestation covers TPM-generated keys and provider attestation bundles, not a private key imported from a file.'
        }
    }
    'ClientSecret' {
        if ($certPathBound -or $pfxPathBound) {
            throw '-CredentialMode ClientSecret uses no certificate at all; -CertPath and -PfxPath do not apply.'
        }
        if ($Attest) {
            throw '-CredentialMode ClientSecret has no key to attest; -Attest does not apply.'
        }
        if (-not $CreateAppRegistration -and [string]::IsNullOrWhiteSpace($AppObjectId)) {
            throw '-CredentialMode ClientSecret requires an app-registration target: pass -CreateAppRegistration (new app) or -AppObjectId (existing app). The client secret must be attached to an application.'
        }
    }
}

# -CreateAppRegistration and -AppObjectId are mutually exclusive app-registration
# targets (create-new vs attach-to-existing). Guard before any tenant contact.
if ($CreateAppRegistration -and -not [string]::IsNullOrWhiteSpace($AppObjectId)) {
    throw 'Specify either -CreateAppRegistration (new app) or -AppObjectId (existing app), not both.'
}
if ($GrantConsent -and -not $CreateAppRegistration) {
    throw '-GrantConsent applies to -CreateAppRegistration (it grants consent on the newly created service principal).'
}
if (-not [string]::IsNullOrWhiteSpace($ConsentRedirectUri) -and -not $CreateAppRegistration) {
    throw '-ConsentRedirectUri applies to -CreateAppRegistration: it registers the reply URL on the newly created app.'
}

# --- Credential-pathway posture disclosure + acknowledgement gate -------------
# Print the selected pathway's security posture for EVERY mode, BEFORE any TPM
# probe, file write or tenant contact (it prints under -WhatIf too). The two
# reduced-assurance pathways (ImportPrivateKey, ClientSecret) then gate on an
# explicit operator acknowledgement and FAIL CLOSED without one.
$posture = Resolve-CredentialPosture -Mode $effectiveMode
Format-CredentialPosture -Posture $posture

# A prompt is only possible when the process is user-interactive AND stdin is a
# real console. ([Environment]::UserInteractive alone is hardcoded $true on Unix
# hosts, so redirected/scripted runs there must still fail closed.)
$ackInteractive = [System.Environment]::UserInteractive
try {
    if ([System.Console]::IsInputRedirected) { $ackInteractive = $false }
}
catch {
    # Console probe unavailable in this host: keep the UserInteractive answer.
}

$ack = Test-CredentialAcknowledgement `
    -RequiresAcknowledgement ([bool]$posture.RequiresAcknowledgement) `
    -Acknowledged ([bool]$AcknowledgeReducedAssurance) `
    -Interactive $ackInteractive

if ($ack.NeedsPrompt) {
    $promptCaption = "Reduced-assurance credential pathway ($effectiveMode) - proceed?"
    $promptMessage = (@($posture.Downsides) -join ' ')
    if (-not $PSCmdlet.ShouldContinue($promptMessage, $promptCaption)) {
        throw ("Credential pathway '$effectiveMode' not acknowledged: the operator declined the reduced-assurance " +
               'prompt. Re-run with -AcknowledgeReducedAssurance to accept the reduced assurance non-interactively.')
    }
}
elseif (-not $ack.ShouldProceed) {
    throw $ack.Reason
}

# --- Dispatch ----------------------------------------------------------------
# All five pathway variables are pre-initialised so StrictMode-safe downstream
# guards can read them regardless of which case ran (e.g. ClientSecret sets
# none of the certificate state).
$meta             = $null
$certificate      = $null
$exportedCertPath = $null
$attestResult     = $null
$bundleVerified   = $false

switch ($effectiveMode) {

    'TpmBound' {
        # 1. Gate: fail closed if no usable TPM / Platform Crypto Provider (FR 8).
        $providerStatus = Test-PlatformCryptoProvider
        if (-not $providerStatus.Available) {
            throw "No usable TPM / Microsoft Platform Crypto Provider available: $($providerStatus.Reason)"
        }

        # 1b. Idempotency notice (FR 20): warn (do NOT block or delete) if the target
        #     store already holds a non-expired certificate with the same subject. A
        #     new key is generated alongside it (legitimate signing-key rotation). The
        #     pure matcher is Tier-A testable without touching a real store.
        $existingStorePath = "Cert:\$StoreLocation\My"
        if (Test-Path -LiteralPath $existingStorePath) {
            $storeCerts = @(Get-ChildItem -LiteralPath $existingStorePath -ErrorAction SilentlyContinue)
            $sameSubject = @(Get-DiscoveryExistingKeyMatch -Certificate $storeCerts -Subject $Subject)
            if ($sameSubject.Count -gt 0) {
                Write-Warning ("Idempotency: $($sameSubject.Count) existing non-expired certificate(s) with subject " +
                               "'$Subject' already in $existingStorePath. A new key will be generated ALONGSIDE them " +
                               '(signing-key rotation); none are deleted or reused:')
                foreach ($c in $sameSubject) {
                    Write-Warning ("  - Thumbprint {0}  (NotAfter {1:yyyy-MM-dd})" -f $c.Thumbprint, $c.NotAfter)
                }
            }
        }

        # 2. Generate the TPM-bound, non-exportable key (FR 7).
        #    New-DiscoveryTpmKey returns METADATA (a PSCustomObject with .Thumbprint
        #    etc.), NOT an [X509Certificate2]. The downstream calls below all need the
        #    live certificate object, so fetch it back out of the store by thumbprint
        #    (mirroring the Tier-B tests). $certificate stays $null under -WhatIf,
        #    where no key was actually created; the guards below handle that.
        if ($PSCmdlet.ShouldProcess("$StoreLocation\My", "Generate TPM-bound key for '$Subject'")) {
            $keyResult = New-DiscoveryTpmKey -Subject $Subject -ValidityMonths $ValidityMonths -StoreLocation $StoreLocation

            $certPath = "Cert:\{0}\My\{1}" -f $StoreLocation, $keyResult.Thumbprint
            if (-not (Test-Path -LiteralPath $certPath)) {
                throw "Generated key not found in the store at '$certPath' (thumbprint '$($keyResult.Thumbprint)'). Refusing to continue."
            }
            $certificate = Get-Item -LiteralPath $certPath
        }

        # 3. Assert non-exportability (FR 7). Skip under -WhatIf (no key generated).
        if ($null -ne $certificate) {
            $nonExport = Assert-KeyNonExportable -Certificate $certificate
            if (-not $nonExport.NonExportable) {
                throw "Generated key is exportable; refusing to continue (provider: $($nonExport.ProviderName))."
            }
        }

        # 4. Export only the public certificate (FR 10). Capture the path so the
        #    app-registration step can embed it as a keyCredential.
        if ($null -ne $certificate -and $PSCmdlet.ShouldProcess($PublicCertPath, 'Export public certificate (.cer)')) {
            $export = Export-DiscoveryPublicCertificate -Certificate $certificate -Path $PublicCertPath -Force:$Force
            $exportedCertPath = $export.Path
        }

        # 5. Collect metadata for output. Use the live cert when present; under
        #    -WhatIf (no key) fall back to a null metadata object so downstream
        #    formatting/handling is skipped cleanly.
        if ($null -ne $certificate) {
            $meta = Get-DiscoveryCertMetadata -Certificate $certificate
        }
    }

    { $_ -eq 'ImportPublicCert' -or $_ -eq 'ProviderHostedCert' } {
        # 1. Import the supplied public certificate; no key generation (FR 11).
        #    Import-DiscoveryPublicCertificate returns METADATA (it validates the
        #    file is a public cert and emits Get-DiscoveryCertMetadata output), NOT
        #    an [X509Certificate2]. Use that metadata directly for output, and load
        #    the real certificate object from the supplied file for any downstream
        #    -Certificate consumer (e.g. attestation verify does not use it; the
        #    cross-user grant below requires a private key the public .cer lacks and
        #    is handled separately via -GrantUserThumbprint).
        $meta = Import-DiscoveryPublicCertificate -Path $CertPath

        # The live public certificate object (the file was already validated above),
        # for any consumer that takes an [X509Certificate2] rather than metadata.
        # The constructor reads DER/PEM .cer files directly. A raw-base64 text file
        # (also accepted by Import-DiscoveryPublicCertificate) is not loadable this
        # way; leave $certificate $null in that case -- the only import-mode consumer
        # of $certificate is the cross-user grant, which requires a private key the
        # public cert never has and is driven via -GrantUserThumbprint instead.
        try {
            $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertPath)
        }
        catch {
            $certificate = $null
        }

        # The supplied .cer is the public cert to embed in the app registration.
        $exportedCertPath = $CertPath

        if ($effectiveMode -eq 'ProviderHostedCert') {
            # The provider-held private key is hardware-bound on PROAXIOM
            # infrastructure; the TPM attestation bundle is the customer's evidence
            # of that binding. Verify it here when supplied -- BEFORE any
            # app-registration write embeds the certificate.
            if (-not [string]::IsNullOrWhiteSpace($AttestationPath)) {
                if (Test-IsWindows) {
                    $attestResult = Invoke-DiscoveryAttestationVerify -Path $AttestationPath `
                        -RequireHardwareRoot ([bool]$RequireHardwareRoot)
                    $bundleVerified = $true
                }
                else {
                    Write-Warning ('ProviderHostedCert: attestation bundle verification requires Windows; skipped. ' +
                                   'Verify the supplied bundle on a Windows host before relying on its ' +
                                   'hardware-binding evidence.')
                }
            }
            else {
                Write-Warning ('ProviderHostedCert: no -AttestationPath was supplied. Proaxiom STRONGLY recommends ' +
                               'verifying the Proaxiom-provided TPM attestation bundle (-AttestationPath <bundle.json>) ' +
                               '-- it is the evidence that the provider-held private key is hardware-bound.')
            }
        }
    }

    'ImportPrivateKey' {
        # 1. Install the supplied PFX (certificate + PRIVATE key) into the store.
        #    Import-DiscoveryPfx fails closed off-Windows, validates the password,
        #    and installs the store copy WITHOUT the Exportable flag. ShouldProcess-
        #    gated: under -WhatIf nothing is installed and $meta/$certificate stay
        #    $null (handled downstream exactly like the TpmBound -WhatIf path).
        if ($PSCmdlet.ShouldProcess("$StoreLocation\My", "Install PFX '$PfxPath' (certificate + private key)")) {
            # 1a. Docs parity: -PfxPassword is PROMPTED interactively when omitted.
            #     Gated on the SAME interactivity probe as the acknowledgement gate
            #     above ($ackInteractive: UserInteractive AND stdin not redirected)
            #     so the two features agree on what "interactive" means. An empty
            #     entry (just Enter) means a password-less PFX ($null password).
            #     Non-interactive sessions never prompt: an omitted password is
            #     treated as a password-less PFX, and Import-DiscoveryPfx's
            #     actionable error covers the wrong/missing-password case.
            if ($pfxPathBound -and -not $PSBoundParameters.ContainsKey('PfxPassword') -and $ackInteractive) {
                $PfxPassword = Read-Host -AsSecureString 'PFX password (press Enter if the file has no password)'
                if ($PfxPassword.Length -eq 0) {
                    $PfxPassword = $null
                }
            }

            $meta = Import-DiscoveryPfx -Path $PfxPath -Password $PfxPassword -StoreLocation $StoreLocation

            # Import-DiscoveryPfx's StorePath is the FULL Cert: item path; load the
            # live certificate object for the downstream consumers (export, grant).
            $certificate = Get-Item -LiteralPath $meta.StorePath
        }

        # 2. Export the PUBLIC certificate so the app-registration step has a .cer
        #    to embed (FR 10 analogue; the .cer never contains the private key).
        if ($null -ne $certificate -and $PSCmdlet.ShouldProcess($PublicCertPath, 'Export public certificate (.cer)')) {
            $export = Export-DiscoveryPublicCertificate -Certificate $certificate -Path $PublicCertPath -Force:$Force
            $exportedCertPath = $export.Path
        }

        # 3. The store copy is non-exportable, but the SOURCE PFX file remains a
        #    portable private key -- remind the operator to destroy it.
        if ($null -ne $meta) {
            Write-Host ''
            Write-Host 'REMINDER: securely delete the source PFX file (and every copy of it) now that it is imported.' -ForegroundColor Yellow
            Write-Host ("  The store copy ({0}) is non-exportable, but any surviving PFX file can mint tokens from ANY machine." -f $meta.StorePath)
            Write-Host ''
        }
    }

    'ClientSecret' {
        # No key and no certificate AT ALL: the credential is a Graph-generated
        # secret attached in the app-registration section below. The consistency
        # guards above already required -CreateAppRegistration/-AppObjectId and
        # rejected every certificate/key input, so there is nothing to do here.
        $meta = $null
    }
}

# --- Common result handling ---
# $meta is $null under -WhatIf in TpmBound/ImportPrivateKey (no key was produced)
# and always in ClientSecret (no certificate by design); in every other executed
# path it is populated. Guard so those cases do not trip ValidateNotNull.
if ($null -ne $meta) {
    Format-DiscoveryKeyResult -Metadata $meta
}

# --- App registration (Task 3.0, FR 12-15) ----------------------------------
# Only runs when the operator opts in via -CreateAppRegistration or -AppObjectId.
# Each tenant-mutating call honours ShouldProcess (so -WhatIf performs no write).
$appResult = $null
$secretResult = $null

if ($CreateAppRegistration -or -not [string]::IsNullOrWhiteSpace($AppObjectId)) {

    # Every certificate pathway must have an exported public cert to embed. The
    # ClientSecret pathway is the deliberate exception: it has no certificate by
    # design (New-DiscoveryAppRegistration -NoKeyCredential below).
    if ($effectiveMode -ne 'ClientSecret' -and [string]::IsNullOrWhiteSpace($exportedCertPath)) {
        throw 'No public certificate is available to register (cert export was skipped, e.g. under -WhatIf).'
    }

    # The provisioner authenticates delegated/interactively with the required scopes.
    # NOTE: -WhatIf:$WhatIfPreference is threaded EXPLICITLY into every tenant-
    # mutating module call below. Preference variables (WhatIfPreference) do NOT
    # propagate from a script's scope into module functions, so without the
    # explicit pass-through a -WhatIf run would still perform real tenant writes.
    Connect-DiscoveryGraph -TenantId $TenantId -WhatIf:$WhatIfPreference

    if ($CreateAppRegistration) {
        $name = New-DiscoveryAppDisplayName -Test:$TestNaming
        if (-not [string]::IsNullOrWhiteSpace($DisplayName)) {
            $name = $DisplayName
        }

        # -ForceNewApp flows into the wrapper's idempotency guard (FR 20): without it,
        # an existing same-name app causes New-DiscoveryAppRegistration to throw rather
        # than silently creating a duplicate.
        if ($effectiveMode -eq 'ClientSecret') {
            # ClientSecret: create the application with NO keyCredential; the
            # Graph-generated client secret below is the credential.
            $appResult = New-DiscoveryAppRegistration -DisplayName $name -NoKeyCredential -ConsentRedirectUri $ConsentRedirectUri -Force:$ForceNewApp -WhatIf:$WhatIfPreference
        }
        else {
            $appResult = New-DiscoveryAppRegistration -DisplayName $name -CertPath $exportedCertPath -ConsentRedirectUri $ConsentRedirectUri -Force:$ForceNewApp -WhatIf:$WhatIfPreference
        }

        # Admin consent is OPT-IN (FR 14): only granted with -GrantConsent.
        if ($GrantConsent) {
            if ($null -ne $appResult.ServicePrincipalId) {
                $consent = Grant-DiscoveryAdminConsent -ServicePrincipalId $appResult.ServicePrincipalId -WhatIf:$WhatIfPreference
                $appResult | Add-Member -NotePropertyName 'ConsentGranted' -NotePropertyValue $true -Force
                $appResult | Add-Member -NotePropertyName 'ConsentGrantedCount' -NotePropertyValue $consent.Granted -Force
            }
        }
    }
    elseif ($effectiveMode -eq 'ClientSecret') {
        # ClientSecret against an EXISTING app (-AppObjectId): no certificate to
        # attach; the secret is added below and reported by the secret formatter
        # ($appResult intentionally stays $null).
    }
    else {
        # Attach the public cert to an existing app registration (FR 13).
        $appResult = Add-DiscoveryAppCredential -AppObjectId $AppObjectId -CertPath $exportedCertPath -WhatIf:$WhatIfPreference
    }

    # ClientSecret: add the Graph-generated secret. ShouldProcess is honoured
    # inside New-DiscoveryAppClientSecret; the secret value is surfaced ONLY as
    # the SecretSecure property and printed exactly once below.
    if ($effectiveMode -eq 'ClientSecret') {
        $secretAppObjectId = $AppObjectId
        if ($CreateAppRegistration -and $null -ne $appResult -and
            -not [string]::IsNullOrWhiteSpace([string]$appResult.ObjectId)) {
            $secretAppObjectId = [string]$appResult.ObjectId
        }

        if (-not [string]::IsNullOrWhiteSpace($secretAppObjectId)) {
            $secretResult = New-DiscoveryAppClientSecret -AppObjectId $secretAppObjectId -WhatIf:$WhatIfPreference
        }
        else {
            # -WhatIf with -CreateAppRegistration: no real application object id
            # exists to attach a secret to. Mirror New-DiscoveryAppClientSecret's
            # -WhatIf result shape so the print-once display still demonstrates
            # the output (placeholder; no secret value exists).
            $secretResult = New-DiscoveryResult -Property @{
                AppObjectId   = $null
                KeyId         = $null
                Hint          = $null
                DisplayName   = 'Proaxiom discovery client secret'
                StartDateTime = $null
                EndDateTime   = $null
                SecretSecure  = $null
                WhatIf        = $true
            }
        }
    }

    if ($null -ne $appResult) {
        if ($effectiveMode -eq 'ClientSecret') {
            # The certificate-flavoured Connect-MgGraph example does not apply;
            # the secret formatter below prints the secret-auth handover instead.
            Format-DiscoveryAppResult -Result $appResult -SuppressConnectExample
        }
        else {
            Format-DiscoveryAppResult -Result $appResult
        }
    }

    if ($null -ne $secretResult) {
        $secretAppId    = $null
        $secretTenantId = $null
        if ($null -ne $appResult) {
            if ($appResult.PSObject.Properties.Name -contains 'AppId')    { $secretAppId    = [string]$appResult.AppId }
            if ($appResult.PSObject.Properties.Name -contains 'TenantId') { $secretTenantId = [string]$appResult.TenantId }
        }
        if ([string]::IsNullOrWhiteSpace($secretTenantId)) {
            try { $secretTenantId = (Get-MgContext).TenantId } catch { $secretTenantId = $null }
        }
        Format-DiscoveryClientSecretResult -Result $secretResult -AppId $secretAppId -TenantId $secretTenantId
    }
}

# --- Cross-user access (Task 4.0, FR 16) ------------------------------------
# Only runs when the operator opts in via -GrantUser. Grants the account Read
# access to the LocalMachine key's private-key ACL; CurrentUser keys warn + no-op.
# The ShouldProcess on Grant-DiscoveryKeyAccess means -WhatIf performs no write.
$grantResult = $null

if (-not [string]::IsNullOrWhiteSpace($GrantUser)) {

    # Resolve the certificate to ACL. Prefer an explicit -GrantUserThumbprint
    # (target a previously-provisioned key); otherwise use the cert from this run.
    $grantCert = $null
    if (-not [string]::IsNullOrWhiteSpace($GrantUserThumbprint)) {
        $grantCertPath = "Cert:\$StoreLocation\My\$GrantUserThumbprint"
        if (-not (Test-Path -LiteralPath $grantCertPath)) {
            throw "No certificate with thumbprint '$GrantUserThumbprint' found in $StoreLocation\My for -GrantUser."
        }
        $grantCert = Get-Item -LiteralPath $grantCertPath
    }
    elseif ($null -ne $certificate) {
        $grantCert = $certificate
    }
    else {
        throw 'No certificate is available for -GrantUser (key generation/import was skipped, e.g. under -WhatIf). Use -GrantUserThumbprint to target an existing key.'
    }

    $grantResult = Grant-DiscoveryKeyAccess -Certificate $grantCert `
        -Account $GrantUser -StoreLocation $StoreLocation
}

# --- Attestation (Task 5.0, FR 17-19) ---------------------------------------
# Only runs when the operator opts in via -Attest.
#   TpmBound                            -> produce a TPM key-attestation bundle
#                                          for the new key (FR 17).
#   ImportPublicCert/ProviderHostedCert -> verify a supplied bundle (FR 18);
#                                          skipped when the ProviderHostedCert
#                                          pathway already auto-verified it.
# (ImportPrivateKey/ClientSecret + -Attest are rejected by the consistency
# guards at the top -- there is nothing attestable in those pathways.)
# FR 19 honesty is enforced in src/Attestation.psm1: a vTPM with no EK certificate
# reports EkChainedToManufacturerRoot = $false and a NOT-hardware-rooted assurance.
# -RequireHardwareRoot is opt-in hard-fail; default is report + warn.
if ($Attest) {

    # Attestation requires Windows + a TPM. Fail closed with a clear message off-host.
    if (-not (Test-IsWindows)) {
        throw 'Attestation (-Attest) is Windows-only: TPM key attestation requires Windows and a TPM (Microsoft Platform Crypto Provider).'
    }

    if ($effectiveMode -eq 'TpmBound') {

        if ($null -eq $certificate) {
            throw 'No generated key is available to attest (key generation was skipped, e.g. under -WhatIf).'
        }

        # Build the TPM key-attestation bundle (claim + EK material + assurance).
        $attestResult = New-DiscoveryAttestation -Certificate $certificate

        # Resolve the bundle output path (default beside the cert / thumbprint).
        $bundlePath = $AttestationPath
        if ([string]::IsNullOrWhiteSpace($bundlePath)) {
            $baseDir = if (-not [string]::IsNullOrWhiteSpace($exportedCertPath)) {
                Split-Path -Parent $exportedCertPath
            }
            else {
                (Get-Location).Path
            }
            if ([string]::IsNullOrWhiteSpace($baseDir)) { $baseDir = (Get-Location).Path }
            $bundlePath = Join-Path $baseDir ("{0}.attestation.json" -f $attestResult.Thumbprint)
        }

        # Write the bundle (ShouldProcess-gated so -WhatIf performs no write).
        if ($PSCmdlet.ShouldProcess($bundlePath, 'Write TPM attestation bundle')) {
            Set-Content -LiteralPath $bundlePath -Value $attestResult.Json -Encoding UTF8
            $attestResult | Add-Member -NotePropertyName 'BundlePath' -NotePropertyValue $bundlePath -Force
        }

        # Enforce -RequireHardwareRoot (opt-in hard-fail) vs default report + warn.
        $enforce = Test-RequireHardwareRoot `
            -RequireHardwareRoot:$RequireHardwareRoot `
            -EkChainedToManufacturerRoot ([bool]$attestResult.EkChainedToManufacturerRoot)
        if ($enforce.ShouldFail) {
            throw $enforce.Reason
        }
        if (-not [bool]$attestResult.EkChainedToManufacturerRoot) {
            Write-Warning ('Attestation: {0}' -f $attestResult.Rationale)
        }

        Write-Host ''
        Write-Host 'TPM attestation bundle' -ForegroundColor Green
        Write-Host '----------------------'
        Write-Host ("  Assurance        : {0}" -f $attestResult.AssuranceLevel)
        Write-Host ("  Hardware root    : {0}" -f $attestResult.EkChainedToManufacturerRoot)
        Write-Host ("  Bundle path      : {0}" -f $(if ($attestResult.PSObject.Properties.Name -contains 'BundlePath') { $attestResult.BundlePath } else { '(not written; -WhatIf)' }))
        Write-Host ''
    }
    elseif ($bundleVerified) {
        # The ProviderHostedCert pathway already verified the supplied bundle
        # during dispatch; do not verify (or print) twice.
        Write-Verbose '-Attest: the attestation bundle was already verified by the ProviderHostedCert pathway; not verifying twice.'
    }
    else {
        # Import modes: verify a supplied bundle (FR 18).
        if ([string]::IsNullOrWhiteSpace($AttestationPath)) {
            throw '-Attest in an import mode (ImportPublicCert / ProviderHostedCert) requires -AttestationPath (the bundle to verify).'
        }

        $attestResult = Invoke-DiscoveryAttestationVerify -Path $AttestationPath `
            -RequireHardwareRoot ([bool]$RequireHardwareRoot)
    }
}

# Emit the structured objects: cert metadata always, app + secret + grant + attest
# results when present.
$meta
if ($null -ne $appResult) {
    $appResult
}
if ($null -ne $secretResult) {
    # Pipeline copy WITHOUT SecretSecure: the print-once display above is the only
    # place the secret value surfaces; the emitted object must not carry it.
    $secretResult | Select-Object -Property * -ExcludeProperty SecretSecure
}
if ($null -ne $grantResult) {
    $grantResult
}
if ($null -ne $attestResult) {
    $attestResult
}
