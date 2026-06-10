<#
.SYNOPSIS
    Output formatting for the discovery app-registration result (FR 15).

.DESCRIPTION
    Pure formatting only -- no Graph SDK, no tenant, no network. Produces:

      * Format-DiscoveryAppResult       - human-readable summary printed to host
      * Get-DiscoveryConnectExample     - the ready-to-paste Connect-MgGraph line
      * Get-DiscoveryConsentInstructions - portal admin-consent steps + URL
      * Format-DiscoveryConsentInstructions - prints the consent steps to host
      * Get-DiscoveryClientSecretInstructions - secret-handover steps (Proaxiom
        Pass one-time link + secret-auth connect example)
      * Format-DiscoveryClientSecretResult - PRINT-ONCE client-secret display +
        the handover steps (the only place the secret value is ever shown)

    All functions are deterministic string builders so they can be unit-tested
    off-host. Connect example and consent URL match the PRD's documented shapes
    (Connect-MgGraph -ClientId <appid> -TenantId <tid> -CertificateThumbprint <tp>).

    SECRET HANDLING (ClientSecret mode): the secret value reaches this module
    only as a SecureString on the result object. Format-DiscoveryClientSecretResult
    decodes it just-in-time, Write-Hosts it EXACTLY ONCE inside a loud banner,
    and nulls the plain-text local immediately. Nothing here returns the value
    on the pipeline, writes it to a file, or logs it. The handover channel is a
    Proaxiom Pass one-time link (print-once + Pass instruction handover is the
    approved design).

    Cross-compatible with Windows PowerShell 5.1 (Desktop) and PowerShell 7.x (Core).
#>

Set-StrictMode -Version Latest

function Get-DiscoveryConnectExample {
    <#
    .SYNOPSIS
        Builds the ready-to-paste Connect-MgGraph certificate-auth example (FR 15).

    .DESCRIPTION
        Returns the exact command an operator runs to authenticate the discovery
        app with its TPM-bound certificate. Placeholders are substituted when the
        real values are known; when AppId/TenantId are not yet available, clear
        <appid>/<tid> placeholders are emitted instead.

    .PARAMETER AppId
        The application's (client) id. Optional; <appid> placeholder if omitted.

    .PARAMETER TenantId
        The tenant id. Optional; <tid> placeholder if omitted.

    .PARAMETER Thumbprint
        The certificate thumbprint. Required.

    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$AppId,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$TenantId,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Thumbprint
    )

    $appToken    = if ([string]::IsNullOrWhiteSpace($AppId))    { '<appid>' } else { $AppId }
    $tenantToken = if ([string]::IsNullOrWhiteSpace($TenantId)) { '<tid>' }   else { $TenantId }

    "Connect-MgGraph -ClientId $appToken -TenantId $tenantToken -CertificateThumbprint $Thumbprint"
}

function Get-DiscoveryConsentInstructions {
    <#
    .SYNOPSIS
        Builds the portal admin-consent instructions for the opt-in consent path (FR 14).

    .DESCRIPTION
        When -GrantConsent is NOT supplied, the tool prints how to grant
        tenant-wide admin consent through the Entra portal, plus the direct admin
        consent URL. Returns the lines as a string array (one step per element) so
        callers can print or test them.

    .PARAMETER AppId
        The application's (client) id. Optional; <appid> placeholder if omitted.

    .PARAMETER TenantId
        The tenant id used to build the admin-consent URL. Optional; 'common' is
        used when omitted (still functional, prompts for tenant selection).

    .PARAMETER ConsentRedirectUri
        Optional registered reply URL. When supplied, the direct admin-consent
        URL includes redirect_uri so Microsoft returns to the controlled landing
        page instead of showing AADSTS500113 after consent.

    .OUTPUTS
        System.String[]
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$AppId,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$TenantId,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ConsentRedirectUri
    )

    $appToken    = if ([string]::IsNullOrWhiteSpace($AppId))    { '<appid>' } else { $AppId }
    $tenantToken = if ([string]::IsNullOrWhiteSpace($TenantId)) { 'common' } else { $TenantId }

    $consentUrl = "https://login.microsoftonline.com/$tenantToken/adminconsent?client_id=$appToken"
    if (-not [string]::IsNullOrWhiteSpace($ConsentRedirectUri)) {
        $encodedRedirect = [System.Uri]::EscapeDataString($ConsentRedirectUri)
        $encodedState = [System.Uri]::EscapeDataString('proaxiom-entraid-discovery')
        $consentUrl = "$consentUrl&redirect_uri=$encodedRedirect&state=$encodedState"
    }

    @(
        'Admin consent was NOT granted (consent is opt-in; re-run with -GrantConsent to automate it).'
        'Grant tenant-wide admin consent manually via the Entra portal:'
        '  1. Entra admin centre -> Identity -> Applications -> App registrations.'
        "  2. Open the app (Application/client id: $appToken)."
        '  3. API permissions -> "Grant admin consent for <tenant>" -> Yes.'
        '  4. Confirm every permission shows "Granted for <tenant>".'
        ''
        'Or use the direct admin-consent URL (sign in as a Privileged Role / Global Administrator):'
        "  $consentUrl"
    )
}

function Format-DiscoveryConsentInstructions {
    <#
    .SYNOPSIS
        Prints the portal admin-consent instructions to the host.

    .PARAMETER AppId
        The application's (client) id. Optional.

    .PARAMETER TenantId
        The tenant id used to build the admin-consent URL. Optional.

    .PARAMETER ConsentRedirectUri
        Optional registered reply URL to include in the direct admin-consent URL.

    .OUTPUTS
        None. Writes to the host only.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$AppId,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$TenantId,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ConsentRedirectUri
    )

    $lines = Get-DiscoveryConsentInstructions -AppId $AppId -TenantId $TenantId -ConsentRedirectUri $ConsentRedirectUri
    Write-Host ''
    Write-Host 'Admin consent required' -ForegroundColor Yellow
    Write-Host '----------------------'
    foreach ($line in $lines) {
        Write-Host $line
    }
    Write-Host ''
}

function Get-DiscoveryClientSecretInstructions {
    <#
    .SYNOPSIS
        Builds the client-secret handover instructions (print-once + Proaxiom Pass).

    .DESCRIPTION
        PURE string builder for the -CredentialMode ClientSecret handover text:
        a security warning (a client secret is a BEARER credential), the
        shown-once / not-stored notice, the Proaxiom Pass one-time-link handover
        steps (the approved sharing channel -- never email/chat the raw value),
        the keyId + expiry / rotation note, and a ready-to-paste app-only
        Connect-MgGraph example for secret auth.

        The secret VALUE itself never passes through this function; displaying it
        (exactly once) is Format-DiscoveryClientSecretResult's job.

    .PARAMETER AppId
        The application's (client) id. Optional; <appid> placeholder if omitted.

    .PARAMETER TenantId
        The tenant id. Optional; <tid> placeholder if omitted.

    .PARAMETER KeyId
        The passwordCredential keyId (identifies this secret for later rotation /
        removal). Optional.

    .PARAMETER EndDateTime
        The secret's expiry instant (datetime or parseable string). Optional.

    .PARAMETER PassUrl
        The Proaxiom Pass URL used for the one-time-link handover. Default
        'https://pass.proaxiom.com'.

    .OUTPUTS
        System.String[]
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$AppId,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$TenantId,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$KeyId,

        [Parameter()]
        [AllowNull()]
        $EndDateTime,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$PassUrl = 'https://pass.proaxiom.com'
    )

    $appToken    = if ([string]::IsNullOrWhiteSpace($AppId))    { '<appid>' }   else { $AppId }
    $tenantToken = if ([string]::IsNullOrWhiteSpace($TenantId)) { '<tid>' }     else { $TenantId }
    $keyIdText   = if ([string]::IsNullOrWhiteSpace($KeyId))    { '(unknown)' } else { $KeyId }

    # Best-effort expiry formatting; never throw over a display nicety.
    $expiryText = '(unknown)'
    if ($null -ne $EndDateTime) {
        try {
            $expiryText = ([datetime]$EndDateTime).ToString('yyyy-MM-dd HH:mm')
        }
        catch {
            $expiryText = [string]$EndDateTime
        }
    }

    @(
        'SECURITY: a client secret is a BEARER credential -- anyone holding the value IS this'
        'application, with every permission granted to it. There is no key and no device binding.'
        ''
        'The value above is shown ONCE and is not stored or written to disk by this tool.'
        'If it is lost, create a new secret and remove this one (keyId below).'
        ''
        'Hand the value over ONLY via a Proaxiom Pass one-time link:'
        "  1. Open $PassUrl and paste the secret value."
        '  2. Set a SHORT expiry and one-time view.'
        '  3. Send the recipient the LINK -- never email/chat/ticket the raw value.'
        ''
        "Secret keyId : $keyIdText"
        "Expires      : $expiryText (rotate -- create a new secret, remove this one -- before expiry)."
        ''
        'Connect (app-only) with the client secret:'
        "  `$cred = [pscredential]::new('$appToken', (Read-Host -AsSecureString 'Client secret'))"
        "  Connect-MgGraph -TenantId $tenantToken -ClientSecretCredential `$cred"
    )
}

function Format-DiscoveryClientSecretResult {
    <#
    .SYNOPSIS
        Prints the client-secret result: the secret value EXACTLY ONCE, then the
        Proaxiom Pass handover instructions.

    .DESCRIPTION
        Host-only print-once display for -CredentialMode ClientSecret. Decodes
        Result.SecretSecure ([securestring]) just-in-time via
        [pscredential]::new('x', $ss).GetNetworkCredential().Password (the
        PowerShell 5.1 + 7 safe decode), Write-Hosts the value once inside a
        loud banner, nulls the plain-text local immediately, then prints the
        handover instructions (Get-DiscoveryClientSecretInstructions, passing
        through KeyId / EndDateTime / AppId / TenantId).

        When SecretSecure is $null (a -WhatIf run), prints a placeholder instead
        of a value. NEVER returns the value -- the function returns nothing.

    .PARAMETER Result
        The result object from New-DiscoveryAppClientSecret. Read properties:
        SecretSecure (securestring or $null), KeyId, EndDateTime (all optional).

    .PARAMETER AppId
        The application's (client) id for the connect example. Optional.

    .PARAMETER TenantId
        The tenant id for the connect example. Optional.

    .OUTPUTS
        None. Writes to the host only.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [pscustomobject]$Result,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$AppId,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$TenantId
    )

    $getProp = {
        param($name)
        if ($Result.PSObject.Properties.Name -contains $name) { $Result.$name } else { $null }
    }

    $secretSecure = & $getProp 'SecretSecure'
    $keyId        = [string](& $getProp 'KeyId')
    $endDateTime  = & $getProp 'EndDateTime'

    Write-Host ''
    Write-Host '=================================================================' -ForegroundColor Yellow
    Write-Host '  CLIENT SECRET -- DISPLAYED ONCE (copy it now; it is NOT stored)' -ForegroundColor Yellow
    Write-Host '=================================================================' -ForegroundColor Yellow

    if ($null -eq $secretSecure) {
        Write-Host '  (no secret created; -WhatIf)'
    }
    else {
        # Decode just-in-time for the single display, then null the local
        # immediately. [pscredential]::new(...).GetNetworkCredential().Password
        # behaves identically on PowerShell 5.1 and 7 (no Marshal/BSTR juggling).
        $plain = [pscredential]::new('x', $secretSecure).GetNetworkCredential().Password
        Write-Host ("  {0}" -f $plain)
        $plain = $null
    }

    Write-Host '=================================================================' -ForegroundColor Yellow
    Write-Host ''

    $lines = Get-DiscoveryClientSecretInstructions -AppId $AppId -TenantId $TenantId `
        -KeyId $keyId -EndDateTime $endDateTime
    foreach ($line in $lines) {
        Write-Host $line
    }
    Write-Host ''
}

function Format-DiscoveryAppResult {
    <#
    .SYNOPSIS
        Writes a human-readable summary of the app-registration result (FR 15).

    .DESCRIPTION
        Prints AppId, TenantId, certificate Thumbprint and the ready-to-paste
        Connect-MgGraph example. When ConsentGranted is $false, also prints the
        portal admin-consent instructions (opt-in consent path).

    .PARAMETER Result
        The app-registration result object. Expected properties: AppId, TenantId,
        Thumbprint, DisplayName (optional), ConsentGranted (optional bool).

    .PARAMETER SuppressConnectExample
        Skip the 'Connect with the TPM-bound certificate' block. Used by the
        ClientSecret mode, which has no certificate and prints its own
        secret-auth connect example (Format-DiscoveryClientSecretResult)
        instead. Default behaviour (block printed) is unchanged.

    .OUTPUTS
        None. Writes to the host only.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [pscustomobject]$Result,

        [switch]$SuppressConnectExample
    )

    $getProp = {
        param($name)
        if ($Result.PSObject.Properties.Name -contains $name) { $Result.$name } else { $null }
    }

    $appId      = [string](& $getProp 'AppId')
    $tenantId   = [string](& $getProp 'TenantId')
    $thumbprint = [string](& $getProp 'Thumbprint')
    $display    = [string](& $getProp 'DisplayName')
    $redirectUri = [string](& $getProp 'ConsentRedirectUri')

    $consentRaw     = & $getProp 'ConsentGranted'
    $consentGranted = if ($null -eq $consentRaw) { $false } else { [bool]$consentRaw }

    Write-Host ''
    Write-Host 'Discovery app registration' -ForegroundColor Green
    Write-Host '--------------------------'
    if (-not [string]::IsNullOrWhiteSpace($display)) {
        Write-Host ("  DisplayName : {0}" -f $display)
    }
    Write-Host ("  AppId       : {0}" -f $(if ([string]::IsNullOrWhiteSpace($appId))    { '(unknown)' } else { $appId }))
    Write-Host ("  TenantId    : {0}" -f $(if ([string]::IsNullOrWhiteSpace($tenantId)) { '(unknown)' } else { $tenantId }))
    Write-Host ("  Thumbprint  : {0}" -f $(if ([string]::IsNullOrWhiteSpace($thumbprint)) { '(unknown)' } else { $thumbprint }))
    Write-Host ("  Consent     : {0}" -f $(if ($consentGranted) { 'granted (admin consent applied)' } else { 'NOT granted (see instructions below)' }))
    Write-Host ''
    if (-not $SuppressConnectExample) {
        Write-Host 'Connect with the TPM-bound certificate:' -ForegroundColor Cyan
        Write-Host ("  {0}" -f (Get-DiscoveryConnectExample -AppId $appId -TenantId $tenantId -Thumbprint $thumbprint))
        Write-Host ''
    }

    if (-not $consentGranted) {
        Format-DiscoveryConsentInstructions -AppId $appId -TenantId $tenantId -ConsentRedirectUri $redirectUri
    }
}

Export-ModuleMember -Function `
    Get-DiscoveryConnectExample, `
    Get-DiscoveryConsentInstructions, `
    Format-DiscoveryConsentInstructions, `
    Get-DiscoveryClientSecretInstructions, `
    Format-DiscoveryClientSecretResult, `
    Format-DiscoveryAppResult
