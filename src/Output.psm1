<#
.SYNOPSIS
    Output formatting for the discovery app-registration result (FR 15).

.DESCRIPTION
    Pure formatting only -- no Graph SDK, no tenant, no network. Produces:

      * Format-DiscoveryAppResult       - human-readable summary printed to host
      * Get-DiscoveryConnectExample     - the ready-to-paste Connect-MgGraph line
      * Get-DiscoveryConsentInstructions - portal admin-consent steps + URL
      * Format-DiscoveryConsentInstructions - prints the consent steps to host

    All functions are deterministic string builders so they can be unit-tested
    off-host. Connect example and consent URL match the PRD's documented shapes
    (Connect-MgGraph -ClientId <appid> -TenantId <tid> -CertificateThumbprint <tp>).

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
        [string]$TenantId
    )

    $appToken    = if ([string]::IsNullOrWhiteSpace($AppId))    { '<appid>' } else { $AppId }
    $tenantToken = if ([string]::IsNullOrWhiteSpace($TenantId)) { 'common' } else { $TenantId }

    $consentUrl = "https://login.microsoftonline.com/$tenantToken/adminconsent?client_id=$appToken"

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
        [string]$TenantId
    )

    $lines = Get-DiscoveryConsentInstructions -AppId $AppId -TenantId $TenantId
    Write-Host ''
    Write-Host 'Admin consent required' -ForegroundColor Yellow
    Write-Host '----------------------'
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

    .OUTPUTS
        None. Writes to the host only.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [pscustomobject]$Result
    )

    $getProp = {
        param($name)
        if ($Result.PSObject.Properties.Name -contains $name) { $Result.$name } else { $null }
    }

    $appId      = [string](& $getProp 'AppId')
    $tenantId   = [string](& $getProp 'TenantId')
    $thumbprint = [string](& $getProp 'Thumbprint')
    $display    = [string](& $getProp 'DisplayName')

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
    Write-Host 'Connect with the TPM-bound certificate:' -ForegroundColor Cyan
    Write-Host ("  {0}" -f (Get-DiscoveryConnectExample -AppId $appId -TenantId $tenantId -Thumbprint $thumbprint))
    Write-Host ''

    if (-not $consentGranted) {
        Format-DiscoveryConsentInstructions -AppId $appId -TenantId $tenantId
    }
}

Export-ModuleMember -Function `
    Get-DiscoveryConnectExample, `
    Get-DiscoveryConsentInstructions, `
    Format-DiscoveryConsentInstructions, `
    Format-DiscoveryAppResult
