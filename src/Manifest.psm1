<#
.SYNOPSIS
    Loads the Entra permission manifest and builds the Graph requiredResourceAccess structure.

.DESCRIPTION
    Pure logic only -- no Graph SDK, no tenant, no network. Reads
    manifests/permissions.csv (columns ResourceAppId, PermissionId, AccessType)
    and transforms it into the Microsoft Graph application-registration
    `requiredResourceAccess` shape:

        @(
            @{
                resourceAppId  = '<resource GUID>'
                resourceAccess = @(
                    @{ id = '<role/scope GUID>'; type = 'Role' }
                    ...
                )
            }
            ...
        )

    Rows are grouped by ResourceAppId so each resource app appears once with all
    of its requested permissions nested underneath. AccessType maps to the Graph
    resourceAccess `type` field ('Role' for application permissions, 'Scope' for
    delegated). The discovery manifest is Role-only, but the transform is generic.

    These functions are imported and unit-tested off-host (macOS, no SDK). The
    output feeds the app-registration payload builders in src/AppRegistration.psm1.

    Cross-compatible with Windows PowerShell 5.1 (Desktop) and PowerShell 7.x (Core).
#>

Set-StrictMode -Version Latest

# Canonical Microsoft Graph resource app id. Referenced where a literal would drift.
$script:GraphResourceAppId = '00000003-0000-0000-c000-000000000000'

function Resolve-DiscoveryManifestPath {
    <#
    .SYNOPSIS
        Resolves the default permission manifest path relative to the module.

    .DESCRIPTION
        Returns the absolute path to manifests/permissions.csv (one directory up
        from src/). Uses nested Join-Path for Windows PowerShell 5.1 compatibility
        (5.1's Join-Path accepts only -Path and -ChildPath). Does NOT require the
        file to exist; callers validate presence.

    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    Join-Path (Join-Path $PSScriptRoot '..') (Join-Path 'manifests' 'permissions.csv')
}

function Import-DiscoveryManifest {
    <#
    .SYNOPSIS
        Loads and validates the permission manifest CSV.

    .DESCRIPTION
        Reads the manifest CSV, asserts the three required columns are present
        (ResourceAppId, PermissionId, AccessType), and returns the parsed rows.
        Fails closed: throws if the file is missing, empty, has the wrong header,
        contains a malformed GUID, or carries a row missing a required field.

    .PARAMETER Path
        Path to the manifest CSV. Defaults to manifests/permissions.csv.

    .OUTPUTS
        System.Object[] (the imported CSV rows).
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        $Path = Resolve-DiscoveryManifestPath
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Permission manifest not found: '$Path'."
    }

    $rows = @(Import-Csv -LiteralPath $Path)
    if ($rows.Count -eq 0) {
        throw "Permission manifest '$Path' contains no data rows."
    }

    $required = @('ResourceAppId', 'PermissionId', 'AccessType')
    $columns  = $rows[0].PSObject.Properties.Name
    foreach ($col in $required) {
        if ($columns -notcontains $col) {
            throw "Permission manifest '$Path' is missing required column '$col'."
        }
    }

    $guidRegex = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    foreach ($row in $rows) {
        foreach ($col in @('ResourceAppId', 'PermissionId')) {
            $val = [string]$row.$col
            if ([string]::IsNullOrWhiteSpace($val)) {
                throw "Permission manifest '$Path' has a row with an empty '$col'."
            }
            if ($val -notmatch $guidRegex) {
                throw "Permission manifest '$Path' has a malformed GUID in '$col': '$val'."
            }
        }
        if ([string]::IsNullOrWhiteSpace([string]$row.AccessType)) {
            throw "Permission manifest '$Path' has a row with an empty 'AccessType'."
        }
    }

    $rows
}

function Get-DiscoveryRequiredResourceAccess {
    <#
    .SYNOPSIS
        Builds the Graph requiredResourceAccess array from the permission manifest.

    .DESCRIPTION
        Loads the manifest (via Import-DiscoveryManifest) and groups its rows by
        ResourceAppId into the `requiredResourceAccess` structure consumed by
        New-MgApplication / Update-MgApplication. Each resource app becomes one
        entry whose `resourceAccess` lists every requested permission as
        @{ id = <PermissionId>; type = <mapped AccessType> }.

        AccessType mapping: 'Role' -> 'Role' (application permission),
        'Scope'/'Delegated' -> 'Scope' (delegated permission). Any other value is
        passed through verbatim so the transform stays generic and fails loudly
        downstream rather than silently mangling input.

        Pure: no Graph SDK, no tenant. Resource apps are emitted in first-seen
        order; permissions within a resource preserve manifest order.

    .PARAMETER Path
        Path to the manifest CSV. Defaults to manifests/permissions.csv.

    .OUTPUTS
        System.Collections.Hashtable[] (one entry per resource app).
    #>
    [CmdletBinding()]
    [OutputType([hashtable[]])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Path
    )

    $rows = Import-DiscoveryManifest -Path $Path

    # Preserve first-seen resource order while grouping.
    $order  = New-Object System.Collections.Generic.List[string]
    $byApp  = @{}

    foreach ($row in $rows) {
        $appId = [string]$row.ResourceAppId
        if (-not $byApp.ContainsKey($appId)) {
            $byApp[$appId] = New-Object System.Collections.Generic.List[hashtable]
            $order.Add($appId)
        }

        $type = switch -Regex ([string]$row.AccessType) {
            '^(?i)Role$'             { 'Role';  break }
            '^(?i)(Scope|Delegated)$' { 'Scope'; break }
            default                  { [string]$row.AccessType }
        }

        $byApp[$appId].Add(@{
            id   = [string]$row.PermissionId
            type = $type
        })
    }

    $result = foreach ($appId in $order) {
        @{
            resourceAppId  = $appId
            resourceAccess = @($byApp[$appId].ToArray())
        }
    }

    # Return as an array even when there is a single resource app. The unary comma
    # prevents the pipeline from unwrapping a one-element array (which would emit a
    # bare hashtable and confuse callers/.Count). $result is $null when no rows.
    if ($null -eq $result) {
        return , @()
    }
    , @($result)
}

Export-ModuleMember -Function `
    Resolve-DiscoveryManifestPath, `
    Import-DiscoveryManifest, `
    Get-DiscoveryRequiredResourceAccess
