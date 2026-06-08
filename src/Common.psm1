<#
.SYNOPSIS
    Shared helpers for the Proaxiom discovery app provisioning tool.

.DESCRIPTION
    Cross-cutting utilities used by both the entry point script and the
    KeyGeneration module. Kept deliberately small and dependency-free so it
    loads identically on Windows PowerShell 5.1 and PowerShell 7.x.
#>

Set-StrictMode -Version Latest

function Test-IsWindows {
    <#
    .SYNOPSIS
        Returns $true when running on Windows.

    .DESCRIPTION
        Windows PowerShell 5.1 (PSEdition = 'Desktop') is always Windows but does
        not define the automatic $IsWindows variable. PowerShell 6+ (PSEdition =
        'Core') defines $IsWindows. This helper papers over that difference so the
        rest of the codebase never has to reference the bare $IsWindows variable
        (which would throw under StrictMode on 5.1).

    .OUTPUTS
        System.Boolean
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        $true
    }
    else {
        $IsWindows
    }
}

function New-DiscoveryResult {
    <#
    .SYNOPSIS
        Factory for a consistently-shaped result object.

    .DESCRIPTION
        Wraps an arbitrary hashtable of properties in a [pscustomobject] so every
        function in the tool emits objects with a predictable shape (and so the
        pass-through properties are easy to extend without changing call sites).

    .PARAMETER Property
        Hashtable of properties to project onto the returned object.

    .EXAMPLE
        New-DiscoveryResult -Property @{ Thumbprint = 'ABC'; Subject = 'CN=x' }

    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [hashtable]$Property
    )

    [pscustomobject]$Property
}

Export-ModuleMember -Function Test-IsWindows, New-DiscoveryResult
