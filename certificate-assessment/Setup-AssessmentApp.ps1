#Requires -Version 7.2
<#
.SYNOPSIS
Run the shared PowerShell engine. The default mode is a local plan.
#>
[CmdletBinding(DefaultParameterSetName = 'Plan')]
param(
    [Parameter(Mandatory)][string]$Config,
    [Parameter(ParameterSetName = 'Preview')][switch]$Preview,
    [Parameter(ParameterSetName = 'Apply')][switch]$Apply
)

$ErrorActionPreference = 'Stop'
try {
    & (Join-Path $PSScriptRoot 'Sync-AssessmentApp.ps1') @PSBoundParameters
    exit 0
}
catch {
    Write-Error 'Assessment setup failed. Review the plan or receipt for recorded progress.' -ErrorAction Continue
    exit 1
}
