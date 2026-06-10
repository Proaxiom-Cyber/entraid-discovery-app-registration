#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
.SYNOPSIS
    Tier-A tests for the Cloudflare Worker admin-consent landing page.

.DESCRIPTION
    Runs the Worker module's Node test suite when Node.js is available. The
    Worker is stateless and local-only under test: no Cloudflare account, network,
    tenant, or secret is required.
#>

BeforeDiscovery {
    $script:NodeAvailable = [bool](Get-Command node -ErrorAction SilentlyContinue)
}

Describe 'Cloudflare consent redirect Worker (Tier A)' {

    BeforeAll {
        $script:RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
        $script:WorkerTest = Join-Path (Join-Path $script:RepoRoot 'cloudflare') 'consent-redirect-worker'
        $script:WorkerTest = Join-Path $script:WorkerTest 'worker.test.mjs'
    }

    It 'passes its local Node test suite' -Skip:(-not $script:NodeAvailable) {
        & node --test $script:WorkerTest
        $LASTEXITCODE | Should -Be 0
    }
}
