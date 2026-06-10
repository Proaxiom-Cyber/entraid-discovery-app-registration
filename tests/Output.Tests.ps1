#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
.SYNOPSIS
    Pester v5 Tier-A suite for Output.psm1 (client-secret handover output).

.DESCRIPTION
    Tier A (hardware/tenant-free; runs anywhere). Validates the print-once
    client-secret handover surface added for -CredentialMode ClientSecret:

      * Get-DiscoveryClientSecretInstructions -- the handover lines: Proaxiom
        Pass one-time-link channel, the shown-ONCE / not-stored notice, the
        ClientSecretCredential connect example, AppId/TenantId substitution and
        placeholders, keyId + expiry passthrough.
      * Format-DiscoveryClientSecretResult -- prints a DUMMY secret EXACTLY once
        on the information stream (Write-Host), returns NOTHING on the success
        stream, and prints the placeholder for the -WhatIf / null-secret shape.
      * Format-DiscoveryAppResult -SuppressConnectExample -- omits the
        certificate connect block (the ClientSecret mode prints its own);
        default behaviour unchanged.

    SECRETS: every value in this file is a DUMMY test fixture -- never a real
    secret. No tenant, no Graph SDK, no network.

    Cross-compatible with Windows PowerShell 5.1 and PowerShell 7.x (no ternary
    / ?? / && / || / 3-segment Join-Path).

    Run with:  Invoke-Pester ./tests/Output.Tests.ps1 -Output Detailed
#>

Describe 'Output.psm1 -- client-secret handover output (Tier A)' {

    BeforeAll {
        $script:RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
        $srcDir = Join-Path $script:RepoRoot 'src'

        Import-Module (Join-Path $srcDir 'Common.psm1') -Force
        Import-Module (Join-Path $srcDir 'Output.psm1') -Force

        # DUMMY value only -- never a real secret.
        $script:DummySecret = 'dummy-secret-for-test'
    }

    Context 'Get-DiscoveryClientSecretInstructions' {

        BeforeAll {
            # Unspecified-kind datetimes: no timezone conversion anywhere, so the
            # formatted date is deterministic on every host.
            $script:LinesWithIds = Get-DiscoveryClientSecretInstructions `
                -AppId 'app-1' -TenantId 'tid-1' -KeyId 'key-1' `
                -EndDateTime ([datetime]'2026-12-01T04:00:00')
            $script:TextWithIds  = ($script:LinesWithIds -join "`n")

            $script:LinesNoIds = Get-DiscoveryClientSecretInstructions
            $script:TextNoIds  = ($script:LinesNoIds -join "`n")
        }

        It 'directs handover through the Proaxiom Pass URL' {
            $script:TextWithIds | Should -Match 'pass\.proaxiom\.com'
        }

        It 'requires a one-time link (never the raw value by email/chat)' {
            $script:TextWithIds | Should -Match 'one-time'
            $script:TextWithIds | Should -Match 'never email/chat'
        }

        It 'states the value is shown ONCE and not stored' {
            $script:TextWithIds | Should -CMatch 'ONCE'
            $script:TextWithIds | Should -Match 'not stored'
        }

        It 'warns the secret is a bearer credential' {
            $script:TextWithIds | Should -Match 'BEARER'
        }

        It 'includes the secret-auth connect example (ClientSecretCredential, Read-Host)' {
            $script:TextWithIds | Should -Match 'ClientSecretCredential'
            $script:TextWithIds | Should -Match 'Read-Host -AsSecureString'
        }

        It 'substitutes the real AppId/TenantId when supplied' {
            $script:TextWithIds | Should -Match "\[pscredential\]::new\('app-1'"
            $script:TextWithIds | Should -Match '-TenantId tid-1'
        }

        It 'falls back to <appid>/<tid> placeholders when ids are omitted' {
            $script:TextNoIds | Should -Match '<appid>'
            $script:TextNoIds | Should -Match '<tid>'
        }

        It 'carries the keyId and expiry for rotation' {
            $script:TextWithIds | Should -Match 'key-1'
            $script:TextWithIds | Should -Match '2026-12-01'
            $script:TextWithIds | Should -Match 'rotate'
        }

        It 'prints (unknown) for keyId/expiry when not supplied' {
            $script:TextNoIds | Should -Match '\(unknown\)'
        }

        It 'honours a custom -PassUrl' {
            $lines = Get-DiscoveryClientSecretInstructions -PassUrl 'https://pass.example.test'
            ($lines -join "`n") | Should -Match 'pass\.example\.test'
        }
    }

    Context 'Format-DiscoveryClientSecretResult print-once semantics' {

        BeforeAll {
            # The live result shape from New-DiscoveryAppClientSecret, with a
            # DUMMY SecureString standing in for the Graph-generated value.
            $script:SecretResult = [pscustomobject]@{
                AppObjectId   = 'obj-1'
                KeyId         = 'key-1'
                Hint          = 'dum'
                DisplayName   = 'Proaxiom discovery client secret'
                StartDateTime = [datetime]'2026-06-10T00:00:00'
                EndDateTime   = [datetime]'2026-12-10T00:00:00'
                SecretSecure  = (ConvertTo-SecureString $script:DummySecret -AsPlainText -Force)
            }
        }

        It 'prints the dummy secret EXACTLY once (information stream)' {
            $merged = Format-DiscoveryClientSecretResult -Result $script:SecretResult `
                -AppId 'app-1' -TenantId 'tid-1' 6>&1
            $hits = @($merged | Where-Object { ("$_" -match [regex]::Escape($script:DummySecret)) })
            @($hits).Count | Should -Be 1 -Because 'the secret value is displayed once and only once'
        }

        It 'returns NOTHING on the success stream (the value is never pipelined)' {
            $merged = @(Format-DiscoveryClientSecretResult -Result $script:SecretResult `
                -AppId 'app-1' -TenantId 'tid-1' 6>&1)
            # With 6>&1 every Write-Host line arrives as an InformationRecord;
            # anything ELSE would be real pipeline (success-stream) output.
            $success = @($merged | Where-Object { $_ -isnot [System.Management.Automation.InformationRecord] })
            $success | Should -BeNullOrEmpty -Because 'the formatter is host-only and returns nothing'
        }

        It 'frames the value with the loud banner and follows with the handover instructions' {
            $merged = Format-DiscoveryClientSecretResult -Result $script:SecretResult `
                -AppId 'app-1' -TenantId 'tid-1' 6>&1
            $text = (@($merged | ForEach-Object { "$_" }) -join "`n")
            $text | Should -Match 'CLIENT SECRET -- DISPLAYED ONCE'
            $text | Should -Match 'pass\.proaxiom\.com'
            $text | Should -Match 'ClientSecretCredential'
            $text | Should -Match 'key-1'
        }

        It 'prints the placeholder (and no value) for the -WhatIf / null-secret shape' {
            $whatIf = [pscustomobject]@{
                AppObjectId   = 'obj-1'
                KeyId         = $null
                Hint          = $null
                DisplayName   = 'Proaxiom discovery client secret'
                StartDateTime = $null
                EndDateTime   = [datetime]'2026-12-10T00:00:00'
                SecretSecure  = $null
                WhatIf        = $true
            }
            $merged = Format-DiscoveryClientSecretResult -Result $whatIf 6>&1
            $text = (@($merged | ForEach-Object { "$_" }) -join "`n")
            $text | Should -Match '\(no secret created; -WhatIf\)'
            $text | Should -Not -Match ([regex]::Escape($script:DummySecret))
        }
    }

    Context 'Format-DiscoveryAppResult -SuppressConnectExample' {

        BeforeAll {
            $script:AppResult = [pscustomobject]@{
                AppId          = 'app-1'
                TenantId       = 'tid-1'
                Thumbprint     = 'TP1'
                DisplayName    = 'Proaxiom Phase 1 Discovery'
                ConsentGranted = $true
            }
        }

        It 'includes the certificate connect example by default' {
            $merged = Format-DiscoveryAppResult -Result $script:AppResult 6>&1
            $text = (@($merged | ForEach-Object { "$_" }) -join "`n")
            $text | Should -Match 'Connect with the TPM-bound certificate'
            $text | Should -Match 'Connect-MgGraph -ClientId app-1 -TenantId tid-1 -CertificateThumbprint TP1'
        }

        It 'omits the connect block when -SuppressConnectExample is set' {
            $merged = Format-DiscoveryAppResult -Result $script:AppResult -SuppressConnectExample 6>&1
            $text = (@($merged | ForEach-Object { "$_" }) -join "`n")
            $text | Should -Not -Match 'Connect with the TPM-bound certificate'
            $text | Should -Not -Match 'CertificateThumbprint'
            # The summary block itself still prints.
            $text | Should -Match 'Discovery app registration'
            $text | Should -Match 'app-1'
        }
    }

    Context 'Exports' {

        It 'exports the client-secret output functions' {
            Get-Command Get-DiscoveryClientSecretInstructions -ErrorAction SilentlyContinue |
                Should -Not -BeNullOrEmpty
            Get-Command Format-DiscoveryClientSecretResult -ErrorAction SilentlyContinue |
                Should -Not -BeNullOrEmpty
        }

        It 'Format-DiscoveryAppResult exposes -SuppressConnectExample' {
            (Get-Command Format-DiscoveryAppResult).Parameters.ContainsKey('SuppressConnectExample') |
                Should -BeTrue
        }
    }
}
