#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
.SYNOPSIS
    Pester v5 validation suite for src/CredentialPosture.psm1 (-CredentialMode posture/disclosure).

.DESCRIPTION
    Tier A only — the module is PURE (no Graph SDK, no tenant, no TPM, no OS calls),
    so every test runs anywhere (macOS PS7, Windows PowerShell 5.1, PowerShell 7):

      * the five credential modes resolve, with ranks exactly 1..5 in the
        ValidateSet order (TpmBound highest ... ClientSecret lowest);
      * ONLY the reduced-assurance pathways (ImportPrivateKey, ClientSecret)
        require an explicit acknowledgement;
      * every posture carries a non-empty Summary/Recommendation and at least
        two Downsides; the load-bearing wording is present (bearer / possession
        for ClientSecret, file / copyable for ImportPrivateKey, Proaxiom Pass in
        both acknowledgement-mode recommendations);
      * an unknown mode throws;
      * the Test-CredentialAcknowledgement truth table (all four rows, including
        the non-interactive fail-closed row's actionable reason);
      * Format-CredentialPosture writes the posture block to the information
        stream only (host output; nothing on the success stream) and surfaces
        the REDUCED-assurance warning for acknowledgement modes.

    Run with:  Invoke-Pester ./tests/CredentialPosture.Tests.ps1 -Output Detailed
#>

Describe 'CredentialPosture.psm1 pure functions (Tier A — runs anywhere)' {

    BeforeAll {
        $script:RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
        # Nested Join-Path for Windows PowerShell 5.1 compatibility.
        Import-Module (Join-Path (Join-Path $script:RepoRoot 'src') 'Common.psm1')            -Force
        Import-Module (Join-Path (Join-Path $script:RepoRoot 'src') 'CredentialPosture.psm1') -Force

        # Assurance order: rank 1 = highest ... rank 5 = lowest. This order is
        # load-bearing — it must equal the ValidateSet order on -Mode.
        $script:ExpectedModeOrder = @(
            'TpmBound', 'ProviderHostedCert', 'ImportPublicCert', 'ImportPrivateKey', 'ClientSecret'
        )
    }

    Context 'Module imports on this host' {

        It 'exports the expected public functions' {
            $exported = (Get-Command -Module 'CredentialPosture').Name
            foreach ($fn in @(
                    'Resolve-CredentialPosture',
                    'Format-CredentialPosture',
                    'Test-CredentialAcknowledgement')) {
                $exported | Should -Contain $fn -Because "$fn must be exported"
            }
        }
    }

    Context 'Resolve-CredentialPosture (mode -> posture decision)' {

        It 'resolves <mode> with rank <rank> and RequiresAcknowledgement=<ack>' -ForEach @(
            @{ mode = 'TpmBound';           rank = 1; ack = $false }
            @{ mode = 'ProviderHostedCert'; rank = 2; ack = $false }
            @{ mode = 'ImportPublicCert';   rank = 3; ack = $false }
            @{ mode = 'ImportPrivateKey';   rank = 4; ack = $true }
            @{ mode = 'ClientSecret';       rank = 5; ack = $true }
        ) {
            $p = Resolve-CredentialPosture -Mode $mode
            $p.Mode                    | Should -BeExactly $mode
            $p.AssuranceRank           | Should -Be $rank
            $p.RequiresAcknowledgement | Should -Be $ack
            $p.AssuranceLevel          | Should -Not -BeNullOrEmpty
        }

        It 'the -Mode ValidateSet order IS the assurance order (ranks exactly 1..5)' {
            $vs = (Get-Command -Name 'Resolve-CredentialPosture').Parameters['Mode'].Attributes |
                Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } |
                Select-Object -First 1
            $vs | Should -Not -BeNullOrEmpty -Because '-Mode must carry a ValidateSet'
            @($vs.ValidValues) | Should -Be $script:ExpectedModeOrder

            $ranks = foreach ($m in @($vs.ValidValues)) {
                (Resolve-CredentialPosture -Mode $m).AssuranceRank
            }
            @($ranks) | Should -Be @(1, 2, 3, 4, 5) `
                -Because 'rank must walk 1 (highest, TpmBound) to 5 (lowest, ClientSecret) in ValidateSet order'
        }

        It 'ONLY ImportPrivateKey and ClientSecret require acknowledgement' {
            $ackModes = $script:ExpectedModeOrder | Where-Object {
                (Resolve-CredentialPosture -Mode $_).RequiresAcknowledgement
            }
            @($ackModes) | Should -Be @('ImportPrivateKey', 'ClientSecret') `
                -Because 'exactly the two reduced-assurance pathways need an explicit acknowledgement'
        }

        It '<mode> has a non-empty Summary, a non-empty Recommendation and at least 2 Downsides' -ForEach @(
            @{ mode = 'TpmBound' }
            @{ mode = 'ProviderHostedCert' }
            @{ mode = 'ImportPublicCert' }
            @{ mode = 'ImportPrivateKey' }
            @{ mode = 'ClientSecret' }
        ) {
            $p = Resolve-CredentialPosture -Mode $mode
            $p.Summary        | Should -Not -BeNullOrEmpty
            $p.Recommendation | Should -Not -BeNullOrEmpty
            @($p.Downsides).Count | Should -BeGreaterOrEqual 2 -Because 'every pathway has at least two stated downsides'
            foreach ($d in @($p.Downsides)) {
                $d | Should -Not -BeNullOrEmpty
            }
        }

        It 'ClientSecret downsides call out the bearer / no-possession-proof nature' {
            $joined = (@((Resolve-CredentialPosture -Mode 'ClientSecret').Downsides) -join ' ')
            $joined | Should -Match '(?i)bearer'
            $joined | Should -Match '(?i)possession'
        }

        It 'ImportPrivateKey downsides call out the file-resident / copyable nature' {
            $joined = (@((Resolve-CredentialPosture -Mode 'ImportPrivateKey').Downsides) -join ' ')
            $joined | Should -Match '(?i)file'
            $joined | Should -Match '(?i)cop' -Because 'the downsides must state the key can be copied'
        }

        It '<mode> recommendation points at Proaxiom Pass for the transfer' -ForEach @(
            @{ mode = 'ImportPrivateKey' }
            @{ mode = 'ClientSecret' }
        ) {
            (Resolve-CredentialPosture -Mode $mode).Recommendation |
                Should -Match 'Proaxiom Pass' `
                -Because 'reduced-assurance material must only move via Proaxiom Pass one-time links'
        }

        It 'an unknown mode throws' {
            { Resolve-CredentialPosture -Mode 'NotARealMode' } | Should -Throw
        }
    }

    Context 'Test-CredentialAcknowledgement (acknowledgement truth table)' {

        It 'pathway needing no acknowledgement -> proceed, no prompt' {
            $r = Test-CredentialAcknowledgement -RequiresAcknowledgement $false -Acknowledged $false -Interactive $false
            $r.ShouldProceed | Should -BeTrue
            $r.NeedsPrompt   | Should -BeFalse
            $r.Reason        | Should -Not -BeNullOrEmpty
        }

        It 'acknowledged (the flag was supplied) -> proceed, no prompt' {
            $r = Test-CredentialAcknowledgement -RequiresAcknowledgement $true -Acknowledged $true -Interactive $false
            $r.ShouldProceed | Should -BeTrue
            $r.NeedsPrompt   | Should -BeFalse
            $r.Reason        | Should -Match 'AcknowledgeReducedAssurance' `
                -Because 'the reason should record that the flag satisfied the acknowledgement'
        }

        It 'not acknowledged + interactive -> do NOT proceed yet; the caller must prompt' {
            $r = Test-CredentialAcknowledgement -RequiresAcknowledgement $true -Acknowledged $false -Interactive $true
            $r.ShouldProceed | Should -BeFalse -Because 'proceeding is conditional on the operator answering yes to the prompt'
            $r.NeedsPrompt   | Should -BeTrue
            $r.Reason        | Should -Not -BeNullOrEmpty
        }

        It 'not acknowledged + non-interactive -> fail closed with an actionable reason' {
            $r = Test-CredentialAcknowledgement -RequiresAcknowledgement $true -Acknowledged $false -Interactive $false
            $r.ShouldProceed | Should -BeFalse
            $r.NeedsPrompt   | Should -BeFalse
            $r.Reason        | Should -Match 'AcknowledgeReducedAssurance' `
                -Because 'the operator must be told exactly how to re-run (with -AcknowledgeReducedAssurance)'
        }
    }

    Context 'Format-CredentialPosture (host output smoke test)' {

        It 'prints the posture block for an acknowledgement mode on the information stream only' {
            $posture  = Resolve-CredentialPosture -Mode 'ImportPrivateKey'
            $captured = Format-CredentialPosture -Posture $posture 6>&1

            # Write-Host emits InformationRecords (stream 6); anything else in the
            # capture would be success-stream leakage from a host-only function.
            $info  = @($captured | Where-Object { $_ -is [System.Management.Automation.InformationRecord] })
            $other = @($captured | Where-Object { $_ -isnot [System.Management.Automation.InformationRecord] })
            $other.Count | Should -Be 0 -Because 'Format-CredentialPosture must return nothing on the success stream'
            $info.Count  | Should -BeGreaterThan 0

            $text = ($info | ForEach-Object { $_.ToString() }) -join "`n"
            $text | Should -Match 'ImportPrivateKey' -Because 'the titled block names the pathway'
            $text | Should -CMatch 'REDUCED' -Because 'an acknowledgement mode must surface the REDUCED-assurance warning'
        }

        It 'does not print the reduced-assurance warning for the default pathway' {
            $captured = Format-CredentialPosture -Posture (Resolve-CredentialPosture -Mode 'TpmBound') 6>&1
            $text = (@($captured) | ForEach-Object { $_.ToString() }) -join "`n"
            $text | Should -Match 'TpmBound'
            $text | Should -Not -Match '(?i)reduced'
        }
    }
}
