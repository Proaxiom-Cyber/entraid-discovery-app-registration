#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
.SYNOPSIS
    Pester v5 validation suite for manifests/permissions.csv.

.DESCRIPTION
    Tier A (hardware/tenant-free) test. Validates the structure and content of the
    Entra ID app-registration permission manifest used by the Phase 1 discovery
    provisioning script. Runs anywhere pwsh + Pester v5 are available — no TPM,
    no tenant, no network required.

    Run with:  Invoke-Pester ./tests/Manifest.Tests.ps1
#>

BeforeDiscovery {
    # Nested Join-Path: Windows PowerShell 5.1's Join-Path accepts only -Path and
    # -ChildPath, so a multi-segment positional call (Join-Path a b c d) throws there.
    $script:ManifestPath = Join-Path (Join-Path (Join-Path $PSScriptRoot '..') 'manifests') 'permissions.csv' |
        Resolve-Path -ErrorAction SilentlyContinue |
        ForEach-Object { $_.Path }

    if (-not $script:ManifestPath) {
        # Fall back to the unresolved path so the "file exists" test fails loudly
        # rather than the suite erroring out during discovery.
        $script:ManifestPath = Join-Path (Join-Path (Join-Path $PSScriptRoot '..') 'manifests') 'permissions.csv'
    }
}

Describe 'permissions.csv manifest' {

    BeforeAll {
        $script:ManifestPath = Join-Path (Join-Path (Join-Path $PSScriptRoot '..') 'manifests') 'permissions.csv'
        $script:ResolvedPath =
            (Resolve-Path -LiteralPath $script:ManifestPath -ErrorAction SilentlyContinue).Path

        $script:GraphResourceAppId = '00000003-0000-0000-c000-000000000000'

        # GUID regex: 8-4-4-4-12 hex, case-insensitive.
        $script:GuidRegex =
            '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

        # The 5 governance/reporting ADD permissions that MUST be present (by GUID).
        $script:RequiredAddGuids = @{
            'EntitlementManagement.Read.All' = 'c74fd47d-ed3c-45c3-9a9e-b8676de685d2'
            'AccessReview.Read.All'          = 'd07a8cc0-3d51-4b77-b3b0-32704d1f69fa'
            'LifecycleWorkflows.Read.All'    = '7c67316a-232a-4b84-be22-cea2c0906404'
            'Agreement.Read.All'             = '2f3e6f8c-093b-4c57-a58b-ba5ce494a169'
            'Reports.Read.All'               = '230c1aed-a721-4c5d-9cb4-a90514e508ef'
        }

        # OnPremDirectorySynchronization.Read.All must be ABSENT.
        #
        # NOTE on GUID selection: the manifest holds *Application* permissions
        # (AccessType = Role / app roles). Per the Microsoft Graph permissions
        # reference, OnPremDirectorySynchronization.Read.All has two distinct IDs:
        #   - Application (app role) : bb70e231-92dc-4729-aff5-697b3f04be95
        #   - Delegated (scope)      : f6609722-4100-44eb-b747-e6ca0536989d
        # The GUID f6609722-... cited in the task brief is the *Delegated* ID, not
        # the Application one. Because this manifest only carries Role entries, the
        # correct value to assert absent is the Application role ID. We assert BOTH
        # are absent for completeness; the Application ID is the load-bearing one.
        $script:OnPremAppRoleGuid   = 'bb70e231-92dc-4729-aff5-697b3f04be95'
        $script:OnPremDelegatedGuid = 'f6609722-4100-44eb-b747-e6ca0536989d'

        if ($script:ResolvedPath) {
            $script:RawLines = Get-Content -LiteralPath $script:ResolvedPath
            $script:Rows     = Import-Csv -LiteralPath $script:ResolvedPath
        }
        else {
            $script:RawLines = @()
            $script:Rows     = @()
        }
    }

    Context 'File presence and structure' {

        It 'exists at manifests/permissions.csv' {
            $script:ResolvedPath | Should -Not -BeNullOrEmpty -Because 'the manifest must exist'
            Test-Path -LiteralPath $script:ResolvedPath | Should -BeTrue
        }

        It 'has the exact header: ResourceAppId,PermissionId,AccessType' {
            $script:RawLines | Should -Not -BeNullOrEmpty
            $script:RawLines[0].Trim() | Should -BeExactly 'ResourceAppId,PermissionId,AccessType'
        }

        It 'parses as CSV with the three expected columns' {
            $script:Rows | Should -Not -BeNullOrEmpty
            $columns = $script:Rows[0].PSObject.Properties.Name
            $columns | Should -Be @('ResourceAppId', 'PermissionId', 'AccessType')
        }
    }

    Context 'Row count' {

        It 'contains exactly 53 data rows' {
            @($script:Rows).Count | Should -Be 53
        }
    }

    Context 'Column invariants' {

        It 'every ResourceAppId is Microsoft Graph (00000003-0000-0000-c000-000000000000)' {
            $offenders = $script:Rows |
                Where-Object { $_.ResourceAppId -ne $script:GraphResourceAppId }
            $offenders | Should -BeNullOrEmpty -Because 'all permissions target Microsoft Graph'
        }

        It 'every AccessType is Role (application permission)' {
            $offenders = $script:Rows | Where-Object { $_.AccessType -ne 'Role' }
            $offenders | Should -BeNullOrEmpty -Because 'manifest holds only application (Role) permissions'
        }
    }

    Context 'PermissionId integrity' {

        It 'every PermissionId is a well-formed GUID' {
            $malformed = $script:Rows |
                Where-Object { $_.PermissionId -notmatch $script:GuidRegex }
            $malformed | Should -BeNullOrEmpty -Because 'each PermissionId must be a valid GUID'
        }

        It 'has no duplicate PermissionId values' {
            $dupes = $script:Rows |
                Group-Object -Property PermissionId |
                Where-Object { $_.Count -gt 1 } |
                ForEach-Object { $_.Name }
            $dupes | Should -BeNullOrEmpty -Because 'each permission should appear exactly once'
        }
    }

    Context 'Required governance/reporting ADD permissions are present' {

        It '<name> (<guid>) is present' -ForEach @(
            foreach ($kv in @{
                'EntitlementManagement.Read.All' = 'c74fd47d-ed3c-45c3-9a9e-b8676de685d2'
                'AccessReview.Read.All'          = 'd07a8cc0-3d51-4b77-b3b0-32704d1f69fa'
                'LifecycleWorkflows.Read.All'    = '7c67316a-232a-4b84-be22-cea2c0906404'
                'Agreement.Read.All'             = '2f3e6f8c-093b-4c57-a58b-ba5ce494a169'
                'Reports.Read.All'               = '230c1aed-a721-4c5d-9cb4-a90514e508ef'
            }.GetEnumerator()) {
                @{ name = $kv.Key; guid = $kv.Value }
            }
        ) {
            $match = $script:Rows | Where-Object { $_.PermissionId -eq $guid }
            $match | Should -Not -BeNullOrEmpty -Because "$name ($guid) must be in the manifest"
        }
    }

    Context 'OnPremDirectorySynchronization.Read.All is absent' {

        It 'the Application (app role) GUID bb70e231-... is NOT present' {
            $match = $script:Rows |
                Where-Object { $_.PermissionId -eq $script:OnPremAppRoleGuid }
            $match | Should -BeNullOrEmpty -Because 'OnPrem dir-sync read (app role) is out of scope'
        }

        It 'the Delegated GUID f6609722-... is NOT present either' {
            $match = $script:Rows |
                Where-Object { $_.PermissionId -eq $script:OnPremDelegatedGuid }
            $match | Should -BeNullOrEmpty -Because 'the delegated ID should not appear in a Role-only manifest'
        }
    }
}
