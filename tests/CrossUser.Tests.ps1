#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
.SYNOPSIS
    Pester v5 validation suite for CrossUser.psm1 cross-user key access (FR 16).

.DESCRIPTION
    Covers the `-GrantUser` private-key ACL feature:

      Tier A (runs ANYWHERE — no TPM, no admin, no Windows):
        * the CurrentUser -> warn/no-op vs LocalMachine -> apply decision
          (Test-GrantUserApplicable);
        * account -> NTAccount/SID resolution for a well-known principal, plus
          the clear-throw path for an unresolvable account (Resolve-GrantAccount);
        * the result-object shape returned by Grant-DiscoveryKeyAccess on the
          CurrentUser store (Applied = $false), exercised on a fixture cert;
        * the off-Windows fail-closed error.

      Tier B (SKIP-GATED on a real TPM host — runs on the CI runner, which is
      LocalSystem = admin with a real vTPM):
        * generate a LocalMachine TPM/MPCP key, grant BUILTIN\Users Read access,
          and assert the key-container file's ACL now carries an Allow/Read entry
          for that principal. Cert + key cleaned up in a finally/AfterAll.

    The Tier-B gate is the SAME inline $script:OnTpmHost probe used in
    tests/KeyGeneration.Tests.ps1, so these tests SKIP on macOS (OnTpmHost=$false)
    and execute for real only on Windows + TPM.

    Run with:  Invoke-Pester ./tests/CrossUser.Tests.ps1 -Output Detailed
#>

BeforeDiscovery {
    # ----------------------------------------------------------------------
    # CAPABILITY GATE — copied VERBATIM from tests/KeyGeneration.Tests.ps1 so
    # both files gate identically. Computed INLINE during DISCOVERY because
    # Pester's discovery scope does not reliably resolve module functions
    # imported here. On macOS / Linux this short-circuits to $false (not
    # Windows) => the Tier-B Context skips. On Windows + usable TPM the MPCP
    # opens via CNG and the Tier-B Context runs.
    # ----------------------------------------------------------------------
    $isWin = if ($PSVersionTable.PSEdition -eq 'Desktop') { $true } else { [bool]$IsWindows }

    # Surface the Windows determination at DISCOVERY scope so -Skip: on Contexts
    # (which Pester evaluates during discovery, not run) resolves correctly. The
    # off-Windows fail-closed Context uses -Skip:($script:IsWindowsHost): on the
    # Windows CI runner the function genuinely does NOT throw, so that test is
    # only meaningful (and only PASSES) off Windows.
    $script:IsWindowsHost = $isWin

    $script:OnTpmHost = $false
    if ($isWin) {
        try {
            $mpcp = [System.Security.Cryptography.CngProvider]::new('Microsoft Platform Crypto Provider')
            $null = [System.Security.Cryptography.CngKey]::Exists(
                '___proaxiom_discovery_gate_probe___',
                $mpcp,
                [System.Security.Cryptography.CngKeyOpenOptions]::None)
            $script:OnTpmHost = $true
        }
        catch {
            $script:OnTpmHost = $false
        }
    }
}

Describe 'CrossUser.psm1 — cross-user key access (FR 16)' {

    BeforeAll {
        $script:RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
        # Nested Join-Path: Windows PowerShell 5.1's Join-Path takes only -Path
        # and -ChildPath, so a 3-segment positional call throws there.
        Import-Module (Join-Path (Join-Path $script:RepoRoot 'src') 'Common.psm1')    -Force
        Import-Module (Join-Path (Join-Path $script:RepoRoot 'src') 'CrossUser.psm1') -Force

        # Inline Windows check for run/teardown phases (mirrors Common.psm1).
        $script:IsWindowsHost =
            if ($PSVersionTable.PSEdition -eq 'Desktop') { $true } else { [bool]$IsWindows }

        $script:TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("proaxiom-crossuser-" + [guid]::NewGuid())
        New-Item -ItemType Directory -Path $script:TmpDir -Force | Out-Null
    }

    AfterAll {
        if ($script:TmpDir -and (Test-Path -LiteralPath $script:TmpDir)) {
            Remove-Item -LiteralPath $script:TmpDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # =======================================================================
    # TIER A — pure logic + shape, runs anywhere.
    # =======================================================================
    Context 'Test-GrantUserApplicable: store decision (pure)' {

        It 'LocalMachine is applicable' {
            $r = Test-GrantUserApplicable -StoreLocation 'LocalMachine'
            $r.Applicable | Should -BeTrue
            $r.Reason     | Should -BeExactly 'OK'
        }

        It 'CurrentUser is NOT applicable (per-profile, not shareable)' {
            $r = Test-GrantUserApplicable -StoreLocation 'CurrentUser'
            $r.Applicable | Should -BeFalse
            $r.Reason     | Should -Match 'per-profile'
        }
    }

    Context 'Resolve-GrantAccount: account -> NTAccount/SID' {

        It 'resolves a well-known principal (BUILTIN\Users) to its fixed SID' {
            # S-1-5-32-545 is the universally-fixed SID for the Users alias and
            # resolves on Windows; on PS7/macOS the NTAccount.Translate path is
            # exercised but may not resolve — so gate this assertion on Windows
            # and assert the throw behaviour off-Windows below.
            if (-not $script:IsWindowsHost) {
                Set-ItResult -Skipped -Because 'arbitrary NTAccount translation is Windows-only'
                return
            }
            $r = Resolve-GrantAccount -Account 'BUILTIN\Users'
            $r.Sid     | Should -BeExactly 'S-1-5-32-545'
            $r.Account | Should -Match 'Users'
        }

        It 'throws a clear error for an unresolvable account' {
            { Resolve-GrantAccount -Account 'NO_SUCH_DOMAIN\definitely-not-a-real-account-zzz' } |
                Should -Throw -ExpectedMessage '*Could not resolve account*'
        }

        It 'rejects whitespace-only input' {
            { Resolve-GrantAccount -Account '   ' } | Should -Throw
        }
    }

    Context 'Grant-DiscoveryKeyAccess: CurrentUser store warns + no-ops (shape)' {

        BeforeAll {
            # A throwaway PUBLIC cert is enough to exercise the store-decision
            # branch: CurrentUser short-circuits BEFORE any key-file lookup, so a
            # cert with no private key still produces the documented result shape.
            $cerPath = Join-Path $script:TmpDir 'shape.cer'
            $keyPath = Join-Path $script:TmpDir 'shape.key.pem'
            $pemPath = Join-Path $script:TmpDir 'shape.pem'

            $ErrorActionPreference = 'Continue'
            & openssl req -x509 -newkey rsa:2048 -nodes `
                -keyout $keyPath -out $pemPath -days 30 `
                -subj '/CN=Proaxiom CrossUser Fixture' 2>$null
            if ($LASTEXITCODE -ne 0) { throw "openssl req failed (exit $LASTEXITCODE)" }
            & openssl x509 -in $pemPath -outform DER -out $cerPath 2>$null
            if ($LASTEXITCODE -ne 0) { throw "openssl x509 (DER) failed (exit $LASTEXITCODE)" }

            $script:FixtureCert =
                [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cerPath)
        }

        It 'returns Applied = $false with the documented 7-property shape on CurrentUser' {
            if (-not $script:IsWindowsHost) {
                # Off-Windows the function fails closed BEFORE the store decision,
                # so the CurrentUser no-op shape is only assertable on Windows.
                Set-ItResult -Skipped -Because 'Grant-DiscoveryKeyAccess is Windows-only off the store-decision path'
                return
            }
            $r = Grant-DiscoveryKeyAccess -Certificate $script:FixtureCert `
                -Account 'BUILTIN\Users' -StoreLocation 'CurrentUser' -WarningAction SilentlyContinue

            $r.Applied       | Should -BeFalse
            $r.StoreLocation | Should -BeExactly 'CurrentUser'
            $r.Reason        | Should -Match 'per-profile'
            $r.KeyFilePath   | Should -BeNullOrEmpty

            $props = @($r.PSObject.Properties.Name | Sort-Object)
            $expected = @('Account', 'Applied', 'KeyFilePath', 'Reason', 'Rights', 'Sid', 'StoreLocation') | Sort-Object
            $props | Should -Be $expected
        }
    }

    Context 'Grant-DiscoveryKeyAccess: off-Windows fail-closed' -Skip:($script:IsWindowsHost) {

        It 'throws a Windows-only error off Windows' {
            $cerPath = Join-Path $script:TmpDir 'offwin.cer'
            $keyPath = Join-Path $script:TmpDir 'offwin.key.pem'
            $pemPath = Join-Path $script:TmpDir 'offwin.pem'

            $ErrorActionPreference = 'Continue'
            & openssl req -x509 -newkey rsa:2048 -nodes `
                -keyout $keyPath -out $pemPath -days 30 `
                -subj '/CN=Proaxiom CrossUser OffWin' 2>$null
            if ($LASTEXITCODE -ne 0) { throw "openssl req failed (exit $LASTEXITCODE)" }
            & openssl x509 -in $pemPath -outform DER -out $cerPath 2>$null
            if ($LASTEXITCODE -ne 0) { throw "openssl x509 (DER) failed (exit $LASTEXITCODE)" }

            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cerPath)
            { Grant-DiscoveryKeyAccess -Certificate $cert -Account 'BUILTIN\Users' -StoreLocation 'LocalMachine' } |
                Should -Throw -ExpectedMessage '*Windows-only*'
        }
    }

    # =======================================================================
    # TIER B — real LocalMachine TPM key + real ACL grant.
    # Runs only on a Windows + TPM host (the CI runner; LocalSystem = admin).
    # =======================================================================
    Context 'Tier B: GrantUser applies a real Read ACL to a LocalMachine TPM key' -Skip:(-not $script:OnTpmHost) {

        BeforeAll {
            Import-Module (Join-Path (Join-Path $script:RepoRoot 'src') 'KeyGeneration.psm1') -Force

            $script:TbSubject = 'CN=zzTEST-CrossUserKey'
            # LocalMachine key: required for cross-user ACL sharing. The CI runner
            # is LocalSystem (admin), so LocalMachine\My + the key-file ACL write
            # both succeed.
            $script:TbMeta = New-DiscoveryTpmKey -Subject $script:TbSubject `
                -ValidityMonths 12 -StoreLocation LocalMachine
            $script:TbCert = Get-Item -LiteralPath "Cert:\LocalMachine\My\$($script:TbMeta.Thumbprint)"
        }

        AfterAll {
            if ($script:TbCert) {
                Remove-Item -LiteralPath "Cert:\LocalMachine\My\$($script:TbCert.Thumbprint)" `
                            -Force -ErrorAction SilentlyContinue
            }
        }

        It 'locates the CNG key-container file for the LocalMachine key' {
            $script:TbKeyFile = Get-CngKeyFilePath -Certificate $script:TbCert
            $script:TbKeyFile | Should -Not -BeNullOrEmpty `
                -Because 'the TPM/MPCP key container must exist under Crypto\Keys or Crypto\PCPKSP'
            Test-Path -LiteralPath $script:TbKeyFile | Should -BeTrue
        }

        It 'grants BUILTIN\Users Read and reports Applied = $true' {
            $r = Grant-DiscoveryKeyAccess -Certificate $script:TbCert `
                -Account 'BUILTIN\Users' -StoreLocation 'LocalMachine'

            $r.Applied       | Should -BeTrue
            $r.Rights        | Should -BeExactly 'Read'
            $r.StoreLocation | Should -BeExactly 'LocalMachine'
            $r.KeyFilePath   | Should -Not -BeNullOrEmpty
            $r.Sid           | Should -BeExactly 'S-1-5-32-545'
        }

        It 'the key file ACL now carries an Allow/Read entry for BUILTIN\Users' {
            $keyFile = Get-CngKeyFilePath -Certificate $script:TbCert
            $acl = Get-Acl -LiteralPath $keyFile
            $usersSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')

            $match = $acl.Access | Where-Object {
                $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $usersSid.Value -and
                $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
                ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Read) -eq [System.Security.AccessControl.FileSystemRights]::Read
            }
            $match | Should -Not -BeNullOrEmpty `
                -Because 'BUILTIN\Users must now have an explicit Allow/Read ACE on the key container'
        }

        It '-WhatIf does NOT modify the ACL (Applied = $false)' {
            $r = Grant-DiscoveryKeyAccess -Certificate $script:TbCert `
                -Account 'NT AUTHORITY\NETWORK SERVICE' -StoreLocation 'LocalMachine' -WhatIf
            $r.Applied | Should -BeFalse
            $r.Reason  | Should -Match 'WhatIf'
        }
    }
}
