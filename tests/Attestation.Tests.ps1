#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
.SYNOPSIS
    Pester v5 validation suite for src/Attestation.psm1 TPM key attestation (FR 17-19).

.DESCRIPTION
    Mixed-tier test:

      * Tier A (anywhere — macOS PS7, no TPM):
          - the New-ProaxiomDiscoveryApp.ps1 attestation parameter surface
            (-Attest, -AttestationPath, -RequireHardwareRoot);
          - the PURE EK-chain -> assurance decision (Resolve-AttestationAssurance);
          - the PURE -RequireHardwareRoot enforcement decision (Test-RequireHardwareRoot);
          - bundle serialization round-trip (ConvertTo-/ConvertFrom-AttestationBundle);
          - off-Windows fail-closed for the Windows-only functions;
          - the module imports on macOS (Add-Type of the P/Invoke signatures is fine).

      * Tier B (gated behind $script:OnAttestableTpm — a REAL / cloud TPM that can
        actually produce a key-attestation claim; the swtpm vTPM CANNOT, so these SKIP
        on the swtpm CI runner rather than failing):
          - generate a TPM key, produce an attestation bundle, then verify it
            (NCryptCreateClaim -> NCryptVerifyClaim round-trip succeeds);
          - assert the bundle reports assurance HONESTLY (HardwareRoot == trusted-root
            chain status; never over-claims);
          - assert verify re-reports the recorded assurance verbatim (never upgrades);
          - assert default does NOT hard-fail; -RequireHardwareRoot enforcement matches
            the live bundle's EK-chain status.

    Why $script:OnAttestableTpm and not just $script:OnTpmHost: the swtpm (emulated) vTPM
    fails NCryptCreateClaim with 0x80290416 ("The TPM key usage policy is invalid") and
    exposes only a self-signed FAKE "IBM" EK cert (no genuine hardware root). The live
    create->verify round-trip therefore can only validate on a real / cloud TPM
    (Azure-first — see docs/reference/attestation.md). The pure-logic + parameter-surface
    Tier-A tests still run anywhere; on the swtpm runner only the LIVE-claim Tier-B tests
    skip => GREEN-WITH-SKIPS.

    Run with:  Invoke-Pester ./tests/Attestation.Tests.ps1 -Output Detailed
#>

BeforeDiscovery {
    # Nested Join-Path: Windows PowerShell 5.1's Join-Path accepts only -Path and
    # -ChildPath, so a 3-segment positional call (Join-Path a b c) throws there.
    $script:ScriptPath = Join-Path (Join-Path $PSScriptRoot '..') 'New-ProaxiomDiscoveryApp.ps1' |
        Resolve-Path -ErrorAction SilentlyContinue |
        ForEach-Object { $_.Path }

    if (-not $script:ScriptPath) {
        $script:ScriptPath = Join-Path (Join-Path $PSScriptRoot '..') 'New-ProaxiomDiscoveryApp.ps1'
    }

    # ----------------------------------------------------------------------
    # CAPABILITY GATE — copied VERBATIM from tests/KeyGeneration.Tests.ps1's
    # BeforeDiscovery so all suites gate identically. On macOS / Linux this
    # short-circuits to $false (not Windows) => every TPM-dependent Context is
    # skipped (GREEN-WITH-SKIPS). On a Windows host with a usable TPM the MPCP
    # opens via CNG and the real tests run.
    # ----------------------------------------------------------------------
    $isWin = if ($PSVersionTable.PSEdition -eq 'Desktop') { $true } else { [bool]$IsWindows }

    # Expose the Windows flag at discovery time so -Skip: expressions can read it
    # (an `if` statement is not a valid -Skip: argument; a plain bool variable is).
    $script:IsWindowsDiscovery = $isWin

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

    # ----------------------------------------------------------------------
    # ATTESTABLE-TPM GATE — the live NCryptCreateClaim / NCryptVerifyClaim
    # create->verify round-trip (and -RequireHardwareRoot enforcement against a
    # live bundle) require a TPM that can actually PRODUCE a key-attestation
    # claim. The swtpm (emulated) vTPM cannot: NCryptCreateClaim fails there with
    # 0x80290416 ("The TPM key usage policy is invalid"), and its single EK cert
    # is a self-signed FAKE "IBM" swtpm cert (NOT a genuine hardware root). So
    # those live-claim Tier-B tests must SKIP on the swtpm CI runner (not FAIL),
    # and will execute for real on a hardware / cloud TPM (Azure-first — see
    # docs/reference/attestation.md). The pure-logic and EK-reporting tests still
    # run on any TPM host.
    #
    # $script:OnAttestableTpm is true ONLY when: we are on a real TPM host AND the
    # TPM is NOT the swtpm emulator (manufacturer "IBM" with a self-signed EK) AND
    # a trial NCryptCreateClaim size-query succeeds (i.e. key attestation is
    # actually supported). Fail closed to $false on any uncertainty.
    # ----------------------------------------------------------------------
    $script:OnAttestableTpm = $false
    if ($script:OnTpmHost) {
        try {
            # 1. Reject the swtpm emulator by manufacturer signature. swtpm reports
            #    manufacturer "IBM" and exposes only a self-signed EK cert.
            $looksLikeSwtpm = $false
            try {
                if (Get-Command -Name 'Get-Tpm' -ErrorAction SilentlyContinue) {
                    $tpm = Get-Tpm -ErrorAction SilentlyContinue
                    if ($null -ne $tpm) {
                        $mid = ''
                        try { $mid = [string]$tpm.ManufacturerIdTxt } catch { $mid = '' }
                        if ($mid -match 'IBM') { $looksLikeSwtpm = $true }
                    }
                }
            }
            catch { }

            # 2. Trial NCryptCreateClaim size-query against a throwaway MPCP key.
            #    If the TPM can't produce a claim (swtpm 0x80290416), this fails
            #    and we stay $false.
            $claimSupported = $false
            $probeName = '___proaxiom_attest_probe___' + [guid]::NewGuid().ToString('N')
            $cngKey = $null
            try {
                Import-Module (Join-Path (Join-Path $PSScriptRoot '..') 'src' |
                    Join-Path -ChildPath 'Attestation.psm1') -Force -ErrorAction SilentlyContinue
                $mpcp = [System.Security.Cryptography.CngProvider]::new('Microsoft Platform Crypto Provider')
                $params = [System.Security.Cryptography.CngKeyCreationParameters]::new()
                $params.Provider = $mpcp
                $params.KeyCreationOptions = [System.Security.Cryptography.CngKeyCreationOptions]::None
                $params.ExportPolicy = [System.Security.Cryptography.CngExportPolicies]::None
                $cngKey = [System.Security.Cryptography.CngKey]::Create(
                    [System.Security.Cryptography.CngAlgorithm]::Rsa, $probeName, $params)

                if (Get-Command -Name 'Add-AttestationInterop' -ErrorAction SilentlyContinue) {
                    Add-AttestationInterop
                    $hKey = $cngKey.Handle.DangerousGetHandle()
                    $cb = [uint32]0
                    $status = [Proaxiom.Attestation.NCryptInterop]::NCryptCreateClaim(
                        $hKey, $hKey, [uint32]1, [System.IntPtr]::Zero,
                        $null, [uint32]0, [ref]$cb, [uint32]0)
                    $claimSupported = ($status -eq 0 -and $cb -gt 0)
                }
            }
            catch { $claimSupported = $false }
            finally {
                if ($null -ne $cngKey) { try { $cngKey.Delete() } catch { } }
            }

            $script:OnAttestableTpm = ((-not $looksLikeSwtpm) -and $claimSupported)
        }
        catch {
            $script:OnAttestableTpm = $false
        }
    }
}

Describe 'New-ProaxiomDiscoveryApp.ps1 attestation parameter surface (Tier A)' {

    BeforeAll {
        $script:ScriptPath =
            (Resolve-Path -LiteralPath (Join-Path (Join-Path $PSScriptRoot '..') 'New-ProaxiomDiscoveryApp.ps1')).Path

        # Get-Command parses the script file and exposes parameter metadata WITHOUT
        # executing the body — safe off-Windows.
        $script:Cmd        = Get-Command -Name $script:ScriptPath
        $script:Parameters = $script:Cmd.Parameters

        function Get-AtParamSetNames {
            param([string]$ParameterName)
            $script:Parameters[$ParameterName].Attributes |
                Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                ForEach-Object { $_.ParameterSetName }
        }
    }

    It 'exposes the <param> parameter' -ForEach @(
        @{ param = 'Attest' }
        @{ param = 'AttestationPath' }
        @{ param = 'RequireHardwareRoot' }
    ) {
        $script:Parameters.ContainsKey($param) | Should -BeTrue -Because "$param must exist"
    }

    It '-Attest is a switch' {
        $script:Parameters['Attest'].ParameterType | Should -Be ([switch])
    }

    It '-RequireHardwareRoot is a switch' {
        $script:Parameters['RequireHardwareRoot'].ParameterType | Should -Be ([switch])
    }

    It '-AttestationPath is a string with ValidateNotNullOrEmpty' {
        $script:Parameters['AttestationPath'].ParameterType | Should -Be ([string])
        $vne = $script:Parameters['AttestationPath'].Attributes |
            Where-Object { $_ -is [System.Management.Automation.ValidateNotNullOrEmptyAttribute] } |
            Select-Object -First 1
        $vne | Should -Not -BeNullOrEmpty -Because '-AttestationPath must reject empty input'
    }

    It '<param> is available in BOTH parameter sets (cross-set)' -ForEach @(
        @{ param = 'Attest' }
        @{ param = 'AttestationPath' }
        @{ param = 'RequireHardwareRoot' }
    ) {
        # A parameter with no ParameterSetName-specific attribute binds to all sets;
        # its ParameterAttribute reports '__AllParameterSets'.
        $sets = @(Get-AtParamSetNames -ParameterName $param)
        $sets | Should -Contain '__AllParameterSets' `
            -Because "$param should be usable from GenerateLocal and ImportCert"
    }
}

Describe 'Attestation.psm1 pure functions (Tier A — runs anywhere)' {

    BeforeAll {
        $script:RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
        # Nested Join-Path for Windows PowerShell 5.1 compatibility.
        Import-Module (Join-Path (Join-Path $script:RepoRoot 'src') 'Common.psm1')      -Force
        Import-Module (Join-Path (Join-Path $script:RepoRoot 'src') 'Attestation.psm1') -Force
    }

    Context 'Module imports on this host' {

        It 'exports the expected public functions' {
            $exported = (Get-Command -Module 'Attestation').Name
            foreach ($fn in @(
                    'Add-AttestationInterop', 'Get-AttestationEkInfo',
                    'Resolve-AttestationAssurance', 'Test-RequireHardwareRoot',
                    'ConvertTo-AttestationBundle', 'ConvertFrom-AttestationBundle',
                    'New-DiscoveryAttestation', 'Test-DiscoveryAttestation')) {
                $exported | Should -Contain $fn -Because "$fn must be exported"
            }
        }

        It 'Add-AttestationInterop compiles the P/Invoke type without throwing (any OS)' {
            { Add-AttestationInterop } | Should -Not -Throw
            ('Proaxiom.Attestation.NCryptInterop' -as [type]) | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Resolve-AttestationAssurance (trusted-root -> assurance decision)' {

        It 'no claim produced -> assurance None, not hardware-rooted' {
            $r = Resolve-AttestationAssurance -ClaimProduced $false -EkChainsToTrustedRoot $false
            $r.AssuranceLevel              | Should -BeExactly 'None'
            $r.EkChainedToManufacturerRoot | Should -BeFalse
            $r.HardwareRoot                | Should -BeFalse
        }

        It 'claim produced but EK does NOT chain to a trusted root (vTPM / no cert) -> NoHardwareRoot' {
            $r = Resolve-AttestationAssurance -ClaimProduced $true -EkChainsToTrustedRoot $false
            $r.AssuranceLevel              | Should -BeExactly 'TpmKeyAttestation-NoHardwareRoot'
            $r.EkChainedToManufacturerRoot | Should -BeFalse `
                -Because 'an EK that does not chain to a trusted root must never be reported as hardware-rooted (FR 19)'
            $r.HardwareRoot                | Should -BeFalse
        }

        It 'FR-19: claim produced and an EK cert is PRESENT but NOT trusted (self-signed/vTPM fake "IBM") -> NoHardwareRoot' {
            # This is the FR-19 honesty fix: merely HAVING an EK cert is NOT enough.
            # The swtpm presents a self-signed fake "IBM" EK cert; EkChainsToTrustedRoot
            # is computed conservatively as $false, so we must NOT over-claim hardware-root.
            $r = Resolve-AttestationAssurance -ClaimProduced $true -EkChainsToTrustedRoot $false
            $r.AssuranceLevel              | Should -BeExactly 'TpmKeyAttestation-NoHardwareRoot'
            $r.EkChainedToManufacturerRoot | Should -BeFalse `
                -Because 'a present-but-untrusted (self-signed) EK cert must NOT be reported as hardware-rooted (FR 19)'
            $r.HardwareRoot                | Should -BeFalse
        }

        It 'claim produced AND EK chains to a TRUSTED root -> HardwareRoot' {
            $r = Resolve-AttestationAssurance -ClaimProduced $true -EkChainsToTrustedRoot $true
            $r.AssuranceLevel              | Should -BeExactly 'TpmKeyAttestation-HardwareRoot'
            $r.EkChainedToManufacturerRoot | Should -BeTrue
            $r.HardwareRoot                | Should -BeTrue
        }
    }

    Context 'Test-RequireHardwareRoot (enforcement decision)' {

        It 'default (no -RequireHardwareRoot) does NOT hard-fail even without EK chain' {
            $r = Test-RequireHardwareRoot -RequireHardwareRoot $false -EkChainedToManufacturerRoot $false
            $r.ShouldFail | Should -BeFalse -Because 'default is report + warn, not hard-fail'
        }

        It '-RequireHardwareRoot DOES hard-fail when EK does not chain' {
            $r = Test-RequireHardwareRoot -RequireHardwareRoot $true -EkChainedToManufacturerRoot $false
            $r.ShouldFail | Should -BeTrue -Because 'opt-in hard-fail when no hardware root'
            $r.Reason     | Should -BeLike '*RequireHardwareRoot*'
        }

        It '-RequireHardwareRoot does NOT hard-fail when EK chains' {
            $r = Test-RequireHardwareRoot -RequireHardwareRoot $true -EkChainedToManufacturerRoot $true
            $r.ShouldFail | Should -BeFalse
        }
    }

    Context 'Bundle serialization round-trip' {

        BeforeAll {
            $script:Assurance = Resolve-AttestationAssurance -ClaimProduced $true -EkChainsToTrustedRoot $false
            $script:Built = ConvertTo-AttestationBundle `
                -Thumbprint 'ABCDEF0123456789ABCDEF0123456789ABCDEF01' `
                -X5tBase64Url 'q83vASNFZ4mrze8BI0VniavN7wE' `
                -ClaimType 1 `
                -ClaimBlobBase64 'AAECAwQF' `
                -PublicKeyBlobBase64 'BgcICQoL' `
                -EkPublicKeyHash 'deadbeef' `
                -Assurance $script:Assurance
        }

        It 'produces a bundle Object and a Json string' {
            $script:Built.Object | Should -Not -BeNullOrEmpty
            $script:Built.Json   | Should -Not -BeNullOrEmpty
            $script:Built.Object.Kind | Should -BeExactly 'ProaxiomDiscoveryAttestationBundle'
        }

        It 'round-trips through ConvertFrom-AttestationBundle preserving load-bearing fields' {
            $parsed = ConvertFrom-AttestationBundle -Json $script:Built.Json
            $parsed.Thumbprint                  | Should -BeExactly 'ABCDEF0123456789ABCDEF0123456789ABCDEF01'
            $parsed.ClaimType                   | Should -Be 1
            $parsed.ClaimBlobBase64             | Should -BeExactly 'AAECAwQF'
            $parsed.PublicKeyBlobBase64         | Should -BeExactly 'BgcICQoL'
            $parsed.AssuranceLevel              | Should -BeExactly 'TpmKeyAttestation-NoHardwareRoot'
            $parsed.EkChainedToManufacturerRoot | Should -BeFalse
        }

        It 'rejects non-bundle JSON' {
            { ConvertFrom-AttestationBundle -Json '{"Kind":"Something else"}' } |
                Should -Throw -ExpectedMessage '*not a Proaxiom*'
        }

        It 'rejects a bundle missing a required field' {
            { ConvertFrom-AttestationBundle -Json '{"Kind":"ProaxiomDiscoveryAttestationBundle"}' } |
                Should -Throw -ExpectedMessage '*missing the required field*'
        }

        It 'rejects malformed JSON' {
            { ConvertFrom-AttestationBundle -Json 'not json {' } |
                Should -Throw -ExpectedMessage '*not valid JSON*'
        }
    }

    # The Windows-only functions must fail closed off-Windows. Skipped on a real
    # TPM host (there they would actually run); runs on macOS / Linux.
    Context 'Windows-only functions fail closed off-Windows' -Skip:($script:OnTpmHost) {

        It 'Get-AttestationEkInfo throws off-Windows' -Skip:($script:IsWindowsDiscovery) {
            { Get-AttestationEkInfo } | Should -Throw -ExpectedMessage '*Windows-only*'
        }

        It 'New-DiscoveryAttestation throws off-Windows' -Skip:($script:IsWindowsDiscovery) {
            # Build a throwaway public cert object (no key) just to satisfy the param;
            # the function must throw on the OS check before touching it.
            $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("at-" + [guid]::NewGuid() + '.cer')
            try {
                & openssl req -x509 -newkey rsa:2048 -nodes -keyout "$tmp.key" -out "$tmp" -days 1 `
                    -subj '/CN=Proaxiom Attest OffWin' 2>$null | Out-Null
                $der = Join-Path ([System.IO.Path]::GetTempPath()) ("at-" + [guid]::NewGuid() + '.der')
                & openssl x509 -in "$tmp" -outform DER -out $der 2>$null | Out-Null
                $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($der)
                { New-DiscoveryAttestation -Certificate $cert } | Should -Throw -ExpectedMessage '*Windows-only*'
            }
            finally {
                Remove-Item -LiteralPath "$tmp", "$tmp.key", $der -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

Describe 'Attestation.psm1 — TPM key attestation round-trip (Tier B)' {

    BeforeAll {
        $script:RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
        Import-Module (Join-Path (Join-Path $script:RepoRoot 'src') 'Common.psm1')         -Force
        Import-Module (Join-Path (Join-Path $script:RepoRoot 'src') 'KeyGeneration.psm1')  -Force
        Import-Module (Join-Path (Join-Path $script:RepoRoot 'src') 'Attestation.psm1')    -Force

        $script:TestSubject = 'CN=zzTEST-AttestKey'

        $script:IsWindowsHost =
            if ($PSVersionTable.PSEdition -eq 'Desktop') { $true } else { [bool]$IsWindows }

        $script:TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("proaxiom-attest-tier-b-" + [guid]::NewGuid())
        New-Item -ItemType Directory -Path $script:TmpDir -Force | Out-Null
    }

    AfterAll {
        # Remove any cert whose subject mentions zzTEST-AttestKey from both personal
        # stores (Windows only). Best-effort; never fail the run on teardown.
        if ($script:IsWindowsHost) {
            foreach ($loc in @('CurrentUser', 'LocalMachine')) {
                $storePath = "Cert:\$loc\My"
                try {
                    Get-ChildItem -LiteralPath $storePath -ErrorAction SilentlyContinue |
                        Where-Object { $_.Subject -like '*zzTEST-AttestKey*' } |
                        ForEach-Object {
                            Remove-Item -LiteralPath (Join-Path $storePath $_.Thumbprint) `
                                        -Force -ErrorAction SilentlyContinue
                        }
                }
                catch { }
            }
        }
        if ($script:TmpDir -and (Test-Path -LiteralPath $script:TmpDir)) {
            Remove-Item -LiteralPath $script:TmpDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # GATED on $script:OnAttestableTpm (NOT just $OnTpmHost): the live
    # NCryptCreateClaim->NCryptVerifyClaim round-trip needs a TPM that can produce
    # an attestation claim. The swtpm vTPM CANNOT (it fails with 0x80290416 "The TPM
    # key usage policy is invalid"), and its sole EK cert is a self-signed fake "IBM"
    # swtpm cert (no genuine hardware root). So these SKIP on the swtpm CI runner
    # rather than failing; they execute on a real / cloud TPM (Azure-first — see
    # docs/reference/attestation.md).
    Context 'Create -> verify a TPM key-attestation bundle' -Skip:(-not $script:OnAttestableTpm) {

        BeforeAll {
            # Generate ONCE for the whole context (CurrentUser avoids needing elevation).
            $script:Meta = New-DiscoveryTpmKey -Subject $script:TestSubject `
                -ValidityMonths 12 -StoreLocation CurrentUser
            $script:Cert = Get-Item -LiteralPath "Cert:\CurrentUser\My\$($script:Meta.Thumbprint)"

            # Produce the bundle and write it to disk.
            $script:Bundle = New-DiscoveryAttestation -Certificate $script:Cert
            $script:BundlePath = Join-Path $script:TmpDir 'attest-bundle.json'
            Set-Content -LiteralPath $script:BundlePath -Value $script:Bundle.Json -Encoding UTF8
        }

        It '1. a claim bundle was produced (non-empty claim blob, expected claim type)' {
            $script:Bundle                  | Should -Not -BeNullOrEmpty
            $script:Bundle.ClaimType        | Should -Be 1 -Because 'AUTHORITY_AND_SUBJECT = 0x1'
            $script:Bundle.ClaimBlobBase64  | Should -Not -BeNullOrEmpty
            $script:Bundle.Thumbprint       | Should -BeExactly $script:Meta.Thumbprint
        }

        It '2. the bundle reports assurance HONESTLY and never over-claims hardware-root (FR 19)' {
            # This context only runs on an ATTESTABLE TPM (real / cloud). The bundle's
            # HardwareRoot must match EkChainedToManufacturerRoot exactly, and the
            # AssuranceLevel must be consistent with that flag — the tool must never
            # report HardwareRoot=$true unless the EK genuinely chains to a trusted root.
            $hw      = [bool]$script:Bundle.HardwareRoot
            $chained = [bool]$script:Bundle.EkChainedToManufacturerRoot
            $hw | Should -Be $chained -Because 'HardwareRoot must equal the trusted-root chain status (FR 19)'
            if ($hw) {
                $script:Bundle.AssuranceLevel | Should -BeExactly 'TpmKeyAttestation-HardwareRoot'
            }
            else {
                $script:Bundle.AssuranceLevel | Should -BeExactly 'TpmKeyAttestation-NoHardwareRoot'
            }
        }

        It '3. the bundle verifies (NCryptVerifyClaim round-trip succeeds)' {
            $v = Test-DiscoveryAttestation -Path $script:BundlePath
            $v.VerifyResult | Should -BeTrue -Because 'a self-claim must verify against its own key'
            $v.Thumbprint   | Should -BeExactly $script:Meta.Thumbprint
        }

        It '4. verification re-reports the recorded assurance verbatim — never upgrades (FR 19)' {
            $v = Test-DiscoveryAttestation -Path $script:BundlePath
            # Verify must faithfully re-report what the bundle recorded; it must NEVER
            # upgrade the assurance. Assert it equals the bundle's recorded values.
            $v.EkChainedToManufacturerRoot | Should -Be ([bool]$script:Bundle.EkChainedToManufacturerRoot) `
                -Because 'verify must not change the recorded trusted-root status'
            $v.HardwareRoot                | Should -Be ([bool]$script:Bundle.HardwareRoot)
            $v.AssuranceLevel              | Should -BeExactly ([string]$script:Bundle.AssuranceLevel)
        }
    }

    # Also gated on $script:OnAttestableTpm — it builds a LIVE bundle via
    # New-DiscoveryAttestation, which the swtpm cannot produce (0x80290416). Skips on
    # the swtpm CI runner; runs on a real / cloud TPM.
    Context '-RequireHardwareRoot enforcement wired to a live bundle (default vs opt-in)' -Skip:(-not $script:OnAttestableTpm) {

        BeforeAll {
            $script:Meta2 = New-DiscoveryTpmKey -Subject $script:TestSubject `
                -ValidityMonths 12 -StoreLocation CurrentUser
            $script:Cert2 = Get-Item -LiteralPath "Cert:\CurrentUser\My\$($script:Meta2.Thumbprint)"
            $script:Bundle2 = New-DiscoveryAttestation -Certificate $script:Cert2
        }

        It '5. default (no -RequireHardwareRoot) NEVER hard-fails, regardless of EK chain' {
            $enforce = Test-RequireHardwareRoot `
                -RequireHardwareRoot $false `
                -EkChainedToManufacturerRoot ([bool]$script:Bundle2.EkChainedToManufacturerRoot)
            $enforce.ShouldFail | Should -BeFalse -Because 'default is report + warn'
        }

        It '6. -RequireHardwareRoot enforcement matches the live bundle EK-chain status' {
            $chained = [bool]$script:Bundle2.EkChainedToManufacturerRoot
            $enforce = Test-RequireHardwareRoot `
                -RequireHardwareRoot $true `
                -EkChainedToManufacturerRoot $chained
            if ($chained) {
                $enforce.ShouldFail | Should -BeFalse `
                    -Because 'a trusted-rooted EK satisfies -RequireHardwareRoot'
            }
            else {
                $enforce.ShouldFail | Should -BeTrue `
                    -Because '-RequireHardwareRoot must refuse a TPM that cannot prove a trusted manufacturer EK root'
            }
        }
    }
}
