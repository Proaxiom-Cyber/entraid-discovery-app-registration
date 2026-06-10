#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
.SYNOPSIS
    Pester v5 validation suite for KeyGeneration.psm1 TPM-backed key generation.

.DESCRIPTION
    Tier B (hardware-dependent) test. Exercises the real TPM / Microsoft Platform
    Crypto Provider key-generation path of KeyGeneration.psm1 (FR 7-11):

      * New-DiscoveryTpmKey produces a non-exportable RSA-2048 signing key whose
        private key lives in the Microsoft Platform Crypto Provider;
      * Assert-KeyNonExportable proves the key cannot leave the TPM (and rejects
        software-KSP exportable keys);
      * Export-DiscoveryPublicCertificate writes a public-only .cer;
      * the off-Windows / public-cert / ImportCert paths behave correctly anywhere.

    SKIP-GATED. The tests that require a real TPM are gated behind
    $script:OnTpmHost = (Test-IsWindows) -and (Test-PlatformCryptoProvider).Available
    so this file is GREEN-WITH-SKIPS on a non-TPM host (e.g. macOS dev box) and
    executes for real only on a Windows + TPM host (physical or vTPM).

    The ImportCert and off-Windows fail-closed Contexts run ANYWHERE (they only
    need pwsh + Pester v5 + openssl).

    Run with:  Invoke-Pester ./tests/KeyGeneration.Tests.ps1 -Output Detailed
#>

BeforeDiscovery {
    # ----------------------------------------------------------------------
    # CAPABILITY GATE — evaluated during Pester DISCOVERY so the -Skip:(...)
    # expressions on each Context can read it.
    #
    # NOTE: Pester's discovery scope does not reliably expose functions from a
    # module Import-Module'd inside this block, so the gate is computed INLINE
    # here (mirroring Test-IsWindows + the MPCP/CNG ProviderOpens probe from
    # Test-PlatformCryptoProvider in KeyGeneration.psm1) rather than by calling
    # the module functions. The module functions are still imported in the
    # Describe-level BeforeAll and used for the actual assertions; the positive
    # Context additionally re-confirms (Test-PlatformCryptoProvider).Available at
    # run time, so the inline probe only ever GATES, never substitutes for the
    # real fail-closed check.
    #
    # On macOS / Linux this short-circuits to $false (not Windows), so every
    # TPM-dependent test below is skipped => GREEN-WITH-SKIPS. On a Windows host
    # with a usable TPM the MPCP opens via CNG and the real tests run.
    # ----------------------------------------------------------------------
    $isWin = if ($PSVersionTable.PSEdition -eq 'Desktop') { $true } else { [bool]$IsWindows }

    # Windows-only gate (no TPM required) for tests that exercise the Windows
    # certificate store but not the MPCP -- e.g. the Import-DiscoveryPfx
    # store-install pathway. Gate on Windows, NOT on TPM.
    $script:OnWindowsHost = $isWin

    $script:OnTpmHost = $false
    if ($isWin) {
        try {
            $mpcp = [System.Security.Cryptography.CngProvider]::new('Microsoft Platform Crypto Provider')
            # Opening the provider (a key-existence probe forces NCryptOpenStorageProvider)
            # succeeds only when the TPM-backed MPCP is actually usable on this host.
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

Describe 'KeyGeneration.psm1 — TPM-backed key generation (Tier B)' {

    BeforeAll {
        $script:RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
        # Nested Join-Path: Windows PowerShell 5.1's Join-Path takes only -Path
        # and -ChildPath, so a 3-segment positional call (Join-Path a b c) throws.
        Import-Module (Join-Path (Join-Path $script:RepoRoot 'src') 'Common.psm1')        -Force
        Import-Module (Join-Path (Join-Path $script:RepoRoot 'src') 'KeyGeneration.psm1') -Force

        $script:MpcpName     = 'Microsoft Platform Crypto Provider'
        $script:TestSubject  = 'CN=zzTEST-DiscoveryKey'

        # Inline Windows check for use in run/teardown phases. Mirrors
        # Common.psm1 Test-IsWindows; kept inline because Pester's run-phase
        # scope does not reliably resolve module-exported functions from this
        # BeforeAll's Import-Module in every nested block (notably AfterAll).
        $script:IsWindowsHost =
            if ($PSVersionTable.PSEdition -eq 'Desktop') { $true } else { [bool]$IsWindows }

        # Per-Describe temp dir for any .cer fixtures / exports.
        $script:TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("proaxiom-tier-b-" + [guid]::NewGuid())
        New-Item -ItemType Directory -Path $script:TmpDir -Force | Out-Null
    }

    AfterAll {
        # --- Teardown: keep the persistent TPM test host clean across runs. ----
        # Remove any cert whose subject mentions zzTEST-DiscoveryKey from both
        # personal stores. Guarded with the Windows check because Cert:\ store
        # removal is a no-op / unavailable off-Windows.
        if ($script:IsWindowsHost) {
            foreach ($loc in @('CurrentUser', 'LocalMachine')) {
                $storePath = "Cert:\$loc\My"
                try {
                    Get-ChildItem -LiteralPath $storePath -ErrorAction SilentlyContinue |
                        Where-Object { $_.Subject -like '*zzTEST-DiscoveryKey*' } |
                        ForEach-Object {
                            Remove-Item -LiteralPath (Join-Path $storePath $_.Thumbprint) `
                                        -Force -ErrorAction SilentlyContinue
                        }
                }
                catch {
                    # Best-effort cleanup; never fail the run on teardown.
                }
            }
        }

        # Clean temp fixture files.
        if ($script:TmpDir -and (Test-Path -LiteralPath $script:TmpDir)) {
            Remove-Item -LiteralPath $script:TmpDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # =======================================================================
    # POSITIVE PATH — requires a real TPM (skipped off-host).
    # =======================================================================
    Context 'Positive path: New-DiscoveryTpmKey produces a TPM-bound key' -Skip:(-not $script:OnTpmHost) {

        BeforeAll {
            # Re-confirm the REAL fail-closed gate at run time (the discovery-time
            # gate is only a lightweight CNG probe). This is the load-bearing
            # check; it must agree before we generate a key. Captured here and
            # asserted in the first It so a disagreement surfaces as a failure
            # rather than a silently-soft key.
            $script:ProviderStatus = Test-PlatformCryptoProvider

            # Generate ONCE for the whole context. CurrentUser avoids needing
            # elevation in the test runner.
            $script:Meta = New-DiscoveryTpmKey -Subject $script:TestSubject `
                -ValidityMonths 12 -StoreLocation CurrentUser

            # Pull the live certificate object back out of the store so we can
            # inspect the CNG key directly.
            $script:Cert = Get-Item -LiteralPath "Cert:\CurrentUser\My\$($script:Meta.Thumbprint)"

            # Cache the live CngKey for the algorithm / provider / policy checks.
            $script:CngKey = $null
            $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($script:Cert)
            if ($null -ne $rsa) { $script:CngKey = $rsa.Key }
        }

        It '1. private key lives in the Microsoft Platform Crypto Provider' {
            # The real fail-closed gate must agree we are on a usable TPM host.
            $script:ProviderStatus.Available | Should -BeTrue `
                -Because 'Test-PlatformCryptoProvider must confirm a usable TPM/MPCP before keys are trusted'
            $script:CngKey | Should -Not -BeNullOrEmpty -Because 'the private key must be a CNG key'
            $script:CngKey.Provider.Provider | Should -BeExactly $script:MpcpName
        }

        It '2. key is RSA-2048, KeySpec Signature, SHA256-signed' {
            # Algorithm + length from the live CNG key.
            $script:CngKey.Algorithm.Algorithm | Should -BeExactly 'RSA'
            $script:CngKey.KeySize             | Should -Be 2048

            # KeySpec Signature: the legacy CSP key-spec exposed on the CNG key.
            # AT_SIGNATURE = 2. On a pure-CNG key this surfaces via the
            # 'KeySpec' property when present; fall back to the CSP enum value.
            $keySpecProp = $script:CngKey.PSObject.Properties['KeySpec']
            if ($null -ne $keySpecProp -and $null -ne $keySpecProp.Value) {
                "$($keySpecProp.Value)" | Should -Match 'Signature|^2$'
            }

            # Signature hash algorithm: the cert was signed SHA256withRSA.
            $script:Cert.SignatureAlgorithm.FriendlyName | Should -Match 'sha256'
        }

        It '3. CNG export policy is None' {
            $script:CngKey.ExportPolicy.ToString() | Should -BeExactly 'None'
        }

        It '5. Assert-KeyNonExportable returns NonExportable = $true' {
            $result = Assert-KeyNonExportable -Certificate $script:Cert
            $result.NonExportable      | Should -BeTrue
            $result.ProviderName       | Should -BeExactly $script:MpcpName
            $result.ExportPolicy       | Should -BeExactly 'None'
            $result.ExportAttemptThrew | Should -BeTrue
        }

        It '6. Export-DiscoveryPublicCertificate writes a DER .cer with no private key' {
            $cerPath = Join-Path $script:TmpDir 'positive-public.cer'
            $export  = Export-DiscoveryPublicCertificate -Certificate $script:Cert -Path $cerPath -Force
            $export.Format | Should -BeExactly 'DER'
            Test-Path -LiteralPath $cerPath | Should -BeTrue

            # Re-import the exported public cert: it must carry no private key.
            $reimport = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cerPath)
            $reimport.HasPrivateKey | Should -BeFalse -Because 'only the public cert is exported'
        }

        It '7. metadata is well-formed (thumbprint, subject, future expiry, x5t)' {
            $script:Meta.Thumbprint   | Should -Not -BeNullOrEmpty
            $script:Meta.Subject      | Should -BeExactly $script:TestSubject
            $script:Meta.NotAfter     | Should -BeGreaterThan (Get-Date)
            $script:Meta.X5tBase64Url | Should -Not -BeNullOrEmpty
            $script:Meta.X5tBase64Url | Should -Not -Match '[+/=]' -Because 'x5t must be base64url without padding'
        }

        It '8. the key is placed in CurrentUser\My' {
            $script:Meta.StorePath | Should -BeExactly 'Cert:\CurrentUser\My'
            Test-Path -LiteralPath "Cert:\CurrentUser\My\$($script:Meta.Thumbprint)" | Should -BeTrue
        }

        # MUST run LAST in this Context. On .NET Framework (PS 5.1) an
        # X509Certificate2.Export('Pfx',...) attempt against this TPM/MPCP
        # non-exportable key THROWS (correct, real-world behaviour) but POISONS
        # the CNG key handle process-wide — afterwards GetRSAPrivateKey() fails
        # even on a fresh Get-Item reload. So this test runs after every sibling
        # that reads the shared $script:Cert private key (tests 1-8) to avoid
        # breaking them. The poisoned key is unique to this Context and removed
        # in AfterAll; later test files create their own keys. (Assert-KeyNonExportable
        # uses a non-poisoning CNG blob export, so test 5 is unaffected.)
        It '4. PFX export of the private key THROWS (poisons the handle — runs last)' {
            $pwd = ConvertTo-SecureString 'x' -AsPlainText -Force
            { $script:Cert.Export('Pfx', $pwd) } | Should -Throw
        }
    }

    # =======================================================================
    # NEGATIVE / FAIL-CLOSED.
    # =======================================================================
    Context 'Negative: the non-exportability guard rejects a software-KSP key' -Skip:(-not $script:OnTpmHost) {

        It '9. Assert-KeyNonExportable returns NonExportable = $false for an exportable software key' {
            # Generate a SOFTWARE-KSP, EXPORTABLE cert -> the antithesis of a TPM key.
            # NB: do NOT set -KeySpec here. The 'Microsoft Software Key Storage
            # Provider' is a CNG-only (NCrypt) KSP with no legacy CSP provider
            # type, so -KeySpec (Signature / KeyExchange) makes
            # New-SelfSignedCertificate attempt a legacy CSP mapping and fail
            # with NTE_PROV_TYPE_NOT_DEF (0x80090017) on a real TPM/CNG host.
            # Mirror the product fix (src/KeyGeneration.psm1 New-DiscoveryTpmKey):
            # express signing intent via -KeyUsage DigitalSignature instead. The
            # fixture must stay EXPORTABLE + software-KSP — that is the negative
            # case Assert-KeyNonExportable has to reject.
            $softCert = New-SelfSignedCertificate `
                -Subject 'CN=zzTEST-DiscoveryKey-SOFTWARE' `
                -Provider 'Microsoft Software Key Storage Provider' `
                -KeyAlgorithm 'RSA' -KeyLength 2048 `
                -KeyExportPolicy Exportable -KeyUsage DigitalSignature `
                -HashAlgorithm SHA256 `
                -CertStoreLocation 'Cert:\CurrentUser\My'

            try {
                $result = Assert-KeyNonExportable -Certificate $softCert
                $result.NonExportable | Should -BeFalse `
                    -Because 'a software-KSP exportable key is NOT TPM-bound and must be rejected'
            }
            finally {
                Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($softCert.Thumbprint)" `
                            -Force -ErrorAction SilentlyContinue
            }
        }
    }

    Context 'Fail-closed: Test-PlatformCryptoProvider off a TPM host' {

        # Runs in every NON-TPM environment; skips only on a TPM-equipped CI
        # runner (Available=$true / Reason='OK'). The suite runs in THREE
        # environments and the fail-closed Reason differs across them:
        #   - macOS / non-Windows dev box  -> 'Not a Windows host'
        #   - GitHub-hosted windows-latest -> 'TPM not present' (Windows, no
        #     vTPM); a TPM-bearing box with a broken provider would instead
        #     report 'TPM present but not ready' or the MPCP reasons ('... not
        #     listed by certutil -csplist' / '... failed to open via CNG')
        #   - Windows WITH a usable TPM (TPM-equipped CI runner) -> SKIPPED here
        # This is the load-bearing proof that the skip gate above is actually
        # engaging (i.e. we are NOT on a usable TPM host).
        It '10. reports Available = $false when not on a TPM host' -Skip:($script:OnTpmHost) {
            $status = Test-PlatformCryptoProvider
            $status.Available | Should -BeFalse -Because 'no TPM/MPCP here -> fail closed'
            $status.Reason    | Should -Match 'Windows|TPM|Platform Crypto' `
                -Because 'every fail-closed path names the missing capability (host OS, TPM, or MPCP) and the success Reason OK matches none of these'
        }
    }

    # =======================================================================
    # IMPORTCERT — runs ANYWHERE (openssl fixtures, no key generated).
    # =======================================================================
    Context 'ImportCert: supplied public certificate imports without generating a key' {

        BeforeAll {
            # Build a single throwaway public cert in three encodings: DER (.cer),
            # PEM, and a raw base64 text file. All three must round-trip to the
            # SAME thumbprint via Import-DiscoveryPublicCertificate.
            $script:FixDir = Join-Path $script:TmpDir 'importcert'
            New-Item -ItemType Directory -Path $script:FixDir -Force | Out-Null

            $keyPath        = Join-Path $script:FixDir 'key.pem'
            $script:PemPath = Join-Path $script:FixDir 'cert.pem'
            $script:DerPath = Join-Path $script:FixDir 'cert.cer'
            $script:B64Path = Join-Path $script:FixDir 'cert.b64'

            # openssl writes key-gen progress to stderr. Under Windows PowerShell 5.1
            # with $ErrorActionPreference='Stop' (the CI step sets Stop, which
            # propagates into this scriptblock) a native command writing to stderr
            # raises a TERMINATING NativeCommandError — even with 2>$null. Scope a
            # LOCAL 'Continue' here so native stderr does not abort the fixture build;
            # the explicit $LASTEXITCODE checks below still fail setup on a real error.
            $ErrorActionPreference = 'Continue'

            # 1. RSA-2048 self-signed cert -> PEM.
            & openssl req -x509 -newkey rsa:2048 -nodes `
                -keyout $keyPath -out $script:PemPath -days 30 `
                -subj '/CN=Proaxiom Tier-B ImportFixture' 2>$null
            if ($LASTEXITCODE -ne 0) { throw "openssl req failed (exit $LASTEXITCODE)" }

            # 2. PEM -> DER (.cer).
            & openssl x509 -in $script:PemPath -outform DER -out $script:DerPath 2>$null
            if ($LASTEXITCODE -ne 0) { throw "openssl x509 (DER) failed (exit $LASTEXITCODE)" }

            # 3. Raw base64 (DER bytes, no PEM armour) text file.
            $derBytes = [System.IO.File]::ReadAllBytes($script:DerPath)
            [System.IO.File]::WriteAllText(
                $script:B64Path,
                [System.Convert]::ToBase64String($derBytes, [System.Base64FormattingOptions]::InsertLineBreaks))
        }

        It '11. a DER .cer imports with HasPrivateKey = $false (no key generated)' {
            $meta = Import-DiscoveryPublicCertificate -Path $script:DerPath
            $meta.HasPrivateKey | Should -BeFalse -Because 'a supplied public cert carries no private key'
            $meta.Thumbprint    | Should -Not -BeNullOrEmpty
            $meta.Subject       | Should -Match 'Proaxiom Tier-B ImportFixture'
            $meta.ProviderName  | Should -BeNullOrEmpty -Because 'no private key => no provider'
        }

        It '12. PEM and base64 variants produce the SAME thumbprint as the DER one' {
            $der = Import-DiscoveryPublicCertificate -Path $script:DerPath
            $pem = Import-DiscoveryPublicCertificate -Path $script:PemPath
            $b64 = Import-DiscoveryPublicCertificate -Path $script:B64Path

            $pem.Thumbprint | Should -BeExactly $der.Thumbprint -Because 'same cert, different encoding'
            $b64.Thumbprint | Should -BeExactly $der.Thumbprint -Because 'same cert, different encoding'
        }
    }

    # =======================================================================
    # IMPORT-DISCOVERYPFX -- ImportPrivateKey pathway (store install).
    # Gated on WINDOWS (the certificate store), NOT on a TPM.
    # =======================================================================
    Context 'Import-DiscoveryPfx: fails closed off-Windows' {

        It '13. throws a Windows-required error on a non-Windows host' -Skip:($script:OnWindowsHost) {
            # The Windows gate is checked FIRST, so the file does not need to exist.
            $pfxPath = Join-Path $script:TmpDir 'does-not-matter.pfx'
            { Import-DiscoveryPfx -Path $pfxPath -StoreLocation CurrentUser } |
                Should -Throw -ExpectedMessage '*Windows*'
        }
    }

    Context 'Import-DiscoveryPfx: rejects a public-only certificate file (any host)' {

        BeforeAll {
            # Self-contained public-cert fixture (DER .cer) -- built here rather
            # than reusing the ImportCert fixture so this Context has no ordering
            # dependency on its siblings.
            $script:PubOnlyDir = Join-Path $script:TmpDir 'pfx-pubonly'
            New-Item -ItemType Directory -Path $script:PubOnlyDir -Force | Out-Null

            $keyPath           = Join-Path $script:PubOnlyDir 'key.pem'
            $pemPath           = Join-Path $script:PubOnlyDir 'cert.pem'
            $script:PubOnlyCer = Join-Path $script:PubOnlyDir 'public-only.cer'

            # Native stderr under WinPS 5.1 + EAP=Stop raises a terminating error
            # even with 2>$null; scope a LOCAL Continue (mirrors the ImportCert
            # Context above).
            $ErrorActionPreference = 'Continue'

            & openssl req -x509 -newkey rsa:2048 -nodes `
                -keyout $keyPath -out $pemPath -days 30 `
                -subj '/CN=zzTEST-PfxPublicOnly' 2>$null
            if ($LASTEXITCODE -ne 0) { throw "openssl req failed (exit $LASTEXITCODE)" }

            & openssl x509 -in $pemPath -outform DER -out $script:PubOnlyCer 2>$null
            if ($LASTEXITCODE -ne 0) { throw "openssl x509 (DER) failed (exit $LASTEXITCODE)" }
        }

        It '14. throws for a public-cert (non-PFX) input on every host' {
            # Off-Windows the fail-closed Windows gate throws first; on Windows the
            # file loads with HasPrivateKey = $false and the no-private-key guidance
            # throws (or a parse error if the host cannot load the file). Every
            # path throws -- a public-only cert NEVER imports through the PFX path.
            { Import-DiscoveryPfx -Path $script:PubOnlyCer -StoreLocation CurrentUser } | Should -Throw
        }
    }

    Context 'Import-DiscoveryPfx: installs a PFX into CurrentUser\My (Windows)' -Skip:(-not $script:OnWindowsHost) {

        BeforeAll {
            # Throwaway openssl-built PFX. The password is a DUMMY test fixture
            # (never a real secret). CurrentUser avoids requiring an elevated
            # test runner.
            $script:PfxDir = Join-Path $script:TmpDir 'pfx-import'
            New-Item -ItemType Directory -Path $script:PfxDir -Force | Out-Null

            $keyPath           = Join-Path $script:PfxDir 'key.pem'
            $pemPath           = Join-Path $script:PfxDir 'cert.pem'
            $script:PfxPath    = Join-Path $script:PfxDir 'fixture.pfx'
            $script:PfxCerPath = Join-Path $script:PfxDir 'fixture.cer'

            $pfxPassPlain       = 'zzTEST-dummy-pfx-password'
            $script:PfxPassword = ConvertTo-SecureString $pfxPassPlain -AsPlainText -Force

            # openssl writes progress to stderr; scope a LOCAL 'Continue' so WinPS
            # 5.1 + EAP=Stop does not turn that into a terminating NativeCommandError.
            $ErrorActionPreference = 'Continue'

            & openssl req -x509 -newkey rsa:2048 -nodes `
                -keyout $keyPath -out $pemPath -days 30 `
                -subj '/CN=zzTEST-DiscoveryKey-PfxFixture' 2>$null
            if ($LASTEXITCODE -ne 0) { throw "openssl req failed (exit $LASTEXITCODE)" }

            & openssl pkcs12 -export -out $script:PfxPath -inkey $keyPath -in $pemPath `
                -passout "pass:$pfxPassPlain" 2>$null
            if ($LASTEXITCODE -ne 0) { throw "openssl pkcs12 failed (exit $LASTEXITCODE)" }

            & openssl x509 -in $pemPath -outform DER -out $script:PfxCerPath 2>$null
            if ($LASTEXITCODE -ne 0) { throw "openssl x509 (DER) failed (exit $LASTEXITCODE)" }

            # Import ONCE for the whole Context.
            $script:PfxMeta = Import-DiscoveryPfx -Path $script:PfxPath `
                -Password $script:PfxPassword -StoreLocation CurrentUser
        }

        AfterAll {
            # Remove the imported fixture cert from CurrentUser\My. (The
            # Describe-level sweep on *zzTEST-DiscoveryKey* is the belt-and-braces
            # fallback -- this subject deliberately matches it.)
            if ($script:IsWindowsHost) {
                try {
                    Get-ChildItem -LiteralPath 'Cert:\CurrentUser\My' -ErrorAction SilentlyContinue |
                        Where-Object { $_.Subject -like '*zzTEST-DiscoveryKey-PfxFixture*' } |
                        ForEach-Object {
                            Remove-Item -LiteralPath (Join-Path 'Cert:\CurrentUser\My' $_.Thumbprint) `
                                        -Force -ErrorAction SilentlyContinue
                        }
                }
                catch {
                    # Best-effort cleanup; never fail the run on teardown.
                }
            }
        }

        It '15. imports with HasPrivateKey = $true' {
            $script:PfxMeta.HasPrivateKey | Should -BeTrue -Because 'a PFX carries the private key'
            $script:PfxMeta.Subject       | Should -Match 'zzTEST-DiscoveryKey-PfxFixture'
        }

        It '16. the certificate is present in the CurrentUser\My store' {
            Test-Path -LiteralPath "Cert:\CurrentUser\My\$($script:PfxMeta.Thumbprint)" | Should -BeTrue
        }

        It '17. metadata carries the full StorePath and ImportedFromPfx = $true' {
            $script:PfxMeta.StorePath       | Should -BeExactly "Cert:\CurrentUser\My\$($script:PfxMeta.Thumbprint)"
            $script:PfxMeta.ImportedFromPfx | Should -BeTrue
        }

        It '18. a wrong password throws a clear, actionable error' {
            $wrong = ConvertTo-SecureString 'zzTEST-wrong-password' -AsPlainText -Force
            { Import-DiscoveryPfx -Path $script:PfxPath -Password $wrong -StoreLocation CurrentUser } |
                Should -Throw -ExpectedMessage '*-Password*'
        }

        It '19. a public-only .cer is rejected with the no-private-key guidance' {
            $err = { Import-DiscoveryPfx -Path $script:PfxCerPath -StoreLocation CurrentUser } |
                Should -Throw -PassThru
            $err.Exception.Message | Should -Match 'private key'
            $err.Exception.Message | Should -Match 'ImportPublicCert' -Because 'the error must point at the public-cert pathway'
        }
    }
}
