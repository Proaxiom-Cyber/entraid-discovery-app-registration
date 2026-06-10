#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
.SYNOPSIS
    Pester v5 validation suite for the New-ProaxiomDiscoveryApp.ps1 parameter
    surface and the off-Windows / public-cert behaviour of KeyGeneration.psm1.

.DESCRIPTION
    Tier A (hardware/tenant-free) test. Validates:
      * the script parses and exposes exactly the GenerateLocal / ImportCert
        parameter sets with the documented membership and validation attributes;
      * Test-PlatformCryptoProvider fails closed on a non-Windows host;
      * Get-DiscoveryCertMetadata / Import-DiscoveryPublicCertificate produce the
        documented 10-property metadata shape for a public-only certificate.

    Runs anywhere pwsh + Pester v5 + openssl are available — no TPM, no tenant,
    no network, no Windows required.

    Run with:  Invoke-Pester ./tests/Parameters.Tests.ps1 -Output Detailed
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
    # CAPABILITY GATE — evaluated during Pester DISCOVERY so the -Skip:(...)
    # expression on the 'fails closed when not on a TPM host' Context can read
    # it. Copied VERBATIM from tests/KeyGeneration.Tests.ps1's BeforeDiscovery so
    # both files gate identically: on a real Windows + TPM host the MPCP opens
    # via CNG ($OnTpmHost = $true) and the fail-closed assertions
    # (Available=$false / a Reason naming the missing capability) would be
    # INVERTED, so we skip them there. Anywhere else — macOS/non-Windows OR
    # Windows WITHOUT a usable TPM (GitHub-hosted windows-latest) — this
    # evaluates to $false and the fail-closed Context runs.
    # ----------------------------------------------------------------------
    $isWin = if ($PSVersionTable.PSEdition -eq 'Desktop') { $true } else { [bool]$IsWindows }

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

Describe 'New-ProaxiomDiscoveryApp.ps1 parameter surface' {

    BeforeAll {
        $script:ScriptPath =
            (Resolve-Path -LiteralPath (Join-Path (Join-Path $PSScriptRoot '..') 'New-ProaxiomDiscoveryApp.ps1')).Path

        # Get-Command on the script file parses it and exposes its parameter
        # metadata WITHOUT executing the body — safe off-Windows.
        $script:Cmd        = Get-Command -Name $script:ScriptPath
        $script:ParamSets  = $script:Cmd.ParameterSets
        $script:Parameters = $script:Cmd.Parameters

        # Helper: which parameter sets a given parameter participates in.
        function Get-ParamSetNames {
            param([string]$ParameterName)
            $script:Parameters[$ParameterName].Attributes |
                Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                ForEach-Object { $_.ParameterSetName }
        }

        # Helper: a named validation attribute on a parameter.
        function Get-ParamAttribute {
            param([string]$ParameterName, [type]$AttributeType)
            $script:Parameters[$ParameterName].Attributes |
                Where-Object { $_ -is $AttributeType } |
                Select-Object -First 1
        }
    }

    Context 'Parameter sets' {

        It 'exposes exactly two parameter sets: GenerateLocal and ImportCert' {
            $names = @($script:ParamSets.Name | Sort-Object)
            $names | Should -Be @('GenerateLocal', 'ImportCert')
        }

        It 'defaults to the GenerateLocal parameter set' {
            $default = $script:ParamSets | Where-Object { $_.IsDefault }
            @($default).Count   | Should -Be 1 -Because 'exactly one set is the default'
            $default.Name       | Should -BeExactly 'GenerateLocal'
        }
    }

    Context '-CertPath membership and mandatoriness' {

        It 'belongs only to the ImportCert set' {
            $sets = @(Get-ParamSetNames -ParameterName 'CertPath' | Sort-Object -Unique)
            $sets | Should -Be @('ImportCert') -Because '-CertPath selects the ImportCert set'
        }

        It 'is mandatory within the ImportCert set' {
            $importAttr = $script:Parameters['CertPath'].Attributes |
                Where-Object {
                    $_ -is [System.Management.Automation.ParameterAttribute] -and
                    $_.ParameterSetName -eq 'ImportCert'
                } | Select-Object -First 1
            $importAttr               | Should -Not -BeNullOrEmpty
            $importAttr.Mandatory     | Should -BeTrue -Because '-CertPath has Mandatory in ImportCert'
        }
    }

    Context 'GenerateLocal-only parameters are absent from the ImportCert set' {

        # NOTE: -PublicCertPath used to be GenerateLocal-bound but is SHARED since
        # Task 8.4 (the ImportPrivateKey pathway also exports a public cert); its
        # cross-set membership is asserted in the credential-mode Describe below.
        It '<param> is in GenerateLocal but not ImportCert' -ForEach @(
            @{ param = 'Subject' }
            @{ param = 'ValidityMonths' }
        ) {
            $sets = @(Get-ParamSetNames -ParameterName $param | Sort-Object -Unique)
            $sets | Should -Contain 'GenerateLocal' -Because "$param is a GenerateLocal parameter"
            $sets | Should -Not -Contain 'ImportCert' -Because "$param must not bind in ImportCert"
        }
    }

    Context '-StoreLocation validation' {

        It 'has ValidateSet(LocalMachine, CurrentUser)' {
            $vs = Get-ParamAttribute -ParameterName 'StoreLocation' `
                -AttributeType ([System.Management.Automation.ValidateSetAttribute])
            $vs | Should -Not -BeNullOrEmpty -Because '-StoreLocation must carry a ValidateSet'
            @($vs.ValidValues | Sort-Object) | Should -Be @('CurrentUser', 'LocalMachine')
        }

        It 'rejects an out-of-set value when bound' {
            # Bind a bad value via -WhatIf so no provisioning body runs even if it
            # somehow got past validation. ValidateSet rejects before that point.
            { & $script:ScriptPath -StoreLocation 'Nope' -WhatIf -ErrorAction Stop } |
                Should -Throw
        }
    }

    Context '-ValidityMonths validation' {

        It 'has ValidateRange(1, 120)' {
            $vr = Get-ParamAttribute -ParameterName 'ValidityMonths' `
                -AttributeType ([System.Management.Automation.ValidateRangeAttribute])
            $vr             | Should -Not -BeNullOrEmpty -Because '-ValidityMonths must carry a ValidateRange'
            $vr.MinRange    | Should -Be 1
            $vr.MaxRange    | Should -Be 120
        }
    }

    Context 'App-registration parameters (Task 3.0)' {

        It 'exposes the <param> parameter' -ForEach @(
            @{ param = 'CreateAppRegistration' }
            @{ param = 'AppObjectId' }
            @{ param = 'GrantConsent' }
            @{ param = 'ConsentRedirectUri' }
            @{ param = 'DisplayName' }
            @{ param = 'TestNaming' }
            @{ param = 'TenantId' }
            @{ param = 'ForceNewApp' }
        ) {
            $script:Parameters.ContainsKey($param) | Should -BeTrue -Because "$param must exist"
        }

        It '-ForceNewApp is a switch (FR 20 idempotency override)' {
            $script:Parameters['ForceNewApp'].ParameterType | Should -Be ([switch])
        }

        It '<param> is available in BOTH parameter sets (cross-set)' -ForEach @(
            @{ param = 'CreateAppRegistration' }
            @{ param = 'AppObjectId' }
            @{ param = 'GrantConsent' }
            @{ param = 'ConsentRedirectUri' }
            @{ param = 'ForceNewApp' }
        ) {
            # A parameter with no ParameterSetName-specific attribute binds to all
            # sets; its ParameterAttribute reports '__AllParameterSets'.
            $sets = @(Get-ParamSetNames -ParameterName $param)
            $sets | Should -Contain '__AllParameterSets' `
                -Because "$param should be usable from GenerateLocal and ImportCert"
        }

        It '-CreateAppRegistration is a switch' {
            $script:Parameters['CreateAppRegistration'].ParameterType | Should -Be ([switch])
        }

        It '-GrantConsent is a switch' {
            $script:Parameters['GrantConsent'].ParameterType | Should -Be ([switch])
        }

        It '-ConsentRedirectUri is an HTTPS string' {
            $script:Parameters['ConsentRedirectUri'].ParameterType | Should -Be ([string])
            $pattern = $script:Parameters['ConsentRedirectUri'].Attributes |
                Where-Object { $_ -is [System.Management.Automation.ValidatePatternAttribute] } |
                Select-Object -First 1
            $pattern.RegexPattern | Should -BeExactly '^https://'
        }

        It '-TestNaming is a switch' {
            $script:Parameters['TestNaming'].ParameterType | Should -Be ([switch])
        }

        It 'rejects -CreateAppRegistration together with -AppObjectId' {
            # -WhatIf so no provisioning body or tenant contact occurs; the guard
            # throws before any Connect-MgGraph.
            { & $script:ScriptPath -CreateAppRegistration -AppObjectId 'obj-1' -WhatIf -ErrorAction Stop } |
                Should -Throw -ExpectedMessage '*not both*'
        }

        It 'rejects -GrantConsent without -CreateAppRegistration' {
            { & $script:ScriptPath -AppObjectId 'obj-1' -GrantConsent -WhatIf -ErrorAction Stop } |
                Should -Throw -ExpectedMessage '*GrantConsent*'
        }

        It 'rejects -ConsentRedirectUri without -CreateAppRegistration' {
            { & $script:ScriptPath -AppObjectId 'obj-1' -ConsentRedirectUri 'https://consent.example.test/complete' -WhatIf -ErrorAction Stop } |
                Should -Throw -ExpectedMessage '*ConsentRedirectUri*CreateAppRegistration*'
        }
    }

    Context 'Cross-user parameters (Task 4.0, FR 16)' {

        It 'exposes the <param> parameter' -ForEach @(
            @{ param = 'GrantUser' }
            @{ param = 'GrantUserThumbprint' }
        ) {
            $script:Parameters.ContainsKey($param) | Should -BeTrue -Because "$param must exist"
        }

        It '<param> is available in BOTH parameter sets (cross-set)' -ForEach @(
            @{ param = 'GrantUser' }
            @{ param = 'GrantUserThumbprint' }
        ) {
            $sets = @(Get-ParamSetNames -ParameterName $param)
            $sets | Should -Contain '__AllParameterSets' `
                -Because "$param should be usable from GenerateLocal and ImportCert"
        }

        It '<param> is a string with ValidateNotNullOrEmpty' -ForEach @(
            @{ param = 'GrantUser' }
            @{ param = 'GrantUserThumbprint' }
        ) {
            $script:Parameters[$param].ParameterType | Should -Be ([string])
            $vne = $script:Parameters[$param].Attributes |
                Where-Object { $_ -is [System.Management.Automation.ValidateNotNullOrEmptyAttribute] } |
                Select-Object -First 1
            $vne | Should -Not -BeNullOrEmpty -Because "$param must reject empty input"
        }
    }

    Context 'Tenant-write guards (FR 22) — no unselected/ambiguous tenant write' {

        # These guards throw BEFORE any Connect-MgGraph, and -WhatIf ensures no
        # provisioning body runs even if a guard were bypassed. They assert the
        # operator cannot trigger an ambiguous or unselected tenant write.

        It 'rejects -CreateAppRegistration together with -AppObjectId (ambiguous target)' {
            { & $script:ScriptPath -CreateAppRegistration -AppObjectId 'obj-1' -WhatIf -ErrorAction Stop } |
                Should -Throw -ExpectedMessage '*not both*'
        }

        It 'rejects -GrantConsent without -CreateAppRegistration (consent has no SP to grant)' {
            { & $script:ScriptPath -AppObjectId 'obj-1' -GrantConsent -WhatIf -ErrorAction Stop } |
                Should -Throw -ExpectedMessage '*GrantConsent*'
        }

        It 'a default run selects NO app-registration switch (no tenant write path entered)' {
            # Neither -CreateAppRegistration nor -AppObjectId is set by default, so the
            # tenant-write branch is never entered. Assert the switches default to off.
            $script:Parameters['CreateAppRegistration'].SwitchParameter | Should -BeTrue
            # A switch not supplied is $false; the entry script's guard
            #   if ($CreateAppRegistration -or -not [string]::IsNullOrWhiteSpace($AppObjectId))
            # is the only gate into Connect-DiscoveryGraph + any write.
        }
    }
}

Describe 'KeyGeneration.psm1 off-Windows behaviour' {

    BeforeAll {
        $script:RepoRoot  = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
        # Nested Join-Path for Windows PowerShell 5.1 compatibility (see above).
        Import-Module (Join-Path (Join-Path $script:RepoRoot 'src') 'Common.psm1')        -Force
        Import-Module (Join-Path (Join-Path $script:RepoRoot 'src') 'KeyGeneration.psm1') -Force

        # The 10 documented metadata properties (order-independent).
        $script:ExpectedMetaProps = @(
            'Thumbprint', 'Subject', 'NotBefore', 'NotAfter', 'KeyAlgorithm',
            'KeyLength', 'ProviderName', 'HasPrivateKey', 'X5tBase64Url', 'StorePath'
        ) | Sort-Object

        # --- Build a throwaway PUBLIC certificate (.cer, DER) via openssl ---
        $script:TmpDir   = Join-Path ([System.IO.Path]::GetTempPath()) ("proaxiom-tier-a-" + [guid]::NewGuid())
        New-Item -ItemType Directory -Path $script:TmpDir -Force | Out-Null

        $keyPath = Join-Path $script:TmpDir 'key.pem'
        $pemPath = Join-Path $script:TmpDir 'cert.pem'
        $script:CerPath = Join-Path $script:TmpDir 'cert.cer'

        # openssl writes key-gen progress to stderr. Under Windows PowerShell 5.1
        # with $ErrorActionPreference='Stop' (the CI step sets Stop, which
        # propagates into this scriptblock) a native command writing to stderr
        # raises a TERMINATING NativeCommandError — even with 2>$null. Scope a
        # LOCAL 'Continue' here so native stderr does not abort the fixture build;
        # the explicit $LASTEXITCODE checks below still fail setup on a real error.
        $ErrorActionPreference = 'Continue'

        # 1. RSA-2048 self-signed cert -> PEM.
        & openssl req -x509 -newkey rsa:2048 -nodes `
            -keyout $keyPath -out $pemPath -days 30 `
            -subj '/CN=Proaxiom Tier-A Fixture' 2>$null
        if ($LASTEXITCODE -ne 0) { throw "openssl req failed (exit $LASTEXITCODE)" }

        # 2. Convert PEM -> DER (.cer) so the public-cert import path is exercised.
        & openssl x509 -in $pemPath -outform DER -out $script:CerPath 2>$null
        if ($LASTEXITCODE -ne 0) { throw "openssl x509 (DER) failed (exit $LASTEXITCODE)" }

        # Import via the module's public-cert path (asserts no private key).
        $script:Meta = Import-DiscoveryPublicCertificate -Path $script:CerPath
    }

    AfterAll {
        if ($script:TmpDir -and (Test-Path -LiteralPath $script:TmpDir)) {
            Remove-Item -LiteralPath $script:TmpDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # Skip-gated on a real TPM host: there the provider IS available
    # (Available=$true, Reason='OK'), which would invert these fail-closed
    # assertions. Runs everywhere else: macOS/non-Windows (Reason 'Not a
    # Windows host') AND Windows WITHOUT a usable TPM, e.g. the GitHub-hosted
    # windows-latest runner (Reason 'TPM not present' / 'TPM present but not
    # ready' / MPCP not listed / MPCP failed to open via CNG).
    Context 'Test-PlatformCryptoProvider fails closed when not on a TPM host' -Skip:($script:OnTpmHost) {

        It 'reports Available = $false' {
            $status = Test-PlatformCryptoProvider
            $status.Available | Should -BeFalse -Because 'no TPM/MPCP off-Windows -> fail closed'
        }

        It 'gives a fail-closed Reason naming the missing capability' {
            $status = Test-PlatformCryptoProvider
            $status.Reason | Should -Match 'Windows|TPM|Platform Crypto' `
                -Because 'every fail-closed path names the missing capability (host OS, TPM, or MPCP) and the success Reason OK matches none of these'
        }
    }

    # Locks in the return-type CONTRACT that caused the GenerateLocal/ImportCert
    # dispatch bug: the module's key-gen / import functions return normalised
    # METADATA (a PSCustomObject with .Thumbprint), NOT an [X509Certificate2].
    # The entry script must therefore fetch/construct the real certificate object
    # before passing it to any -Certificate parameter. (New-DiscoveryTpmKey shares
    # this contract but needs a TPM to run, so we pin it via Import here — the same
    # metadata factory backs both — plus its declared OutputType.)
    Context 'Key-gen / import functions return METADATA, not an X509Certificate2' {

        It 'Import-DiscoveryPublicCertificate returns a metadata PSCustomObject, not an X509Certificate2' {
            $script:Meta -is [System.Security.Cryptography.X509Certificates.X509Certificate2] |
                Should -BeFalse -Because 'it returns Get-DiscoveryCertMetadata output, not a cert object'
            $script:Meta.PSObject.Properties.Name | Should -Contain 'Thumbprint'
        }

        It 'New-DiscoveryTpmKey declares an OutputType of PSCustomObject (metadata), not X509Certificate2' {
            $cmd = Get-Command -Name 'New-DiscoveryTpmKey'
            $outTypes = @($cmd.OutputType.Type)
            $outTypes | Should -Contain ([pscustomobject])
            $outTypes | Should -Not -Contain ([System.Security.Cryptography.X509Certificates.X509Certificate2]) `
                -Because 'callers must fetch the live cert from the store by .Thumbprint'
        }
    }

    Context 'Get-DiscoveryExistingKeyMatch idempotency matcher (FR 20)' {

        # A tiny store-cert stand-in: the matcher only reads .Subject / .NotAfter /
        # .Thumbprint, so a PSCustomObject suffices (no real cert store needed).
        BeforeAll {
            function New-FakeCert {
                param([string]$Subject, [datetime]$NotAfter, [string]$Thumbprint = 'TP')
                [pscustomobject]@{ Subject = $Subject; NotAfter = $NotAfter; Thumbprint = $Thumbprint }
            }
            $script:Now = Get-Date '2026-06-08T00:00:00Z'
        }

        It 'returns only same-subject, non-expired certificates' {
            $certs = @(
                New-FakeCert -Subject 'CN=Proaxiom Discovery App' -NotAfter $script:Now.AddDays(30)  -Thumbprint 'KEEP1'
                New-FakeCert -Subject 'CN=Proaxiom Discovery App' -NotAfter $script:Now.AddDays(-1)  -Thumbprint 'EXPIRED'
                New-FakeCert -Subject 'CN=Other Subject'          -NotAfter $script:Now.AddDays(30)  -Thumbprint 'OTHER'
            )
            $m = @(Get-DiscoveryExistingKeyMatch -Certificate $certs -Subject 'CN=Proaxiom Discovery App' -AsOf $script:Now)
            $m.Count             | Should -Be 1
            $m[0].Thumbprint     | Should -BeExactly 'KEEP1'
        }

        It 'returns nothing when no certificate matches the subject' {
            $certs = @(New-FakeCert -Subject 'CN=Other' -NotAfter $script:Now.AddDays(30))
            @(Get-DiscoveryExistingKeyMatch -Certificate $certs -Subject 'CN=Proaxiom Discovery App' -AsOf $script:Now).Count |
                Should -Be 0
        }

        It 'returns nothing for a null / empty certificate set' {
            @(Get-DiscoveryExistingKeyMatch -Certificate $null -Subject 'CN=x' -AsOf $script:Now).Count | Should -Be 0
            @(Get-DiscoveryExistingKeyMatch -Certificate @()   -Subject 'CN=x' -AsOf $script:Now).Count | Should -Be 0
        }

        It 'excludes a cert that expires exactly at AsOf (strictly-future only)' {
            $certs = @(New-FakeCert -Subject 'CN=x' -NotAfter $script:Now)
            @(Get-DiscoveryExistingKeyMatch -Certificate $certs -Subject 'CN=x' -AsOf $script:Now).Count | Should -Be 0
        }

        It 'is exported (callable as a public, store-free pure matcher)' {
            (Get-Command Get-DiscoveryExistingKeyMatch -ErrorAction SilentlyContinue) | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Get-DiscoveryCertMetadata output shape (public cert)' {

        It 'returns an object with exactly the 10 documented properties' {
            $props = @($script:Meta.PSObject.Properties.Name | Sort-Object)
            $props | Should -Be $script:ExpectedMetaProps
        }

        It 'reports HasPrivateKey = $false for a public-only certificate' {
            $script:Meta.HasPrivateKey | Should -BeFalse -Because 'the .cer carries no private key'
        }

        It 'has a non-empty Thumbprint and Subject' {
            $script:Meta.Thumbprint | Should -Not -BeNullOrEmpty
            $script:Meta.Subject    | Should -Match 'Proaxiom Tier-A Fixture'
        }

        It 'X5tBase64Url is base64url (no +, /, or = characters)' {
            $x5t = $script:Meta.X5tBase64Url
            $x5t      | Should -Not -BeNullOrEmpty
            $x5t      | Should -Not -Match '[+/=]' -Because 'x5t must be base64url without padding'
        }
    }
}

Describe 'CredentialMode parameter surface and guards (Task 8.4)' {

    BeforeDiscovery {
        # The fail-closed acknowledgement assertion may only run when the session
        # CANNOT prompt (stdin redirected, as in CI and scripted runs): on a real
        # interactive console the script would pose a ShouldContinue prompt
        # instead of throwing, hanging the test run. Skip it there.
        $script:AckPromptPossible = $false
        try {
            $script:AckPromptPossible = -not [System.Console]::IsInputRedirected
        }
        catch {
            $script:AckPromptPossible = $false
        }
    }

    BeforeAll {
        $script:ScriptPath =
            (Resolve-Path -LiteralPath (Join-Path (Join-Path $PSScriptRoot '..') 'New-ProaxiomDiscoveryApp.ps1')).Path

        # Get-Command parses the script and exposes parameter metadata WITHOUT
        # executing the body -- safe off-Windows.
        $script:Cmd        = Get-Command -Name $script:ScriptPath
        $script:Parameters = $script:Cmd.Parameters

        # Helper: which parameter sets a given parameter participates in.
        function Get-CmParamSetNames {
            param([string]$ParameterName)
            $script:Parameters[$ParameterName].Attributes |
                Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                ForEach-Object { $_.ParameterSetName }
        }

        # --- Build a throwaway PUBLIC certificate (.cer, DER) via openssl ---
        # (Same fixture pattern as the off-Windows Describe above; that Describe's
        # AfterAll removes ITS fixture, so this one builds its own.)
        $script:TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("proaxiom-tier-a-cm-" + [guid]::NewGuid())
        New-Item -ItemType Directory -Path $script:TmpDir -Force | Out-Null

        $keyPath = Join-Path $script:TmpDir 'key.pem'
        $pemPath = Join-Path $script:TmpDir 'cert.pem'
        $script:CmCerPath = Join-Path $script:TmpDir 'cert.cer'

        # openssl writes key-gen progress to stderr; under Windows PowerShell 5.1
        # with $ErrorActionPreference = 'Stop' that raises a terminating
        # NativeCommandError even with 2>$null. Scope a LOCAL 'Continue' here.
        $ErrorActionPreference = 'Continue'

        & openssl req -x509 -newkey rsa:2048 -nodes `
            -keyout $keyPath -out $pemPath -days 30 `
            -subj '/CN=Proaxiom CredentialMode Fixture' 2>$null
        if ($LASTEXITCODE -ne 0) { throw "openssl req failed (exit $LASTEXITCODE)" }

        & openssl x509 -in $pemPath -outform DER -out $script:CmCerPath 2>$null
        if ($LASTEXITCODE -ne 0) { throw "openssl x509 (DER) failed (exit $LASTEXITCODE)" }
    }

    AfterAll {
        if ($script:TmpDir -and (Test-Path -LiteralPath $script:TmpDir)) {
            Remove-Item -LiteralPath $script:TmpDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Context 'Parameter surface' {

        It '-CredentialMode exists with exactly the five pathway values in assurance order' {
            $script:Parameters.ContainsKey('CredentialMode') | Should -BeTrue
            $vs = $script:Parameters['CredentialMode'].Attributes |
                Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } |
                Select-Object -First 1
            $vs | Should -Not -BeNullOrEmpty -Because '-CredentialMode must carry a ValidateSet'
            @($vs.ValidValues) | Should -Be @(
                'TpmBound', 'ProviderHostedCert', 'ImportPublicCert', 'ImportPrivateKey', 'ClientSecret'
            ) -Because 'the ValidateSet order IS the assurance order (rank 1..5)'
        }

        It '-CredentialMode defaults to TpmBound (and the script parses clean)' {
            $tokens = $null
            $parseErrors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile(
                $script:ScriptPath, [ref]$tokens, [ref]$parseErrors)
            @($parseErrors).Count | Should -Be 0 -Because 'the entry script must parse without errors'
            $param = @($ast.ParamBlock.Parameters |
                Where-Object { $_.Name.VariablePath.UserPath -eq 'CredentialMode' })
            $param.Count | Should -Be 1
            $param[0].DefaultValue.Extent.Text | Should -Be "'TpmBound'" `
                -Because 'TpmBound is the default (and highest-assurance) pathway'
        }

        It '-PfxPath is a string with ValidateNotNullOrEmpty' {
            $script:Parameters['PfxPath'].ParameterType | Should -Be ([string])
            $vne = $script:Parameters['PfxPath'].Attributes |
                Where-Object { $_ -is [System.Management.Automation.ValidateNotNullOrEmptyAttribute] } |
                Select-Object -First 1
            $vne | Should -Not -BeNullOrEmpty -Because '-PfxPath must reject empty input'
        }

        It '-PfxPassword is a SecureString' {
            $script:Parameters.ContainsKey('PfxPassword') | Should -BeTrue
            $script:Parameters['PfxPassword'].ParameterType | Should -Be ([securestring]) `
                -Because 'the PFX password must never be accepted as plain text'
        }

        It '-AcknowledgeReducedAssurance is a switch' {
            $script:Parameters.ContainsKey('AcknowledgeReducedAssurance') | Should -BeTrue
            $script:Parameters['AcknowledgeReducedAssurance'].ParameterType | Should -Be ([switch])
        }

        It '<param> is shared across both parameter sets (cross-set)' -ForEach @(
            @{ param = 'CredentialMode' }
            @{ param = 'PfxPath' }
            @{ param = 'PfxPassword' }
            @{ param = 'AcknowledgeReducedAssurance' }
            @{ param = 'PublicCertPath' }
        ) {
            $sets = @(Get-CmParamSetNames -ParameterName $param)
            $sets | Should -Contain '__AllParameterSets' `
                -Because "$param must be usable from GenerateLocal and ImportCert invocations"
        }
    }

    Context 'PFX password interactive prompt (docs parity)' {

        # The public docs promise: "-PfxPassword is prompted interactively when
        # omitted". Assert structurally (via the AST -- no execution, no real
        # prompt) that the entry script contains a Read-Host -AsSecureString
        # invocation gated on BOTH the "-PfxPassword was not bound" check and the
        # interactivity probe (the same probe the acknowledgement gate uses), so
        # non-interactive runs never prompt and stay on the password-less path.
        It 'prompts for an omitted -PfxPassword (Read-Host -AsSecureString) gated on the interactivity probe' {
            $tokens = $null
            $parseErrors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile(
                $script:ScriptPath, [ref]$tokens, [ref]$parseErrors)
            @($parseErrors).Count | Should -Be 0 -Because 'the entry script must parse without errors'

            # Every Read-Host -AsSecureString invocation in the script.
            $readHosts = @($ast.FindAll({
                param($node)
                ($node -is [System.Management.Automation.Language.CommandAst]) -and
                ($node.GetCommandName() -eq 'Read-Host') -and
                (@($node.CommandElements | Where-Object {
                    ($_ -is [System.Management.Automation.Language.CommandParameterAst]) -and
                    ($_.ParameterName -eq 'AsSecureString')
                }).Count -gt 0)
            }, $true))

            # At least one must be the PFX password prompt: walk up its parents to
            # an enclosing 'if' whose condition checks that -PfxPassword was NOT
            # bound AND that the session is interactive. (Condition text is matched
            # loosely -- ContainsKey('PfxPassword') + an interactivity variable --
            # so the assertion survives refactors without being satisfiable by an
            # ungated prompt.)
            $gatedPfxPrompts = @($readHosts | Where-Object {
                $gated  = $false
                $parent = $_.Parent
                while ($null -ne $parent) {
                    if ($parent -is [System.Management.Automation.Language.IfStatementAst]) {
                        foreach ($clause in $parent.Clauses) {
                            $condText = $clause.Item1.Extent.Text
                            if ($condText -match "ContainsKey\(\s*'PfxPassword'\s*\)" -and
                                $condText -match '(?i)interactive') {
                                $gated = $true
                            }
                        }
                        if ($gated) { break }
                    }
                    $parent = $parent.Parent
                }
                $gated
            })

            $gatedPfxPrompts.Count | Should -BeGreaterThan 0 -Because (
                'the docs promise -PfxPassword is prompted interactively when omitted, so the entry ' +
                'script must contain a Read-Host -AsSecureString gated on the unbound-password check ' +
                'plus the same interactivity probe as the acknowledgement gate')
        }
    }

    Context 'Credential-mode consistency guards (fire before any TPM/Graph/file work)' {

        # Each guard throws from pure parameter checks at the top of the script:
        # no TPM probe, no Graph/SDK import, no tenant contact, no file access --
        # which is what makes them assertable on any OS. -WhatIf is belt-and-braces.

        It 'rejects ImportPublicCert without -CertPath' {
            { & $script:ScriptPath -CredentialMode ImportPublicCert -WhatIf -ErrorAction Stop } |
                Should -Throw -ExpectedMessage '*ImportPublicCert requires -CertPath*'
        }

        It 'rejects ProviderHostedCert without -CertPath' {
            { & $script:ScriptPath -CredentialMode ProviderHostedCert -WhatIf -ErrorAction Stop } |
                Should -Throw -ExpectedMessage '*ProviderHostedCert requires -CertPath*'
        }

        It 'rejects ImportPrivateKey without -PfxPath' {
            { & $script:ScriptPath -CredentialMode ImportPrivateKey -AcknowledgeReducedAssurance -WhatIf -ErrorAction Stop } |
                Should -Throw -ExpectedMessage '*ImportPrivateKey requires -PfxPath*'
        }

        It 'rejects -PfxPath with an explicit non-ImportPrivateKey mode (TpmBound)' {
            { & $script:ScriptPath -CredentialMode TpmBound -PfxPath 'supplied.pfx' -WhatIf -ErrorAction Stop } |
                Should -Throw -ExpectedMessage '*applies only to the ImportPrivateKey pathway*'
        }

        It 'rejects -CertPath and -PfxPath together' {
            { & $script:ScriptPath -CertPath 'a.cer' -PfxPath 'b.pfx' -WhatIf -ErrorAction Stop } |
                Should -Throw -ExpectedMessage '*not both*'
        }

        It 'rejects ClientSecret with -CertPath' {
            { & $script:ScriptPath -CredentialMode ClientSecret -CertPath 'a.cer' -AcknowledgeReducedAssurance -WhatIf -ErrorAction Stop } |
                Should -Throw -ExpectedMessage '*ClientSecret uses no certificate*'
        }

        It 'rejects ClientSecret with -Attest' {
            { & $script:ScriptPath -CredentialMode ClientSecret -CreateAppRegistration -Attest -AcknowledgeReducedAssurance -WhatIf -ErrorAction Stop } |
                Should -Throw -ExpectedMessage '*no key to attest*'
        }

        It 'rejects ClientSecret without -CreateAppRegistration or -AppObjectId' {
            { & $script:ScriptPath -CredentialMode ClientSecret -AcknowledgeReducedAssurance -WhatIf -ErrorAction Stop } |
                Should -Throw -ExpectedMessage '*requires an app-registration target*'
        }

        It 'rejects -Attest in ImportPrivateKey mode' {
            { & $script:ScriptPath -CredentialMode ImportPrivateKey -PfxPath 'supplied.pfx' -Attest -AcknowledgeReducedAssurance -WhatIf -ErrorAction Stop } |
                Should -Throw -ExpectedMessage '*not valid with -CredentialMode ImportPrivateKey*'
        }
    }

    Context 'Back-compatible mode inference' {

        It 'a plain -CertPath run still takes the ImportPublicCert pathway (no throw, metadata out)' {
            $out = @(& $script:ScriptPath -CertPath $script:CmCerPath -WhatIf -ErrorAction Stop 6>$null)
            $out.Count | Should -BeGreaterThan 0
            $out[0].Thumbprint    | Should -Not -BeNullOrEmpty
            $out[0].Subject       | Should -Match 'Proaxiom CredentialMode Fixture'
            $out[0].HasPrivateKey | Should -BeFalse
        }

        It 'an explicit -CredentialMode ImportPublicCert -CertPath run is equivalent' {
            $implicit = @(& $script:ScriptPath -CertPath $script:CmCerPath -WhatIf -ErrorAction Stop 6>$null)
            $explicit = @(& $script:ScriptPath -CredentialMode ImportPublicCert -CertPath $script:CmCerPath -WhatIf -ErrorAction Stop 6>$null)
            $explicit.Count | Should -BeGreaterThan 0
            $explicit[0].Thumbprint | Should -BeExactly $implicit[0].Thumbprint
        }
    }

    Context 'Reduced-assurance acknowledgement gate' {

        It 'ClientSecret without -AcknowledgeReducedAssurance fails closed (non-interactive), naming the flag' -Skip:($script:AckPromptPossible) {
            { & $script:ScriptPath -CredentialMode ClientSecret -CreateAppRegistration -WhatIf -ErrorAction Stop 6>$null } |
                Should -Throw -ExpectedMessage '*-AcknowledgeReducedAssurance*'
        }

        It 'ClientSecret with -AcknowledgeReducedAssurance proceeds past the gate' {
            # Past the gate the run may legitimately stop later (e.g. the Graph
            # SDK assert on a machine without the SDK); assert only that any
            # failure is NOT the acknowledgement gate.
            $err = $null
            try {
                $null = & $script:ScriptPath -CredentialMode ClientSecret -CreateAppRegistration `
                    -AcknowledgeReducedAssurance -WhatIf -ErrorAction Stop 6>$null 3>$null
            }
            catch {
                $err = $_
            }
            if ($null -ne $err) {
                $err.Exception.Message | Should -Not -Match '(?i)acknowledg' `
                    -Because 'the acknowledgement gate must be satisfied by the flag'
            }
        }
    }

    Context 'Posture disclosure' {

        It 'prints the credential-pathway posture block (information stream)' {
            $captured = & $script:ScriptPath -CertPath $script:CmCerPath -WhatIf -ErrorAction Stop 6>&1
            ($captured | Out-String) | Should -Match 'Credential pathway' `
                -Because 'every run must disclose the selected pathway posture before provisioning'
        }
    }
}
