#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
.SYNOPSIS
    Pester v5 Tier-A suite for the app-registration pure logic (Task 3.0).

.DESCRIPTION
    Tier A (hardware/tenant-free). Validates the PURE payload-builders and the
    manifest -> requiredResourceAccess transform WITHOUT the Microsoft.Graph SDK
    installed and WITHOUT reaching any tenant:

      * Get-DiscoveryRequiredResourceAccess transforms permissions.csv correctly
        (resource grouping, count, type='Role', GUIDs).
      * New-DiscoveryKeyCredential builds a keyCredential from a public .cer.
      * New-DiscoveryAppPayload builds the New-MgApplication body.
      * New-DiscoveryAppDisplayName production + zzTEST-DiscoveryApp-<ts> naming.
      * Output formatting strings (Connect-MgGraph example + consent instructions).

    The Graph-invoking wrappers are NOT exercised here (they belong to the live
    live integration tier). The modules import the SDK lazily inside the
    wrappers, so this suite loads and runs on macOS PowerShell 7 with no SDK.

    Run with:  Invoke-Pester ./tests/AppRegistration.Tests.ps1 -Output Detailed
#>

BeforeDiscovery {
    # Nested Join-Path for Windows PowerShell 5.1 compatibility (5.1's Join-Path
    # accepts only -Path and -ChildPath).
    $script:RepoRoot = Join-Path $PSScriptRoot '..' |
        Resolve-Path -ErrorAction SilentlyContinue |
        ForEach-Object { $_.Path }
    if (-not $script:RepoRoot) {
        $script:RepoRoot = Join-Path $PSScriptRoot '..'
    }
}

Describe 'App-registration pure logic (Tier A)' {

    BeforeAll {
        $script:RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
        $srcDir = Join-Path $script:RepoRoot 'src'

        Import-Module (Join-Path $srcDir 'Common.psm1')         -Force
        Import-Module (Join-Path $srcDir 'Manifest.psm1')       -Force
        Import-Module (Join-Path $srcDir 'AppRegistration.psm1') -Force
        Import-Module (Join-Path $srcDir 'Output.psm1')          -Force

        $script:GraphResourceAppId = '00000003-0000-0000-c000-000000000000'

        # --- Build a throwaway PUBLIC certificate (.cer, DER) via openssl ---
        $script:TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("proaxiom-appreg-" + [guid]::NewGuid())
        New-Item -ItemType Directory -Path $script:TmpDir -Force | Out-Null

        $keyPath        = Join-Path $script:TmpDir 'key.pem'
        $pemPath        = Join-Path $script:TmpDir 'cert.pem'
        $script:CerPath = Join-Path $script:TmpDir 'cert.cer'

        # Native stderr under WinPS 5.1 + EAP=Stop raises a terminating error even
        # with 2>$null; scope a LOCAL Continue (mirrors Parameters.Tests.ps1).
        $ErrorActionPreference = 'Continue'
        & openssl req -x509 -newkey rsa:2048 -nodes `
            -keyout $keyPath -out $pemPath -days 30 `
            -subj '/CN=Proaxiom AppReg Fixture' 2>$null
        if ($LASTEXITCODE -ne 0) { throw "openssl req failed (exit $LASTEXITCODE)" }
        & openssl x509 -in $pemPath -outform DER -out $script:CerPath 2>$null
        if ($LASTEXITCODE -ne 0) { throw "openssl x509 (DER) failed (exit $LASTEXITCODE)" }
    }

    AfterAll {
        if ($script:TmpDir -and (Test-Path -LiteralPath $script:TmpDir)) {
            Remove-Item -LiteralPath $script:TmpDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Context 'Get-DiscoveryRequiredResourceAccess transforms the manifest' {

        BeforeAll {
            $script:Rra  = Get-DiscoveryRequiredResourceAccess
            $script:Rows = Import-Csv -LiteralPath (Resolve-DiscoveryManifestPath)
        }

        It 'returns an array (even for a single resource app)' {
            , $script:Rra | Should -BeOfType [System.Object[]]
        }

        It 'groups all permissions under a single Microsoft Graph resource app' {
            @($script:Rra).Count | Should -Be 1
            $script:Rra[0].resourceAppId | Should -BeExactly $script:GraphResourceAppId
        }

        It 'carries one resourceAccess entry per manifest row (53)' {
            @($script:Rra[0].resourceAccess).Count | Should -Be @($script:Rows).Count
            @($script:Rra[0].resourceAccess).Count | Should -Be 53
        }

        It 'marks every resourceAccess entry type = Role' {
            $offenders = $script:Rra[0].resourceAccess | Where-Object { $_.type -ne 'Role' }
            $offenders | Should -BeNullOrEmpty
        }

        It 'preserves the exact set of PermissionId GUIDs from the manifest' {
            $fromRra = @($script:Rra[0].resourceAccess | ForEach-Object { $_.id } | Sort-Object)
            $fromCsv = @($script:Rows | ForEach-Object { $_.PermissionId } | Sort-Object)
            $fromRra | Should -Be $fromCsv
        }

        It 'each resourceAccess entry has exactly id and type keys' {
            $bad = $script:Rra[0].resourceAccess | Where-Object {
                $keys = @($_.Keys | Sort-Object)
                ($keys -join ',') -ne 'id,type'
            }
            $bad | Should -BeNullOrEmpty
        }
    }

    Context 'New-DiscoveryKeyCredential builds a keyCredential from a public cert' {

        BeforeAll {
            $script:KeyCred = New-DiscoveryKeyCredential -Path $script:CerPath
        }

        It 'has type AsymmetricX509Cert and usage Verify' {
            $script:KeyCred.type  | Should -BeExactly 'AsymmetricX509Cert'
            $script:KeyCred.usage | Should -BeExactly 'Verify'
        }

        It 'embeds the raw DER certificate bytes in key' {
            $script:KeyCred.key | Should -Not -BeNullOrEmpty
            $script:KeyCred.key.Length | Should -BeGreaterThan 0
        }

        It 'carries start/end datetimes from the certificate' {
            $script:KeyCred.startDateTime | Should -BeOfType [datetime]
            $script:KeyCred.endDateTime   | Should -BeOfType [datetime]
            $script:KeyCred.endDateTime   | Should -BeGreaterThan $script:KeyCred.startDateTime
        }

        It 'rejects a file that carries a private key' {
            $keyOnly = Join-Path $script:TmpDir 'key.pem'
            { New-DiscoveryKeyCredential -Path $keyOnly } | Should -Throw
        }

        It 'throws on a missing file' {
            { New-DiscoveryKeyCredential -Path (Join-Path $script:TmpDir 'nope.cer') } | Should -Throw
        }
    }

    Context 'New-DiscoveryAppPayload builds the New-MgApplication body' {

        BeforeAll {
            $script:Payload = New-DiscoveryAppPayload -DisplayName 'Proaxiom Phase 1 Discovery' -CertPath $script:CerPath
        }

        It 'sets the displayName' {
            $script:Payload.displayName | Should -BeExactly 'Proaxiom Phase 1 Discovery'
        }

        It 'defaults signInAudience to single-tenant (AzureADMyOrg)' {
            $script:Payload.signInAudience | Should -BeExactly 'AzureADMyOrg'
        }

        It 'embeds exactly one keyCredential' {
            @($script:Payload.keyCredentials).Count | Should -Be 1
            $script:Payload.keyCredentials[0].type | Should -BeExactly 'AsymmetricX509Cert'
        }

        It 'includes requiredResourceAccess with the 53-permission Graph entry' {
            @($script:Payload.requiredResourceAccess).Count | Should -Be 1
            @($script:Payload.requiredResourceAccess[0].resourceAccess).Count | Should -Be 53
        }

        It 'throws when no certificate source is supplied' {
            { New-DiscoveryAppPayload -DisplayName 'x' } | Should -Throw
        }

        It 'accepts a prebuilt keyCredential' {
            $kc = New-DiscoveryKeyCredential -Path $script:CerPath
            $p  = New-DiscoveryAppPayload -DisplayName 'y' -KeyCredential $kc
            @($p.keyCredentials).Count | Should -Be 1
        }
    }

    Context 'New-DiscoveryAppDisplayName naming convention' {

        It 'returns the production name by default' {
            New-DiscoveryAppDisplayName | Should -BeExactly 'Proaxiom Phase 1 Discovery'
        }

        It 'honours an explicit base name' {
            New-DiscoveryAppDisplayName -BaseName 'Custom' | Should -BeExactly 'Custom'
        }

        It 'builds zzTEST-DiscoveryApp-<timestamp> with -Test' {
            New-DiscoveryAppDisplayName -Test -Timestamp '20260608120000' |
                Should -BeExactly 'zzTEST-DiscoveryApp-20260608120000'
        }

        It 'auto-generates a 14-digit UTC timestamp when -Test and no -Timestamp' {
            $n = New-DiscoveryAppDisplayName -Test
            $n | Should -Match '^zzTEST-DiscoveryApp-\d{14}$'
        }
    }

    Context 'Resolve-DiscoveryAppCreateAction idempotency guard (FR 20)' {

        # A tiny stand-in for a Graph application object: the resolver only reads
        # .DisplayName / .AppId / .Id, so a PSCustomObject suffices (no SDK, no tenant).
        # Defined in BeforeAll so it is available to the It run-phase (a function
        # declared in the Context body only exists during Pester v5 discovery).
        BeforeAll {
            function New-FakeApp {
                param([string]$DisplayName, [string]$AppId, [string]$Id)
                [pscustomobject]@{ DisplayName = $DisplayName; AppId = $AppId; Id = $Id }
            }
        }

        It 'returns Create when no existing app matches the name' {
            $existing = @(New-FakeApp -DisplayName 'Something Else' -AppId 'a1' -Id 'o1')
            $d = Resolve-DiscoveryAppCreateAction -DisplayName 'Proaxiom Phase 1 Discovery' -ExistingApp $existing
            $d.Action            | Should -BeExactly 'Create'
            @($d.Matches).Count  | Should -Be 0
        }

        It 'returns Create when the existing-app set is empty / null' {
            (Resolve-DiscoveryAppCreateAction -DisplayName 'X' -ExistingApp @()).Action   | Should -BeExactly 'Create'
            (Resolve-DiscoveryAppCreateAction -DisplayName 'X' -ExistingApp $null).Action | Should -BeExactly 'Create'
        }

        It 'Blocks on a single name match and names the matching AppId in the message' {
            $existing = @(New-FakeApp -DisplayName 'Proaxiom Phase 1 Discovery' -AppId 'app-dup-1' -Id 'obj-dup-1')
            $d = Resolve-DiscoveryAppCreateAction -DisplayName 'Proaxiom Phase 1 Discovery' -ExistingApp $existing
            $d.Action           | Should -BeExactly 'Blocked'
            @($d.Matches).Count | Should -Be 1
            $d.Message          | Should -Match 'app-dup-1'
            $d.Message          | Should -Match 'obj-dup-1'
            # The actionable ways-forward are surfaced.
            $d.Message          | Should -Match '-AppObjectId'
            $d.Message          | Should -Match '-ForceNewApp'
        }

        It 'Blocks on multiple name matches and lists each AppId' {
            $existing = @(
                New-FakeApp -DisplayName 'Dup Name' -AppId 'app-a' -Id 'obj-a'
                New-FakeApp -DisplayName 'Dup Name' -AppId 'app-b' -Id 'obj-b'
                New-FakeApp -DisplayName 'Other'    -AppId 'app-c' -Id 'obj-c'
            )
            $d = Resolve-DiscoveryAppCreateAction -DisplayName 'Dup Name' -ExistingApp $existing
            $d.Action           | Should -BeExactly 'Blocked'
            @($d.Matches).Count | Should -Be 2
            $d.Message          | Should -Match 'app-a'
            $d.Message          | Should -Match 'app-b'
            $d.Message          | Should -Not -Match 'app-c'
        }

        It 'returns Create on a name match when -Force is set (deliberate duplicate)' {
            $existing = @(New-FakeApp -DisplayName 'Dup Name' -AppId 'app-a' -Id 'obj-a')
            $d = Resolve-DiscoveryAppCreateAction -DisplayName 'Dup Name' -ExistingApp $existing -Force
            $d.Action           | Should -BeExactly 'Create'
            @($d.Matches).Count | Should -Be 1
            $d.Message          | Should -Match 'deliberate duplicate'
        }

        It 'matches the display name case-insensitively' {
            $existing = @(New-FakeApp -DisplayName 'proaxiom phase 1 discovery' -AppId 'app-ci' -Id 'obj-ci')
            (Resolve-DiscoveryAppCreateAction -DisplayName 'Proaxiom Phase 1 Discovery' -ExistingApp $existing).Action |
                Should -BeExactly 'Blocked'
        }

        It 'is exported (callable as a public, tenant-free pure resolver)' {
            (Get-Command Resolve-DiscoveryAppCreateAction -ErrorAction SilentlyContinue) | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Test-DiscoveryTransientGraphError classification' {

        # The classifier is an internal (non-exported) helper; reach it via the
        # module scope so we can unit-test it without a tenant or the Graph SDK.
        BeforeAll {
            $script:AppRegModule = Get-Module AppRegistration
        }

        It 'treats the replication-lag SP-create message as transient' {
            & $script:AppRegModule {
                Test-DiscoveryTransientGraphError -ErrorRecord "New-MgServicePrincipal: The appId 'x' of the service principal does not reference a valid application object."
            } | Should -BeTrue
        }

        It 'treats Request_BadRequest as transient' {
            & $script:AppRegModule {
                Test-DiscoveryTransientGraphError -ErrorRecord 'Status: 400 (BadRequest) ErrorCode: Request_BadRequest'
            } | Should -BeTrue
        }

        It 'treats a 404 on a just-created object as transient' {
            & $script:AppRegModule {
                Test-DiscoveryTransientGraphError -ErrorRecord 'Response status code: 404 (Not Found) ResourceNotFound'
            } | Should -BeTrue
        }

        It 'treats 429 throttling as transient' {
            & $script:AppRegModule {
                Test-DiscoveryTransientGraphError -ErrorRecord 'Status: 429 (TooManyRequests)'
            } | Should -BeTrue
        }

        It 'treats 503 ServiceUnavailable as transient' {
            & $script:AppRegModule {
                Test-DiscoveryTransientGraphError -ErrorRecord 'Status: 503 (ServiceUnavailable)'
            } | Should -BeTrue
        }

        It 'treats 403 authorization-denied as PERMANENT (no retry)' {
            & $script:AppRegModule {
                Test-DiscoveryTransientGraphError -ErrorRecord 'Status: 403 (Forbidden) ErrorCode: Authorization_RequestDenied'
            } | Should -BeFalse
        }

        It 'treats 401 invalid-token as PERMANENT (no retry)' {
            & $script:AppRegModule {
                Test-DiscoveryTransientGraphError -ErrorRecord 'Status: 401 (Unauthorized) InvalidAuthenticationToken'
            } | Should -BeFalse
        }

        It 'authz wins even when a transient token co-occurs' {
            # A 403 authz error that also literally contains "BadRequest" must NOT retry.
            & $script:AppRegModule {
                Test-DiscoveryTransientGraphError -ErrorRecord 'Authorization_RequestDenied Request_BadRequest 403'
            } | Should -BeFalse
        }

        It 'treats an unrelated validation error as PERMANENT (no retry)' {
            & $script:AppRegModule {
                Test-DiscoveryTransientGraphError -ErrorRecord "A property with the name 'foo' is not valid."
            } | Should -BeFalse
        }

        It 'treats $null as non-transient (fail closed)' {
            & $script:AppRegModule {
                Test-DiscoveryTransientGraphError -ErrorRecord $null
            } | Should -BeFalse
        }

        It 'classifies a real ErrorRecord (not just a string)' {
            & $script:AppRegModule {
                $rec = $null
                try { throw 'does not reference a valid application object' }
                catch { $rec = $_ }
                Test-DiscoveryTransientGraphError -ErrorRecord $rec
            } | Should -BeTrue
        }
    }

    Context 'Test-DiscoveryNotFoundGraphError classification (delete path)' {

        BeforeAll {
            $script:AppRegModule = Get-Module AppRegistration
        }

        It 'treats Request_ResourceNotFound as already-gone (success)' {
            & $script:AppRegModule {
                Test-DiscoveryNotFoundGraphError -ErrorRecord 'Status: 404 (NotFound) ErrorCode: Request_ResourceNotFound'
            } | Should -BeTrue
        }

        It 'treats a bare 404 ResourceNotFound as already-gone' {
            & $script:AppRegModule {
                Test-DiscoveryNotFoundGraphError -ErrorRecord 'Response status code: 404 (Not Found) ResourceNotFound'
            } | Should -BeTrue
        }

        It 'does NOT treat 403 authz as already-gone (a real delete failure)' {
            & $script:AppRegModule {
                Test-DiscoveryNotFoundGraphError -ErrorRecord 'Status: 403 (Forbidden) Authorization_RequestDenied'
            } | Should -BeFalse
        }

        It 'does NOT treat a 429 throttle as already-gone' {
            & $script:AppRegModule {
                Test-DiscoveryNotFoundGraphError -ErrorRecord 'Status: 429 (TooManyRequests)'
            } | Should -BeFalse
        }

        It 'treats $null as not-already-gone (fail closed)' {
            & $script:AppRegModule {
                Test-DiscoveryNotFoundGraphError -ErrorRecord $null
            } | Should -BeFalse
        }
    }

    Context 'Invoke-DiscoveryGraphDelete idempotent delete semantics' {

        BeforeAll {
            $script:AppRegModule = Get-Module AppRegistration
        }

        It 'returns $true on a clean delete' {
            & $script:AppRegModule {
                Invoke-DiscoveryGraphDelete -OperationName 'clean' -ScriptBlock { }
            } | Should -BeTrue
        }

        It 'treats a 404 from the delete as success WITHOUT retrying' {
            & $script:AppRegModule {
                $script:__delCalls = 0
                $r = Invoke-DiscoveryGraphDelete -OperationName '404' -ScriptBlock {
                    $script:__delCalls++
                    throw 'Status: 404 (NotFound) Request_ResourceNotFound'
                }
                "$r/$script:__delCalls"
            } | Should -BeExactly 'True/1'
        }

        It 're-throws a permanent (403 authz) delete error' {
            & $script:AppRegModule {
                $script:__delCalls = 0
                { Invoke-DiscoveryGraphDelete -OperationName 'authz' -ScriptBlock {
                    $script:__delCalls++
                    throw 'Status: 403 (Forbidden) Authorization_RequestDenied'
                } } | Should -Throw
                $script:__delCalls
            } | Should -Be 1
        }
    }

    Context 'Invoke-DiscoveryGraphWithRetry behaviour' {

        BeforeAll {
            $script:AppRegModule = Get-Module AppRegistration
        }

        It 'returns the scriptblock result on first success (no retry)' {
            & $script:AppRegModule {
                Invoke-DiscoveryGraphWithRetry -OperationName 'ok' -ScriptBlock { 'value' }
            } | Should -BeExactly 'value'
        }

        It 'retries a transient failure then succeeds (bounded, fast)' {
            & $script:AppRegModule {
                $script:__calls = 0
                $r = Invoke-DiscoveryGraphWithRetry -OperationName 'flaky' -MaxAttempts 3 -MaxDelaySeconds 1 -ScriptBlock {
                    $script:__calls++
                    if ($script:__calls -lt 2) { throw 'does not reference a valid application object' }
                    'done'
                }
                "$r/$script:__calls"
            } | Should -BeExactly 'done/2'
        }

        It 're-throws a permanent failure immediately (single attempt)' {
            & $script:AppRegModule {
                $script:__calls = 0
                try {
                    Invoke-DiscoveryGraphWithRetry -OperationName 'authz' -MaxAttempts 5 -MaxDelaySeconds 1 -ScriptBlock {
                        $script:__calls++
                        throw 'Authorization_RequestDenied 403'
                    }
                }
                catch { }
                $script:__calls
            } | Should -Be 1
        }

        It 're-throws after exhausting the budget on persistent transient errors' {
            & $script:AppRegModule {
                $script:__calls = 0
                { Invoke-DiscoveryGraphWithRetry -OperationName 'stuck' -MaxAttempts 2 -MaxDelaySeconds 1 -ScriptBlock {
                    $script:__calls++
                    throw 'Request_BadRequest'
                } } | Should -Throw
                $script:__calls
            } | Should -Be 2
        }
    }

    Context 'Output formatting (Connect-MgGraph example + consent)' {

        It 'builds a Connect-MgGraph example with placeholders when ids are unknown' {
            Get-DiscoveryConnectExample -Thumbprint 'ABC123' |
                Should -BeExactly 'Connect-MgGraph -ClientId <appid> -TenantId <tid> -CertificateThumbprint ABC123'
        }

        It 'substitutes real AppId/TenantId/Thumbprint' {
            Get-DiscoveryConnectExample -AppId 'app-1' -TenantId 'tid-1' -Thumbprint 'TP1' |
                Should -BeExactly 'Connect-MgGraph -ClientId app-1 -TenantId tid-1 -CertificateThumbprint TP1'
        }

        It 'requires -Thumbprint (mandatory)' {
            # Assert via parameter metadata rather than calling without -Thumbprint:
            # omitting a Mandatory parameter triggers an interactive prompt in a
            # host (instead of a reliable throw), which would hang/poison CI.
            $attr = (Get-Command Get-DiscoveryConnectExample).Parameters['Thumbprint'].Attributes |
                Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] }
            ($attr | Where-Object { $_.Mandatory }) | Should -Not -BeNullOrEmpty
        }

        It 'consent instructions include the direct admin-consent URL' {
            $lines = Get-DiscoveryConsentInstructions -AppId 'app-1' -TenantId 'tid-1'
            ($lines -join "`n") | Should -Match 'https://login\.microsoftonline\.com/tid-1/adminconsent\?client_id=app-1'
        }

        It 'consent instructions mention -GrantConsent (opt-in)' {
            $lines = Get-DiscoveryConsentInstructions -AppId 'a' -TenantId 't'
            ($lines -join "`n") | Should -Match '-GrantConsent'
        }

        It 'consent URL falls back to common tenant when TenantId omitted' {
            $lines = Get-DiscoveryConsentInstructions -AppId 'a'
            ($lines -join "`n") | Should -Match 'login\.microsoftonline\.com/common/adminconsent'
        }
    }
}
