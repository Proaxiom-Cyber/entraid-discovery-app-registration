#requires -Version 7.2
<#
.SYNOPSIS
    Plan or reconcile certificate-based access for an assessment application.
.DESCRIPTION
    Default: validate local inputs and save plan.json without authentication.
    Preview: read the tenant and save the proposed additions without making changes.
    Apply: read current state, add missing certificates and permissions, then verify.
    Existing certificates, requested permissions and consent grants are preserved.
    Use a dedicated PowerShell process. Run only one updater for an application at
    a time. Graph does not provide a compare-and-swap guarantee for this update.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][Alias('Config')][string]$ConfigPath,
    [switch]$Preview,
    [switch]$Apply
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'

function Assert-Condition([bool]$Condition, [string]$Code) { if (-not $Condition) { throw $Code } }
function Get-Identifier($Value) {
    $parsed = [guid]::Empty
    Assert-Condition ([guid]::TryParse([string]$Value, [ref]$parsed) -and $parsed -ne [guid]::Empty) 'invalid-identifier'
    $parsed.ToString()
}
function Get-Label($Value, [int]$Maximum) {
    Assert-Condition ($Value -is [string] -and $Value.Length -gt 0 -and $Value.Length -le $Maximum) 'invalid-label'
    Assert-Condition ($Value -ceq $Value.Trim() -and $Value -notmatch '[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]') 'invalid-label'
    $Value
}
function Resolve-ConfigPath([string]$Value) {
    Assert-Condition (-not [string]::IsNullOrWhiteSpace($Value)) 'invalid-config-path'
    if ([IO.Path]::IsPathFullyQualified($Value)) { return [IO.Path]::GetFullPath($Value) }
    Assert-Condition (-not [IO.Path]::IsPathRooted($Value)) 'ambiguous-rooted-path'
    [IO.Path]::GetFullPath([IO.Path]::Combine($directory, $Value))
}
function Read-Json([string]$Path) {
    $value = [IO.File]::ReadAllText($Path) | ConvertFrom-Json -AsHashtable
    Assert-Condition ($value -is [Collections.IDictionary]) 'json-object-required'
    $value
}
function Write-Json([string]$Path, $Value) {
    $temporary = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        [IO.File]::WriteAllText($temporary, (ConvertTo-Json -InputObject $Value -Depth 50) + "`n", [Text.UTF8Encoding]::new($false))
        [IO.File]::Move($temporary, $Path, $true)
    } finally { if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) } }
}
function ConvertTo-Canonical($Value) {
    if ($Value -is [Collections.IDictionary]) {
        $result = [ordered]@{}
        foreach ($key in @($Value.Keys | Sort-Object -CaseSensitive)) { $result[$key] = ConvertTo-Canonical $Value[$key] }
        return $result
    }
    if ($Value -is [Collections.IEnumerable] -and $Value -isnot [string]) {
        return ,@(foreach ($item in $Value) { ConvertTo-Canonical $item })
    }
    return $Value
}
function Get-CanonicalJson($Value) { ConvertTo-Json -InputObject (ConvertTo-Canonical $Value) -Depth 50 -Compress }
function Copy-Value($Value) { Get-CanonicalJson $Value | ConvertFrom-Json -AsHashtable }
function Get-Sha256([byte[]]$Bytes) { [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant() }
function Get-PublicCertificate([byte[]]$Bytes, [switch]$New) {
    Assert-Condition ($Bytes.Length -ge 128 -and $Bytes.Length -le 65536) 'invalid-certificate-size'
    Assert-Condition ([Security.Cryptography.X509Certificates.X509Certificate2]::GetCertContentType($Bytes) -eq [Security.Cryptography.X509Certificates.X509ContentType]::Cert) 'public-certificate-required'
    $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($Bytes)
    $rsa = $null
    try {
        Assert-Condition (-not $certificate.HasPrivateKey -and [Convert]::ToBase64String($certificate.RawData) -ceq [Convert]::ToBase64String($Bytes)) 'public-der-required'
        $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($certificate)
        if ($New) {
            # RSAOpenSsl exposes KeySize as write-only through PowerShell on Linux.
            # Call the inherited getter directly; do not weaken the size check.
            Assert-Condition ($null -ne $rsa -and $rsa.get_KeySize() -ge 2048) 'rsa-2048-required'
            $start = $certificate.NotBefore.ToUniversalTime()
            $end = $certificate.NotAfter.ToUniversalTime()
            Assert-Condition ($start -le [DateTime]::UtcNow -and $end -gt [DateTime]::UtcNow -and ($end - $start).TotalDays -le 90) 'invalid-certificate-validity'
        }
        @{ sha256 = (Get-Sha256 $Bytes); key = [Convert]::ToBase64String($Bytes); thumbprint = $certificate.Thumbprint
           startDateTime = $certificate.NotBefore.ToUniversalTime().ToString('o'); endDateTime = $certificate.NotAfter.ToUniversalTime().ToString('o') }
    } finally { if ($null -ne $rsa) { $rsa.Dispose() }; $certificate.Dispose() }
}
function Assert-GraphContext {
    $context = Get-MgContext -ErrorAction Stop
    Assert-Condition ($null -ne $context -and [string]$context.TenantId -ieq $tenantId -and
        [string]$context.AuthType -ceq 'Delegated' -and [string]$context.ContextScope -ceq 'Process' -and
        [string]$context.Environment -ceq 'Global' -and -not [string]::IsNullOrWhiteSpace([string]$context.Account)) 'wrong-graph-context'
    foreach ($scope in $setupScopes) { Assert-Condition (@($context.Scopes) -ccontains $scope) 'missing-setup-scope' }
}
function Get-GraphUri([string]$Path) {
    $uri = if ($Path.StartsWith('/')) { [uri]("https://graph.microsoft.com/v1.0$Path") } else { [uri]$Path }
    Assert-Condition ($uri.Scheme -ceq 'https' -and $uri.Host -ceq 'graph.microsoft.com' -and $uri.IsDefaultPort -and
        $uri.AbsolutePath.StartsWith('/v1.0/') -and -not $uri.UserInfo -and -not $uri.Fragment) 'invalid-graph-url'
    $uri.AbsoluteUri
}
function Read-Graph([string]$Path) {
    $value = Invoke-MgGraphRequest -Method GET -Uri (Get-GraphUri $Path) -OutputType Hashtable -ErrorAction Stop
    Assert-Condition ($value -is [Collections.IDictionary]) 'invalid-graph-object'
    $value
}
function Read-GraphList([string]$Path) {
    $rows = @(); $seen = @{}
    do {
        Assert-Condition (-not $seen.ContainsKey($Path)) 'pagination-loop'
        $seen[$Path] = $true
        $page = Read-Graph $Path
        Assert-Condition ($page.Contains('value') -and $page.value -is [Collections.IList]) 'invalid-graph-list'
        $rows += @($page.value)
        $Path = [string]$page['@odata.nextLink']
    } while ($Path)
    return ,$rows
}
function Write-Graph([string]$Kind, [string]$Method, [string]$Path, $Body) {
    Assert-GraphContext
    $receipt.pending_operation = $Kind
    Write-Json $receiptPath $receipt
    # SDK retries are disabled. A failed POST can have succeeded on the server.
    $result = Invoke-MgGraphRequest -Method $Method -Uri (Get-GraphUri $Path) -Body (ConvertTo-Json -InputObject $Body -Depth 50 -Compress) -ContentType 'application/json' -OutputType Hashtable -ErrorAction Stop
    $receipt.operations += @{ kind = $Kind; at = [DateTime]::UtcNow.ToString('o') }
    return $result
}
function Read-Application([string]$ObjectId) {
    $value = Read-Graph ("/applications/$(Get-Identifier $ObjectId)" + '?$select=id,appId,displayName,signInAudience,keyCredentials,requiredResourceAccess')
    foreach ($field in @('id','appId','displayName','signInAudience','keyCredentials','requiredResourceAccess')) {
        Assert-Condition ($value.Contains($field)) 'application-fields-missing'
    }
    # Exclude OData metadata when comparing consecutive reads.
    $result = [ordered]@{}
    foreach ($field in @('id','appId','displayName','signInAudience','keyCredentials','requiredResourceAccess')) { $result[$field] = $value[$field] }
    $result
}
function Get-ExistingKeyMap($Application) {
    Assert-Condition ($Application.keyCredentials -is [Collections.IList]) 'key-credentials-missing'
    $keys = @{}
    foreach ($key in $Application.keyCredentials) {
        Assert-Condition ($key -is [Collections.IDictionary] -and $key.type -ceq 'AsymmetricX509Cert' -and $key.key) 'unreadable-existing-key'
        $allowed = @('customKeyIdentifier','displayName','endDateTime','key','keyId','startDateTime','type','usage')
        Assert-Condition (@($key.Keys | Where-Object { $_ -notin $allowed }).Count -eq 0) 'unknown-key-fields'
        $null = Get-Identifier $key.keyId
        $cert = Get-PublicCertificate ([Convert]::FromBase64String($key.key))
        $keys[$cert.sha256] = $key
    }
    $keys
}
function Get-NewKey($Certificate) {
    @{ type = 'AsymmetricX509Cert'; usage = 'Verify'; key = $Certificate.key
       displayName = 'Assessment public certificate'; startDateTime = $Certificate.startDateTime; endDateTime = $Certificate.endDateTime }
}
function Get-State {
    Assert-GraphContext
    $id = $applicationId
    if ($receipt -and $receipt.application_id) { $id = $receipt.application_id }
    $app = $null
    if ($id) {
        $matchingObjects = Read-GraphList ('/applications?$filter=' + [uri]::EscapeDataString("appId eq '$id'"))
        Assert-Condition ($matchingObjects.Count -eq 1) 'application-id-not-unique-or-missing'
        $app = Read-Application $matchingObjects[0].id
        Assert-Condition ((Get-Identifier $app.appId) -eq $id -and $app.displayName -ceq $displayName -and $app.signInAudience -ceq 'AzureADMyOrg') 'application-identity-conflict'
        if ($receipt -and $receipt.application_object_id) { Assert-Condition ($app.id -eq $receipt.application_object_id) 'receipt-object-conflict' }
    } else {
        Assert-Condition (-not $receipt -or $receipt.pending_operation -ne 'create-application') 'uncertain-create-requires-explicit-id'
        $escaped = $displayName.Replace("'", "''")
        $matchingObjects = Read-GraphList ('/applications?$filter=' + [uri]::EscapeDataString("displayName eq '$escaped'"))
        Assert-Condition ($matchingObjects.Count -eq 0) 'existing-name-requires-explicit-id'
        Assert-Condition ($certificates.Count -gt 0 -and $permissions.Count -gt 0) 'new-app-requires-certificate-and-profile'
    }
    $resolved = @(); $resourceId = $null
    if ($permissions.Count -gt 0) {
        $resources = Read-GraphList ('/servicePrincipals?$filter=' + [uri]::EscapeDataString("appId eq '$graphAppId'") + '&$select=id,appId,appRoles')
        Assert-Condition ($resources.Count -eq 1 -and $resources[0].appId -eq $graphAppId) 'graph-resource-not-unique'
        $resourceId = Get-Identifier $resources[0].id
        foreach ($name in $permissions) {
            $roles = @($resources[0].appRoles | Where-Object { $_.value -ceq $name -and $_.isEnabled -eq $true -and @($_.allowedMemberTypes) -ccontains 'Application' })
            Assert-Condition ($roles.Count -eq 1) 'permission-role-not-unique-or-enabled'
            $resolved += @{ name = $name; id = (Get-Identifier $roles[0].id) }
        }
    }
    Assert-Condition (@($resolved | ForEach-Object {$_.id} | Sort-Object -Unique).Count -eq $resolved.Count) 'duplicate-role-identifiers'
    $sp = $null; $grants = @(); $access = @(); $keys = @{}
    if ($app) {
        $sps = Read-GraphList ('/servicePrincipals?$filter=' + [uri]::EscapeDataString("appId eq '$($app.appId)'") + '&$select=id,appId')
        Assert-Condition ($sps.Count -le 1) 'service-principal-not-unique'
        if ($sps.Count -eq 1) { $sp = $sps[0]; $null = Get-Identifier $sp.id; Assert-Condition ($sp.appId -eq $app.appId) 'service-principal-conflict' }
        if ($receipt -and $receipt.service_principal_id) { Assert-Condition ($null -ne $sp -and $sp.id -eq $receipt.service_principal_id) 'receipt-service-principal-conflict' }
        if ($sp -and $resolved.Count -gt 0) {
            $grants = Read-GraphList ("/servicePrincipals/$($sp.id)/appRoleAssignments" + '?$select=id,principalId,resourceId,appRoleId')
            Assert-Condition (@($grants | Where-Object { $_.principalId -ne $sp.id }).Count -eq 0) 'grant-principal-conflict'
        }
        if ($certificates.Count -gt 0) { $keys = Get-ExistingKeyMap $app }
        Assert-Condition ($app.requiredResourceAccess -is [Collections.IList]) 'required-access-missing'
        $access = @(Copy-Value $app.requiredResourceAccess)
    }
    if ($resolved.Count -gt 0) {
        $resources = @($access | Where-Object { $_.resourceAppId -eq $graphAppId })
        Assert-Condition ($resources.Count -le 1) 'duplicate-resource-access'
        if ($resources.Count -eq 0) { $resources = @(@{resourceAppId=$graphAppId;resourceAccess=@()}); $access += $resources }
        Assert-Condition ($resources[0].resourceAccess -is [Collections.IList]) 'invalid-resource-access'
        foreach ($role in $resolved) {
            if (@($resources[0].resourceAccess | Where-Object { $_.id -eq $role.id -and $_.type -ceq 'Role' }).Count -eq 0) {
                $resources[0].resourceAccess += @{id=$role.id;type='Role'}
            }
        }
    }
    $missingCerts = @($certificates | Where-Object { -not $keys.ContainsKey($_.sha256) })
    $patch = @{}
    if ($app -and $missingCerts.Count -gt 0) { $patch.keyCredentials = @($app.keyCredentials) + @($missingCerts | ForEach-Object { Get-NewKey $_ }) }
    if ($app -and (Get-CanonicalJson $access) -cne (Get-CanonicalJson $app.requiredResourceAccess)) { $patch.requiredResourceAccess = $access }
    $missingRoles = @($resolved | Where-Object { $roleId=$_.id; @($grants | Where-Object { $_.resourceId -eq $resourceId -and $_.appRoleId -eq $roleId }).Count -eq 0 })
    @{app=$app;sp=$sp;grants=$grants;access=$access;patch=$patch;missingCerts=$missingCerts;missingRoles=$missingRoles;resolved=$resolved;resourceId=$resourceId}
}

$stage = 'local-validation'; $connected = $false; $receipt = $null; $receiptPath = $null; $applyStarted = $false
try {
    Assert-Condition (-not ($Preview -and $Apply)) 'preview-and-apply-conflict'
    $stage = 'config-validation'
    $configFile = (Resolve-Path -LiteralPath $ConfigPath).Path
    $directory = Split-Path $configFile -Parent
    $config = Read-Json $configFile
    $tenantId = Get-Identifier $config.tenant_id
    $displayName = Get-Label $config.display_name 120
    $reference = if ($config['engagement_reference']) { Get-Label $config['engagement_reference'] 100 } else { $null }
    $applicationId = if ($config['application_id']) { Get-Identifier $config['application_id'] } else { $null }
    Assert-Condition ($config.output_directory -is [string] -and $config.output_directory) 'output-directory-required'
    $output = Resolve-ConfigPath $config.output_directory
    $certificates = @(); $permissions = @(); $profileHash = $null
    if ($config['certificates']) {
        Assert-Condition ($config['certificates'] -is [Collections.IList]) 'invalid-certificate-list'
        foreach ($inputCert in $config['certificates']) {
            Assert-Condition ($inputCert.path -is [string] -and [IO.Path]::GetExtension($inputCert.path) -ieq '.cer') 'public-cer-required'
            $stage = 'certificate-file-read'
            $bytes = [IO.File]::ReadAllBytes((Resolve-ConfigPath $inputCert.path))
            Assert-Condition ($inputCert.sha256 -is [string] -and (Get-Sha256 $bytes) -ceq $inputCert.sha256.ToLowerInvariant()) 'certificate-hash-mismatch'
            $stage = 'certificate-validation'
            $certificates += Get-PublicCertificate $bytes -New
        }
        Assert-Condition (@($certificates.sha256 | Sort-Object -Unique).Count -eq $certificates.Count) 'duplicate-input-certificate'
    }
    $stage = 'permission-profile-validation'
    $allowed = @('Directory.Read.All','Policy.Read.All','UserAuthenticationMethod.Read.All','AuditLog.Read.All','Member.Read.Hidden','RoleManagement.Read.Directory','IdentityRiskyUser.Read.All','DeviceManagementConfiguration.Read.All','DeviceManagementManagedDevices.Read.All','CustomSecAttributeDefinition.Read.All','CustomSecAttributeAssignment.Read.All','CrossTenantInformation.ReadBasic.All','DeviceManagementApps.Read.All','DeviceManagementRBAC.Read.All','DeviceManagementServiceConfig.Read.All','SecurityEvents.Read.All','Domain-InternalFederation.Read.All')
    if ($config['permission_profile']) {
        $profileFile = Resolve-ConfigPath $config['permission_profile']
        $permissionProfile = Read-Json $profileFile
        Assert-Condition ($permissionProfile.application_permissions -is [Collections.IList] -and $permissionProfile.application_permissions.Count -gt 0) 'invalid-permission-profile'
        foreach ($role in $permissionProfile.application_permissions) {
            Assert-Condition ($role.name -is [string] -and $allowed -ccontains $role.name -and $permissions -cnotcontains $role.name) 'disallowed-or-duplicate-permission'
            $permissions += $role.name
        }
        $profileHash = (Get-FileHash -LiteralPath $profileFile -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    Assert-Condition ($certificates.Count -gt 0 -or $permissions.Count -gt 0) 'certificate-or-profile-required'
    $stage = 'local-plan'
    [IO.Directory]::CreateDirectory($output) | Out-Null
    $receiptPath = Join-Path $output 'setup-receipt.json'; $planPath = Join-Path $output 'plan.json'
    if ([IO.File]::Exists($receiptPath)) {
        $receipt = Read-Json $receiptPath
        Assert-Condition ($receipt.tenant_id -eq $tenantId -and $receipt.display_name -ceq $displayName) 'receipt-identity-conflict'
        Assert-Condition (-not $applicationId -or -not $receipt.application_id -or $applicationId -eq $receipt.application_id) 'receipt-application-conflict'
    }
    $graphAppId = '00000003-0000-0000-c000-000000000000'
    $setupScopes = if ($Preview) { @('Application.Read.All') } else { @('Application.ReadWrite.All') }
    if (-not $Preview -and $permissions.Count -gt 0) { $setupScopes += 'AppRoleAssignment.ReadWrite.All' }
    $plan = [ordered]@{schema_version=1;mode='local-intent';tenant_id=$tenantId;display_name=$displayName;engagement_reference=$reference
        application_id=$applicationId;certificate_sha256=@($certificates | ForEach-Object {$_.sha256});permissions=$permissions
        profile_sha256=$profileHash;script_sha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant();delegated_setup_scopes=$setupScopes}
    if ($receipt -and $receipt.application_id) { $plan.application_id = $receipt.application_id }
    if (-not $Preview -and -not $Apply) {
        Assert-Condition ($plan.application_id -or ($certificates.Count -gt 0 -and $permissions.Count -gt 0)) 'new-app-requires-certificate-and-profile'
        Write-Json $planPath $plan
        [pscustomobject]@{status='planned';plan_path=$planPath}
        return
    }
    $stage = 'connection'
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    if ($null -ne (Get-MgContext -ErrorAction Stop)) { Disconnect-MgGraph -ErrorAction Stop | Out-Null }
    $connected = $true
    Connect-MgGraph -TenantId $tenantId -Scopes $setupScopes -ContextScope Process -Environment Global -NoWelcome -ErrorAction Stop | Out-Null
    Assert-GraphContext
    Set-MgRequestContext -MaxRetry 0 -ErrorAction Stop | Out-Null
    $stage = 'read-current-state'
    $state = Get-State
    $plan.mode='live-diff'; $plan.create_application=($null -eq $state.app)
    $plan.create_service_principal=($null -eq $state.sp -and $state.resolved.Count -gt 0)
    $plan.patch_fields=@($state.patch.Keys | Sort-Object)
    $plan.add_certificate_sha256=@($state.missingCerts | ForEach-Object {$_.sha256})
    $plan.add_permission_names=@($state.missingRoles | ForEach-Object {$_.name})
    $plan.existing_grant_count=$state.grants.Count
    $plan.existing_certificate_count=if ($state.app) {$state.app.keyCredentials.Count} else {0}
    if ($state.app) {$plan.application_id=$state.app.appId}
    Write-Json $planPath $plan
    if ($Preview) { [pscustomobject]@{status='previewed';plan_path=$planPath}; return }
    if (-not $receipt) { $receipt=@{schema_version=1;tenant_id=$tenantId;display_name=$displayName;application_id=$null;application_object_id=$null;service_principal_id=$null;pending_operation=$null;operations=@()} }
    $receipt.status='applying'; $receipt.plan=$plan; $receipt.engagement_reference=$reference
    $applyStarted=$true; $mutationsBefore=$receipt.operations.Count
    $app=$state.app; $sp=$state.sp
    if ($app) {$receipt.application_id=$app.appId;$receipt.application_object_id=$app.id}
    if ($sp) {$receipt.service_principal_id=$sp.id}
    Write-Json $receiptPath $receipt
    if (-not $app) {
        $stage='create-application'
        $tags=@('CertificateAssessment',"setup-sha256:$($plan.script_sha256)")
        if ($reference) {$tags += "engagement:$reference"}
        $created=Write-Graph 'create-application' POST '/applications' @{displayName=$displayName;signInAudience='AzureADMyOrg';tags=$tags;keyCredentials=@($certificates | ForEach-Object {Get-NewKey $_});requiredResourceAccess=$state.access}
        $receipt.application_id=Get-Identifier $created.appId; $receipt.application_object_id=Get-Identifier $created.id
        $receipt.pending_operation=$null; Write-Json $receiptPath $receipt
        $app=Read-Application $receipt.application_object_id
    } elseif ($state.patch.Count -gt 0) {
        $stage='patch-application'
        $fresh=Read-Application $app.id
        Assert-Condition ((Get-CanonicalJson $fresh) -ceq (Get-CanonicalJson $app)) 'application-changed-before-patch'
        $null=Write-Graph 'patch-application' PATCH ("/applications/$($app.id)") $state.patch
        $updated=Read-Application $app.id
        if ($state.patch.ContainsKey('keyCredentials')) {
            $newKeys=Get-ExistingKeyMap $updated
            foreach ($oldKey in $app.keyCredentials) {
                $matchingObjects = @($updated.keyCredentials | Where-Object {$_.keyId -eq $oldKey.keyId})
                Assert-Condition ($matchingObjects.Count -eq 1 -and (Get-CanonicalJson $matchingObjects[0]) -ceq (Get-CanonicalJson $oldKey)) 'existing-certificate-not-preserved'
            }
            foreach ($cert in $certificates) { Assert-Condition ($newKeys.ContainsKey($cert.sha256)) 'certificate-readback-incomplete' }
        }
        if ($state.patch.ContainsKey('requiredResourceAccess')) { Assert-Condition ((Get-CanonicalJson $updated.requiredResourceAccess) -ceq (Get-CanonicalJson $state.patch.requiredResourceAccess)) 'permission-request-readback-incomplete' }
        $receipt.pending_operation=$null; Write-Json $receiptPath $receipt
        $app=$updated
    }
    if (-not $sp -and $state.resolved.Count -gt 0) {
        $stage='create-service-principal'
        $sp=Write-Graph 'create-service-principal' POST '/servicePrincipals' @{appId=$receipt.application_id}
        $receipt.service_principal_id=Get-Identifier $sp.id; $receipt.pending_operation=$null; Write-Json $receiptPath $receipt
    }
    foreach ($role in $state.missingRoles) {
        $stage='grant-permission'
        $null=Write-Graph ("grant-permission:$($role.id)") POST ("/servicePrincipals/$($receipt.service_principal_id)/appRoleAssignments") @{principalId=$receipt.service_principal_id;resourceId=$state.resourceId;appRoleId=$role.id}
        $receipt.pending_operation=$null; Write-Json $receiptPath $receipt
    }
    $stage='verify-final-state'
    $final=Get-State
    Assert-Condition ($null -ne $final.app -and $final.patch.Count -eq 0 -and $final.missingRoles.Count -eq 0) 'final-readback-incomplete'
    $receipt.status='complete';$receipt.pending_operation=$null;$receipt.completed_utc=[DateTime]::UtcNow.ToString('o')
    Write-Json $receiptPath $receipt
    [pscustomobject]@{status='complete';receipt_path=$receiptPath;mutations=($receipt.operations.Count-$mutationsBefore)}
} catch {
    $failureType = $_.Exception.GetBaseException().GetType().Name
    $failureReason = 'not-reported'
    $safeCertificateReasons = @('invalid-certificate-size','public-certificate-required','public-der-required','rsa-2048-required','invalid-certificate-validity')
    if ($safeCertificateReasons -ccontains $_.Exception.Message) { $failureReason = $_.Exception.Message }
    if ($applyStarted -and $null -ne $receipt) {
        $receipt.status='incomplete';$receipt.failure_stage=$stage
        try {Write-Json $receiptPath $receipt} catch {Write-Warning 'The progress receipt could not be saved. Review the application before retrying.'}
    }
    throw "Assessment setup stopped at '$stage'. Failure type: $failureType. Reason: $failureReason. Review local inputs and the receipt before retrying. Response details are suppressed."
} finally {
    if ($connected) {try {Disconnect-MgGraph -ErrorAction Stop | Out-Null} catch {Write-Warning 'Close this PowerShell process to end the setup session.'}}
}
