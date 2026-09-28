#requires -Version 7.2
<#
.SYNOPSIS
    Offline tests for additive assessment application reconciliation.
.DESCRIPTION
    All Graph calls are mocked. Test certificates contain fixed public numbers
    and dummy signatures. No private key, authentication or network is used.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '', Justification='Isolated fixture state is shared with child-script mocks and removed in finally.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification='Mocks retain the exact SDK parameter interface.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Mocks and disposable public fixture creation do not change a tenant.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification='The fixture overrides Import-Module to prevent SDK loading or authentication.')]
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$engine=Join-Path (Split-Path $PSScriptRoot -Parent) 'Sync-AssessmentApp.ps1'
$tempRoot=Join-Path ([IO.Path]::GetTempPath()) ('assessment-fixture-'+[guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($tempRoot)
$checks=0
function Assert-Test([bool]$Condition,[string]$Name) {if(-not $Condition){throw "Fixture failed: $Name"};$script:checks++}
function Copy-TestValue($Value) {ConvertTo-Json -InputObject $Value -Depth 50 -Compress | ConvertFrom-Json -AsHashtable}
function New-PublicFixture([string]$Name,[int]$Bits=2048,[int]$Start=-1,[int]$End=29,[byte]$Number=163) {
    # X.509 structure only. The signature is deliberately invalid; no signer exists.
    $w=[System.Formats.Asn1.AsnWriter]::new([System.Formats.Asn1.AsnEncodingRules]::DER)
    $null=$w.PushSequence();$null=$w.PushSequence()
    $tag=[System.Formats.Asn1.Asn1Tag]::new([System.Formats.Asn1.TagClass]::ContextSpecific,0,$true)
    $null=$w.PushSequence($tag);$w.WriteInteger(2);$w.PopSequence($tag);$w.WriteInteger(1)
    $null=$w.PushSequence();$w.WriteObjectIdentifier('1.2.840.113549.1.1.11');$w.WriteNull();$w.PopSequence()
    foreach($field in @('issuer','validity','subject')){
        $null=$w.PushSequence()
        if($field -eq 'validity'){$w.WriteUtcTime([DateTimeOffset]::UtcNow.AddDays($Start));$w.WriteUtcTime([DateTimeOffset]::UtcNow.AddDays($End))}
        else{$null=$w.PushSetOf();$null=$w.PushSequence();$w.WriteObjectIdentifier('2.5.4.3');$w.WriteCharacterString([System.Formats.Asn1.UniversalTagNumber]::UTF8String,'Offline public fixture');$w.PopSequence();$w.PopSetOf()}
        $w.PopSequence()
    }
    $null=$w.PushSequence();$null=$w.PushSequence();$w.WriteObjectIdentifier('1.2.840.113549.1.1.1');$w.WriteNull();$w.PopSequence()
    $pub=[System.Formats.Asn1.AsnWriter]::new([System.Formats.Asn1.AsnEncodingRules]::DER)
    $null=$pub.PushSequence();$mod=[byte[]]::new($Bits/8);[Array]::Fill[byte]($mod,$Number);$pub.WriteIntegerUnsigned($mod);$pub.WriteInteger(65537);$pub.PopSequence()
    $w.WriteBitString($pub.Encode(),0);$w.PopSequence();$w.PopSequence()
    $null=$w.PushSequence();$w.WriteObjectIdentifier('1.2.840.113549.1.1.11');$w.WriteNull();$w.PopSequence()
    $w.WriteBitString([byte[]]::new($Bits/8),0);$w.PopSequence()
    $path=Join-Path $tempRoot "$Name.cer";[IO.File]::WriteAllBytes($path,$w.Encode())
    @{path=$path;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
}
function Reset-Mock {
    $global:AssessmentMock=@{Tenant='11111111-1111-1111-1111-111111111111';Context=$null;Apps=@();Sps=@();Grants=@();Writes=@();Connects=0;Reads=0;Fail='';GetAppCount=0;MaxRetry=-1;LastFilter='';LastScopes=@();Roles=@()}
    $names=@('AuditLog.Read.All','Directory.Read.All','Policy.Read.All')
    for($i=0;$i -lt $names.Count;$i++){$global:AssessmentMock.Roles+=@{id=('66666666-6666-6666-6666-'+($i+1).ToString('D12'));value=$names[$i];isEnabled=$true;allowedMemberTypes=@('Application')}}
}
function Import-Module {[CmdletBinding()]param($Name)}
function Get-MgContext {[CmdletBinding()]param() $global:AssessmentMock.Context}
function Disconnect-MgGraph {[CmdletBinding()]param() $global:AssessmentMock.Context=$null}
function Connect-MgGraph {
    [CmdletBinding()]param($TenantId,$Scopes,$ContextScope,$Environment,[switch]$NoWelcome)
    $m=$global:AssessmentMock;$m.Connects++;$m.LastScopes=@($Scopes)
    $tid=if($m.Fail -eq 'wrong-tenant'){'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'}else{$TenantId}
    $m.Context=@{TenantId=$tid;Scopes=$Scopes;ContextScope=$ContextScope;Environment=$Environment;AuthType='Delegated';Account='fixture'}
}
function Set-MgRequestContext {[CmdletBinding()]param($MaxRetry) $global:AssessmentMock.MaxRetry=$MaxRetry}
function Invoke-MgGraphRequest {
    [CmdletBinding()]param($Method,$Uri,$Body,$ContentType,$OutputType)
    $m=$global:AssessmentMock;$u=[uri]$Uri;$path=$u.AbsolutePath.Replace('/v1.0','');$query=[uri]::UnescapeDataString($u.Query)
    if($Method -eq 'GET'){
        $m.Reads++
        if($m.Fail -eq 'read-error'){throw 'SENSITIVE_SENTINEL response body'}
        if($path -eq '/applications'){
            $m.LastFilter=$query
            if($query -match "appId eq '([^']+)'" ){$items=@($m.Apps | Where-Object {$_.appId -eq $Matches[1]})}
            elseif($query -match "displayName eq '((?:[^']|'')*)'" ){$name=$Matches[1].Replace("''", "'");$items=@($m.Apps | Where-Object {$_.displayName -ceq $name})}
            else{throw 'unexpected application filter'}
            return @{value=@($items | ForEach-Object {Copy-TestValue $_})}
        }
        if($path -like '/applications/*'){
            $id=$path.Split('/')[-1];$app=@($m.Apps | Where-Object {$_.id -eq $id})
            if($app.Count -ne 1){throw 'missing-app'}
            $m.GetAppCount++
            $result=Copy-TestValue $app[0]
            if($m.Fail -eq 'unreadable-key'){$result.keyCredentials[0].key=$null}
            if($m.Fail -eq 'concurrent' -and $m.GetAppCount -eq 2){$result.displayName='Concurrent change'}
            return $result
        }
        if($path -eq '/servicePrincipals'){
            if($query.Contains('00000003-0000-0000-c000-000000000000')){
                $roles=if($m.Fail -eq 'missing-role'){@()}else{$m.Roles}
                return @{value=@(@{id='22222222-2222-2222-2222-222222222222';appId='00000003-0000-0000-c000-000000000000';appRoles=$roles})}
            }
            return @{value=@($m.Sps | ForEach-Object {Copy-TestValue $_})}
        }
        if($path -like '/servicePrincipals/*/appRoleAssignments'){return @{value=@($m.Grants | ForEach-Object {Copy-TestValue $_})}}
        throw 'unexpected GET route'
    }
    $payload=$Body | ConvertFrom-Json -AsHashtable
    if($m.Fail -eq 'partial-grant' -and $path -like '*/appRoleAssignments' -and $m.Grants.Count -eq 1){throw 'SENSITIVE_SENTINEL grant response'}
    $m.Writes+=@{method=$Method;path=$path;body=(Copy-TestValue $payload)}
    if($Method -eq 'POST' -and $path -eq '/applications'){
        $app=Copy-TestValue $payload;$app.id='33333333-3333-3333-3333-333333333333';$app.appId='44444444-4444-4444-4444-444444444444'
        foreach($key in $app.keyCredentials){$key.keyId=[guid]::NewGuid().ToString()}
        $m.Apps+=,$app
        if($m.Fail -eq 'lost-create-response'){throw 'SENSITIVE_SENTINEL network failure'}
        return Copy-TestValue $app
    }
    if($Method -eq 'PATCH' -and $path -like '/applications/*'){
        foreach($field in $payload.Keys){$m.Apps[0][$field]=$payload[$field]}
        foreach($key in $m.Apps[0].keyCredentials){if(-not $key['keyId']){$key.keyId=[guid]::NewGuid().ToString()}}
        return $null
    }
    if($Method -eq 'POST' -and $path -eq '/servicePrincipals'){
        $sp=@{id='55555555-5555-5555-5555-555555555555';appId=$payload.appId};$m.Sps+=,$sp;return Copy-TestValue $sp
    }
    if($Method -eq 'POST' -and $path -like '*/appRoleAssignments'){
        $payload.id=[guid]::NewGuid().ToString();$m.Grants+=,$payload;return Copy-TestValue $payload
    }
    throw 'unexpected write route'
}
function Save-Config([string]$Name,$Certs=$script:firstCert,[string[]]$Roles=@('AuditLog.Read.All','Directory.Read.All'),[string]$AppId='', [string]$DisplayName='Example Assessment'){
    $dir=Join-Path $tempRoot $Name;$null=[IO.Directory]::CreateDirectory($dir)
    $config=@{tenant_id=$global:AssessmentMock.Tenant;display_name=$DisplayName;output_directory='output';certificates=@($Certs);engagement_reference='EXAMPLE'}
    if($Roles.Count -gt 0){@{application_permissions=@($Roles | ForEach-Object {@{name=$_;purpose='Offline test'}})} | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $dir 'profile.json');$config.permission_profile='profile.json'}
    if($AppId){$config.application_id=$AppId}
    $path=Join-Path $dir 'config.json';$config | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path
    $path
}
function Invoke-Case([string]$Path,[string]$Mode='apply'){
    $invokeArguments=@{ConfigPath=$Path};if($Mode -eq 'apply'){$invokeArguments.Apply=$true};if($Mode -eq 'preview'){$invokeArguments.Preview=$true}
    $failure='';$result=$null
    try{$result=& $engine @invokeArguments}catch{$failure=$_.ToString()}
    Assert-Test (-not $failure.Contains('SENSITIVE_SENTINEL')) 'sanitized errors'
    @{error=$failure;result=$result}
}
try {
    $firstCert=New-PublicFixture 'first';$secondCert=New-PublicFixture 'second' -Number 165
    Reset-Mock
    $cfg=Save-Config 'normal'
    $r=Invoke-Case $cfg 'plan'
    if ($r.error) { Write-Warning ('Offline fixture diagnostic: ' + $r.error) }
    Assert-Test (-not $r.error -and $r.result.status -eq 'planned' -and $global:AssessmentMock.Connects -eq 0) 'offline plan'
    $r=Invoke-Case $cfg 'preview';Assert-Test (-not $r.error -and $global:AssessmentMock.Writes.Count -eq 0) 'read-only preview'
    $r=Invoke-Case $cfg;Assert-Test (-not $r.error -and $r.result.mutations -eq 4) 'first create app SP two grants'
    Assert-Test ($global:AssessmentMock.MaxRetry -eq 0) 'SDK write retry disabled'
    $before=$global:AssessmentMock.Writes.Count;$r=Invoke-Case $cfg
    Assert-Test (-not $r.error -and $r.result.mutations -eq 0 -and $global:AssessmentMock.Writes.Count -eq $before) 'same config makes zero changes'
    $old=Copy-TestValue $global:AssessmentMock.Apps[0].keyCredentials[0]
    $global:AssessmentMock.Apps[0].requiredResourceAccess+=@{resourceAppId='99999999-9999-9999-9999-999999999999';resourceAccess=@(@{id='88888888-8888-8888-8888-888888888888';type='Scope'})}
    $global:AssessmentMock.Apps[0].requiredResourceAccess[0].resourceAccess+=@{id='77777777-7777-7777-7777-777777777777';type='Scope'}
    $global:AssessmentMock.Grants+=@{id='unrelated';principalId=$global:AssessmentMock.Sps[0].id;resourceId='99999999-9999-9999-9999-999999999999';appRoleId='88888888-8888-8888-8888-888888888888'}
    $certOnly=Save-Config 'cert-only' -Certs $secondCert -Roles @() -AppId $global:AssessmentMock.Apps[0].appId
    $before=$global:AssessmentMock.Writes.Count;$r=Invoke-Case $certOnly
    Assert-Test (-not $r.error -and $r.result.mutations -eq 1 -and $global:AssessmentMock.Writes.Count -eq $before+1) 'add certificate makes one write'
    $write=$global:AssessmentMock.Writes[-1]
    Assert-Test ($write.method -eq 'PATCH' -and $write.body.Keys.Count -eq 1 -and $write.body.Contains('keyCredentials')) 'certificate patch changes only keyCredentials'
    Assert-Test ($global:AssessmentMock.Apps[0].keyCredentials.Count -eq 2 -and $global:AssessmentMock.Apps[0].keyCredentials[0].keyId -eq $old.keyId -and $global:AssessmentMock.Apps[0].keyCredentials[0].key -eq $old.key) 'existing certificate preserved'
    Assert-Test ($global:AssessmentMock.Apps[0].requiredResourceAccess.Count -eq 2 -and $global:AssessmentMock.Grants.Count -eq 3) 'unrelated requested access and grants preserved'
    Assert-Test ($global:AssessmentMock.LastScopes.Count -eq 1 -and $global:AssessmentMock.LastScopes[0] -eq 'Application.ReadWrite.All') 'certificate-only scopes'
    Assert-Test (@($global:AssessmentMock.Apps[0].requiredResourceAccess[0].resourceAccess | Where-Object {$_.type -eq 'Scope'}).Count -eq 1) 'existing delegated Graph scope preserved'
    $r=Invoke-Case $certOnly;Assert-Test (-not $r.error -and $r.result.mutations -eq 0) 'certificate rerun no-op'
    $expanded=Save-Config 'expanded' -Certs @() -Roles @('AuditLog.Read.All','Directory.Read.All','Policy.Read.All') -AppId $global:AssessmentMock.Apps[0].appId
    $r=Invoke-Case $expanded;Assert-Test (-not $r.error -and $r.result.mutations -eq 2) 'expanded profile patches and grants only missing role'
    Assert-Test ($global:AssessmentMock.Apps[0].keyCredentials.Count -eq 2 -and $global:AssessmentMock.Grants.Count -eq 4 -and $global:AssessmentMock.Apps[0].requiredResourceAccess.Count -eq 2) 'expanded profile preserves existing state'
    $smaller=Save-Config 'smaller' -Certs @() -Roles @('AuditLog.Read.All') -AppId $global:AssessmentMock.Apps[0].appId
    $r=Invoke-Case $smaller;Assert-Test (-not $r.error -and $r.result.mutations -eq 0 -and $global:AssessmentMock.Grants.Count -eq 4) 'smaller profile never prunes'
    $unknown=Save-Config 'unknown-name';$before=$global:AssessmentMock.Writes.Count;$r=Invoke-Case $unknown
    Assert-Test ($r.error -and $global:AssessmentMock.Writes.Count -eq $before) 'unknown duplicate refuses adoption'
    foreach($problem in @('unreadable-key','concurrent')){
        $global:AssessmentMock.Fail=$problem;$global:AssessmentMock.GetAppCount=0
        $other=New-PublicFixture $problem -Number 167
        $path=Save-Config $problem -Certs $other -Roles @() -AppId $global:AssessmentMock.Apps[0].appId
        $before=$global:AssessmentMock.Writes.Count;$r=Invoke-Case $path
        Assert-Test ($r.error -and $global:AssessmentMock.Writes.Count -eq $before) "$problem prevents writes"
    }
    $seed=Copy-TestValue $global:AssessmentMock.Apps[0]
    Reset-Mock;$global:AssessmentMock.Apps=@($seed)
    $thirdCert=New-PublicFixture 'third' -Number 171
    $withoutSp=Save-Config 'without-sp' -Certs $thirdCert -Roles @() -AppId $seed.appId
    $r=Invoke-Case $withoutSp
    Assert-Test (-not $r.error -and $r.result.mutations -eq 1 -and $global:AssessmentMock.Sps.Count -eq 0 -and $global:AssessmentMock.Grants.Count -eq 0) 'certificate-only does not create service principal or grants'
    $r=Invoke-Case $withoutSp;Assert-Test (-not $r.error -and $r.result.mutations -eq 0) 'certificate-only without service principal no-op'
    foreach($problem in @('wrong-tenant','read-error','missing-role')){
        Reset-Mock;$global:AssessmentMock.Fail=$problem;$r=Invoke-Case (Save-Config $problem)
        Assert-Test ($r.error -and $global:AssessmentMock.Writes.Count -eq 0) "$problem fails before writes"
    }
    Reset-Mock;$global:AssessmentMock.Fail='partial-grant';$partial=Save-Config 'partial';$r=Invoke-Case $partial
    Assert-Test ($r.error -and $global:AssessmentMock.Apps.Count -eq 1 -and $global:AssessmentMock.Sps.Count -eq 1 -and $global:AssessmentMock.Grants.Count -eq 1) 'partial grant receipt state'
    $global:AssessmentMock.Fail='';$before=$global:AssessmentMock.Writes.Count;$r=Invoke-Case $partial
    Assert-Test (-not $r.error -and $r.result.mutations -eq 1 -and $global:AssessmentMock.Writes.Count -eq $before+1) 'resume only missing grant'
    $config=Get-Content -LiteralPath $partial -Raw | ConvertFrom-Json -AsHashtable;$config.tenant_id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';$config | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $partial
    $before=$global:AssessmentMock.Connects;$r=Invoke-Case $partial;Assert-Test ($r.error -and $global:AssessmentMock.Connects -eq $before) 'receipt tenant conflict rejected offline'
    Reset-Mock;$global:AssessmentMock.Fail='lost-create-response';$lost=Save-Config 'lost';$r=Invoke-Case $lost
    Assert-Test ($r.error -and $global:AssessmentMock.Apps.Count -eq 1) 'lost create response keeps uncertain receipt'
    $global:AssessmentMock.Fail='';$before=$global:AssessmentMock.Writes.Count;$r=Invoke-Case $lost
    Assert-Test ($r.error -and $global:AssessmentMock.Writes.Count -eq $before) 'lost create is never blindly retried'
    $config=Get-Content -LiteralPath $lost -Raw | ConvertFrom-Json -AsHashtable;$config.application_id=$global:AssessmentMock.Apps[0].appId;$config | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $lost
    $r=Invoke-Case $lost;Assert-Test (-not $r.error -and $r.result.mutations -eq 3) 'explicit ID recovers lost create response'
    foreach($bad in @('Mail.Read','Application.ReadWrite.All','BitlockerKey.Read.All','DeviceLocalCredential.Read.All')){
        Reset-Mock;$r=Invoke-Case (Save-Config ($bad.Replace('.','-')) -Roles @($bad));Assert-Test ($r.error -and $global:AssessmentMock.Connects -eq 0) "$bad rejected offline"
    }
    foreach($case in @(@{name='expired';start=-30;end=-1;bits=2048},@{name='future';start=1;end=30;bits=2048},@{name='long';start=-1;end=91;bits=2048},@{name='weak';start=-1;end=29;bits=1024})){
        Reset-Mock;$bad=New-PublicFixture $case.name -Bits $case.bits -Start $case.start -End $case.end
        $r=Invoke-Case (Save-Config $case.name -Certs $bad);Assert-Test ($r.error -and $global:AssessmentMock.Connects -eq 0) "$($case.name) certificate rejected"
    }
    Reset-Mock;$a=Save-Config 'customer-a' -DisplayName 'Example A Assessment';$r=Invoke-Case $a 'plan';Assert-Test (-not $r.error) 'first customer plan'
    $global:AssessmentMock.Tenant='bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';$b=Save-Config 'customer-b' -DisplayName 'Example B Assessment';$r=Invoke-Case $b 'plan';Assert-Test (-not $r.error -and $global:AssessmentMock.Connects -eq 0) 'second independent customer plan'
    $pa=Get-Content -LiteralPath (Join-Path (Split-Path $a) 'output/plan.json') -Raw | ConvertFrom-Json
    $pb=Get-Content -LiteralPath (Join-Path (Split-Path $b) 'output/plan.json') -Raw | ConvertFrom-Json
    Assert-Test ($pa.tenant_id -ne $pb.tenant_id -and $pa.display_name -ne $pb.display_name) 'customer identifiers stay separate'
    foreach($name in @("bad`nname","bad`tname","bad$([char]0x202e)name",' padded',('x'*121))){Reset-Mock;$r=Invoke-Case (Save-Config ([guid]::NewGuid().ToString('N')) -DisplayName $name);Assert-Test ($r.error -and $global:AssessmentMock.Connects -eq 0) 'unsafe display name rejected'}
    Reset-Mock;$quoted="Example's app' or startswith(displayName,'x";$r=Invoke-Case (Save-Config 'quoted' -DisplayName $quoted) 'preview'
    Assert-Test (-not $r.error -and $global:AssessmentMock.LastFilter.Contains($quoted.Replace("'","''"))) 'OData name quotes escaped'
    Assert-Test ($global:AssessmentMock.LastScopes.Count -eq 1 -and $global:AssessmentMock.LastScopes[0] -eq 'Application.Read.All') 'preview uses read-only delegated scope'
    # Relative paths and paths with spaces resolve against the configuration file.
    Reset-Mock;$relative=Save-Config 'relative paths'
    $dir=Split-Path $relative;$assets=Join-Path $dir 'input files';$null=[IO.Directory]::CreateDirectory($assets)
    Copy-Item -LiteralPath $firstCert.path -Destination (Join-Path $assets 'public cert.cer')
    Move-Item -LiteralPath (Join-Path $dir 'profile.json') -Destination (Join-Path $assets 'permission profile.json')
    $config=Get-Content -LiteralPath $relative -Raw | ConvertFrom-Json -AsHashtable
    $config.certificates[0].path='input files/public cert.cer';$config.permission_profile='input files/permission profile.json';$config.output_directory='output files'
    $config.Remove('engagement_reference');$config | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $relative
    $r=Invoke-Case $relative 'plan'
    Assert-Test (-not $r.error -and [IO.File]::Exists((Join-Path $dir 'output files/plan.json'))) 'relative paths and omitted optional reference'
    # Absolute certificate, profile and output paths must remain absolute.
    $config.certificates[0].path=Join-Path $assets 'public cert.cer';$config.permission_profile=Join-Path $assets 'permission profile.json';$config.output_directory=Join-Path $tempRoot 'absolute output files'
    $config | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $relative
    $r=Invoke-Case $relative 'plan'
    Assert-Test (-not $r.error -and [IO.File]::Exists((Join-Path $config.output_directory 'plan.json'))) 'absolute paths preserved'
    $config.Remove('certificates');$config.application_id='44444444-4444-4444-4444-444444444444';$config | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $relative
    $r=Invoke-Case $relative 'plan';Assert-Test (-not $r.error) 'profile-only explicit ID with omitted certificate list'
    foreach($profileName in @('allcaps-mfa.json','assessment-read.json')){
        $config.permission_profile=Join-Path (Split-Path $PSScriptRoot -Parent) ('profiles/'+$profileName)
        $config | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $relative
        $r=Invoke-Case $relative 'plan';Assert-Test (-not $r.error) "reviewed profile $profileName accepted"
    }
    [pscustomobject]@{status='passed';assertions=$checks;network_calls=0;generated_keys=0;private_key_files=0}
} finally {Remove-Item -LiteralPath $tempRoot -Recurse -Force;Remove-Variable AssessmentMock -Scope Global}
