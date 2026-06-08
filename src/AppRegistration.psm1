<#
.SYNOPSIS
    Entra app-registration creation, cert attachment, consent, and teardown (FR 12-15).

.DESCRIPTION
    Splits each tenant operation into a PURE payload-builder (testable off-host,
    no Graph SDK, no tenant) and a THIN Graph-invoking wrapper that calls the
    Microsoft.Graph PowerShell SDK. Tier-A tests target the builders; the wrappers
    run only in the live integration tier.

    Pure builders:
      * New-DiscoveryKeyCredential         - keyCredential from a public .cer (FR 12)
      * New-DiscoveryAppPayload            - full New-MgApplication body (FR 12)
      * New-DiscoveryAppDisplayName        - naming incl. zzTEST-DiscoveryApp-<ts> (3.5)

    Graph wrappers (lazy SDK import; honour ShouldProcess via -WhatIf passthrough):
      * Connect-DiscoveryGraph             - ensure connected with required scopes
      * New-DiscoveryAppRegistration       - create app + SP, embed cert (FR 12)
      * Add-DiscoveryAppCredential         - attach cert to an existing app (FR 13)
      * Grant-DiscoveryAdminConsent        - app-role assignments on the SP (FR 14)
      * Remove-DiscoveryAppRegistration    - teardown app + SP (3.5)

    The Microsoft.Graph SDK is imported LAZILY inside each wrapper (not at module
    load) so this module imports and its builders unit-test on macOS PowerShell 7
    with no SDK installed and no tenant reachable.

    Cross-compatible with Windows PowerShell 5.1 (Desktop) and PowerShell 7.x (Core).

    ---------------------------------------------------------------------------
    TENANT-WRITE SURFACE (FR 22 — auditable from source)
    ---------------------------------------------------------------------------
    The COMPLETE set of tenant-mutating Graph calls this module can make, and the
    operator-selected switch that gates each. NOTHING here runs unless the operator
    opted in via the corresponding entry-script switch, and EVERY write is gated by
    ShouldProcess so -WhatIf performs no write:

      Graph write cmdlet                       | Wrapper                        | Gating entry-script switch
      -----------------------------------------|--------------------------------|---------------------------------
      New-MgApplication                        | New-DiscoveryAppRegistration   | -CreateAppRegistration
      New-MgServicePrincipal                   | New-DiscoveryAppRegistration   | -CreateAppRegistration (post-create)
      Update-MgApplication (add keyCredential) | Add-DiscoveryAppCredential     | -AppObjectId
      New-MgServicePrincipalAppRoleAssignment  | Grant-DiscoveryAdminConsent    | -GrantConsent
      Remove-MgServicePrincipal                | Remove-DiscoveryAppRegistration| (teardown — integration tier only)
      Remove-MgApplication                     | Remove-DiscoveryAppRegistration| (teardown — integration tier only)

    Connect-DiscoveryGraph performs an interactive sign-in only (no tenant write)
    and requests ONLY the minimum scopes: Application.ReadWrite.All,
    AppRoleAssignment.ReadWrite.All, Directory.Read.All (no broader write scope).
    All Get-Mg* reads are non-mutating. No other tenant-write cmdlet is invoked.
    ---------------------------------------------------------------------------
#>

Set-StrictMode -Version Latest

# Imported WITHOUT -Force: these provide helpers (New-DiscoveryResult,
# Get-DiscoveryRequiredResourceAccess) used internally. Using -Force here would
# re-import the dependency into THIS module's scope and remove its session-level
# exports, shadowing the caller's view of those functions. A plain Import-Module
# is a no-op if the module is already loaded, which is exactly what we want.
Import-Module "$PSScriptRoot/Common.psm1"
Import-Module "$PSScriptRoot/Manifest.psm1"

# Default display name for the discovery app registration.
$script:DefaultDisplayName = 'Proaxiom Phase 1 Discovery'

# Scopes the PROVISIONER must consent to (delegated/interactive) to do this work.
$script:RequiredProvisionerScopes = @(
    'Application.ReadWrite.All',
    'AppRoleAssignment.ReadWrite.All',
    'Directory.Read.All'
)

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

function Test-DiscoveryTransientGraphError {
    <#
    .SYNOPSIS
        Classifies a Graph error as transient (retry) vs permanent (fail fast).

    .DESCRIPTION
        Pure classifier (no Graph SDK, no tenant) used by Invoke-DiscoveryGraphWithRetry.
        Returns $true ONLY for conditions consistent with Entra eventual-consistency /
        replication lag or short-lived service pushback that a bounded retry can clear:

          * 'does not reference a valid application object'  (the canonical SP-create
            replication-lag failure: the freshly-created app is not yet visible)
          * 'Request_BadRequest' Graph error code (the wrapper Entra returns for the
            replication-lag case above)
          * HTTP 404 / 'ResourceNotFound' / 'Request_ResourceNotFound' on a
            just-created object that has not replicated yet
          * HTTP 429 (throttling / 'TooManyRequests') and 503/504
            ('ServiceUnavailable' / 'GatewayTimeout' / 'serviceNotAvailable')

        Returns $false for clear PERMANENT errors so we never burn the budget on them:

          * HTTP 401 / 403 and authorization codes
            ('Authorization_RequestDenied', 'Authentication_*', 'InvalidAuthenticationToken',
            'Forbidden', 'Unauthorized') — a missing permission must STOP, not retry.

        Authz wins over the BadRequest/NotFound heuristics: if the message looks like an
        authz failure it is treated as permanent even if it also contains other tokens.

    .PARAMETER ErrorRecord
        The caught error: an [System.Management.Automation.ErrorRecord], an [Exception],
        or any object whose string form carries the Graph message/status. Required.

    .OUTPUTS
        System.Boolean ($true = transient/retry, $false = permanent/fail).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $ErrorRecord
    )

    if ($null -eq $ErrorRecord) {
        return $false
    }

    # Build a single haystack from every place Graph stashes the message / status.
    $parts = New-Object System.Collections.Generic.List[string]
    $parts.Add([string]$ErrorRecord)
    if ($ErrorRecord.PSObject.Properties.Match('Exception').Count -gt 0 -and $null -ne $ErrorRecord.Exception) {
        $parts.Add([string]$ErrorRecord.Exception.Message)
        # Mg* cmdlets often surface a response status on the exception.
        foreach ($p in @('Response', 'StatusCode', 'HttpStatusCode')) {
            if ($ErrorRecord.Exception.PSObject.Properties.Match($p).Count -gt 0) {
                $parts.Add([string]$ErrorRecord.Exception.$p)
            }
        }
    }
    if ($ErrorRecord.PSObject.Properties.Match('Message').Count -gt 0) {
        $parts.Add([string]$ErrorRecord.Message)
    }
    if ($ErrorRecord.PSObject.Properties.Match('FullyQualifiedErrorId').Count -gt 0) {
        $parts.Add([string]$ErrorRecord.FullyQualifiedErrorId)
    }
    if ($ErrorRecord.PSObject.Properties.Match('ErrorDetails').Count -gt 0 -and $null -ne $ErrorRecord.ErrorDetails) {
        $parts.Add([string]$ErrorRecord.ErrorDetails.Message)
    }

    $haystack = ($parts -join ' ')

    # PERMANENT first — authz must never be retried, even if other tokens co-occur.
    $permanentPatterns = @(
        'Authorization_RequestDenied',
        'Authentication_',
        'InvalidAuthenticationToken',
        'Insufficient privileges',
        '\bForbidden\b',
        '\bUnauthorized\b',
        '\b401\b',
        '\b403\b'
    )
    foreach ($pat in $permanentPatterns) {
        if ($haystack -match $pat) {
            return $false
        }
    }

    # TRANSIENT — replication lag and short-lived service pushback.
    $transientPatterns = @(
        'does not reference a valid application object',
        'Request_BadRequest',
        'Request_ResourceNotFound',
        'ResourceNotFound',
        'serviceNotAvailable',
        'ServiceUnavailable',
        'GatewayTimeout',
        'TooManyRequests',
        '\b404\b',
        '\b429\b',
        '\b503\b',
        '\b504\b'
    )
    foreach ($pat in $transientPatterns) {
        if ($haystack -match $pat) {
            return $true
        }
    }

    return $false
}

function Invoke-DiscoveryGraphWithRetry {
    <#
    .SYNOPSIS
        Runs a Graph scriptblock with bounded retry on transient (replication-lag)
        failures.

    .DESCRIPTION
        Wraps the primary Entra write paths (service-principal creation, post-create
        consent lookups + app-role assignments) so a freshly-created object that has
        not yet replicated is retried rather than failing the whole run. Only errors
        classified transient by Test-DiscoveryTransientGraphError are retried; clear
        permanent errors (401/403 authz, unrelated validation) re-throw immediately.

        Bounded and fail-closed: at most -MaxAttempts tries with incremental backoff
        (2s, 3s, 5s, 8s, … capped at -MaxDelaySeconds), never an infinite loop. The
        last error is always re-thrown if the budget is exhausted.

    .PARAMETER ScriptBlock
        The Graph operation to run (e.g. { New-MgServicePrincipal -AppId $id }).

    .PARAMETER OperationName
        Human-readable name for log/throw messages (e.g. 'service-principal creation').

    .PARAMETER MaxAttempts
        Maximum attempts including the first. Default 8 (~45s total worst case).

    .PARAMETER MaxDelaySeconds
        Cap on a single backoff sleep. Default 13.

    .OUTPUTS
        Whatever the scriptblock returns.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [scriptblock]$ScriptBlock,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$OperationName = 'Graph operation',

        [Parameter()]
        [ValidateRange(1, 50)]
        [int]$MaxAttempts = 8,

        [Parameter()]
        [ValidateRange(1, 120)]
        [int]$MaxDelaySeconds = 13
    )

    # Incremental backoff schedule (Fibonacci-ish), capped at MaxDelaySeconds.
    $delays = @(2, 3, 5, 8, 13, 21, 34, 55)

    $attempt = 0
    $lastError = $null

    while ($attempt -lt $MaxAttempts) {
        $attempt++
        try {
            return & $ScriptBlock
        }
        catch {
            $lastError = $_

            if (-not (Test-DiscoveryTransientGraphError -ErrorRecord $_)) {
                # Permanent: do not burn the budget — re-throw immediately.
                throw
            }

            if ($attempt -ge $MaxAttempts) {
                # Budget exhausted on a transient error — re-throw with context below.
                break
            }

            $idx = $attempt - 1
            if ($idx -ge $delays.Count) { $idx = $delays.Count - 1 }
            $sleep = $delays[$idx]
            if ($sleep -gt $MaxDelaySeconds) { $sleep = $MaxDelaySeconds }

            Write-Verbose ("$OperationName attempt $attempt/$MaxAttempts failed with a transient Graph error " +
                           "(likely replication lag); retrying in ${sleep}s. Detail: " + [string]$_)
            Start-Sleep -Seconds $sleep
        }
    }

    $detail = ''
    if ($null -ne $lastError) { $detail = [string]$lastError }
    throw ("$OperationName did not succeed after $MaxAttempts attempts (transient Graph errors " +
           "persisted beyond the retry budget). Last error: $detail")
}

function Test-DiscoveryNotFoundGraphError {
    <#
    .SYNOPSIS
        Classifies a Graph error as "the target object is already gone" (404 /
        ResourceNotFound) for the DELETE path.

    .DESCRIPTION
        Pure classifier (no Graph SDK, no tenant). For a DELETE, a 404 /
        'ResourceNotFound' / 'Request_ResourceNotFound' means the object is already
        absent, which is SUCCESS for an idempotent teardown -- NOT something to retry
        or to fail on. (Note: Test-DiscoveryTransientGraphError deliberately treats
        404 as transient because for CREATE/RESOLVE right after creation a 404 is
        replication lag; on the DELETE path the opposite is true, hence this distinct
        classifier that is consulted FIRST in the delete helper.)

        Returns $true ONLY for the not-found family. Authorization failures (401/403)
        and any other error return $false so the caller can retry-or-throw them.

    .PARAMETER ErrorRecord
        The caught error (ErrorRecord, Exception, or any object whose string form
        carries the Graph message/status). Required.

    .OUTPUTS
        System.Boolean ($true = already gone / treat delete as success).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $ErrorRecord
    )

    if ($null -eq $ErrorRecord) {
        return $false
    }

    # Build a single haystack from every place Graph stashes the message / status
    # (mirrors Test-DiscoveryTransientGraphError so both classifiers see the same text).
    $parts = New-Object System.Collections.Generic.List[string]
    $parts.Add([string]$ErrorRecord)
    if ($ErrorRecord.PSObject.Properties.Match('Exception').Count -gt 0 -and $null -ne $ErrorRecord.Exception) {
        $parts.Add([string]$ErrorRecord.Exception.Message)
        foreach ($p in @('Response', 'StatusCode', 'HttpStatusCode')) {
            if ($ErrorRecord.Exception.PSObject.Properties.Match($p).Count -gt 0) {
                $parts.Add([string]$ErrorRecord.Exception.$p)
            }
        }
    }
    if ($ErrorRecord.PSObject.Properties.Match('Message').Count -gt 0) {
        $parts.Add([string]$ErrorRecord.Message)
    }
    if ($ErrorRecord.PSObject.Properties.Match('FullyQualifiedErrorId').Count -gt 0) {
        $parts.Add([string]$ErrorRecord.FullyQualifiedErrorId)
    }
    if ($ErrorRecord.PSObject.Properties.Match('ErrorDetails').Count -gt 0 -and $null -ne $ErrorRecord.ErrorDetails) {
        $parts.Add([string]$ErrorRecord.ErrorDetails.Message)
    }

    $haystack = ($parts -join ' ')

    # Authz never counts as "already gone" -- a 403 on delete is a real failure.
    $authzPatterns = @(
        'Authorization_RequestDenied',
        'Authentication_',
        'InvalidAuthenticationToken',
        'Insufficient privileges',
        '\bForbidden\b',
        '\bUnauthorized\b',
        '\b401\b',
        '\b403\b'
    )
    foreach ($pat in $authzPatterns) {
        if ($haystack -match $pat) {
            return $false
        }
    }

    $notFoundPatterns = @(
        'Request_ResourceNotFound',
        'ResourceNotFound',
        '\b404\b'
    )
    foreach ($pat in $notFoundPatterns) {
        if ($haystack -match $pat) {
            return $true
        }
    }

    return $false
}

function Invoke-DiscoveryGraphDelete {
    <#
    .SYNOPSIS
        Runs a Graph DELETE scriptblock idempotently: 404/ResourceNotFound is treated
        as SUCCESS (already gone); other transient errors are retried; permanent
        errors (e.g. 403 authz) throw.

    .DESCRIPTION
        Teardown must be idempotent and robust against a transient Graph delete quirk
        where Remove-Mg* can return 404/Request_ResourceNotFound for an object that
        still exists (or has just been removed). For a DELETE:

          * 404 / ResourceNotFound  -> already gone, return SUCCESS (do NOT retry,
            do NOT throw). This is checked FIRST, so the not-found case never burns the
            retry budget (Test-DiscoveryTransientGraphError treats 404 as transient,
            which is correct for create/resolve but wrong for delete).
          * other transient errors  -> retried with bounded incremental backoff
            (Test-DiscoveryTransientGraphError, minus the 404 family handled above).
          * permanent errors (403 authz, etc.) -> thrown clearly.

        This uses its own bounded retry loop (rather than Invoke-DiscoveryGraphWithRetry)
        so the 404 family can be reclassified as success per-attempt without the
        transient classifier looping on it.

        Returns $true when the delete succeeded OR the object was already absent.

    .PARAMETER ScriptBlock
        The delete operation (e.g. { Remove-MgApplication -ApplicationId $id -ErrorAction Stop }).

    .PARAMETER OperationName
        Human-readable name for log/throw messages.

    .OUTPUTS
        System.Boolean ($true = removed or already absent).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [scriptblock]$ScriptBlock,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$OperationName = 'Graph delete'
    )

    # Bounded incremental backoff, mirroring Invoke-DiscoveryGraphWithRetry's schedule
    # (kept self-contained so the 404-as-success reclassification happens per attempt
    # without the transient classifier looping on a 404). Capped at MaxDelaySeconds.
    $maxAttempts     = 8
    $maxDelaySeconds = 13
    $delays          = @(2, 3, 5, 8, 13, 21, 34, 55)

    $attempt   = 0
    $lastError = $null

    while ($attempt -lt $maxAttempts) {
        $attempt++
        try {
            & $ScriptBlock | Out-Null
            return $true
        }
        catch {
            $lastError = $_

            # 404 / ResourceNotFound on a DELETE means already gone -> success.
            # Checked FIRST so a 404 is never retried (the transient classifier would).
            if (Test-DiscoveryNotFoundGraphError -ErrorRecord $_) {
                Write-Verbose ("${OperationName}: target already absent (404/ResourceNotFound) -- treating as success.")
                return $true
            }

            # Non-404 permanent error (e.g. 403 authz) -> fail fast.
            if (-not (Test-DiscoveryTransientGraphError -ErrorRecord $_)) {
                throw
            }

            if ($attempt -ge $maxAttempts) {
                break
            }

            $idx = $attempt - 1
            if ($idx -ge $delays.Count) { $idx = $delays.Count - 1 }
            $sleep = $delays[$idx]
            if ($sleep -gt $maxDelaySeconds) { $sleep = $maxDelaySeconds }

            Write-Verbose ("${OperationName} attempt $attempt/$maxAttempts failed with a transient Graph error; " +
                           "retrying in ${sleep}s. Detail: " + [string]$_)
            Start-Sleep -Seconds $sleep
        }
    }

    $detail = ''
    if ($null -ne $lastError) { $detail = [string]$lastError }
    throw ("${OperationName} did not succeed after $maxAttempts attempts (transient Graph errors " +
           "persisted beyond the retry budget). Last error: $detail")
}

function Assert-GraphModuleAvailable {
    <#
    .SYNOPSIS
        Lazily ensures the required Microsoft.Graph sub-modules are importable.

    .DESCRIPTION
        Called only inside Graph wrappers (never at module load) so Tier-A imports
        succeed without the SDK. Throws a clear, actionable error if either the
        Applications or Authentication sub-module is not installed.

        Multi-version robustness: machines often have several Microsoft.Graph SDK
        versions side-by-side (e.g. Authentication 2.37.0 + 2.36.1 + 2.35.1,
        Applications 2.36.1 + 2.28). Two failure modes are avoided here:

          1. Re-importing an already-loaded module unversioned pulls the *newest on
             disk* alongside the loaded one, causing
             "Assembly with same name is already loaded". We therefore NEVER import
             a module that is already loaded (Get-Module -Name) — this also respects
             a caller that has pre-pinned a consistent version pair.

          2. Importing Authentication first (unversioned) grabs its newest (2.37.0),
             but Applications' newest (2.36.1) requires Authentication 2.36.1 — a
             mismatched pair whose cmdlets fail at call time. We instead import the
             higher-level Microsoft.Graph.Applications first: its module manifest
             declares and pulls its *matching* Authentication dependency, giving a
             consistent pair. Authentication is then imported explicitly only if it
             is somehow still not loaded.

    .OUTPUTS
        None.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()

    # Presence checks first: throw a clear, actionable error if either sub-module
    # is neither already loaded nor available on disk.
    $needed = @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Applications')
    foreach ($mod in $needed) {
        if (-not (Get-Module -Name $mod) -and -not (Get-Module -ListAvailable -Name $mod)) {
            throw ("Required module '$mod' is not installed. Install the Microsoft Graph PowerShell SDK: " +
                   "Install-Module Microsoft.Graph -Scope CurrentUser")
        }
    }

    # Import the higher-level module first (only if not already loaded). Its
    # manifest pulls a matching Authentication dependency — avoiding a
    # newest-Authentication-vs-older-Applications mismatch.
    if (-not (Get-Module -Name 'Microsoft.Graph.Applications')) {
        Import-Module Microsoft.Graph.Applications -ErrorAction Stop
    }

    # Normally already loaded as Applications' dependency; import explicitly only
    # if still missing. Never re-import an already-loaded module.
    if (-not (Get-Module -Name 'Microsoft.Graph.Authentication')) {
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    }
}

# ---------------------------------------------------------------------------
# Pure payload builders (Tier-A testable)
# ---------------------------------------------------------------------------

function New-DiscoveryAppDisplayName {
    <#
    .SYNOPSIS
        Builds the app-registration display name, with optional test-naming (3.5).

    .DESCRIPTION
        Returns the production display name by default. With -Test, returns the
        integration-tier convention 'zzTEST-DiscoveryApp-<timestamp>' so test apps
        are obvious in the tenant and easy to find for teardown. The timestamp is
        UTC, format yyyyMMddHHmmss, unless an explicit -Timestamp is supplied.

    .PARAMETER BaseName
        Base display name for production. Default: 'Proaxiom Phase 1 Discovery'.

    .PARAMETER Test
        Emit the 'zzTEST-DiscoveryApp-<timestamp>' test naming instead.

    .PARAMETER Timestamp
        Explicit timestamp string for the test name (else UTC now). Test-only.

    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$BaseName = $script:DefaultDisplayName,

        [switch]$Test,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Timestamp
    )

    if (-not $Test) {
        return $BaseName
    }

    if ([string]::IsNullOrWhiteSpace($Timestamp)) {
        $Timestamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss')
    }

    "zzTEST-DiscoveryApp-$Timestamp"
}

function Resolve-DiscoveryAppCreateAction {
    <#
    .SYNOPSIS
        Decides whether to CREATE a new app or BLOCK on a name collision (FR 20).

    .DESCRIPTION
        Idempotency guard for app creation. A prior live run created duplicate apps
        because nothing checked for an existing app of the same display name. This
        PURE resolver (no Graph SDK, no tenant — fully Tier-A testable) takes the
        desired display name and the set of apps that already exist in the tenant,
        and returns a decision:

          * No existing app matches the display name              -> Action 'Create'.
          * One or more apps match the name AND -Force not set     -> Action 'Blocked',
            with an actionable Message naming each matching AppId / ObjectId and the
            ways forward (attach to it, pick a new name, use test naming, or force a
            deliberate duplicate).
          * One or more apps match the name AND -Force set         -> Action 'Create'
            (the operator deliberately wants a duplicate).

        Match is a case-insensitive exact comparison on DisplayName (Entra app
        display names are not unique, so a collision is "same name", not "same app").

    .PARAMETER DisplayName
        The desired display name for the new app registration. Required.

    .PARAMETER ExistingApp
        The apps already present in the tenant (e.g. from
        Get-MgApplication -Filter "displayName eq '...'"). Each item is expected to
        expose .DisplayName, .AppId, and .Id (object id). May be $null / empty.

    .PARAMETER Force
        Treat a name collision as an intentional duplicate: return 'Create' anyway.

    .OUTPUTS
        System.Collections.Hashtable with keys:
          Action  - 'Create' or 'Blocked'
          Matches - array of the matching existing apps (possibly empty)
          Message - human-readable explanation (actionable when Blocked)
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DisplayName,

        [Parameter()]
        [AllowNull()]
        [object[]]$ExistingApp,

        [switch]$Force
    )

    # Case-insensitive exact match on display name (Entra names are not unique).
    # NB: avoid the automatic $matches variable name; use $nameMatches.
    $nameMatches = @()
    if ($null -ne $ExistingApp) {
        $nameMatches = @($ExistingApp | Where-Object {
            $null -ne $_ -and
            $_.PSObject.Properties.Match('DisplayName').Count -gt 0 -and
            [string]$_.DisplayName -eq $DisplayName
        })
    }

    if ($nameMatches.Count -eq 0) {
        return @{
            Action  = 'Create'
            Matches = @()
            Message = "No existing application named '$DisplayName' found; creating a new app registration."
        }
    }

    # Build a "<AppId> (objectId <Id>)" descriptor for each collision.
    $descriptors = @($nameMatches | ForEach-Object {
        $appId    = if ($_.PSObject.Properties.Match('AppId').Count -gt 0) { [string]$_.AppId } else { '<unknown>' }
        $objectId = if ($_.PSObject.Properties.Match('Id').Count -gt 0)    { [string]$_.Id }    else { '<unknown>' }
        "AppId $appId (objectId $objectId)"
    })

    if ($Force) {
        return @{
            Action  = 'Create'
            Matches = $nameMatches
            Message = ("An application named '$DisplayName' already exists ({0}), but -ForceNewApp was specified; " +
                       'creating a deliberate duplicate.') -f ($descriptors -join '; ')
        }
    }

    $message = @(
        "An application named '$DisplayName' already exists in this tenant:"
        ($descriptors | ForEach-Object { "  - $_" })
        ''
        'Refusing to silently create a duplicate (FR 20). Choose one:'
        "  * Attach this cert to the existing app:  -AppObjectId $($nameMatches[0].Id)"
        '  * Create under a different name:          -DisplayName ''<new name>'''
        '  * Use a unique test name:                 -TestNaming'
        '  * Deliberately create a duplicate anyway: -ForceNewApp'
    ) -join [System.Environment]::NewLine

    @{
        Action  = 'Blocked'
        Matches = $nameMatches
        Message = $message
    }
}

function New-DiscoveryKeyCredential {
    <#
    .SYNOPSIS
        Builds a Graph keyCredential hashtable from a public certificate (FR 12).

    .DESCRIPTION
        Loads a public .cer (DER or PEM/base64) and produces the keyCredential
        object embedded at app creation or added to an existing app. Asserts the
        supplied cert has NO private key (a public cert is required). The `key`
        field is the raw DER cert bytes (what Graph expects for type
        'AsymmetricX509Cert', usage 'Verify').

        Pure: no Graph SDK, no tenant. Accepts either a path or a preloaded
        X509Certificate2.

    .PARAMETER Path
        Path to the public certificate (.cer / PEM / base64). Mutually exclusive
        with -Certificate.

    .PARAMETER Certificate
        A preloaded public X509Certificate2. Mutually exclusive with -Path.

    .OUTPUTS
        System.Collections.Hashtable (a single keyCredential).
    #>
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    [OutputType([hashtable])]
    param(
        [Parameter(ParameterSetName = 'Path', Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(ParameterSetName = 'Certificate', Mandatory)]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    # Use a local (the -Certificate param carries [ValidateNotNull], which would
    # re-trigger validation if we assigned $null to it under StrictMode).
    $cert = $null

    if ($PSCmdlet.ParameterSetName -eq 'Path') {
        if (-not (Test-Path -LiteralPath $Path)) {
            throw "Public certificate file not found: '$Path'."
        }

        # Attempt 1: DER/PEM .cer sniffed directly.
        try {
            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($Path)
        }
        catch {
            $cert = $null
        }

        # Attempt 2: base64 (possibly PEM-armoured) text.
        if ($null -eq $cert) {
            $raw = Get-Content -LiteralPath $Path -Raw
            $b64 = ($raw -replace '-----BEGIN [^-]+-----', '' -replace '-----END [^-]+-----', '')
            $b64 = ($b64 -replace '\s', '')
            if ([string]::IsNullOrWhiteSpace($b64)) {
                throw "Could not parse '$Path' as a certificate (empty after stripping armour)."
            }
            try {
                $bytes = [System.Convert]::FromBase64String($b64)
                $cert  = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes)
            }
            catch {
                throw "Could not parse '$Path' as a certificate (not valid DER and not valid base64)."
            }
        }
    }
    else {
        $cert = $Certificate
    }

    if ($null -eq $cert) {
        throw 'No certificate could be resolved for the keyCredential.'
    }

    if ($cert.HasPrivateKey) {
        throw 'The supplied certificate contains a private key. A PUBLIC certificate is required for the keyCredential.'
    }

    # GetRawCertData() returns the DER-encoded public certificate bytes.
    $rawBytes = $cert.GetRawCertData()

    @{
        type          = 'AsymmetricX509Cert'
        usage         = 'Verify'
        key           = $rawBytes
        displayName   = $cert.Subject
        startDateTime = $cert.NotBefore.ToUniversalTime()
        endDateTime   = $cert.NotAfter.ToUniversalTime()
    }
}

function New-DiscoveryAppPayload {
    <#
    .SYNOPSIS
        Builds the full New-MgApplication request body (FR 12).

    .DESCRIPTION
        Assembles the application-creation payload: displayName, signInAudience
        (single-tenant by default), the requiredResourceAccess built from the
        permission manifest, and the keyCredential embedded from the supplied
        public certificate (no separate upload step).

        Pure: no Graph SDK, no tenant. Either a cert -Path / -Certificate (built
        into a keyCredential here) OR a prebuilt -KeyCredential may be supplied.

    .PARAMETER DisplayName
        Application display name. Required.

    .PARAMETER CertPath
        Path to the public certificate to embed. One of CertPath/Certificate/
        KeyCredential is required.

    .PARAMETER Certificate
        Preloaded public certificate to embed.

    .PARAMETER KeyCredential
        A prebuilt keyCredential hashtable (from New-DiscoveryKeyCredential).

    .PARAMETER ManifestPath
        Path to the permission manifest CSV. Defaults to manifests/permissions.csv.

    .PARAMETER SignInAudience
        signInAudience value. Default 'AzureADMyOrg' (single tenant).

    .OUTPUTS
        System.Collections.Hashtable (the New-MgApplication body).
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DisplayName,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$CertPath,

        [Parameter()]
        [AllowNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter()]
        [AllowNull()]
        [hashtable]$KeyCredential,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ManifestPath,

        [Parameter()]
        [ValidateSet('AzureADMyOrg', 'AzureADMultipleOrgs', 'AzureADandPersonalMicrosoftAccount')]
        [string]$SignInAudience = 'AzureADMyOrg'
    )

    # Resolve the keyCredential from whichever input was supplied.
    $keyCred = $null
    if ($null -ne $KeyCredential) {
        $keyCred = $KeyCredential
    }
    elseif ($null -ne $Certificate) {
        $keyCred = New-DiscoveryKeyCredential -Certificate $Certificate
    }
    elseif (-not [string]::IsNullOrWhiteSpace($CertPath)) {
        $keyCred = New-DiscoveryKeyCredential -Path $CertPath
    }
    else {
        throw 'New-DiscoveryAppPayload requires one of -KeyCredential, -Certificate, or -CertPath.'
    }

    $rra = Get-DiscoveryRequiredResourceAccess -Path $ManifestPath

    @{
        displayName            = $DisplayName
        signInAudience         = $SignInAudience
        requiredResourceAccess = $rra
        keyCredentials         = @($keyCred)
    }
}

# ---------------------------------------------------------------------------
# Graph wrappers (lazy SDK import; live-tenant only)
# ---------------------------------------------------------------------------

function Connect-DiscoveryGraph {
    <#
    .SYNOPSIS
        Ensures an authenticated Graph session with the required provisioner scopes.

    .DESCRIPTION
        If a session is already present that carries all required scopes, reuses it.
        Otherwise calls Connect-MgGraph with the required scopes (and -TenantId when
        supplied). The provisioner authenticates delegated/interactively. Required
        scopes: Application.ReadWrite.All, AppRoleAssignment.ReadWrite.All,
        Directory.Read.All.

        Lazily imports the SDK. This is the only place an interactive sign-in occurs.

    .PARAMETER TenantId
        Optional tenant id to connect to.

    .PARAMETER Scopes
        Override the default required scopes (advanced).

    .OUTPUTS
        None.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([void])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$TenantId,

        [Parameter()]
        [string[]]$Scopes = $script:RequiredProvisionerScopes
    )

    Assert-GraphModuleAvailable

    $context = $null
    try { $context = Get-MgContext } catch { $context = $null }

    $haveAll = $false
    if ($null -ne $context -and $null -ne $context.Scopes) {
        $missing = @($Scopes | Where-Object { $context.Scopes -notcontains $_ })
        $haveAll = ($missing.Count -eq 0)
    }

    if ($haveAll) {
        Write-Verbose 'Reusing existing Microsoft Graph session (required scopes present).'
        return
    }

    $connectParams = @{ Scopes = $Scopes }
    if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
        $connectParams['TenantId'] = $TenantId
    }

    if ($PSCmdlet.ShouldProcess('Microsoft Graph', "Connect-MgGraph -Scopes $($Scopes -join ', ')")) {
        Connect-MgGraph @connectParams | Out-Null
    }
}

function New-DiscoveryAppRegistration {
    <#
    .SYNOPSIS
        Creates the application + service principal, embedding the cert (FR 12).

    .DESCRIPTION
        Builds the payload via New-DiscoveryAppPayload, creates the application with
        New-MgApplication (cert embedded as a keyCredential at creation -- no
        separate upload), then creates the matching service principal. Honours
        ShouldProcess so -WhatIf performs no tenant write. Returns a result object
        (AppId, ObjectId, ServicePrincipalId, TenantId, DisplayName, Thumbprint,
        ConsentGranted=$false).

        Requires an authenticated session (call Connect-DiscoveryGraph first).

    .PARAMETER DisplayName
        Application display name. Required.

    .PARAMETER CertPath
        Path to the public certificate to embed (or use -Certificate).

    .PARAMETER Certificate
        Preloaded public certificate to embed.

    .PARAMETER ManifestPath
        Permission manifest path. Defaults to manifests/permissions.csv.

    .PARAMETER Force
        Idempotency override (FR 20). By default this wrapper queries the tenant for
        an existing application of the same display name and THROWS (refusing to
        silently duplicate) if one is found. -Force creates the app anyway (a
        deliberate duplicate). Flows from the entry script's -ForceNewApp switch.

    .OUTPUTS
        PSCustomObject.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DisplayName,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$CertPath,

        [Parameter()]
        [AllowNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ManifestPath,

        [switch]$Force
    )

    Assert-GraphModuleAvailable

    # Idempotency guard (FR 20): refuse to silently duplicate an app of the same
    # display name. Query existing apps by display name (escape single quotes by
    # doubling for the OData filter), then let the PURE resolver decide. -Force
    # (from -ForceNewApp) creates a deliberate duplicate. This read is non-mutating.
    $escapedName = $DisplayName.Replace("'", "''")
    $existingApps = @(Get-MgApplication -Filter "displayName eq '$escapedName'" -ErrorAction SilentlyContinue)
    $decision = Resolve-DiscoveryAppCreateAction -DisplayName $DisplayName -ExistingApp $existingApps -Force:$Force
    if ($decision.Action -eq 'Blocked') {
        throw $decision.Message
    }

    $payloadArgs = @{ DisplayName = $DisplayName; ManifestPath = $ManifestPath }
    if ($null -ne $Certificate)                       { $payloadArgs['Certificate'] = $Certificate }
    elseif (-not [string]::IsNullOrWhiteSpace($CertPath)) { $payloadArgs['CertPath'] = $CertPath }
    $payload = New-DiscoveryAppPayload @payloadArgs

    $thumbprint = $null
    if ($null -ne $Certificate) {
        $thumbprint = $Certificate.Thumbprint
    }
    elseif (-not [string]::IsNullOrWhiteSpace($CertPath)) {
        try { $thumbprint = ([System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertPath)).Thumbprint } catch { $thumbprint = $null }
    }

    if (-not $PSCmdlet.ShouldProcess($DisplayName, 'Create app registration + service principal')) {
        $whatIfTenant = $null
        try { $whatIfTenant = (Get-MgContext).TenantId } catch { $whatIfTenant = $null }
        return New-DiscoveryResult -Property @{
            AppId              = $null
            ObjectId           = $null
            ServicePrincipalId = $null
            TenantId           = $whatIfTenant
            DisplayName        = $DisplayName
            Thumbprint         = $thumbprint
            ConsentGranted     = $false
            WhatIf             = $true
        }
    }

    $app = New-MgApplication -BodyParameter $payload

    # SP creation is the primary replication-lag failure point: the just-created
    # application object is not yet visible to the SP-create endpoint, which returns
    # 'does not reference a valid application object' (Request_BadRequest). Retry on
    # that transient window rather than failing (and orphaning the app).
    $newAppId = $app.AppId
    $sp = Invoke-DiscoveryGraphWithRetry -OperationName 'service-principal creation' -ScriptBlock {
        New-MgServicePrincipal -AppId $newAppId
    }

    $tenantId = $null
    try { $tenantId = (Get-MgContext).TenantId } catch { $tenantId = $null }

    New-DiscoveryResult -Property @{
        AppId              = $app.AppId
        ObjectId           = $app.Id
        ServicePrincipalId = $sp.Id
        TenantId           = $tenantId
        DisplayName        = $DisplayName
        Thumbprint         = $thumbprint
        ConsentGranted     = $false
    }
}

function Add-DiscoveryAppCredential {
    <#
    .SYNOPSIS
        Attaches a public certificate to an existing app registration (FR 13).

    .DESCRIPTION
        Adds a keyCredential to an existing application (targeted by its object id),
        merging with any existing keyCredentials so prior certs are not dropped.
        Honours ShouldProcess. Returns a result object with AppObjectId, AppId,
        Thumbprint.

        Requires an authenticated session (call Connect-DiscoveryGraph first).

    .PARAMETER AppObjectId
        The object id of the existing application registration. Required.

    .PARAMETER CertPath
        Path to the public certificate to attach (or use -Certificate).

    .PARAMETER Certificate
        Preloaded public certificate to attach.

    .OUTPUTS
        PSCustomObject.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$AppObjectId,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$CertPath,

        [Parameter()]
        [AllowNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    Assert-GraphModuleAvailable

    if ($null -ne $Certificate) {
        $keyCred = New-DiscoveryKeyCredential -Certificate $Certificate
        $thumbprint = $Certificate.Thumbprint
    }
    elseif (-not [string]::IsNullOrWhiteSpace($CertPath)) {
        $keyCred = New-DiscoveryKeyCredential -Path $CertPath
        try { $thumbprint = ([System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertPath)).Thumbprint } catch { $thumbprint = $null }
    }
    else {
        throw 'Add-DiscoveryAppCredential requires one of -Certificate or -CertPath.'
    }

    # Merge with existing keyCredentials so we do not clobber prior certs.
    $existing = @()
    try {
        $app = Get-MgApplication -ApplicationId $AppObjectId
        if ($null -ne $app -and $null -ne $app.KeyCredentials) {
            $existing = @($app.KeyCredentials)
        }
    }
    catch {
        $existing = @()
    }

    $merged = @($existing) + @($keyCred)

    if ($PSCmdlet.ShouldProcess($AppObjectId, "Attach certificate $thumbprint")) {
        Update-MgApplication -ApplicationId $AppObjectId -KeyCredentials $merged
    }

    New-DiscoveryResult -Property @{
        AppObjectId = $AppObjectId
        Thumbprint  = $thumbprint
    }
}

function Grant-DiscoveryAdminConsent {
    <#
    .SYNOPSIS
        Grants tenant-wide admin consent via app-role assignments on the SP (FR 14).

    .DESCRIPTION
        For each application permission in the manifest, creates an app-role
        assignment on the discovery app's service principal against the resource
        service principal (Microsoft Graph). This is the programmatic equivalent of
        clicking "Grant admin consent" in the portal. Idempotent: existing
        assignments are skipped. Honours ShouldProcess.

        Requires AppRoleAssignment.ReadWrite.All. Call Connect-DiscoveryGraph first.

    .PARAMETER ServicePrincipalId
        The discovery app's service principal object id. Required.

    .PARAMETER ManifestPath
        Permission manifest path. Defaults to manifests/permissions.csv.

    .OUTPUTS
        PSCustomObject (Granted count, Skipped count).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ServicePrincipalId,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ManifestPath
    )

    Assert-GraphModuleAvailable

    $rra = Get-DiscoveryRequiredResourceAccess -Path $ManifestPath

    $granted = 0
    $skipped = 0

    foreach ($resource in $rra) {
        $resourceAppId = $resource.resourceAppId

        # Resolve the resource service principal (e.g. Microsoft Graph) by appId.
        # Wrapped: the discovery SP we just created can lag, and resolving the
        # resource SP right after SP creation can hit the same transient window.
        $resourceSp = Invoke-DiscoveryGraphWithRetry -OperationName "resolve resource SP for appId '$resourceAppId'" -ScriptBlock {
            Get-MgServicePrincipal -Filter "appId eq '$resourceAppId'" -ErrorAction Stop |
                Select-Object -First 1
        }
        if ($null -eq $resourceSp) {
            throw "Resource service principal not found for appId '$resourceAppId'."
        }

        # Existing assignments on the discovery SP (idempotency). Wrapped: the
        # just-created discovery SP may not yet be readable.
        $spId = $ServicePrincipalId
        $existing = @(Invoke-DiscoveryGraphWithRetry -OperationName 'read existing app-role assignments' -ScriptBlock {
            Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $spId -ErrorAction Stop
        })

        foreach ($access in $resource.resourceAccess) {
            if ($access.type -ne 'Role') {
                # Only application permissions are granted via app-role assignment.
                $skipped++
                continue
            }

            $alreadyGranted = $existing | Where-Object {
                $_.ResourceId -eq $resourceSp.Id -and $_.AppRoleId -eq $access.id
            }
            if ($alreadyGranted) {
                $skipped++
                continue
            }

            if ($PSCmdlet.ShouldProcess($ServicePrincipalId, "Grant app role $($access.id) on $resourceAppId")) {
                # Each assignment can transiently fail right after SP creation
                # (replication lag) or under throttling when assigning ~53 roles in
                # quick succession. Retry transient failures; the idempotent
                # "already assigned" pre-check above still suppresses dupes.
                $roleId      = $access.id
                $resourceSpId = $resourceSp.Id
                Invoke-DiscoveryGraphWithRetry -OperationName "grant app role $roleId on $resourceAppId" -ScriptBlock {
                    New-MgServicePrincipalAppRoleAssignment `
                        -ServicePrincipalId $spId `
                        -PrincipalId $spId `
                        -ResourceId $resourceSpId `
                        -AppRoleId $roleId | Out-Null
                }
            }
            $granted++
        }
    }

    New-DiscoveryResult -Property @{
        Granted = $granted
        Skipped = $skipped
    }
}

function Remove-DiscoveryAppRegistration {
    <#
    .SYNOPSIS
        Teardown: deletes the discovery app registration and its SP (3.5).

    .DESCRIPTION
        Removes the application (and its service principal) created for an
        integration run. Consumed by the live integration tier to clean up
        zzTEST-DiscoveryApp-<timestamp> apps. Honours ShouldProcess. Tolerant: a
        missing app/SP is treated as already-removed rather than an error.

        Requires Application.ReadWrite.All. Call Connect-DiscoveryGraph first.

    .PARAMETER AppObjectId
        The object id of the application to delete. Required (one of this or AppId).

    .PARAMETER AppId
        The application's (client) appId, used to resolve the object id and SP when
        AppObjectId is not supplied.

    .OUTPUTS
        PSCustomObject (RemovedApp, RemovedServicePrincipal booleans).
    #>
    [CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'ByObjectId')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(ParameterSetName = 'ByObjectId', Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$AppObjectId,

        [Parameter(ParameterSetName = 'ByAppId', Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$AppId
    )

    Assert-GraphModuleAvailable

    $objectId = $AppObjectId
    $clientId = $AppId

    # Resolve object id from appId when needed.
    if ([string]::IsNullOrWhiteSpace($objectId) -and -not [string]::IsNullOrWhiteSpace($clientId)) {
        $app = Get-MgApplication -Filter "appId eq '$clientId'" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -ne $app) { $objectId = $app.Id }
    }

    # Resolve client id from object id when needed (to find the SP).
    if ([string]::IsNullOrWhiteSpace($clientId) -and -not [string]::IsNullOrWhiteSpace($objectId)) {
        $app = Get-MgApplication -ApplicationId $objectId -ErrorAction SilentlyContinue
        if ($null -ne $app) { $clientId = $app.AppId }
    }

    $removedSp  = $false
    $removedApp = $false

    # Delete the service principal first (by appId). A missing SP is already-removed
    # (success). Transient delete quirks (incl. a 404 on an SP that still exists) are
    # handled by Invoke-DiscoveryGraphDelete: 404 -> success, other transient ->
    # retry, authz -> throw. So an absent SP is reported RemovedServicePrincipal=$true
    # (idempotent: tearing down something already gone succeeds).
    if (-not [string]::IsNullOrWhiteSpace($clientId)) {
        $sp = Get-MgServicePrincipal -Filter "appId eq '$clientId'" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -eq $sp) {
            # SP not present at all -> already absent -> idempotent success.
            $removedSp = $true
        }
        elseif ($PSCmdlet.ShouldProcess($sp.Id, 'Remove service principal')) {
            $spId = $sp.Id
            $removedSp = Invoke-DiscoveryGraphDelete -OperationName "remove service principal $spId" -ScriptBlock {
                Remove-MgServicePrincipal -ServicePrincipalId $spId -ErrorAction Stop
            }
        }
    }

    # Delete the application. Same idempotent/robust delete semantics: a 404 from
    # Remove-MgApplication (the observed transient quirk on an app that still exists)
    # is treated as success, other transient errors are retried, authz throws.
    if (-not [string]::IsNullOrWhiteSpace($objectId)) {
        if ($PSCmdlet.ShouldProcess($objectId, 'Remove application')) {
            $appObjId = $objectId
            $removedApp = Invoke-DiscoveryGraphDelete -OperationName "remove application $appObjId" -ScriptBlock {
                Remove-MgApplication -ApplicationId $appObjId -ErrorAction Stop
            }
        }
    }
    elseif (-not [string]::IsNullOrWhiteSpace($clientId)) {
        # We had an appId but could not resolve an object id -> the application is
        # already absent (could not be found). Idempotent success.
        $removedApp = $true
    }

    New-DiscoveryResult -Property @{
        RemovedApp              = $removedApp
        RemovedServicePrincipal = $removedSp
        AppObjectId             = $objectId
        AppId                   = $clientId
    }
}

Export-ModuleMember -Function `
    New-DiscoveryAppDisplayName, `
    Resolve-DiscoveryAppCreateAction, `
    New-DiscoveryKeyCredential, `
    New-DiscoveryAppPayload, `
    Connect-DiscoveryGraph, `
    New-DiscoveryAppRegistration, `
    Add-DiscoveryAppCredential, `
    Grant-DiscoveryAdminConsent, `
    Remove-DiscoveryAppRegistration
