<#
.SYNOPSIS
    Cross-user private-key access for the discovery app (FR 16).

.DESCRIPTION
    Implements the `-GrantUser` functional requirement: granting a non-admin
    operator account Read access to the NTFS ACL of a LocalMachine certificate's
    CNG private-key container file, so that account can use the TPM-bound key to
    sign client assertions without being a local administrator.

      * Resolve-GrantAccount        - normalise an account string to an NTAccount + SID
      * Test-GrantUserApplicable    - the CurrentUser-vs-LocalMachine decision (pure)
      * Get-CngKeyFilePath          - locate the CNG key-container file for a cert
      * Grant-DiscoveryKeyAccess    - apply (or warn/no-op) the private-key ACL

    Design mirrors src/KeyGeneration.psm1: comment-based help on every public
    function, the New-DiscoveryResult factory for shaped output, Test-IsWindows
    for the OS gate, fail-closed behaviour, and backtick line continuations.

    The ACL operation is Windows-only. CurrentUser keys are per-profile and not
    cross-user shareable, so for the CurrentUser store the function WARNS and
    no-ops (Applied = $false) rather than touching anything. Off Windows it
    fails closed with a clear error.

    Cross-compatible with Windows PowerShell 5.1 (Desktop) and PowerShell 7.x
    (Core) on Windows (FR 21).
#>

Set-StrictMode -Version Latest

Import-Module "$PSScriptRoot/Common.psm1" -Force

# ---------------------------------------------------------------------------
# Exported functions
# ---------------------------------------------------------------------------

function Resolve-GrantAccount {
    <#
    .SYNOPSIS
        Resolves an account string to an NTAccount and its SID.

    .DESCRIPTION
        Accepts 'MACHINE\user', 'DOMAIN\user', a UPN-style name, or a bare name
        (resolved against the local machine / default domain), and translates it
        to a security identifier (SID). Throws a clear error if the account can
        not be translated. This logic is OS-independent enough to unit-test on any
        platform that has the System.Security.Principal types (PowerShell 7 on
        macOS resolves well-known SIDs but typically NOT arbitrary local accounts,
        so tests use well-known principals or assert the throw path).

    .PARAMETER Account
        The account string to resolve (e.g. 'CONTOSO\jdoe', '.\operator',
        'BUILTIN\Users', 'NT AUTHORITY\NETWORK SERVICE', or 'operator').

    .OUTPUTS
        PSCustomObject with: Account (resolved NTAccount string), Sid (string).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Account
    )

    $trimmed = $Account.Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed)) {
        throw "Account '$Account' is empty after trimming; supply a real account name."
    }

    # A leading '.\' means "this machine". Expand it so NTAccount can translate it.
    if ($trimmed.StartsWith('.\')) {
        $trimmed = "$env:COMPUTERNAME\" + $trimmed.Substring(2)
    }

    try {
        $ntAccount = [System.Security.Principal.NTAccount]::new($trimmed)
        $sid       = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier])
    }
    catch {
        throw "Could not resolve account '$Account' to a security identifier: $($_.Exception.Message)"
    }

    New-DiscoveryResult -Property @{
        Account = $ntAccount.Value
        Sid     = $sid.Value
    }
}

function Test-GrantUserApplicable {
    <#
    .SYNOPSIS
        Decides whether -GrantUser applies for a given store location (pure).

    .DESCRIPTION
        The cross-user ACL grant only makes sense for a LocalMachine key, whose
        private-key container file lives under a machine-wide path that other
        accounts can be granted access to. A CurrentUser key lives in the calling
        user's profile (DPAPI-scoped per user) and cannot be shared by ACL, so the
        caller must WARN and no-op. This helper isolates that decision so it can be
        unit-tested without any filesystem or registry access.

    .PARAMETER StoreLocation
        'LocalMachine' or 'CurrentUser'.

    .OUTPUTS
        PSCustomObject with: Applicable (bool), Reason (string).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('LocalMachine', 'CurrentUser')]
        [string]$StoreLocation
    )

    if ($StoreLocation -eq 'LocalMachine') {
        New-DiscoveryResult -Property @{
            Applicable = $true
            Reason     = 'OK'
        }
    }
    else {
        New-DiscoveryResult -Property @{
            Applicable = $false
            Reason     = 'CurrentUser keys are per-profile (DPAPI-scoped) and cannot be shared by ACL; use -StoreLocation LocalMachine to grant cross-user access.'
        }
    }
}

function Get-CngKeyFilePath {
    <#
    .SYNOPSIS
        Locates the on-disk CNG private-key container file for a certificate.

    .DESCRIPTION
        Reads the certificate's CNG private key via RSACertificateExtensions
        (an RSACng exposing a CngKey) and takes the key container's UniqueName.

        UniqueName means different things by provider:
          * TPM / Microsoft Platform Crypto Provider keys expose UniqueName as
            the ABSOLUTE PATH to the .PCPKEY container file. When it is a rooted
            path that exists, that path IS the key file and is returned directly.
          * Software CNG keys expose UniqueName as a bare container file *name*.
            In that case the machine-wide CNG key directories are searched for a
            file of that name:

              * "$env:ProgramData\Microsoft\Crypto\Keys"        - software CNG keys
              * "$env:ProgramData\Microsoft\Crypto\PCPKSP\*"    - TPM / Platform keys
                                                                   (recursed)

        Returns the resolved full path, or $null when the file cannot be found
        (or when the cert has no CNG private key). Windows-only; off Windows it
        throws (the caller gates this).

    .PARAMETER Certificate
        The certificate whose CNG key file is located.

    .OUTPUTS
        System.String (full path) or $null.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    if (-not (Test-IsWindows)) {
        throw 'Get-CngKeyFilePath is Windows-only (CNG key containers do not exist off Windows).'
    }

    # --- Read the CNG key container's UniqueName (the on-disk file name) ----
    $uniqueName = $null
    try {
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
        if ($null -ne $rsa) {
            $cngKey = $null
            try { $cngKey = $rsa.Key } catch { $cngKey = $null }
            if ($null -ne $cngKey) {
                try { $uniqueName = $cngKey.UniqueName } catch { $uniqueName = $null }
            }
        }
    }
    catch {
        $uniqueName = $null
    }

    if ([string]::IsNullOrWhiteSpace($uniqueName)) {
        return $null
    }

    # --- TPM / Platform Crypto Provider case --------------------------------
    # A PCP/TPM key exposes its CngKey.UniqueName as the ABSOLUTE path to the
    # on-disk .PCPKEY container file (e.g.
    # C:\ProgramData\Microsoft\Crypto\PCPKSP\<...>\<...>.PCPKEY), whereas a
    # software CNG key exposes only a bare container file *name*. So if the
    # UniqueName is already a rooted path that exists on disk, that IS the key
    # file — return it directly (the directory-name search below would never
    # match a full path).
    if ([System.IO.Path]::IsPathRooted($uniqueName) -and (Test-Path -LiteralPath $uniqueName)) {
        return (Resolve-Path -LiteralPath $uniqueName).Path
    }

    # --- Software-CNG case: search the machine-wide CNG key dirs by file name -
    # Primary: software CNG keys. Secondary: TPM/Platform keys (PCPKSP), recursed
    # because the platform KSP nests its containers under per-provider subdirs.
    $searchDirs = @(
        (Join-Path $env:ProgramData (Join-Path 'Microsoft' (Join-Path 'Crypto' 'Keys')))
    )
    $pcpRoot = Join-Path $env:ProgramData (Join-Path 'Microsoft' (Join-Path 'Crypto' 'PCPKSP'))

    foreach ($dir in $searchDirs) {
        if (Test-Path -LiteralPath $dir) {
            $candidate = Join-Path $dir $uniqueName
            if (Test-Path -LiteralPath $candidate) {
                return (Resolve-Path -LiteralPath $candidate).Path
            }
        }
    }

    # PCPKSP: recurse, since the UniqueName may live in a nested provider folder.
    if (Test-Path -LiteralPath $pcpRoot) {
        $found = Get-ChildItem -LiteralPath $pcpRoot -Recurse -File -Filter $uniqueName `
                    -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -ne $found) {
            return $found.FullName
        }
    }

    return $null
}

function Grant-DiscoveryKeyAccess {
    <#
    .SYNOPSIS
        Grants an operator account Read access to a LocalMachine key's private-key ACL (FR 16).

    .DESCRIPTION
        Enables cross-user use of a TPM-bound signing key: a non-admin operator
        account that is NOT the provisioner can sign client assertions once it has
        Read NTFS access to the key's CNG container file.

        Behaviour by store:
          * LocalMachine -> resolve the account to an NTAccount/SID, locate the CNG
            key file (Get-CngKeyFilePath), and add an Allow/Read FileSystemAccessRule
            for that account to the file's ACL via Get-Acl / Set-Acl.
          * CurrentUser  -> WARN and no-op (Applied = $false, Reason set); per-profile
            keys are not cross-user shareable.

        Honours SupportsShouldProcess: under -WhatIf the ACL is NOT written and the
        result reports Applied = $false with a WhatIf reason. Off Windows it fails
        closed with a clear error.

    .PARAMETER Certificate
        The certificate whose private-key ACL is modified.

    .PARAMETER Account
        The account to grant Read access to (e.g. 'CONTOSO\operator',
        'BUILTIN\Users', '.\operator').

    .PARAMETER StoreLocation
        The store the key resides in: 'LocalMachine' (ACL applied) or
        'CurrentUser' (warn / no-op). Defaults to 'LocalMachine'.

    .OUTPUTS
        PSCustomObject with: Account, Sid, Rights, Applied (bool), Reason,
        KeyFilePath, StoreLocation.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Account,

        [Parameter()]
        [ValidateSet('LocalMachine', 'CurrentUser')]
        [string]$StoreLocation = 'LocalMachine'
    )

    # --- Off-Windows: fail closed --------------------------------------------
    if (-not (Test-IsWindows)) {
        throw 'Grant-DiscoveryKeyAccess is Windows-only: private-key ACLs apply to Windows CNG key containers.'
    }

    # --- Resolve the account to an NTAccount + SID (clear error if it fails) --
    $resolved = Resolve-GrantAccount -Account $Account
    $rights   = 'Read'

    # --- Store decision: CurrentUser warns + no-ops --------------------------
    $applicable = Test-GrantUserApplicable -StoreLocation $StoreLocation
    if (-not $applicable.Applicable) {
        Write-Warning $applicable.Reason
        return New-DiscoveryResult -Property @{
            Account       = $resolved.Account
            Sid           = $resolved.Sid
            Rights        = $rights
            Applied       = $false
            Reason        = $applicable.Reason
            KeyFilePath   = $null
            StoreLocation = $StoreLocation
        }
    }

    # --- Locate the CNG key-container file ------------------------------------
    $keyFilePath = Get-CngKeyFilePath -Certificate $Certificate
    if ([string]::IsNullOrWhiteSpace($keyFilePath)) {
        $reason = 'Could not locate the CNG private-key container file for this certificate under the machine Crypto\Keys or Crypto\PCPKSP directories.'
        Write-Warning $reason
        return New-DiscoveryResult -Property @{
            Account       = $resolved.Account
            Sid           = $resolved.Sid
            Rights        = $rights
            Applied       = $false
            Reason        = $reason
            KeyFilePath   = $null
            StoreLocation = $StoreLocation
        }
    }

    # --- Apply the ACL (ShouldProcess-gated) ---------------------------------
    if (-not $PSCmdlet.ShouldProcess($keyFilePath, "Grant '$($resolved.Account)' Read access to the private-key file")) {
        return New-DiscoveryResult -Property @{
            Account       = $resolved.Account
            Sid           = $resolved.Sid
            Rights        = $rights
            Applied       = $false
            Reason        = 'WhatIf: ACL not modified.'
            KeyFilePath   = $keyFilePath
            StoreLocation = $StoreLocation
        }
    }

    $acl  = Get-Acl -LiteralPath $keyFilePath
    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
        [System.Security.Principal.NTAccount]::new($resolved.Account),
        [System.Security.AccessControl.FileSystemRights]::Read,
        [System.Security.AccessControl.AccessControlType]::Allow)
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $keyFilePath -AclObject $acl

    New-DiscoveryResult -Property @{
        Account       = $resolved.Account
        Sid           = $resolved.Sid
        Rights        = $rights
        Applied       = $true
        Reason        = 'OK'
        KeyFilePath   = $keyFilePath
        StoreLocation = $StoreLocation
    }
}

Export-ModuleMember -Function `
    Resolve-GrantAccount, `
    Test-GrantUserApplicable, `
    Get-CngKeyFilePath, `
    Grant-DiscoveryKeyAccess
