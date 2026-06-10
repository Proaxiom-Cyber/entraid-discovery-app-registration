<#
.SYNOPSIS
    Credential-pathway security posture decisions and disclosure for the discovery app (-CredentialMode).

.DESCRIPTION
    Implements the PURE decision/disclosure surface for the five credential pathways
    the tool can provision, selected by the entry script's -CredentialMode parameter:

      * Resolve-CredentialPosture      - PURE: mode -> posture (assurance rank, summary,
                                         downsides, recommendation, acknowledgement requirement)
      * Format-CredentialPosture       - host-only print of the posture block
      * Test-CredentialAcknowledgement - PURE: acknowledgement truth table (fail-closed)

    DESIGN — pure disclosure, no side effects (testability):
      Nothing in this module touches the Graph SDK, a tenant, a TPM, or the OS — it
      imports and runs anywhere (including macOS PS7) and is unit-tested in Tier A.
      The entry script consumes these decisions: it resolves the posture for the
      selected mode, prints it (Format-CredentialPosture), and enforces the
      acknowledgement decision (Test-CredentialAcknowledgement) before any
      credential is created. Enforcement/wiring lives in the entry script; the
      POLICY (what each mode means and whether it needs an explicit operator
      acknowledgement) lives here, in one place.

    PATHWAY ORDER — load-bearing:
      The script-scoped posture table is ordered from highest to lowest assurance,
      and that order IS the ValidateSet order on -Mode (and on the entry script's
      -CredentialMode): rank 1 = TpmBound (highest) ... rank 5 = ClientSecret
      (lowest). Keep the table, the ValidateSet and the ranks in lock-step when a
      pathway is added.

    ACKNOWLEDGEMENT MODEL (honesty / fail-closed):
      The two reduced-assurance pathways — ImportPrivateKey (a portable, file-resident
      private key) and ClientSecret (a bearer secret with no possession proof) — must
      never be provisioned silently. They require an explicit operator acknowledgement
      (-AcknowledgeReducedAssurance), or an interactive yes to a prompt; a
      non-interactive run without the flag FAILS CLOSED with an actionable message.

    Cross-compatible with Windows PowerShell 5.1 (Desktop) and PowerShell 7.x (Core)
    on any OS (FR 21).
#>

Set-StrictMode -Version Latest

Import-Module "$PSScriptRoot/Common.psm1" -Force

# ---------------------------------------------------------------------------
# Credential pathway posture table
# ---------------------------------------------------------------------------
# ORDER IS LOAD-BEARING: table order == assurance order == the ValidateSet order
# on -Mode / the entry script's -CredentialMode. Rank 1 = highest assurance,
# rank 5 = lowest. RequiresAcknowledgement marks the reduced-assurance pathways
# that must never proceed without an explicit operator acknowledgement.
$script:CredentialPostureTable = [ordered]@{

    TpmBound = @{
        AssuranceRank           = 1
        AssuranceLevel          = 'Highest — hardware-bound, non-exportable key'
        Summary                 = 'The private key is generated inside THIS machine''s TPM (Microsoft Platform Crypto Provider) and cannot be exported or copied; tokens can only be minted from this machine.'
        Downsides               = @(
            'Requires a Windows host with a usable TPM (Microsoft Platform Crypto Provider).'
            'The key is not portable: a host rebuild or hardware replacement means provisioning a new certificate.'
        )
        Recommendation          = 'The default and recommended pathway — the strongest binding between the app credential and a single known machine.'
        RequiresAcknowledgement = $false
    }

    ProviderHostedCert = @{
        AssuranceRank           = 2
        AssuranceLevel          = 'High — hardware-bound, provider-held (custody trade-off)'
        Summary                 = 'The private key is TPM-bound on a Proaxiom-operated Azure (Trusted Launch / Confidential) VM; the customer imports only the public certificate, optionally verifying a TPM attestation bundle.'
        Downsides               = @(
            'Proaxiom retains custody of the private key — the customer trusts Proaxiom''s controls and contract rather than holding the key themselves.'
            'Token issuance occurs on provider infrastructure, not on customer-controlled hosts.'
            'Revocation means removing the certificate from the app registration (there is no customer-side key to destroy).'
        )
        Recommendation          = 'Choose when the customer cannot host a TPM but wants hardware-bound assurance; require the TPM attestation bundle as evidence of the key''s hardware binding.'
        RequiresAcknowledgement = $false
    }

    ImportPublicCert = @{
        AssuranceRank           = 3
        AssuranceLevel          = 'Holder-dependent — key custody and quality unknown to this tool'
        Summary                 = 'The customer supplies only a public certificate; this tool never sees the private key.'
        Downsides               = @(
            'Assurance depends ENTIRELY on how the holder generated and protects the private key — it could be an exportable software key.'
            'This tool cannot verify non-exportability or hardware binding of a key it never sees.'
        )
        Recommendation          = 'Acceptable when the customer has their own HSM/TPM key discipline; document where the private key lives and how it is protected.'
        RequiresAcknowledgement = $false
    }

    ImportPrivateKey = @{
        AssuranceRank           = 4
        AssuranceLevel          = 'Reduced — portable private key (file-resident)'
        Summary                 = 'A supplied PFX/P12 file (private key + certificate) is installed into the Windows certificate store.'
        Downsides               = @(
            'The private key exists as a FILE that has been transported between parties — it can be copied, intercepted, or retained at any point along the way.'
            'Anyone holding the PFX file and its password can mint tokens from ANY machine — there is no machine binding.'
            'The store copy is installed non-exportable, but the source PFX file remains the exposure.'
        )
        Recommendation          = 'Transfer the PFX and its password ONLY via Proaxiom Pass (https://pass.proaxiom.com) one-time links — the password in a SEPARATE link — delete the PFX after import, use a short certificate validity, and prefer TpmBound or ProviderHostedCert.'
        RequiresAcknowledgement = $true
    }

    ClientSecret = @{
        AssuranceRank           = 5
        AssuranceLevel          = 'Lowest — bearer secret, no possession proof'
        Summary                 = 'No certificate at all — a generated secret string is the credential.'
        Downsides               = @(
            'A BEARER credential: anyone who obtains the secret string IS the app, from anywhere — no machine or key binding.'
            'Secrets leak easily — pasted into chats, written to logs, committed to source control.'
            'Cannot prove possession of a private key, and offers weaker workload-identity Conditional Access options.'
        )
        Recommendation          = 'Use the shortest viable expiry, share the secret ONLY via a Proaxiom Pass (https://pass.proaxiom.com) one-time link, rotate it regularly, and treat it as a stopgap until a certificate pathway is possible.'
        RequiresAcknowledgement = $true
    }
}

# ---------------------------------------------------------------------------
# PURE functions (OS-independent; unit-tested in Tier A on macOS)
# ---------------------------------------------------------------------------

function Resolve-CredentialPosture {
    <#
    .SYNOPSIS
        PURE decision: given a credential mode, state its security posture and acknowledgement requirement.

    .DESCRIPTION
        No OS calls, no tenant, no TPM. Looks the mode up in the script-scoped
        posture table and projects a posture object the entry script can print
        (Format-CredentialPosture) and enforce (Test-CredentialAcknowledgement).

        Rank semantics: 1 = highest assurance (TpmBound) ... 5 = lowest
        (ClientSecret). The ValidateSet order on -Mode is exactly that assurance
        order. RequiresAcknowledgement is $true only for the reduced-assurance
        pathways (ImportPrivateKey, ClientSecret).

    .PARAMETER Mode
        The credential pathway: TpmBound, ProviderHostedCert, ImportPublicCert,
        ImportPrivateKey or ClientSecret.

    .EXAMPLE
        Resolve-CredentialPosture -Mode TpmBound

    .OUTPUTS
        PSCustomObject with: Mode, AssuranceRank (int, 1 = highest), AssuranceLevel,
        Summary, Downsides (string[]), Recommendation, RequiresAcknowledgement (bool).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('TpmBound', 'ProviderHostedCert', 'ImportPublicCert', 'ImportPrivateKey', 'ClientSecret')]
        [string]$Mode
    )

    # Belt-and-braces beyond ValidateSet: if the ValidateSet and the posture table
    # ever drift apart, fail with a clear error rather than emitting a half-shaped
    # posture object.
    if (-not $script:CredentialPostureTable.Contains($Mode)) {
        throw "Unknown credential mode '$Mode'. Known modes: $($script:CredentialPostureTable.Keys -join ', ')."
    }

    $entry = $script:CredentialPostureTable[$Mode]

    New-DiscoveryResult -Property @{
        Mode                    = $Mode
        AssuranceRank           = [int]$entry.AssuranceRank
        AssuranceLevel          = [string]$entry.AssuranceLevel
        Summary                 = [string]$entry.Summary
        Downsides               = [string[]]$entry.Downsides
        Recommendation          = [string]$entry.Recommendation
        RequiresAcknowledgement = [bool]$entry.RequiresAcknowledgement
    }
}

function Format-CredentialPosture {
    <#
    .SYNOPSIS
        Writes a human-readable credential-pathway posture block to the host.

    .DESCRIPTION
        Prints the posture resolved by Resolve-CredentialPosture: a titled block
        (Green for a full-assurance pathway, Yellow for one that requires an
        acknowledgement), the assurance level with its rank, the summary, the
        downsides as bullets and the recommendation. When the pathway requires an
        acknowledgement, a prominent warning line states that this is a
        REDUCED-ASSURANCE pathway needing explicit operator acknowledgement.

    .PARAMETER Posture
        The posture object from Resolve-CredentialPosture. Expected properties:
        Mode, AssuranceRank, AssuranceLevel, Summary, Downsides, Recommendation,
        RequiresAcknowledgement.

    .OUTPUTS
        None. Writes to the host only.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [pscustomobject]$Posture
    )

    $getProp = {
        param($name)
        if ($Posture.PSObject.Properties.Name -contains $name) { $Posture.$name } else { $null }
    }

    $mode           = [string](& $getProp 'Mode')
    $level          = [string](& $getProp 'AssuranceLevel')
    $summary        = [string](& $getProp 'Summary')
    $recommendation = [string](& $getProp 'Recommendation')

    $rankRaw = & $getProp 'AssuranceRank'
    $rank    = if ($null -eq $rankRaw) { 0 } else { [int]$rankRaw }

    $downsidesRaw = & $getProp 'Downsides'
    $downsides    = @()
    if ($null -ne $downsidesRaw) { $downsides = @($downsidesRaw) }

    $ackRaw      = & $getProp 'RequiresAcknowledgement'
    $requiresAck = if ($null -eq $ackRaw) { $false } else { [bool]$ackRaw }

    $titleColor = if ($requiresAck) { 'Yellow' } else { 'Green' }
    $rankOf     = $script:CredentialPostureTable.Count
    $title      = "Credential pathway: $mode"

    Write-Host ''
    Write-Host $title -ForegroundColor $titleColor
    Write-Host ('-' * $title.Length)
    Write-Host ("  Assurance      : {0} (rank {1} of {2})" -f $level, $rank, $rankOf)
    Write-Host ("  Summary        : {0}" -f $summary)
    Write-Host '  Downsides      :'
    foreach ($d in $downsides) {
        Write-Host ("    * {0}" -f $d)
    }
    Write-Host ("  Recommendation : {0}" -f $recommendation)

    if ($requiresAck) {
        Write-Host ''
        Write-Host '  WARNING: this is a REDUCED-ASSURANCE credential pathway — it requires explicit operator acknowledgement (-AcknowledgeReducedAssurance) before the tool will proceed.' -ForegroundColor Yellow
    }
    Write-Host ''
}

function Test-CredentialAcknowledgement {
    <#
    .SYNOPSIS
        PURE decision: may the tool proceed on this pathway, and should the operator be prompted?

    .DESCRIPTION
        No OS calls. Encodes the fail-closed acknowledgement truth table for the
        reduced-assurance pathways:

          * RequiresAcknowledgement = $false                 -> proceed, no prompt.
          * Requires + Acknowledged (the flag was supplied)  -> proceed, no prompt.
          * Requires + not acknowledged + interactive        -> do NOT proceed yet;
            the caller should prompt (ShouldContinue) and proceed only on yes.
          * Requires + not acknowledged + non-interactive    -> FAIL CLOSED with an
            actionable message (re-run with -AcknowledgeReducedAssurance).

        This helper isolates the decision so it is testable without any host
        interaction; the entry script owns the actual ShouldContinue prompt.

    .PARAMETER RequiresAcknowledgement
        Whether the selected pathway requires an explicit acknowledgement
        (from Resolve-CredentialPosture).

    .PARAMETER Acknowledged
        Whether the operator passed -AcknowledgeReducedAssurance.

    .PARAMETER Interactive
        Whether the session can prompt the operator (the caller's interactivity
        determination).

    .OUTPUTS
        PSCustomObject with: ShouldProceed (bool), NeedsPrompt (bool), Reason.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [bool]$RequiresAcknowledgement,

        [Parameter(Mandatory)]
        [bool]$Acknowledged,

        [Parameter(Mandatory)]
        [bool]$Interactive
    )

    if (-not $RequiresAcknowledgement) {
        return New-DiscoveryResult -Property @{
            ShouldProceed = $true
            NeedsPrompt   = $false
            Reason        = 'No acknowledgement required for this credential pathway.'
        }
    }

    if ($Acknowledged) {
        return New-DiscoveryResult -Property @{
            ShouldProceed = $true
            NeedsPrompt   = $false
            Reason        = 'Reduced-assurance pathway acknowledged: the -AcknowledgeReducedAssurance flag was supplied.'
        }
    }

    if ($Interactive) {
        return New-DiscoveryResult -Property @{
            ShouldProceed = $false
            NeedsPrompt   = $true
            Reason        = 'Reduced-assurance pathway not acknowledged; the session is interactive — prompt the operator (ShouldContinue) and proceed only on an explicit yes.'
        }
    }

    # Non-interactive, not acknowledged: fail closed with an actionable message.
    New-DiscoveryResult -Property @{
        ShouldProceed = $false
        NeedsPrompt   = $false
        Reason        = 'Refusing to proceed: this is a REDUCED-ASSURANCE credential pathway, it was not acknowledged, and the session is non-interactive so the operator cannot be prompted. Read the credential posture block, then re-run with -AcknowledgeReducedAssurance to accept the reduced assurance.'
    }
}

Export-ModuleMember -Function `
    Resolve-CredentialPosture, `
    Format-CredentialPosture, `
    Test-CredentialAcknowledgement
