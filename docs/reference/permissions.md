# Permission scoping reference

How the discovery app's permission set is derived from
[`EntraIDAssessmentAppRegistration`](https://github.com/Proaxiom-Cyber/EntraIDAssessmentAppRegistration)
by cross-referencing the
Phase 1 Entra ID discovery runbook (modules 1.03–1.20) and its own scope-area map of
Graph API permissions.

> **GUIDs:** the *Keep* permissions retain their GUIDs from the source app registration's README
> permissions table. The 5 *Add* permissions' GUIDs are to be locked into `permissions.csv` during
> implementation by reading the live Microsoft Graph service principal's `appRoles` (authoritative
> per-tenant), rather than transcribed by hand here.

All permissions are **application** (Role) type and **read-only** unless noted.

---

## Keep — used by Phase 1 discovery (mapped to runbook modules)

| Permission | Scope area / module |
|------------|---------------------|
| `Directory.Read.All` | Tenant architecture (1.03), Hybrid (1.17), Audit (1.18) |
| `Domain.Read.All` | Tenant architecture (1.03) |
| `CrossTenantInformation.ReadBasic.All` | Tenant architecture (1.03), External identities (1.16) |
| `MultiTenantOrganization.Read.All` | Tenant architecture (1.03) |
| `DirectoryRecommendations.Read.All` | Tenant architecture (1.03) |
| `User.Read.All` | User management (1.04) |
| `User.ReadBasic.All` | User management (1.04) — redundant with `User.Read.All`; optional |
| `Group.Read.All` | Group management (1.05) |
| `CustomSecAttributeAssignment.Read.All` | User/group management (1.04/1.05) |
| `CustomSecAttributeDefinition.Read.All` | User/group management (1.04/1.05) |
| `Policy.Read.ConditionalAccess` | Conditional access (1.06) |
| `Policy.Read.All` | Conditional access (1.06), Security defaults (1.19), Audit (1.18) |
| `AuthenticationContext.Read.All` | Conditional access (1.06) |
| `UserAuthenticationMethod.Read.All` | Authentication methods (1.07) |
| `UserAuthMethod-Passkey.Read.All` | Authentication methods (1.07) |
| `Policy.Read.AuthenticationMethod` | Authentication methods (1.07) |
| `PrivilegedAccess.Read.AzureAD` | PIM (1.08), Identity governance (1.13) |
| `PrivilegedAccess.Read.AzureADGroup` | PIM (1.08), Identity governance (1.13) |
| `PrivilegedAccess.Read.AzureResources` | PIM (1.08) — Azure RBAC; optional, see judgment calls |
| `PrivilegedAssignmentSchedule.Read.AzureADGroup` | PIM (1.08) |
| `PrivilegedEligibilitySchedule.Read.AzureADGroup` | PIM (1.08) |
| `RoleManagementPolicy.Read.Directory` | PIM (1.08) |
| `RoleManagement.Read.Directory` | Privileged access / role assignments (1.09) |
| `RoleAssignmentSchedule.Read.Directory` | Privileged access / role assignments (1.09) |
| `RoleEligibilitySchedule.Read.Directory` | Privileged access / role assignments (1.09) |
| `RoleManagementAlert.Read.Directory` | Privileged access / role assignments (1.09) |
| `Application.Read.All` | App registrations (1.10), Enterprise apps (1.11), Workload identities (1.12) |
| `DelegatedPermissionGrant.Read.All` | Enterprise apps & consent (1.11) |
| `Policy.Read.PermissionGrant` | Enterprise apps & consent (1.11), Security defaults (1.19) |
| `IdentityRiskyServicePrincipal.Read.All` | Workload identities (1.12), Identity protection (1.14) |
| `IdentityRiskEvent.Read.All` | Identity protection (1.14) |
| `IdentityRiskyUser.Read.All` | Identity protection (1.14) |
| `Policy.Read.IdentityProtection` | Identity protection (1.14) |
| `Device.Read.All` | Device management (1.15) |
| `DeviceTemplate.Read.All` | Device management (1.15) — niche; optional |
| `Policy.Read.DeviceConfiguration` | Device management (1.15) |
| `DeviceManagementConfiguration.Read.All` | Device management (1.15) |
| `DeviceManagementManagedDevices.Read.All` | Device management (1.15) |
| `DeviceManagementServiceConfig.Read.All` | Device management (1.15) |
| `CrossTenantUserProfileSharing.Read.All` | External identities (1.16) |
| `ExternalUserProfile.Read.All` | External identities (1.16) |
| `IdentityProvider.Read.All` | External identities (1.16) |
| `IdentityUserFlow.Read.All` | External identities (1.16) |
| `AuditLog.Read.All` | Audit & sign-in logging (1.18) — most-used permission in the runbook |
| `SecurityEvents.Read.All` | Audit (1.18), Secure score (1.20) |
| `SecurityActions.Read.All` | Secure score (1.20) |
| `SecurityAlert.Read.All` | Identity protection (1.14), Secure score (1.20) |
| `SecurityIncident.Read.All` | Security posture (1.18/1.20) |

## Add — needed by the runbook, missing from the source app

| Permission | Needed by | Why |
|------------|-----------|-----|
| `EntitlementManagement.Read.All` | Identity governance (1.13) | Access packages, catalogs, assignments, connected orgs |
| `AccessReview.Read.All` | Identity governance (1.13) | Access review definitions and instances |
| `LifecycleWorkflows.Read.All` | Identity governance (1.13) | Lifecycle workflow definitions |
| `Agreement.Read.All` | Identity governance (1.13) | Terms-of-use agreements |
| `Reports.Read.All` | Auth methods (1.07), Audit (1.18), Secure score (1.20) | Auth-method registration + usage reports |

> Without these, module 1.13 (identity governance) fails its collection — this is the
> "insufficiency" the broad app would have hit despite its size.

## Remove — not used by Phase 1 discovery

| Group | Permissions | Why removed |
|-------|-------------|-------------|
| Windows Defender ATP (all 10) | `Machine.Read.All`, `RemediationTasks.Read.All`, `Score.Read.All`, `SecurityConfiguration.Read.All`, `SecurityRecommendation.Read.All`, `Software.Read.All`, `Ti.Read.All`, `Url.Read.All`, `User.Read.All` (ATP), `Vulnerability.Read.All` | Defender for Endpoint — belongs to the `m365defender` add-on, not core discovery |
| Backup & Recovery | `BackupRestore-Configuration.Read.All`, `BackupRestore-Control.Read.All`, `BackupRestore-Monitor.Read.All` | Never referenced |
| Information Protection / Purview | `InformationProtectionConfig.Read.All`, `InformationProtectionPolicy.Read.All`, `SensitivityLabels.Read.All`, `RecordsManagement.Read.All`, `ProtectionScopes.Compute.All` | `purview` add-on |
| Teams | `TeamsAppInstallation.Read.All`, `TeamSettings.Read.All`, `TeamsUserConfiguration.Read.All`, `TeamworkDevice.Read.All` | `teams` add-on |
| Extra Intune detail | `DeviceManagementApps.Read.All`, `DeviceManagementRBAC.Read.All`, `DeviceManagementScripts.Read.All`, `DeviceManagementCloudCA.Read.All`, `CloudPC.Read.All` | `intune` add-on (core keeps only Config/ManagedDevices/ServiceConfig) |
| Threat intel / advanced security | `AttackSimulation.Read.All`, `CloudApp-Discovery.Read.All`, `CustomDetection.Read.All`, `SecurityAnalyzedMessage.Read.All`, `SecurityIdentitiesSensors.Read.All`, `SecurityIdentitiesUserActions.Read.All` | Defender / MDI territory; not referenced in core |
| Mailbox reading | `Mail.Read`, `MailboxSettings.Read` | Reading user data; not needed for Entra posture and the most privacy-sensitive scope to carry |
| PKI | `PublicKeyInfrastructure.Read.All`, `MutualTlsOauthConfiguration.Read.All` | Not referenced |
| Other | `ExternalConnection.Read.All`, `PlaceDevice.Read.All`, `PartnerSecurity.Read.All` | Not referenced |
| Delegated cruft | `User.Read` (Scope) | App is app-only (client credentials); delegated sign-in scope is vestigial |

## Judgment calls (decide per engagement)

| Permission | Consideration |
|------------|---------------|
| `ThreatIntelligence.Read.All` | Referenced once (1.14) for enrichment; only useful if the tenant has Defender TI. Keep if doing TI cross-reference, else drop. |
| `SecurityIdentitiesHealth.Read.All` | Referenced in 1.18 but only fires if Defender for Identity is deployed. Keep if the customer has MDI. |
| `PrivilegedAccess.Read.AzureResources` | Azure ARM RBAC, arguably out of scope for an *Entra ID* assessment. Drop unless covering Azure resource PIM. |
| `User.ReadBasic.All` | Redundant with `User.Read.All`; optional cleanup. |
| `DeviceTemplate.Read.All` | Listed under area 11 but never actually invoked; low-risk either way. |

## Known limitation

`OnPremDirectorySynchronization.Read.All` (used in 1.17 Hybrid) is **delegated-only** and cannot be
granted as an application permission. The runbook treats the resulting 403 as expected and falls
back to `Directory.Read.All`. It is intentionally **not** in the manifest.

---

## Net effect

Roughly **92 → ~62** permissions: drops the most privacy-sensitive scope (mailbox content) and all
add-on surface, while *closing* the governance/reporting gaps that would otherwise break module 1.13.
