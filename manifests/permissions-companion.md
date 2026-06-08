# Permissions manifest — companion

Human-readable companion to [`permissions.csv`](./permissions.csv).

This manifest is the exact set of Microsoft Graph **application** permissions requested by the
Phase 1 discovery app registration. It contains **53 permissions** — **48 keep** (carried over from
the broad
[`EntraIDAssessmentAppRegistration`](https://github.com/Proaxiom-Cyber/EntraIDAssessmentAppRegistration)
and confirmed in use) plus **5 add** (governance/reporting reads the broad app was missing). Every
permission is:

- **Microsoft Graph** — `ResourceAppId` `00000003-0000-0000-c000-000000000000` for all 53 rows.
- **Application type** — `Role` (app-only / client-credentials), never delegated.
- **Read-only** — no write, no action-invoking scopes.

Each permission is scoped to one or more modules of the Phase 1 Entra ID discovery runbook (modules
**1.03–1.20**). The derivation and judgment calls behind this set are documented in the project's
permissions reference; this file is the operational view that mirrors `permissions.csv` row-for-row,
with the `PermissionId` GUID included for traceability.

> The `PermissionId` values below are the Microsoft Graph **app role** (`Role`) ids and match
> `permissions.csv` exactly.

---

## Keep — used by Phase 1 discovery (48)

| Permission | Type | Runbook module(s) | Rationale | PermissionId |
|------------|------|-------------------|-----------|--------------|
| `Directory.Read.All` | Role (application) | Tenant architecture (1.03), Hybrid (1.17), Audit (1.18) | Core directory read; also the documented fallback for the delegated-only on-prem sync read | `7ab1d382-f21e-4acd-a863-ba3e13f7da61` |
| `Domain.Read.All` | Role (application) | Tenant architecture (1.03) | Read custom/verified domains | `dbb9058a-0e50-45d7-ae91-66909b5d4664` |
| `CrossTenantInformation.ReadBasic.All` | Role (application) | Tenant architecture (1.03), External identities (1.16) | Basic cross-tenant info | `cac88765-0581-4025-9725-5ebc13f729ee` |
| `MultiTenantOrganization.Read.All` | Role (application) | Tenant architecture (1.03) | Read multi-tenant org configuration | `4f994bc0-31bb-44bb-b480-7a7c1be8c02e` |
| `DirectoryRecommendations.Read.All` | Role (application) | Tenant architecture (1.03) | Read Entra directory recommendations | `ae73097b-cb2a-4447-b064-5d80f6093921` |
| `User.Read.All` | Role (application) | User management (1.04) | Read all user profiles | `df021288-bdef-4463-88db-98f22de89214` |
| `User.ReadBasic.All` | Role (application) | User management (1.04) | Redundant with `User.Read.All`; optional | `97235f07-e226-4f63-ace3-39588e11d3a1` |
| `Group.Read.All` | Role (application) | Group management (1.05) | Read all groups | `5b567255-7703-4780-807c-7be8301ae99b` |
| `CustomSecAttributeAssignment.Read.All` | Role (application) | User/group management (1.04/1.05) | Read custom security attribute assignments | `3b37c5a4-1226-493d-bec3-5d6c6b866f3f` |
| `CustomSecAttributeDefinition.Read.All` | Role (application) | User/group management (1.04/1.05) | Read custom security attribute definitions | `b185aa14-d8d2-42c1-a685-0f5596613624` |
| `Policy.Read.ConditionalAccess` | Role (application) | Conditional access (1.06) | Read Conditional Access policies | `37730810-e9ba-4e46-b07e-8ca78d182097` |
| `Policy.Read.All` | Role (application) | Conditional access (1.06), Security defaults (1.19), Audit (1.18) | Read all org policies | `246dd0d5-5bd0-4def-940b-0421030a5b68` |
| `AuthenticationContext.Read.All` | Role (application) | Conditional access (1.06) | Read authentication context class references | `381f742f-e1f8-4309-b4ab-e3d91ae4c5c1` |
| `UserAuthenticationMethod.Read.All` | Role (application) | Authentication methods (1.07) | Read users' registered auth methods | `38d9df27-64da-44fd-b7c5-a6fbac20248f` |
| `UserAuthMethod-Passkey.Read.All` | Role (application) | Authentication methods (1.07) | Read passkey (FIDO2) auth method detail | `72e00c1d-3e3d-43bb-a0b9-c435611bb1d2` |
| `Policy.Read.AuthenticationMethod` | Role (application) | Authentication methods (1.07) | Read authentication methods policy | `8e3bc81b-d2f3-4b7b-838c-32c88218d2f0` |
| `PrivilegedAccess.Read.AzureAD` | Role (application) | PIM (1.08), Identity governance (1.13) | Read PIM for Entra roles | `4cdc2547-9148-4295-8d11-be0db1391d6b` |
| `PrivilegedAccess.Read.AzureADGroup` | Role (application) | PIM (1.08), Identity governance (1.13) | Read PIM for groups | `01e37dc9-c035-40bd-b438-b2879c4870a6` |
| `PrivilegedAccess.Read.AzureResources` | Role (application) | PIM (1.08) | Azure RBAC PIM; optional, see judgment calls | `5df6fe86-1be0-44eb-b916-7bd443a71236` |
| `PrivilegedAssignmentSchedule.Read.AzureADGroup` | Role (application) | PIM (1.08) | Read group PIM active assignment schedules | `cd4161cb-f098-48f8-a884-1eda9a42434c` |
| `PrivilegedEligibilitySchedule.Read.AzureADGroup` | Role (application) | PIM (1.08) | Read group PIM eligibility schedules | `edb419d6-7edc-42a3-9345-509bfdf5d87c` |
| `RoleManagementPolicy.Read.Directory` | Role (application) | PIM (1.08) | Read directory role management policies (PIM settings) | `fdc4c997-9942-4479-bfcb-75a36d1138df` |
| `RoleManagement.Read.Directory` | Role (application) | Privileged access / role assignments (1.09) | Read directory RBAC role definitions/assignments | `483bed4a-2ad3-4361-a73b-c83ccdbdc53c` |
| `RoleAssignmentSchedule.Read.Directory` | Role (application) | Privileged access / role assignments (1.09) | Read directory role active assignment schedules | `d5fe8ce8-684c-4c83-a52c-46e882ce4be1` |
| `RoleEligibilitySchedule.Read.Directory` | Role (application) | Privileged access / role assignments (1.09) | Read directory role eligibility schedules | `ff278e11-4a33-4d0c-83d2-d01dc58929a5` |
| `RoleManagementAlert.Read.Directory` | Role (application) | Privileged access / role assignments (1.09) | Read PIM/role security alerts | `ef31918f-2d50-4755-8943-b8638c0a077e` |
| `Application.Read.All` | Role (application) | App registrations (1.10), Enterprise apps (1.11), Workload identities (1.12) | Read all app registrations and service principals | `9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30` |
| `DelegatedPermissionGrant.Read.All` | Role (application) | Enterprise apps & consent (1.11) | Read delegated (OAuth2) permission grants | `81b4724a-58aa-41c1-8a55-84ef97466587` |
| `Policy.Read.PermissionGrant` | Role (application) | Enterprise apps & consent (1.11), Security defaults (1.19) | Read consent/permission-grant policies | `9e640839-a198-48fb-8b9a-013fd6f6cbcd` |
| `IdentityRiskyServicePrincipal.Read.All` | Role (application) | Workload identities (1.12), Identity protection (1.14) | Read risky service principals | `607c7344-0eed-41e5-823a-9695ebe1b7b0` |
| `IdentityRiskEvent.Read.All` | Role (application) | Identity protection (1.14) | Read Identity Protection risk detections | `6e472fd1-ad78-48da-a0f0-97ab2c6b769e` |
| `IdentityRiskyUser.Read.All` | Role (application) | Identity protection (1.14) | Read risky users | `dc5007c0-2d7d-4c42-879c-2dab87571379` |
| `Policy.Read.IdentityProtection` | Role (application) | Identity protection (1.14) | Read Identity Protection policies | `b21b72f6-4e6a-4533-9112-47eea9f97b28` |
| `Device.Read.All` | Role (application) | Device management (1.15) | Read all device objects | `7438b122-aefc-4978-80ed-43db9fcc7715` |
| `DeviceTemplate.Read.All` | Role (application) | Device management (1.15) | Read device templates; niche, optional | `dd9febb5-0c6d-419f-b256-3afe12c6adeb` |
| `Policy.Read.DeviceConfiguration` | Role (application) | Device management (1.15) | Read device configuration policy | `bdba4817-6ba1-4a7c-8a01-be9bc7c242dd` |
| `DeviceManagementConfiguration.Read.All` | Role (application) | Device management (1.15) | Read Intune device configuration/compliance policies | `dc377aa6-52d8-4e23-b271-2a7ae04cedf3` |
| `DeviceManagementManagedDevices.Read.All` | Role (application) | Device management (1.15) | Read Intune-managed device properties | `2f51be20-0bb4-4fed-bf7b-db946066c75e` |
| `DeviceManagementServiceConfig.Read.All` | Role (application) | Device management (1.15) | Read Intune service configuration | `06a5fe6d-c49d-46a7-b082-56b1b14103c7` |
| `CrossTenantUserProfileSharing.Read.All` | Role (application) | External identities (1.16) | Read cross-tenant user profile sharing | `8b919d44-6192-4f3d-8a3b-f86f8069ae3c` |
| `ExternalUserProfile.Read.All` | Role (application) | External identities (1.16) | Read external user profiles | `1987d7a0-d602-4262-ab90-cfdd43b37545` |
| `IdentityProvider.Read.All` | Role (application) | External identities (1.16) | Read external identity providers | `e321f0bb-e7f7-481e-bb28-e3b0b32d4bd0` |
| `IdentityUserFlow.Read.All` | Role (application) | External identities (1.16) | Read user flows (External ID / B2C-style) | `1b0c317f-dd31-4305-9932-259a8b6e8099` |
| `AuditLog.Read.All` | Role (application) | Audit & sign-in logging (1.18) | Read audit and sign-in logs; most-used permission in the runbook | `b0afded3-3588-46d8-8b3d-9842eff778da` |
| `SecurityEvents.Read.All` | Role (application) | Audit (1.18), Secure score (1.20) | Read security events | `bf394140-e372-4bf9-a898-299cfc7564e5` |
| `SecurityActions.Read.All` | Role (application) | Secure score (1.20) | Read security actions | `5e0edab9-c148-49d0-b423-ac253e121825` |
| `SecurityAlert.Read.All` | Role (application) | Identity protection (1.14), Secure score (1.20) | Read all security alerts | `472e4a4d-bb4a-4026-98d1-0b0d74cb74a5` |
| `SecurityIncident.Read.All` | Role (application) | Security posture (1.18/1.20) | Read security incidents | `45cc0394-e837-488b-a098-1918f48d186c` |

## Add — needed by the runbook, missing from the source app (5)

| Permission | Type | Runbook module(s) | Rationale | PermissionId |
|------------|------|-------------------|-----------|--------------|
| `EntitlementManagement.Read.All` | Role (application) | Identity governance (1.13) | Access packages, catalogs, assignments, connected orgs | `c74fd47d-ed3c-45c3-9a9e-b8676de685d2` |
| `AccessReview.Read.All` | Role (application) | Identity governance (1.13) | Access review definitions and instances | `d07a8cc0-3d51-4b77-b3b0-32704d1f69fa` |
| `LifecycleWorkflows.Read.All` | Role (application) | Identity governance (1.13) | Lifecycle workflow definitions | `7c67316a-232a-4b84-be22-cea2c0906404` |
| `Agreement.Read.All` | Role (application) | Identity governance (1.13) | Terms-of-use agreements | `2f3e6f8c-093b-4c57-a58b-ba5ce494a169` |
| `Reports.Read.All` | Role (application) | Auth methods (1.07), Audit (1.18), Secure score (1.20) | Auth-method registration + usage reports | `230c1aed-a721-4c5d-9cb4-a90514e508ef` |

> Without the five **Add** permissions, module 1.13 (identity governance) fails its collection — the
> "insufficiency" the broad app would have hit despite its size.

---

## Known limitation — `OnPremDirectorySynchronization.Read.All`

`OnPremDirectorySynchronization.Read.All` is used by module **1.17 (Hybrid)** to read the on-premises
directory synchronization configuration. It is **delegated-only**: Microsoft Graph does **not**
publish an application (`Role`) variant of this permission, so it **cannot be granted to an app-only
client-credentials identity** and **cannot appear in `permissions.csv`**. It is therefore
**intentionally excluded** from this manifest.

The runbook accounts for this directly:

- When module 1.17 calls the on-prem sync endpoint app-only, Graph returns **HTTP 403** — this is
  **expected**, not a misconfiguration or a missing grant.
- The module **falls back to `Directory.Read.All`** (already in the keep set above), which surfaces
  the directory-level sync signals available app-only.

No operator action closes this gap; it is a platform limitation of Microsoft Graph.

---

## Net count

This manifest is **53** permissions (48 keep + 5 add), matching `permissions.csv` exactly.

The PRD's figure of "~62" net permissions is an **approximation** from the planning phase. The
authoritative number is the one enumerated here: the explicit keep + add lists total **53**.
