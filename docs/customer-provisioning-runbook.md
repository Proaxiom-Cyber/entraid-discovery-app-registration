# Customer provisioning runbook — TPM-bound discovery app

A step-by-step guide to provisioning the least-privilege, TPM-bound Entra ID app
registration used by the Phase 1 discovery security assessment.

This runbook follows the **portal-consent path** ("Path A"): the provisioner creates the
app and embeds the certificate, then **your own Entra administrator grants admin consent
in the portal** — so the moment a privileged identity authorises the permissions is
performed by you, in your tenant, on your own screen. Nothing is consented automatically.

> There is also an automated consent flag (`-GrantConsent`) used by the tool's internal
> test pipeline. It is **not** part of this runbook — this guide deliberately leaves
> consent to your administrator in the portal. The flag is mentioned only as an optional
> advanced shortcut in [Appendix: automated consent](#appendix-automated-consent).

---

## Who does what, and where

There are **two actors** and **two hosts**:

| Actor | Role | Host |
|-------|------|------|
| **Provisioner** | Runs the PowerShell tool to generate the key, create the app, and embed the certificate. | A **TPM-equipped Windows 11 workstation** (the endpoint the credential will be bound to). |
| **Customer Entra admin** | Reviews the requested permissions and grants tenant-wide admin consent. | The **Entra admin centre** (portal), signed in as a Global Administrator or Privileged Role Administrator. |

The private signing key is generated **inside the workstation's TPM** and is
non-exportable: it never leaves that machine. Only the **public certificate** (`.cer`) and,
later, the app's identifiers, cross the boundary between provisioner and customer admin.

---

## Prerequisites

- A **Windows 11 endpoint with a TPM 2.0** present and enabled (the key-generation step
  fails closed without one — see Stage 1).
- **PowerShell 7.x** (or Windows PowerShell 5.1) on that endpoint.
- The **Microsoft.Graph** PowerShell SDK for the app-creation step.
- For Stage 2 (app creation), the provisioner signs in interactively as an
  **Application Administrator** or **Cloud Application Administrator**.
- For Stage 3 (consent), the customer admin is a **Global Administrator** or
  **Privileged Role Administrator**.

---

## Stage 1 — Generate the TPM-bound key and export the public certificate

Run on the **TPM-equipped workstation**. This generates a new RSA-2048 signing key inside
the **Microsoft Platform Crypto Provider** (the TPM-backed key store), proves the private
key is non-exportable, and writes out **only** the public certificate.

```powershell
./New-ProaxiomDiscoveryApp.ps1 -GenerateLocal -PublicCertPath .\discovery.cer
```

Expected output:

```
Discovery certificate provisioned
---------------------------------
  Thumbprint : <thumbprint>
  Subject    : CN=Proaxiom Discovery App
  Store      : Cert:\LocalMachine\My
  Key        : RSA 2048-bit
  Provider   : Microsoft Platform Crypto Provider
  Validity   : <start-date> -> <end-date>
  x5t        : <x5t-base64url>

Connect hint (fill in ClientId / TenantId once the app registration exists):
  Connect-MgGraph -ClientId <appid> -TenantId <tid> -CertificateThumbprint <thumbprint>
```

What this guarantees:

- **The private key never leaves the TPM.** It is created inside the
  Microsoft Platform Crypto Provider, marked **non-exportable**, and the tool actively
  verifies this — it attempts a private-key export and requires the attempt to fail before
  it will continue. `Provider : Microsoft Platform Crypto Provider` confirms the key is
  TPM-resident.
- **Only the public certificate leaves the workstation.** `discovery.cer` contains the
  public key only — there is no private-key material in it. This is the single artefact
  that needs to travel to the app-registration step.
- **It fails closed with no TPM.** If no usable TPM / Microsoft Platform Crypto Provider is
  present, the tool stops with an error rather than silently falling back to a software key.
  A successful run is itself evidence that the key is hardware-bound.

Keep `discovery.cer`. You will pass it to Stage 2.

---

## Stage 2 — Create the app and embed the certificate (no consent)

Run on the same workstation, signed in interactively as an Application Administrator /
Cloud Application Administrator. This creates a **new** app registration and service
principal carrying the trimmed read-only permission set, embedding the public certificate
as the app's credential **at creation** — there is no separate upload step.

Note there is **no `-GrantConsent`** here: the app is created *without* consent, so an
admin can review and grant it deliberately in Stage 3.

```powershell
./New-ProaxiomDiscoveryApp.ps1 -ImportCert -CertPath .\discovery.cer `
  -CreateAppRegistration -DisplayName '<your app name>'
```

Expected output:

```
Discovery certificate provisioned
---------------------------------
  Thumbprint : <thumbprint>
  Subject    : CN=Proaxiom Discovery App
  Store      : (not in a local store)
  Key        : RSA 2048-bit
  Provider   : (public cert / no private key)
  Validity   : <start-date> -> <end-date>
  x5t        : <x5t-base64url>

Connect hint (fill in ClientId / TenantId once the app registration exists):
  Connect-MgGraph -ClientId <appid> -TenantId <tid> -CertificateThumbprint <thumbprint>

Discovery app registration
--------------------------
  DisplayName : <your app name>
  AppId       : <appid>
  TenantId    : <tenantid>
  Thumbprint  : <thumbprint>
  Consent     : NOT granted (see instructions below)

Connect with the TPM-bound certificate:
  Connect-MgGraph -ClientId <appid> -TenantId <tenantid> -CertificateThumbprint <thumbprint>

Admin consent required
----------------------
Admin consent was NOT granted (consent is opt-in; re-run with -GrantConsent to automate it).
Grant tenant-wide admin consent manually via the Entra portal:
  1. Entra admin centre -> Identity -> Applications -> App registrations.
  2. Open the app (Application/client id: <appid>).
  3. API permissions -> "Grant admin consent for <tenant>" -> Yes.
  4. Confirm every permission shows "Granted for <tenant>".

Or use the direct admin-consent URL (sign in as a Privileged Role / Global Administrator):
  https://login.microsoftonline.com/<tenantid>/adminconsent?client_id=<appid>
```

Record the **AppId**, **TenantId**, and **Thumbprint** from this output — they are needed
for Stage 3 (consent) and Stage 4 (token). Hand the **AppId** and the **admin-consent URL**
to the customer Entra admin.

> Running this with `-ImportCert -CertPath .\discovery.cer` means the tool generates **no**
> new key in this step — it embeds the public certificate produced in Stage 1. (If you run
> Stages 1 and 2 in a single sitting on the same endpoint, you can instead use
> `-GenerateLocal -CreateAppRegistration` to do both at once.)

---

## Stage 3 — Customer admin grants consent in the Entra portal

This is the **trust moment**. The app exists but can do nothing until a privileged admin in
**your** tenant reviews its requested permissions and grants consent. Performed by the
**customer Entra administrator** in the portal.

Two equivalent ways to do it:

**Option A — App registrations blade**

1. Entra admin centre → **Identity** → **Applications** → **App registrations**.
2. Open the app by its **Application (client) id** (`<appid>` from Stage 2).
3. **API permissions** → **Grant admin consent for &lt;tenant&gt;** → **Yes**.
4. Confirm **every** permission shows **Granted for &lt;tenant&gt;**.

**Option B — Direct admin-consent URL**

Sign in as a Global Administrator / Privileged Role Administrator and open:

```
https://login.microsoftonline.com/<tenantid>/adminconsent?client_id=<appid>
```

Review the consent screen and approve.

### What the admin is approving

Before approving, the admin can review the full permission list. **All 53 permissions are
read-only** — every one is a `*.Read*` Microsoft Graph **application** permission against
the Microsoft Graph resource (`00000003-0000-0000-c000-000000000000`). There are **no
write permissions, no action-invoking scopes, and no mailbox-content access**.

The complete, GUID-accurate list — what each permission is for and which discovery module
uses it — is in the permission manifest companion:
[`manifests/permissions-companion.md`](../manifests/permissions-companion.md). The set is
**53** permissions: **48 kept** from the broad assessment app (only the reads Phase 1
discovery actually uses) plus **5 added** governance/reporting reads. See
[`docs/reference/permissions.md`](reference/permissions.md) for the full derivation.

The consent is granted **in your tenant**, and you retain full control: you can revoke it
at any time (see [Stage 5](#stage-5--decommission)).

---

## Stage 4 — Acquire a token with the TPM certificate and verify

Back on the **TPM-equipped workstation** (the one that holds the private key), authenticate
the app using its TPM-bound certificate. Substitute the `AppId`, `TenantId`, and
`Thumbprint` recorded in Stage 2.

```powershell
Connect-MgGraph -ClientId <appid> -TenantId <tenantid> -CertificateThumbprint <thumbprint>
```

Verify the connection is app-only and carries the full permission set:

```powershell
(Get-MgContext).AuthType        # -> AppOnly
(Get-MgContext).Scopes.Count    # -> 53
```

Run a live read to confirm the token works end-to-end — for example, read the tenant
organisation:

```powershell
Get-MgOrganization | Select-Object DisplayName, Id
```

How this works: `Connect-MgGraph -CertificateThumbprint` builds a JWT **client assertion**
and signs it **inside the TPM** with the non-exportable private key. Entra matches the
assertion's `x5t` thumbprint to the public certificate you registered in Stage 2 and issues
an app-only token carrying the 53 consented scopes. The signature is produced by the TPM, so
this token can only be obtained on this specific machine.

> This step **must** run on the workstation whose TPM generated the key — that is the whole
> point of the hardware binding. The credential cannot be used from any other device.

---

## Stage 5 — Decommission

The credential **is** the TPM certificate, and the app registration is what makes it usable.
To revoke all access, delete the app registration in your tenant:

- Entra admin centre → **Identity** → **Applications** → **App registrations** → open the
  app (`<appid>`) → **Delete**.

Deleting the app immediately revokes the consent and invalidates the credential — any token
request with the TPM certificate will fail because there is no longer an app to match the
`x5t` thumbprint to. (You may also retire the TPM key on the workstation by deleting the
certificate from its local store; the private key is destroyed with it and cannot be
recovered.)

You can also narrow access without full deletion by removing the key credential from the app
or disabling the service principal — either step stops the certificate from authenticating
while leaving the app object in place.

---

## What this does NOT do

> **The TPM binding is a local, customer-side control — not something Entra enforces.**
>
> - **Entra does not enforce TPM residency for app-credential auth.** The cloud only checks
>   that the caller holds the private key matching the registered public certificate. It has
>   no way to require that the key live in a TPM. The machine-binding is enforced entirely by
>   the TPM refusing to let the key leave the device.
> - **Attestation is local machine-binding evidence only.** The optional `-Attest` flag
>   produces a TPM key-attestation bundle for the engagement evidence pack — Entra does not
>   consume it. On a **virtual TPM** (e.g. a lab vTPM), the tool reports
>   `TpmKeyAttestation-NoHardwareRoot` and **fails closed**: it will never claim a hardware
>   root it cannot prove, and `-RequireHardwareRoot` will hard-fail there by design. Full
>   hardware-root assurance requires physical TPM hardware whose manufacturer EK certificate
>   is visible to Windows. See [`docs/reference/attestation.md`](reference/attestation.md).
> - **The TPM stops key *exfiltration*, not local *use*.** A local administrator on the
>   provisioned box could ask the TPM to sign and obtain tokens; they cannot steal the key
>   and walk away. A hardened, EDR-secured endpoint is the compensating control for in-place
>   abuse.

---

## Appendix: automated consent

The tool can grant tenant-wide admin consent itself with `-GrantConsent` on the
`-CreateAppRegistration` run, instead of leaving it for an admin to click in the portal:

```powershell
./New-ProaxiomDiscoveryApp.ps1 -ImportCert -CertPath .\discovery.cer `
  -CreateAppRegistration -GrantConsent -TenantId <tenantid> -DisplayName '<your app name>'
```

This requires the signed-in identity to itself hold privileged consent rights, and it is
primarily intended for the tool's automated test pipeline. **For a customer engagement the
portal-consent path above is preferred**, because it keeps the explicit approval decision in
the hands of your own Entra administrator, reviewing the permissions on their own screen.
