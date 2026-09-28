# Certificate assessment app setup

Use this path to create a dedicated Microsoft Entra assessment app or add a
certificate to an existing app. Shell and PowerShell entrypoints use one PowerShell
engine. Both require **PowerShell 7.2 or later**. Customer app setup does not need
Python or a separate sign-in app registration.

The assessment app receives the selected read-only Microsoft Graph application
permissions. An administrator uses a separate delegated sign-in to make the setup
changes. This path supports commercial tenants in the Microsoft public cloud.

The optional Mac helper creates a non-extractable RSA key in the software login
Keychain. It is **not TPM-backed or Secure Enclave-backed**. For the existing Windows
TPM workflow, use the [customer provisioning runbook](../docs/customer-provisioning-runbook.md).

## Download a reviewed revision

Get this repository from a reviewed release or a specific public commit. Ask the
assessment operator for the approved revision and permission profile. Inspect the
downloaded files before execution. Do not execute a script piped from a URL.

For example, replace the revision placeholder with the approved full commit ID:

```sh
git clone https://github.com/Proaxiom-Cyber/entraid-discovery-app-registration.git
cd entraid-discovery-app-registration
git checkout --detach '<REVIEWED-PUBLIC-COMMIT>'
```

The public certificate is delivered separately for the engagement. Compare its
SHA-256 digest with the value supplied through the agreed handover channel. The
certificate digest identifies the expected public file; it does not prove hardware
protection of the private key.

## Choose the permission profile

| Profile | Application permissions | Intended use |
|---|---:|---|
| [allcaps-mfa.json](profiles/allcaps-mfa.json) | 12 | Conditional Access and MFA analysis, including the related identity, device and risk reads. |
| [assessment-read.json](profiles/assessment-read.json) | 17 | The MFA profile plus wider Intune, Secure Score and federation reads. |

Each profile records a purpose for each permission. Select the profile that matches
the agreed collection. Granting a permission does not make a collector use its
endpoint. It also does not provide unavailable licences, features or log history.

`Directory.Read.All` and several other permissions cover broad tenant populations.
These profiles are practical read bundles, not claims of minimum permissions for
every individual endpoint. Read access can expose personal and security data.

## Prepare the customer configuration

Copy [customer.example.json](examples/customer.example.json) into an engagement
working directory outside this checkout. Replace its placeholders. Update the
profile path to the downloaded profile and the certificate path to the supplied
public DER `.cer` file. Relative paths resolve from the configuration file's folder.
Keep the configuration and output with the engagement records.

| Field | Meaning |
|---|---|
| `tenant_id` | The target tenant GUID. Confirm it before sign-in. |
| `display_name` | An agreed name for a new app. A name does not identify an existing app for update. |
| `output_directory` | Folder for `plan.json` and the resumable `setup-receipt.json`. Retain the receipt between runs. |
| `application_id` | Optional application/client GUID for an existing app. This is not the app's object GUID. |
| `permission_profile` | Profile path. Omit it for a certificate-only update. |
| `certificates` | Public certificate paths and expected SHA-256 values. An array allows more than one certificate. |
| `engagement_reference` | Optional nonsecret reference for the setup records. |

Creating an app needs a profile and at least one certificate. For an existing app,
use its explicit application/client ID or the saved receipt. Reuse that identity
for subsequent runs. The engine adds missing requested certificates and grants.
It preserves existing certificates and permissions and avoids duplicate additions.
A certificate-only update omits the profile and changes no permission grants.

## Plan, preview, then apply

The local plan needs no Microsoft Graph module or tenant connection. Online modes
need the Microsoft Graph Authentication module and an administrator sign-in. Install
the reviewed module version through your normal software process. A basic install is:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

Use one entrypoint. These examples assume the current directory is
`certificate-assessment` and the filled configuration is outside the checkout.

| Mode | POSIX shell, Linux or macOS | PowerShell, Windows, Linux or macOS |
|---|---|---|
| Local intent, no sign-in | `./setup.sh --config ../../engagement/setup.json` | `./Setup-AssessmentApp.ps1 -Config ../../engagement/setup.json` |
| Online read-only difference | `./setup.sh --config ../../engagement/setup.json --preview` | `./Setup-AssessmentApp.ps1 -Config ../../engagement/setup.json -Preview` |
| Apply missing changes | `./setup.sh --config ../../engagement/setup.json --apply` | `./Setup-AssessmentApp.ps1 -Config ../../engagement/setup.json -Apply` |

On Windows, use `pwsh -NoProfile -File` before the PowerShell script path if your
current shell is not PowerShell 7. Paths with spaces need quotes. The shared engine
is [Sync-AssessmentApp.ps1](Sync-AssessmentApp.ps1); the launchers add no separate
provisioning behavior.

Review `plan.json` before the online steps. A local plan records intent; it cannot
show current tenant state. The preview signs in and reads the current app state.
Review its proposed changes before `--apply` or `-Apply`. Preserve the receipt even
if a run fails partway through. Reconcile the recorded IDs and completed operations
before a retry. Do not create another app to work around a partial run.

Arrange a window without concurrent certificate edits on the same app. Graph's
certificate update replaces the credential array. Fresh reads and verification
reduce overwrite risk, but do not provide a guaranteed atomic compare-and-swap.

## Administrator authority and authentication

Profile grants require a **Privileged Role Administrator**, or a custom role with
the relevant consent authority. Application Administrator and Cloud Application
Administrator cannot grant Microsoft Graph application permissions merely because
they can manage an app. Use the customer's normal privileged-access activation
process. [Microsoft admin-consent guidance](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/grant-admin-consent).

The preview requests delegated `Application.Read.All`. Apply requests
`Application.ReadWrite.All`; it also requests `AppRoleAssignment.ReadWrite.All`
when a permission profile is present. A certificate-only update requests only
`Application.ReadWrite.All`. These write scopes belong to the administrator's
setup session. The assessment app receives only the selected read roles.

The engine uses Microsoft Graph PowerShell's supported sign-in and a process-scoped
context. It does not serialize tokens or ask you to paste one. On Windows, the SDK
can use the operating system's authentication broker and its protected cache.
Process scope does not mean that no browser or broker session exists.
[Microsoft Graph authentication](https://learn.microsoft.com/en-us/powershell/microsoftgraph/authentication-commands).

Return the receipt and approved public certificate metadata to the operator. Do not
send an access token, client assertion, password, PFX, or private key. A successful
setup receipt proves the recorded app changes, not that every assessment endpoint
is licensed, accessible or complete.

## Operator: prepare a certificate on a Mac

This separate step needs macOS, an unlocked login Keychain, the Swift compiler,
Python 3.11 or later, and [the Mac requirements](macos/requirements.txt).
Use a fresh key tag for each customer engagement. Choose a unique value instead of
reusing a sample tag.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r macos/requirements.txt
python macos/mac_certificate.py prepare \
  --output-dir ../../engagement/public-certificate \
  --key-tag 'com.proaxiom.assessment.<customer-slug>.<unique-run>' \
  --common-name 'Customer Entra assessment' \
  --days 60
```

The default validity is 60 days; the helper accepts 1–90 days. It exports
`certificate.cer` and `certificate-metadata.json`. Send only these public files.
Keep the key tag and helper build records with the operator records. The helper
checks its source and compiled binary hashes before reuse. Keep it at a stable path.

The helper checks the key's non-extractable attribute and verifies signatures. Those
checks concern a software Keychain key, not hardware attestation. Its Python API
provides `CertificateSigner` and `CertificateTokenProvider` for an approved collector.
It has no command that prints tokens. This setup package does not run allcaps or
collect customer assessment data.

## Close or reduce access

For a dedicated app, the customer can disable the enterprise application when
collection ends, then remove its service principal and app registration. Use the
receipt's object IDs to identify both records. Record the removal and retain the
receipt as engagement evidence.

For an app that predated the engagement, remove only the engagement credential and
any separately approved engagement grants after a dependency review. Do not delete
the app or another operator's certificate. Additive setup preserves those records;
it does not decide which are safe to remove.

The operator separately removes the engagement's key from the Mac through the
approved Keychain administration procedure. Certificate expiry does not delete
the app, its permissions, or the local key. No production cleanup command is
included in this package.

## Tests and limits

The new tests use synthetic fixtures and mocked Graph operations. They make no
tenant calls. Run them from the repository root:

```sh
pwsh -NoProfile -File certificate-assessment/tests/Test-AssessmentApp.ps1
python -m pytest -q certificate-assessment/tests/test_launchers.py
python -m pytest -q certificate-assessment/macos/test_mac_certificate.py
```

Python test commands need `pytest`; the Mac tests also need the Mac requirements.
Native Keychain tests skip on non-macOS systems. The CI workflow runs the shared
engine tests on Windows, Linux and macOS. Its optional native test step runs only
when a login Keychain is available; a missing Keychain is an explicit skip.
Neither mocked tests nor local native tests establish customer consent or live
tenant compatibility.
