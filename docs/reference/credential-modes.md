# Credential pathways reference

How the discovery tool's `-CredentialMode` switch selects the credential the app
registration authenticates with, what each pathway does and does **not** assure, and how
the acknowledgement gate on the reduced-assurance pathways behaves.

> **The default is the strongest pathway.** `TpmBound` — a non-exportable key generated
> inside the local machine's TPM — is the default and the recommended mode, and the tool
> **never downgrades on its own**: there is no silent fallback from `TpmBound` to anything
> weaker. Every other pathway is an explicit opt-in. Every mode prints its security
> posture **before** anything is written to the tenant, and the two reduced-assurance
> modes additionally require a recorded acknowledgement.

Back-compatibility: existing invocations keep working. A `-GenerateLocal` run *is* the
`TpmBound` pathway (the default), and a plain `-CertPath` import *is* the
`ImportPublicCert` shape — `-CredentialMode` simply makes the choice, and its security
posture, explicit.

---

## The assurance ladder

| Mode | Rank | Where the private key lives | Machine-bound? | Ack required |
|------|------|-----------------------------|----------------|--------------|
| [`TpmBound`](#tpmbound-default) (default) | 1 — highest | This machine's TPM (non-exportable) | Yes — this machine | No |
| [`ProviderHostedCert`](#providerhostedcert) | 2 — high | A TPM on a Proaxiom-operated Azure VM | Yes — Proaxiom's VM (Proaxiom custody) | No (custody disclosed) |
| [`ImportPublicCert`](#importpubliccert) | 3 — holder-dependent | Wherever the holder keeps it — the tool never sees it | Unknown to the tool | No |
| [`ImportPrivateKey`](#importprivatekey) | 4 — reduced | A PFX file that travelled between parties | No | **Yes** |
| [`ClientSecret`](#clientsecret) | 5 — lowest | No key at all — a bearer secret string | No | **Yes** |

Recommendation order: **`TpmBound` > `ProviderHostedCert` > `ImportPublicCert` >
`ImportPrivateKey` > `ClientSecret`** — see [Choosing a pathway](#choosing-a-pathway).

---

## Posture disclosure and the acknowledgement gate

Every run prints the selected pathway's **security-posture block first** — what the
pathway binds, what it does not, and who holds the key — **before any tenant write**.
This is unconditional: no switch disables it, and it applies to the default mode too.

The two reduced-assurance modes (`ImportPrivateKey`, `ClientSecret`) additionally gate on
an explicit acknowledgement after the posture block:

| Context | Behaviour |
|---------|-----------|
| Interactive session | The tool prompts (Y/N). Anything other than an explicit yes aborts the run. |
| Non-interactive (scripted) | `-AcknowledgeReducedAssurance` must be supplied. |
| Neither | The tool **fails closed**: it exits without touching the tenant. |

The other three pathways print their posture (including the `ProviderHostedCert` custody
disclosure) but do not prompt.

---

## `TpmBound` (default)

**Mechanics.** Generates a new RSA-2048 signing key inside **this machine's TPM** via the
Microsoft Platform Crypto Provider, `KeyExportPolicy = NonExportable`. The tool actively
verifies non-exportability (a private-key export attempt must fail before it continues)
and exports **only the public certificate** (`.cer`) — the private key physically cannot
leave the machine. If no usable TPM / Platform Crypto Provider is present, the tool
**fails closed within this mode**: no software-key fallback, no silent downgrade to
another credential mode.

**What you experience.** Run the tool on the TPM-equipped Windows endpoint that will
perform the discovery collection. One run produces the key, the certificate, and (with
`-CreateAppRegistration`) the app. From then on, tokens can be acquired **only from this
machine** — the TPM signs each client assertion.

**Downsides.** Requires a Windows endpoint with a TPM 2.0; the credential is welded to
that endpoint (a lost or rebuilt machine means re-provisioning); collection must run from
that machine.

**When to choose it.** Always, unless the engagement genuinely cannot run collection from
a single controlled Windows endpoint. It is the default for a reason: possession of the
credential is enforced by hardware, not by policy.

**Switches.** `TpmBound` is the default, so `-CredentialMode` may be omitted:

```powershell
./New-ProaxiomDiscoveryApp.ps1 -GenerateLocal -PublicCertPath .\discovery.cer
# equivalent: add -CredentialMode TpmBound explicitly
```

---

## `ProviderHostedCert`

**Mechanics.** Proaxiom generates the key **TPM-bound on a Proaxiom-operated Azure VM**
(Trusted Launch / Confidential VM) and supplies the **public** certificate plus,
optionally, a TPM attestation bundle. The customer-side run imports the public
certificate (`-CertPath`) and can verify the supplied bundle (`-AttestationPath`). The
private key stays inside the Azure VM's TPM — non-exportable there, exactly as in
`TpmBound`, just on Proaxiom's machine instead of yours.

**What you experience.** Receive `proaxiom-provided.cer` (and optionally a `bundle.json`
attestation bundle) from Proaxiom, then run the tool to create the app registration with
that certificate. Tokens are acquired by Proaxiom from its hosted VM — no customer
endpoint is needed.

**Downsides.** The key is hardware-bound, but **Proaxiom retains custody** of it: the
control that `TpmBound` enforces with *your* hardware becomes a **trust / contract
trade-off** — you are trusting Proaxiom's operation of the hosting VM. Hardware-root
attestation validation on Azure (proving the hosting TPM chains to a trusted cloud root)
is a documented follow-on — see [`docs/reference/attestation.md`](attestation.md).

**When to choose it.** Hardware-bound key assurance is wanted but no customer endpoint is
available or practical, and provider custody is acceptable under the engagement contract.

**Switches.**

```powershell
./New-ProaxiomDiscoveryApp.ps1 -CredentialMode ProviderHostedCert `
  -CertPath .\proaxiom-provided.cer -AttestationPath .\bundle.json `
  -CreateAppRegistration -DisplayName '<your app name>'
```

`-AttestationPath` is optional; when supplied, the bundle is verified and reported under
the same honesty rules as `-Attest` (see the attestation reference).

---

## `ImportPublicCert`

**Mechanics.** The customer supplies their **own** public certificate (`-CertPath`,
`.cer` / PEM / base64), produced by whatever key infrastructure they trust — an HSM, a
smartcard, their own TPM process. The tool embeds the public certificate in the app
registration and **never sees the private key**.

**What you experience.** Bring a `.cer`; the tool performs the app-registration stage;
key custody and key hygiene remain entirely with you.

**Downsides.** Assurance is **entirely holder-dependent**: the tool cannot verify
non-exportability, where the key lives, or who can use it. The pathway is exactly as
strong as the holder's key management — possibly stronger than `TpmBound` (a managed
HSM), possibly far weaker (an exportable software key on a shared box). The posture block
states precisely this.

**When to choose it.** The customer has an established key-management discipline and
wants — or is required — to keep custody of the key material.

**Switches.**

```powershell
./New-ProaxiomDiscoveryApp.ps1 -CredentialMode ImportPublicCert -CertPath .\customer.cer `
  -CreateAppRegistration -DisplayName '<your app name>'
```

---

## `ImportPrivateKey`

> **Acknowledgement required** — see [the gate](#posture-disclosure-and-the-acknowledgement-gate).

**Mechanics.** The customer supplies a **PFX/P12 containing the private key** plus its
password (`-PfxPath`; `-PfxPassword` as a SecureString, prompted interactively when
omitted). The tool installs it into `LocalMachine\My` with the **store copy marked
non-exportable**.

**What you experience.** Hand the tool the PFX and its password; the app registration
uses the contained certificate; signing happens from the machine the PFX was imported on.

**Downsides.** The key is a **file that travelled between parties**. Marking the store
copy non-exportable does **not** undo that: every copy of the source PFX — the original,
the transfer copy, a backup, an attachment — can mint tokens from **anywhere**, for
anyone holding PFX + password. There is no machine binding. **The source PFX remains the
exposure after import.**

**When to choose it.** Only when an existing PFX-based issuance process is mandated and
neither on-endpoint generation (`TpmBound`) nor public-cert import (`ImportPublicCert`)
is possible. Pair it with the hygiene rules below: short validity, file and password
transferred as **separate one-time Proaxiom Pass links**, and **delete every copy of the
PFX** once imported.

**Switches.**

```powershell
./New-ProaxiomDiscoveryApp.ps1 -CredentialMode ImportPrivateKey -PfxPath .\supplied.pfx `
  -CreateAppRegistration -DisplayName '<your app name>' -AcknowledgeReducedAssurance
# interactive runs may omit -AcknowledgeReducedAssurance and answer the prompt instead;
# pass -PfxPassword <SecureString> for non-interactive use (prompted when omitted)
```

---

## `ClientSecret`

> **Acknowledgement required** — see [the gate](#posture-disclosure-and-the-acknowledgement-gate).

**Mechanics.** No certificate at all: the tool adds a **generated secret**
(`passwordCredential`) to the app registration. The secret value is printed exactly
**once**, together with handover instructions; the tool **never writes it to a file** and
cannot show it again.

**What you experience.** The app authenticates with a string. The tool prints the value
once; you place it straight into Proaxiom Pass and share the one-time link.

**Downsides.** A client secret is a **bearer credential**: anyone holding the string *is*
the app, from anywhere — no possession proof, no machine binding, nothing to attest.
Secrets leak easily (logs, shell history, chat, screenshots). This is the weakest pathway
the tool supports.

**When to choose it.** Last resort — tooling or platform constraints that genuinely
cannot perform certificate authentication. Use the shortest practical validity and
rotate.

**Switches.**

```powershell
./New-ProaxiomDiscoveryApp.ps1 -CredentialMode ClientSecret `
  -CreateAppRegistration -DisplayName '<your app name>' -AcknowledgeReducedAssurance
```

---

## Secret and PFX handover — Proaxiom Pass

The reduced-assurance pathways move secret material between parties. The handover channel
is **Proaxiom Pass — <https://pass.proaxiom.com>**: one-time links with a short expiry,
destroyed on first read.

- **Client secret:** the tool prints the value once and never persists it. Place it
  straight into a one-time Proaxiom Pass link; never email or message the raw value;
  treat console scrollback and the clipboard as transient exposure to be cleared.
- **PFX:** transfer the **file and the password as two separate one-time links** — an
  intercepted single link then yields nothing usable. After a successful import, **delete
  every copy of the PFX** (source, transfer, downloads): the store copy is
  non-exportable, but any surviving file copy is a portable credential.
- **Validity and rotation:** keep reduced-assurance credentials short-lived and rotate
  them — a leaked short-lived secret has a bounded blast radius.

---

## Choosing a pathway

Work down the ladder and stop at the first pathway you can satisfy:

1. **Can collection run from a TPM-equipped Windows endpoint you control?** →
   **`TpmBound`** (the default). Hardware possession proof, no custody questions.
2. **No suitable endpoint, but hardware binding still wanted?** →
   **`ProviderHostedCert`**, if Proaxiom key custody is acceptable contractually.
3. **You operate your own key infrastructure (HSM / smartcard / managed PKI)?** →
   **`ImportPublicCert`**. Custody stays with you; the assurance is yours to maintain.
4. **A private key must move between parties anyway?** → **`ImportPrivateKey`**,
   acknowledged, with the PFX hygiene rules above.
5. **Certificate authentication is genuinely impossible?** → **`ClientSecret`**,
   acknowledged, short-lived, rotated.

The order is deliberate: **`TpmBound` > `ProviderHostedCert` > `ImportPublicCert` >
`ImportPrivateKey` > `ClientSecret`**. Each step down trades hardware- or
holder-enforced possession for convenience. The posture block and the acknowledgement
gate exist so that the trade is made knowingly — never by accident, and never silently.

---

## Summary

- `-CredentialMode` selects one of five pathways; **`TpmBound` is the default**, and the
  tool never downgrades on its own — weaker pathways are explicit opt-ins.
- Every mode prints its **security posture before any tenant write**.
- `ImportPrivateKey` and `ClientSecret` require an **acknowledgement** (interactive
  prompt or `-AcknowledgeReducedAssurance`) and **fail closed** without it.
- Client secrets are printed **once** and never persisted by the tool; handover is via
  **Proaxiom Pass** one-time links (PFX: file and password in separate links; delete the
  PFX after import).
- Choose the highest pathway you can satisfy: `TpmBound` > `ProviderHostedCert` >
  `ImportPublicCert` > `ImportPrivateKey` > `ClientSecret`.
