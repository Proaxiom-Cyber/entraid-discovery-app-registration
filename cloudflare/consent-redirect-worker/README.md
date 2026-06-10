# Entra discovery consent redirect Worker

Cloudflare Worker landing page for the Path A Microsoft admin-consent redirect.

The app registration must include this Worker URL as a reply URL, and the direct
admin-consent URL must include it as `redirect_uri`. The discovery tool does both
when `-ConsentRedirectUri` is supplied during `-CreateAppRegistration`.

```powershell
./New-ProaxiomDiscoveryApp.ps1 -ImportCert -CertPath .\discovery.cer `
  -CreateAppRegistration -DisplayName '<your app name>' `
  -ConsentRedirectUri https://consent.proaxiom.com/entraid-discovery/complete
```

Local tests:

```bash
node --test cloudflare/consent-redirect-worker/worker.test.mjs
```

Cloudflare deploy:

```bash
cd cloudflare/consent-redirect-worker
npx wrangler deploy
```

The Worker is stateless. It does not verify consent, store data, set cookies, or
use secrets. Graph-side verification remains the source of truth for whether the
53 Microsoft Graph application permissions landed.
