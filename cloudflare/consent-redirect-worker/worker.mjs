const HEADERS = {
  "content-type": "text/html; charset=utf-8",
  "cache-control": "no-store, max-age=0",
  "referrer-policy": "no-referrer",
  "x-content-type-options": "nosniff",
  "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
};

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function getStatus(searchParams) {
  const error = searchParams.get("error");
  if (error) {
    return {
      kind: "error",
      title: "Admin consent was not completed",
      body: searchParams.get("error_description") || error,
    };
  }

  const consent = (searchParams.get("admin_consent") || "").toLowerCase();
  if (consent === "true") {
    return {
      kind: "success",
      title: "Admin consent request completed",
      body: "Return to the provisioning terminal. The tool will verify the 53 Microsoft Graph permissions in the tenant.",
    };
  }

  return {
    kind: "neutral",
    title: "Consent landing page",
    body: "Open this page from the Microsoft admin-consent flow. A direct visit does not prove consent was granted.",
  };
}

function renderPage(url) {
  const status = getStatus(url.searchParams);
  const tenant = url.searchParams.get("tenant");
  const state = url.searchParams.get("state");
  const indicator = status.kind === "success" ? "success" : status.kind === "error" ? "error" : "neutral";

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(status.title)}</title>
  <style>
    :root { color-scheme: light; font-family: "Segoe UI", Arial, sans-serif; }
    body { margin: 0; background: #f7f7f8; color: #1f2328; }
    main { max-width: 760px; margin: 9vh auto; padding: 0 24px; }
    .panel { background: #fff; border: 1px solid #d8dee4; border-radius: 8px; padding: 32px; box-shadow: 0 8px 28px rgba(27, 31, 36, 0.08); }
    .mark { width: 12px; height: 12px; border-radius: 50%; display: inline-block; margin-right: 10px; vertical-align: 2px; }
    .success { background: #1a7f37; }
    .error { background: #cf222e; }
    .neutral { background: #57606a; }
    h1 { font-size: 28px; line-height: 1.2; margin: 0 0 16px; font-weight: 650; }
    p { font-size: 16px; line-height: 1.55; margin: 0 0 18px; }
    dl { margin: 24px 0 0; display: grid; grid-template-columns: 120px 1fr; gap: 10px 16px; }
    dt { color: #57606a; }
    dd { margin: 0; overflow-wrap: anywhere; }
    .note { color: #57606a; font-size: 14px; margin-top: 24px; }
  </style>
</head>
<body>
  <main>
    <section class="panel" aria-labelledby="title">
      <h1 id="title"><span class="mark ${indicator}" aria-hidden="true"></span>${escapeHtml(status.title)}</h1>
      <p>${escapeHtml(status.body)}</p>
      <dl>
        <dt>Tenant</dt><dd>${escapeHtml(tenant || "Not returned")}</dd>
        <dt>State</dt><dd>${escapeHtml(state || "Not returned")}</dd>
      </dl>
      <p class="note">This page is only a completion landing page. Graph-side verification remains the source of truth for permission grants.</p>
    </section>
  </main>
</body>
</html>`;
}

export default {
  async fetch(request) {
    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response("Method Not Allowed", {
        status: 405,
        headers: { allow: "GET, HEAD", ...HEADERS },
      });
    }

    const url = new URL(request.url);
    const body = request.method === "HEAD" ? null : renderPage(url);
    return new Response(body, { status: 200, headers: HEADERS });
  },
};

export { escapeHtml, getStatus, renderPage };
