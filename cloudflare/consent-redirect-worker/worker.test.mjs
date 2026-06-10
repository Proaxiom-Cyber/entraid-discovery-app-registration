import assert from "node:assert/strict";
import test from "node:test";
import worker, { escapeHtml } from "./worker.mjs";

async function fetchText(url, init) {
  const response = await worker.fetch(new Request(url, init));
  return {
    response,
    text: await response.text(),
  };
}

test("renders a success landing page for Microsoft admin_consent=True", async () => {
  const { response, text } = await fetchText(
    "https://consent.example.test/entraid-discovery/complete?admin_consent=True&tenant=tid-1&state=proaxiom-entraid-discovery",
  );

  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "no-store, max-age=0");
  assert.match(text, /Admin consent request completed/);
  assert.match(text, /tid-1/);
  assert.match(text, /Graph-side verification remains the source of truth/);
});

test("renders Microsoft error details safely", async () => {
  const { response, text } = await fetchText(
    "https://consent.example.test/entraid-discovery/complete?error=access_denied&error_description=%3Cscript%3Ebad%3C%2Fscript%3E",
  );

  assert.equal(response.status, 200);
  assert.match(text, /Admin consent was not completed/);
  assert.match(text, /&lt;script&gt;bad&lt;\/script&gt;/);
  assert.doesNotMatch(text, /<script>bad<\/script>/);
});

test("rejects non-GET methods", async () => {
  const response = await worker.fetch(
    new Request("https://consent.example.test/entraid-discovery/complete", { method: "POST" }),
  );

  assert.equal(response.status, 405);
  assert.equal(response.headers.get("allow"), "GET, HEAD");
});

test("escapeHtml escapes markup and quotes", () => {
  assert.equal(escapeHtml(`<a href="x">'y' & z</a>`), "&lt;a href=&quot;x&quot;&gt;&#39;y&#39; &amp; z&lt;/a&gt;");
});
