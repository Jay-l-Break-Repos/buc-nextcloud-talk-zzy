/**
 * Carrier app for GHSA-r5h9-vjqc-hq3r
 * @openclaw/nextcloud-talk <= 2026.2.2
 *
 * Vulnerability: resolveNextcloudTalkAllowlistMatch() checks actor.name
 * (user-controlled display name) against the allowlist in addition to actor.id.
 * An attacker can set their Nextcloud display name to match an allowlisted user ID
 * and bypass DM/group allowlist access controls.
 *
 * The vulnerable logic is extracted verbatim from:
 *   node_modules/@openclaw/nextcloud-talk/src/policy.ts
 * (package ships only TypeScript source, no compiled JS)
 */

const express = require("express");
const app = express();
app.use(express.json());

// ---------------------------------------------------------------------------
// SAML SSO Configuration (placeholder values – will be made configurable later)
// ---------------------------------------------------------------------------

const SAML_CONFIG = {
  // Service Provider entity ID – uniquely identifies this SP to the IdP
  spEntityId: "https://nextcloud.example.com/saml/sp",

  // Assertion Consumer Service URL – where the IdP posts the SAML response
  acsUrl: "https://nextcloud.example.com/api/auth/saml/callback",

  // Identity Provider SSO URL – where we redirect users to authenticate
  idpSsoUrl: "https://idp.example.com/saml2/sso",
};

// ---------------------------------------------------------------------------
// Verbatim vulnerable logic from @openclaw/nextcloud-talk@2026.2.2 policy.ts
// ---------------------------------------------------------------------------

function normalizeAllowEntry(raw) {
  return raw
    .trim()
    .toLowerCase()
    .replace(/^(nextcloud-talk|nc-talk|nc):/i, "");
}

function normalizeNextcloudTalkAllowlist(values) {
  return (values ?? []).map((value) => normalizeAllowEntry(String(value))).filter(Boolean);
}

/**
 * VULNERABLE: accepts senderName (actor.name / display name) as a match source.
 * An attacker who sets their display name to an allowlisted user ID will pass
 * this check with matchSource === "name".
 *
 * Fixed in >= 2026.2.6 by removing the senderName parameter entirely.
 */
function resolveNextcloudTalkAllowlistMatch({ allowFrom, senderId, senderName }) {
  const normalized = normalizeNextcloudTalkAllowlist(allowFrom);
  if (normalized.length === 0) {
    return { allowed: false };
  }
  if (normalized.includes("*")) {
    return { allowed: true, matchKey: "*", matchSource: "wildcard" };
  }
  const normId = normalizeAllowEntry(senderId);
  if (normalized.includes(normId)) {
    return { allowed: true, matchKey: normId, matchSource: "id" };
  }
  // VULNERABLE: senderName (actor.name) is attacker-controlled display name
  const normName = senderName ? normalizeAllowEntry(senderName) : "";
  if (normName && normalized.includes(normName)) {
    return { allowed: true, matchKey: normName, matchSource: "name" };
  }
  return { allowed: false };
}

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

/**
 * POST /vuln
 *
 * Simulates the Nextcloud Talk webhook allowlist check as performed by the
 * vulnerable @openclaw/nextcloud-talk plugin.
 *
 * Expected JSON body (mirrors a Nextcloud Talk webhook payload + bot config):
 * {
 *   "actor": {
 *     "id":   "<real Nextcloud user ID>",
 *     "name": "<attacker-controlled display name>"
 *   },
 *   "allowFrom": ["<allowlisted-user-id>", ...]   // bot's configured allowlist
 * }
 *
 * Exploit: set actor.name == an entry in allowFrom while actor.id differs.
 * The vulnerable check will return { allowed: true, matchSource: "name" }.
 */
app.post("/vuln", (req, res) => {
  const body = req.body || {};

  const actor     = body.actor     || {};
  const senderId  = actor.id   || "";          // actor.id   — stable, from Nextcloud
  const senderName = actor.name || "";         // actor.name — mutable display name (attacker-controlled)
  const allowFrom = body.allowFrom || [];      // bot's configured allowlist

  // Call the vulnerable function exactly as inbound.ts does in the affected version
  const result = resolveNextcloudTalkAllowlistMatch({
    allowFrom,
    senderId,
    senderName,
  });

  res.json({
    // Access-control decision
    allowed:     result.allowed,
    matchSource: result.matchSource ?? null,   // "id" | "name" | "wildcard" | null
    matchKey:    result.matchKey   ?? null,

    // Echo inputs for clarity
    input: {
      senderId,
      senderName,
      allowFrom,
    },

    // Explain what happened
    note: result.allowed && result.matchSource === "name"
      ? "VULNERABLE: access granted via actor.name (display name) — allowlist bypass succeeded"
      : result.allowed && result.matchSource === "id"
      ? "Access granted via actor.id (legitimate)"
      : result.allowed
      ? "Access granted (wildcard)"
      : "Access denied",
  });
});

// ---------------------------------------------------------------------------
// SAML SSO Routes
// ---------------------------------------------------------------------------

/**
 * GET /api/auth/saml/metadata
 *
 * Returns the SAML 2.0 Service Provider (SP) metadata XML document.
 * Identity Providers use this document to learn how to communicate with
 * this SP (entity ID, supported bindings, ACS URL, etc.).
 *
 * Placeholder values are used for spEntityId and acsUrl; these will be
 * replaced with environment-driven configuration in a later step.
 */
app.get("/api/auth/saml/metadata", (req, res) => {
  const { spEntityId, acsUrl } = SAML_CONFIG;

  // Build a minimal but spec-compliant SAML 2.0 SP metadata document.
  // Namespace declarations follow the OASIS SAML 2.0 metadata schema.
  const metadataXml = `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor
  xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
  xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
  entityID="${spEntityId}"
  validUntil="2099-01-01T00:00:00Z">

  <md:SPSSODescriptor
    AuthnRequestsSigned="false"
    WantAssertionsSigned="true"
    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">

    <!-- Assertion Consumer Service: where the IdP will POST the SAML Response -->
    <md:AssertionConsumerService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="${acsUrl}"
      index="1"
      isDefault="true"/>

  </md:SPSSODescriptor>

</md:EntityDescriptor>`;

  res.set("Content-Type", "application/xml; charset=utf-8");
  res.send(metadataXml);
});

/**
 * GET /api/auth/saml/login
 *
 * Initiates the SAML SSO login flow by redirecting the user's browser to
 * the configured Identity Provider (IdP) SSO URL.
 *
 * In a full implementation this endpoint would:
 *   1. Generate a signed AuthnRequest
 *   2. Encode it as a query parameter (HTTP-Redirect binding)
 *   3. Include a RelayState value to restore the original destination
 *
 * For now we perform a simple redirect to the placeholder IdP SSO URL so
 * the route is wired up and ready for the AuthnRequest logic in the next step.
 */
app.get("/api/auth/saml/login", (req, res) => {
  const { idpSsoUrl } = SAML_CONFIG;

  // Preserve any RelayState passed by the caller (e.g. the original page URL)
  // so it can be forwarded to the IdP and echoed back in the SAML response.
  const relayState = req.query.RelayState || "";
  const redirectUrl = relayState
    ? `${idpSsoUrl}?RelayState=${encodeURIComponent(relayState)}`
    : idpSsoUrl;

  // 302 Found – temporary redirect; keeps the door open for future changes
  // (e.g. switching to a signed AuthnRequest redirect in the next step).
  res.redirect(302, redirectUrl);
});

app.listen(9090, "0.0.0.0", () => {
  console.log("Carrier app listening on 0.0.0.0:9090");
  console.log("  GET  /health                  — liveness check");
  console.log("  POST /vuln                    — Nextcloud Talk allowlist bypass demo");
  console.log("  GET  /api/auth/saml/metadata  — SAML SP metadata XML");
  console.log("  GET  /api/auth/saml/login     — Initiate SAML SSO login flow");
});
