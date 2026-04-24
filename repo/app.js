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

// SAML SSO authentication routes
const samlRoutes = require("./samlRoutes");
app.use("/api/auth/saml", samlRoutes);

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

app.listen(9090, "0.0.0.0", () => {
  console.log("Carrier app listening on 0.0.0.0:9090");
  console.log("  GET  /health                  — liveness check");
  console.log("  POST /vuln                    — Nextcloud Talk allowlist bypass demo");
  console.log("  GET  /api/auth/saml/login     — SAML SSO login redirect");
  console.log("  POST /api/auth/saml/callback  — SAML ACS callback (placeholder)");
  console.log("  GET  /api/auth/saml/metadata  — SP metadata XML");
});
