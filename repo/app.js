"use strict";

// ---------------------------------------------------------------------------
// Carrier app for GHSA-r5h9-vjqc-hq3r
// @openclaw/nextcloud-talk <= 2026.2.2
// ---------------------------------------------------------------------------

console.log("=== app.js loading ===");
console.log("Node:", process.version, "| cwd:", process.cwd());

const express = require("express");
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// ---------------------------------------------------------------------------
// SAML SSO routes
// ---------------------------------------------------------------------------
const samlRouter = require("./routes/saml");
app.use("/api/auth/saml", samlRouter);
console.log("SAML router mounted.");

// ---------------------------------------------------------------------------
// Health / root
// ---------------------------------------------------------------------------
app.get("/", (req, res) => {
  res.json({ status: "ok" });
});

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

// ---------------------------------------------------------------------------
// Nextcloud Talk allowlist-bypass demo (GHSA-r5h9-vjqc-hq3r)
// ---------------------------------------------------------------------------

function normalizeAllowEntry(raw) {
  return raw.trim().toLowerCase().replace(/^(nextcloud-talk|nc-talk|nc):/i, "");
}

function normalizeNextcloudTalkAllowlist(values) {
  return (values ?? []).map((v) => normalizeAllowEntry(String(v))).filter(Boolean);
}

/**
 * VULNERABLE: accepts senderName (actor.name / display name) as a match source.
 * Fixed in >= 2026.2.6 by removing the senderName parameter entirely.
 */
function resolveNextcloudTalkAllowlistMatch({ allowFrom, senderId, senderName }) {
  const normalized = normalizeNextcloudTalkAllowlist(allowFrom);
  if (normalized.length === 0) return { allowed: false };
  if (normalized.includes("*")) return { allowed: true, matchKey: "*", matchSource: "wildcard" };
  const normId = normalizeAllowEntry(senderId);
  if (normalized.includes(normId)) return { allowed: true, matchKey: normId, matchSource: "id" };
  const normName = senderName ? normalizeAllowEntry(senderName) : "";
  if (normName && normalized.includes(normName)) return { allowed: true, matchKey: normName, matchSource: "name" };
  return { allowed: false };
}

app.post("/vuln", (req, res) => {
  const body       = req.body || {};
  const actor      = body.actor || {};
  const senderId   = actor.id   || "";
  const senderName = actor.name || "";
  const allowFrom  = body.allowFrom || [];

  const result = resolveNextcloudTalkAllowlistMatch({ allowFrom, senderId, senderName });

  res.json({
    allowed:     result.allowed,
    matchSource: result.matchSource ?? null,
    matchKey:    result.matchKey    ?? null,
    input:       { senderId, senderName, allowFrom },
    note: result.allowed && result.matchSource === "name"
      ? "VULNERABLE: access granted via actor.name (display name) — allowlist bypass succeeded"
      : result.allowed && result.matchSource === "id"
      ? "Access granted via actor.id (legitimate)"
      : result.allowed ? "Access granted (wildcard)" : "Access denied",
  });
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------
try {
  app.listen(9090, "0.0.0.0", () => {
    console.log("=== SERVER STARTED SUCCESSFULLY on 0.0.0.0:9090 ===");
  });
} catch (e) {
  console.error("=== SERVER FAILED TO START ===", e);
  process.exit(1);
}
