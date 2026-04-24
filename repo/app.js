"use strict";

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

var express = require("express");
var app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// ---------------------------------------------------------------------------
// SAML SSO Configuration
// ---------------------------------------------------------------------------

var IDP_SSO_URL  = process.env.SAML_IDP_SSO_URL   || "http://localhost:8080/sso";
var SP_ENTITY_ID = process.env.SAML_SP_ENTITY_ID   || "urn:sp:nextcloud-talk";
var SP_ACS_URL   = process.env.SAML_SP_ACS_URL     || "http://localhost:9090/api/auth/saml/callback";
var IDP_CERT     = process.env.SAML_IDP_CERTIFICATE || "";

// ---------------------------------------------------------------------------
// SAML SSO Endpoints
// ---------------------------------------------------------------------------

// GET /api/auth/saml/login — redirect to IdP
app.get("/api/auth/saml/login", function(req, res) {
  res.writeHead(302, { "Location": IDP_SSO_URL });
  res.end();
});

// POST /api/auth/saml/callback — validate SAML response
app.post("/api/auth/saml/callback", function(req, res) {
  var body = req.body || {};
  var raw = body.SAMLResponse;

  if (!raw || String(raw).trim() === "") {
    return res.status(400).json({
      status: "error",
      message: "Missing SAMLResponse in request body."
    });
  }

  // No IdP certificate configured — cannot verify any signature → 401
  if (!IDP_CERT) {
    return res.status(401).json({
      status: "error",
      message: "SAMLResponse signature cannot be verified: IdP certificate not configured."
    });
  }

  // IdP certificate is configured — attempt verification
  var xml;
  try {
    xml = Buffer.from(raw, "base64").toString("utf-8");
  } catch (e) {
    return res.status(401).json({
      status: "error",
      message: "Invalid SAMLResponse encoding."
    });
  }

  try {
    var crypto = require("crypto");
    var sigValueMatch = xml.match(/<(?:ds:)?SignatureValue[^>]*>([\s\S]*?)<\/(?:ds:)?SignatureValue>/);
    var signedInfoMatch = xml.match(/(<(?:ds:)?SignedInfo[\s\S]*?<\/(?:ds:)?SignedInfo>)/);

    if (!sigValueMatch || !signedInfoMatch) {
      return res.status(401).json({ status: "error", message: "No valid XML signature found." });
    }

    var pemCert = IDP_CERT.trim();
    if (pemCert.indexOf("-----BEGIN") !== 0) {
      pemCert = "-----BEGIN CERTIFICATE-----\n" + pemCert + "\n-----END CERTIFICATE-----";
    }

    var verifier = crypto.createVerify("RSA-SHA256");
    verifier.update(signedInfoMatch[1]);
    var isValid = verifier.verify(pemCert, sigValueMatch[1].replace(/\s+/g, ""), "base64");

    if (!isValid) {
      return res.status(401).json({ status: "error", message: "XML signature verification failed." });
    }
  } catch (err) {
    return res.status(401).json({ status: "error", message: "Signature validation error." });
  }

  var nameIdMatch = xml.match(/<(?:saml2?:)?NameID[^>]*>([\s\S]*?)<\/(?:saml2?:)?NameID>/);
  return res.json({ status: "authenticated", user: { nameID: nameIdMatch ? nameIdMatch[1].trim() : null } });
});

// GET /api/auth/saml/metadata — SP metadata XML
app.get("/api/auth/saml/metadata", function(req, res) {
  var xml =
    '<?xml version="1.0" encoding="UTF-8"?>' +
    '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="' + SP_ENTITY_ID + '">' +
      '<SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">' +
        '<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="' + SP_ACS_URL + '" index="0" isDefault="true"/>' +
      '</SPSSODescriptor>' +
    '</EntityDescriptor>';

  res.set("Content-Type", "application/xml; charset=utf-8");
  return res.status(200).send(xml);
});

// ---------------------------------------------------------------------------
// Health / root
// ---------------------------------------------------------------------------

app.get("/", function(req, res) {
  res.json({ status: "ok" });
});

app.get("/health", function(req, res) {
  res.json({ status: "ok" });
});

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
  return (values ?? []).map(function(value) { return normalizeAllowEntry(String(value)); }).filter(Boolean);
}

/**
 * VULNERABLE: accepts senderName (actor.name / display name) as a match source.
 * An attacker who sets their display name to an allowlisted user ID will pass
 * this check with matchSource === "name".
 *
 * Fixed in >= 2026.2.6 by removing the senderName parameter entirely.
 */
function resolveNextcloudTalkAllowlistMatch(opts) {
  var allowFrom = opts.allowFrom;
  var senderId = opts.senderId;
  var senderName = opts.senderName;
  var normalized = normalizeNextcloudTalkAllowlist(allowFrom);
  if (normalized.length === 0) {
    return { allowed: false };
  }
  if (normalized.includes("*")) {
    return { allowed: true, matchKey: "*", matchSource: "wildcard" };
  }
  var normId = normalizeAllowEntry(senderId);
  if (normalized.includes(normId)) {
    return { allowed: true, matchKey: normId, matchSource: "id" };
  }
  var normName = senderName ? normalizeAllowEntry(senderName) : "";
  if (normName && normalized.includes(normName)) {
    return { allowed: true, matchKey: normName, matchSource: "name" };
  }
  return { allowed: false };
}

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

/**
 * POST /vuln
 *
 * Simulates the Nextcloud Talk webhook allowlist check as performed by the
 * vulnerable @openclaw/nextcloud-talk plugin.
 */
app.post("/vuln", function(req, res) {
  var body = req.body || {};
  var actor = body.actor || {};
  var senderId = actor.id || "";
  var senderName = actor.name || "";
  var allowFrom = body.allowFrom || [];

  var result = resolveNextcloudTalkAllowlistMatch({
    allowFrom: allowFrom,
    senderId: senderId,
    senderName: senderName
  });

  res.json({
    allowed: result.allowed,
    matchSource: result.matchSource ?? null,
    matchKey: result.matchKey ?? null,
    input: {
      senderId: senderId,
      senderName: senderName,
      allowFrom: allowFrom
    },
    note: result.allowed && result.matchSource === "name"
      ? "VULNERABLE: access granted via actor.name (display name) — allowlist bypass succeeded"
      : result.allowed && result.matchSource === "id"
      ? "Access granted via actor.id (legitimate)"
      : result.allowed
      ? "Access granted (wildcard)"
      : "Access denied"
  });
});

app.listen(9090, "0.0.0.0", function() {
  console.log("Carrier app listening on 0.0.0.0:9090");
});
