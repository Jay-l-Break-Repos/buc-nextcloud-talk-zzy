"use strict";

/**
 * Carrier app for GHSA-r5h9-vjqc-hq3r
 * @openclaw/nextcloud-talk <= 2026.2.2
 */

const express = require("express");
const crypto = require("crypto");
const zlib = require("zlib");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// ---------------------------------------------------------------------------
// SAML SSO Configuration
// ---------------------------------------------------------------------------

const IDP_SSO_URL   = process.env.SAML_IDP_SSO_URL   || "http://localhost:8080/sso";
const SP_ENTITY_ID  = process.env.SAML_SP_ENTITY_ID   || "urn:sp:nextcloud-talk";
const SP_ACS_URL    = process.env.SAML_SP_ACS_URL     || "http://localhost:9090/api/auth/saml/callback";
const IDP_CERT      = process.env.SAML_IDP_CERTIFICATE || "";

// ---------------------------------------------------------------------------
// SAML SSO Endpoints
// ---------------------------------------------------------------------------

// GET /api/auth/saml/login — redirect to IdP
app.get("/api/auth/saml/login", (req, res) => {
  return res.redirect(302, IDP_SSO_URL);
});

// POST /api/auth/saml/callback — validate SAML response
app.post("/api/auth/saml/callback", (req, res) => {
  const body = req.body || {};
  const raw = body.SAMLResponse;

  // No SAMLResponse field → 400
  if (!raw || String(raw).trim() === "") {
    return res.status(400).json({
      status: "error",
      message: "Missing SAMLResponse in request body.",
    });
  }

  // SAMLResponse present but we have no IdP certificate to verify it → 401
  if (!IDP_CERT) {
    return res.status(401).json({
      status: "error",
      message: "SAMLResponse signature cannot be verified: IdP certificate not configured.",
    });
  }

  // Attempt signature verification
  var xml;
  try {
    xml = Buffer.from(raw, "base64").toString("utf-8");
  } catch (e) {
    return res.status(401).json({
      status: "error",
      message: "Invalid SAMLResponse encoding.",
    });
  }

  // Check for signature
  var hasSignature = xml.indexOf("<ds:Signature") >= 0 || xml.indexOf("<Signature") >= 0;
  if (!hasSignature) {
    return res.status(401).json({
      status: "error",
      message: "SAMLResponse does not contain a signature.",
    });
  }

  // Verify signature
  try {
    var sigValueMatch = xml.match(/<(?:ds:)?SignatureValue[^>]*>([\s\S]*?)<\/(?:ds:)?SignatureValue>/);
    var signedInfoMatch = xml.match(/(<(?:ds:)?SignedInfo[\s\S]*?<\/(?:ds:)?SignedInfo>)/);
    if (!sigValueMatch || !signedInfoMatch) {
      return res.status(401).json({ status: "error", message: "Malformed XML signature." });
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
    return res.status(401).json({ status: "error", message: "Signature validation error: " + err.message });
  }

  // Valid signature — extract NameID
  var nameIdMatch = xml.match(/<(?:saml2?:)?NameID[^>]*>([\s\S]*?)<\/(?:saml2?:)?NameID>/);
  return res.json({ status: "authenticated", user: { nameID: nameIdMatch ? nameIdMatch[1].trim() : null } });
});

// GET /api/auth/saml/metadata — SP metadata XML
app.get("/api/auth/saml/metadata", (req, res) => {
  var xml = '<?xml version="1.0" encoding="UTF-8"?>' +
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
app.listen(9090, "0.0.0.0", () => {
  console.log("Carrier app listening on 0.0.0.0:9090");
});
