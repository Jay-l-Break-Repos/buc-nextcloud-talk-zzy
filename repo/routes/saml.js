"use strict";

// ---------------------------------------------------------------------------
// SAML SSO routes
//
// Implements three endpoints:
//   GET  /api/auth/saml/metadata   – SP metadata XML
//   GET  /api/auth/saml/login      – Redirect to IdP SSO URL
//   POST /api/auth/saml/callback   – Receive & validate SAML Response,
//                                    extract user attributes, create session
//
// All XML parsing and signature verification is done with Node.js built-ins
// (crypto, Buffer) — no external XML/SAML libraries required.
// ---------------------------------------------------------------------------

const { Router } = require("express");
const crypto     = require("crypto");

const router = Router();

// ---------------------------------------------------------------------------
// Configuration  (env-overridable; safe defaults for local dev / testing)
// ---------------------------------------------------------------------------

const IDP_SSO_URL    = process.env.SAML_IDP_SSO_URL    || "http://localhost:8080/sso";
const IDP_CERT_B64   = process.env.SAML_IDP_CERTIFICATE || ""; // base64 DER or PEM body
const SP_ENTITY_ID   = process.env.SAML_SP_ENTITY_ID   || "urn:sp:nextcloud-talk";
const SP_ACS_URL     = process.env.SAML_SP_ACS_URL     || "http://localhost:9090/api/auth/saml/callback";

// ---------------------------------------------------------------------------
// In-memory session store  { sessionId → { userId, email, name, createdAt } }
// ---------------------------------------------------------------------------

const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8 hours
const sessions       = new Map();

/**
 * Create a new session for a validated user and return the session ID.
 * @param {{ userId: string, email: string, name: string }} attrs
 * @returns {string} sessionId
 */
function createSession(attrs) {
  const sessionId = crypto.randomUUID();
  sessions.set(sessionId, {
    userId:    attrs.userId,
    email:     attrs.email,
    name:      attrs.name,
    createdAt: Date.now(),
  });
  return sessionId;
}

/**
 * Look up a session by ID.  Returns null if not found or expired.
 * @param {string} sessionId
 * @returns {{ userId: string, email: string, name: string, createdAt: number }|null}
 */
function getSession(sessionId) {
  const session = sessions.get(sessionId);
  if (!session) return null;
  if (Date.now() - session.createdAt > SESSION_TTL_MS) {
    sessions.delete(sessionId);
    return null;
  }
  return session;
}

// ---------------------------------------------------------------------------
// XML helpers  (regex-based; sufficient for well-formed SAML responses)
// ---------------------------------------------------------------------------

/**
 * Extract the text content of the first element matching `localName`.
 * Handles both prefixed (<saml:NameID>) and un-prefixed (<NameID>) tags.
 * @param {string} xml
 * @param {string} localName
 * @returns {string|null}
 */
function extractElement(xml, localName) {
  // Match <(prefix:)?localName ...>content</(prefix:)?localName>
  const re = new RegExp(
    `<(?:[A-Za-z0-9_-]+:)?${localName}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/(?:[A-Za-z0-9_-]+:)?${localName}>`,
    "i"
  );
  const m = xml.match(re);
  return m ? m[1].trim() : null;
}

/**
 * Extract the value of a named attribute from the first matching element.
 * @param {string} xml
 * @param {string} localName   – element local name
 * @param {string} attrName    – attribute name
 * @returns {string|null}
 */
function extractAttr(xml, localName, attrName) {
  const re = new RegExp(
    `<(?:[A-Za-z0-9_-]+:)?${localName}[^>]*\\s${attrName}="([^"]*)"`,
    "i"
  );
  const m = xml.match(re);
  return m ? m[1] : null;
}

/**
 * Extract all <saml:Attribute> / <Attribute> Name + AttributeValue pairs.
 * Returns a plain object { attributeName: firstValue, ... }.
 * @param {string} xml
 * @returns {Record<string, string>}
 */
function extractAttributes(xml) {
  const attrs = {};
  // Match each Attribute block
  const blockRe = /<(?:[A-Za-z0-9_-]+:)?Attribute\s[^>]*>([\s\S]*?)<\/(?:[A-Za-z0-9_-]+:)?Attribute>/gi;
  let blockMatch;
  while ((blockMatch = blockRe.exec(xml)) !== null) {
    const block    = blockMatch[0];
    const nameMatch = block.match(/\sName="([^"]*)"/i);
    if (!nameMatch) continue;
    const attrName  = nameMatch[1];
    const valMatch  = block.match(/<(?:[A-Za-z0-9_-]+:)?AttributeValue[^>]*>([\s\S]*?)<\/(?:[A-Za-z0-9_-]+:)?AttributeValue>/i);
    if (valMatch) attrs[attrName] = valMatch[1].trim();
  }
  return attrs;
}

/**
 * Extract the raw <SignedInfo> block (including its opening/closing tags).
 * This is the canonical byte sequence that was signed.
 * @param {string} xml
 * @returns {string|null}
 */
function extractSignedInfo(xml) {
  const re = /(<(?:[A-Za-z0-9_-]+:)?SignedInfo[\s\S]*?<\/(?:[A-Za-z0-9_-]+:)?SignedInfo>)/i;
  const m  = xml.match(re);
  return m ? m[1] : null;
}

/**
 * Extract the base64-encoded SignatureValue.
 * @param {string} xml
 * @returns {string|null}
 */
function extractSignatureValue(xml) {
  return extractElement(xml, "SignatureValue");
}

/**
 * Extract the first X509Certificate value (base64 DER, no headers).
 * @param {string} xml
 * @returns {string|null}
 */
function extractX509Certificate(xml) {
  const raw = extractElement(xml, "X509Certificate");
  return raw ? raw.replace(/\s+/g, "") : null;
}

/**
 * Determine the digest algorithm from a SignatureMethod Algorithm URI.
 * @param {string} xml
 * @returns {"SHA256"|"SHA1"}
 */
function detectSignatureAlgorithm(xml) {
  const m = xml.match(/SignatureMethod[^>]+Algorithm="([^"]*)"/i);
  if (!m) return "SHA256";
  const uri = m[1].toLowerCase();
  if (uri.includes("sha512")) return "SHA512";
  if (uri.includes("sha256")) return "SHA256";
  return "SHA1"; // rsa-sha1 fallback
}

// ---------------------------------------------------------------------------
// Signature verification
// ---------------------------------------------------------------------------

/**
 * Convert a raw base64 DER certificate body to a PEM string.
 * @param {string} b64der  – base64 with no whitespace
 * @returns {string}
 */
function derToPem(b64der) {
  const lines = b64der.match(/.{1,64}/g) || [b64der];
  return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----`;
}

/**
 * Verify the XML-DSig signature embedded in a SAML Response XML string.
 *
 * The function:
 *   1. Extracts the <SignedInfo> block (the signed data)
 *   2. Extracts the <SignatureValue> (the signature bytes)
 *   3. Determines the signing algorithm from <SignatureMethod>
 *   4. Resolves the IdP public key from either:
 *        a. The X509Certificate embedded in the response, OR
 *        b. The SAML_IDP_CERTIFICATE environment variable
 *   5. Verifies the signature with Node's built-in `crypto` module
 *
 * @param {string} xml  – decoded SAML Response XML
 * @returns {{ valid: boolean, reason?: string }}
 */
function verifyXmlSignature(xml) {
  // 1. Extract signed data
  const signedInfo = extractSignedInfo(xml);
  if (!signedInfo) {
    return { valid: false, reason: "No <SignedInfo> element found in SAMLResponse." };
  }

  // 2. Extract signature bytes
  const sigValueB64 = extractSignatureValue(xml);
  if (!sigValueB64) {
    return { valid: false, reason: "No <SignatureValue> element found in SAMLResponse." };
  }
  const sigBuffer = Buffer.from(sigValueB64.replace(/\s+/g, ""), "base64");

  // 3. Determine algorithm
  const algorithm = detectSignatureAlgorithm(xml);

  // 4. Resolve IdP certificate
  //    Prefer the certificate embedded in the response (allows IdP-initiated SSO
  //    with key rollover), but fall back to the configured env-var certificate.
  let certPem;
  const embeddedCert = extractX509Certificate(xml);
  if (embeddedCert) {
    certPem = derToPem(embeddedCert);
  } else if (IDP_CERT_B64) {
    // Env var may already be PEM or raw base64 DER
    certPem = IDP_CERT_B64.includes("-----BEGIN")
      ? IDP_CERT_B64
      : derToPem(IDP_CERT_B64.replace(/\s+/g, ""));
  } else {
    return {
      valid:  false,
      reason: "SAMLResponse signature cannot be verified: IdP certificate not configured.",
    };
  }

  // 5. Verify
  try {
    const verify = crypto.createVerify(`RSA-${algorithm}`);
    verify.update(signedInfo, "utf8");
    const ok = verify.verify(certPem, sigBuffer);
    return ok
      ? { valid: true }
      : { valid: false, reason: "Signature verification failed: signature does not match." };
  } catch (err) {
    return { valid: false, reason: `Signature verification error: ${err.message}` };
  }
}

// ---------------------------------------------------------------------------
// GET /api/auth/saml/metadata
// ---------------------------------------------------------------------------

/**
 * Returns the SAML 2.0 SP metadata XML.
 * Identity Providers import this document to configure trust with this SP.
 */
router.get("/metadata", (req, res) => {
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor
  xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
  entityID="${SP_ENTITY_ID}">
  <SPSSODescriptor
    AuthnRequestsSigned="false"
    WantAssertionsSigned="true"
    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <AssertionConsumerService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="${SP_ACS_URL}"
      index="0"
      isDefault="true"/>
  </SPSSODescriptor>
</EntityDescriptor>`;

  res.set("Content-Type", "application/xml; charset=utf-8");
  return res.status(200).send(xml);
});

// ---------------------------------------------------------------------------
// GET /api/auth/saml/login
// ---------------------------------------------------------------------------

/**
 * Initiates the SAML SSO flow by redirecting the user to the IdP SSO URL.
 * An optional `RelayState` query parameter is forwarded to the IdP so the
 * original destination URL can be restored after authentication.
 *
 * Next step: generate and sign an AuthnRequest and encode it in the redirect.
 */
router.get("/login", (req, res) => {
  const relayState = req.query.RelayState || "";
  const target     = relayState
    ? `${IDP_SSO_URL}?RelayState=${encodeURIComponent(relayState)}`
    : IDP_SSO_URL;

  return res.status(302).redirect(target);
});

// ---------------------------------------------------------------------------
// POST /api/auth/saml/callback
// ---------------------------------------------------------------------------

/**
 * Assertion Consumer Service (ACS) endpoint.
 *
 * Processes the SAML Response posted by the IdP after the user authenticates.
 *
 * Flow:
 *   1. Validate that `SAMLResponse` is present in the POST body            → 400
 *   2. Base64-decode the SAMLResponse to obtain the XML                    → 400
 *   3. Verify the XML-DSig signature against the IdP certificate           → 401
 *   4. Check the response Status code (must be Success)                    → 401
 *   5. Extract user attributes (NameID, email, displayName, etc.)
 *   6. Create an in-memory session and return the session token            → 200
 */
router.post("/callback", (req, res) => {
  const body = req.body || {};

  // ── Step 1: SAMLResponse must be present ──────────────────────────────────
  const rawB64 = body.SAMLResponse;
  if (!rawB64 || String(rawB64).trim() === "") {
    return res.status(400).json({
      status:  "error",
      message: "Missing SAMLResponse in request body.",
    });
  }

  // ── Step 2: Base64-decode ─────────────────────────────────────────────────
  let xml;
  try {
    xml = Buffer.from(String(rawB64).replace(/\s+/g, ""), "base64").toString("utf8");
  } catch (err) {
    return res.status(400).json({
      status:  "error",
      message: "SAMLResponse is not valid base64.",
    });
  }

  if (!xml || xml.trim() === "") {
    return res.status(400).json({
      status:  "error",
      message: "SAMLResponse decoded to an empty string.",
    });
  }

  // ── Step 3: Verify XML-DSig signature ─────────────────────────────────────
  const sigResult = verifyXmlSignature(xml);
  if (!sigResult.valid) {
    return res.status(401).json({
      status:  "error",
      message: sigResult.reason || "SAMLResponse signature verification failed.",
    });
  }

  // ── Step 4: Check SAML Status ─────────────────────────────────────────────
  const statusCode = extractAttr(xml, "StatusCode", "Value") || "";
  if (!statusCode.includes("status:Success")) {
    return res.status(401).json({
      status:  "error",
      message: `IdP returned a non-success status: ${statusCode || "(none)"}`,
    });
  }

  // ── Step 5: Extract user attributes ───────────────────────────────────────
  // NameID is the primary user identifier (typically a username or email)
  const nameId = extractElement(xml, "NameID") || "";

  // Friendly attribute map — covers common IdP attribute naming conventions
  const samlAttrs = extractAttributes(xml);

  const email = samlAttrs["email"]
    || samlAttrs["mail"]
    || samlAttrs["urn:oid:0.9.2342.19200300.100.1.3"]  // eduPerson mail OID
    || nameId;

  const displayName = samlAttrs["displayName"]
    || samlAttrs["cn"]
    || samlAttrs["urn:oid:2.16.840.1.113730.3.1.241"]  // displayName OID
    || samlAttrs["givenName"]
    || nameId;

  const userId = nameId || email;

  if (!userId) {
    return res.status(401).json({
      status:  "error",
      message: "SAMLResponse did not contain a NameID or user identifier.",
    });
  }

  // ── Step 6: Create session ────────────────────────────────────────────────
  const sessionId = createSession({ userId, email, name: displayName });

  return res.status(200).json({
    status:    "ok",
    message:   "Authentication successful.",
    sessionId,
    user: {
      id:    userId,
      email,
      name:  displayName,
    },
  });
});

// ---------------------------------------------------------------------------
// Exports (session store exposed for testing)
// ---------------------------------------------------------------------------

module.exports = router;
module.exports.getSession  = getSession;
module.exports.createSession = createSession;
