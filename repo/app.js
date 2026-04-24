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
const crypto  = require("crypto");
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// ---------------------------------------------------------------------------
// SAML SSO Configuration (env-overridable; safe defaults for local dev)
// ---------------------------------------------------------------------------

const SAML_CONFIG = {
  // Service Provider entity ID – uniquely identifies this SP to the IdP
  spEntityId: process.env.SAML_SP_ENTITY_ID || "https://nextcloud.example.com/saml/sp",

  // Assertion Consumer Service URL – where the IdP posts the SAML response
  acsUrl: process.env.SAML_SP_ACS_URL || "https://nextcloud.example.com/api/auth/saml/callback",

  // Identity Provider SSO URL – where we redirect users to authenticate
  idpSsoUrl: process.env.SAML_IDP_SSO_URL || "https://idp.example.com/saml2/sso",

  // Base64-encoded X.509 certificate from the IdP (PEM body or raw DER base64).
  // Used to verify the digital signature on SAML responses / assertions.
  // When unset, the /callback endpoint rejects all SAMLResponses with 401.
  idpCertificate: process.env.SAML_IDP_CERTIFICATE || "",
};

// ---------------------------------------------------------------------------
// In-memory session store  { sessionId → { userId, email, name, createdAt } }
// ---------------------------------------------------------------------------

const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8 hours
const sessions = new Map();

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
 * Look up a session by ID. Returns null if not found or expired.
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
// XML helpers (regex-based; sufficient for well-formed SAML responses)
// ---------------------------------------------------------------------------

/**
 * Extract the text content of the first element matching `localName`.
 * Handles both prefixed (<saml:NameID>) and un-prefixed (<NameID>) tags.
 */
function extractElement(xml, localName) {
  const re = new RegExp(
    `<(?:[A-Za-z0-9_-]+:)?${localName}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/(?:[A-Za-z0-9_-]+:)?${localName}>`,
    "i"
  );
  const m = xml.match(re);
  return m ? m[1].trim() : null;
}

/**
 * Extract the value of a named attribute from the first matching element.
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
 * Extract all <Attribute> Name + AttributeValue pairs.
 * Returns a plain object { attributeName: firstValue, ... }.
 */
function extractAttributes(xml) {
  const attrs = {};
  const blockRe = /<(?:[A-Za-z0-9_-]+:)?Attribute\s[^>]*>([\s\S]*?)<\/(?:[A-Za-z0-9_-]+:)?Attribute>/gi;
  let blockMatch;
  while ((blockMatch = blockRe.exec(xml)) !== null) {
    const block = blockMatch[0];
    const nameMatch = block.match(/\sName="([^"]*)"/i);
    if (!nameMatch) continue;
    const attrName = nameMatch[1];
    const valMatch = block.match(
      /<(?:[A-Za-z0-9_-]+:)?AttributeValue[^>]*>([\s\S]*?)<\/(?:[A-Za-z0-9_-]+:)?AttributeValue>/i
    );
    if (valMatch) attrs[attrName] = valMatch[1].trim();
  }
  return attrs;
}

/** Extract the raw <SignedInfo> block (the canonical signed data). */
function extractSignedInfo(xml) {
  const re = /(<(?:[A-Za-z0-9_-]+:)?SignedInfo[\s\S]*?<\/(?:[A-Za-z0-9_-]+:)?SignedInfo>)/i;
  const m = xml.match(re);
  return m ? m[1] : null;
}

/** Extract the base64-encoded SignatureValue. */
function extractSignatureValue(xml) {
  return extractElement(xml, "SignatureValue");
}

/** Extract the first X509Certificate value (base64 DER, no headers). */
function extractX509Certificate(xml) {
  const raw = extractElement(xml, "X509Certificate");
  return raw ? raw.replace(/\s+/g, "") : null;
}

/** Detect RSA signing algorithm from <SignatureMethod Algorithm> URI. */
function detectSignatureAlgorithm(xml) {
  const m = xml.match(/SignatureMethod[^>]+Algorithm="([^"]*)"/i);
  if (!m) return "SHA256";
  const uri = m[1].toLowerCase();
  if (uri.includes("sha512")) return "SHA512";
  if (uri.includes("sha256")) return "SHA256";
  return "SHA1";
}

/** Convert raw base64 DER certificate body to a PEM string. */
function derToPem(b64der) {
  const lines = b64der.match(/.{1,64}/g) || [b64der];
  return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----`;
}

/**
 * Verify the XML-DSig signature embedded in a SAML Response XML string.
 *
 * 1. Extracts <SignedInfo> as the signed canonical data
 * 2. Extracts <SignatureValue> as the signature bytes
 * 3. Detects algorithm from <SignatureMethod Algorithm> URI
 * 4. Resolves IdP public key from embedded <X509Certificate> or env var
 * 5. Verifies with Node's built-in crypto.createVerify()
 *
 * @param {string} xml – decoded SAML Response XML
 * @returns {{ valid: boolean, reason?: string }}
 */
function verifyXmlSignature(xml) {
  const signedInfo = extractSignedInfo(xml);
  if (!signedInfo) {
    return { valid: false, reason: "No <SignedInfo> element found in SAMLResponse." };
  }

  const sigValueB64 = extractSignatureValue(xml);
  if (!sigValueB64) {
    return { valid: false, reason: "No <SignatureValue> element found in SAMLResponse." };
  }
  const sigBuffer = Buffer.from(sigValueB64.replace(/\s+/g, ""), "base64");

  const algorithm = detectSignatureAlgorithm(xml);

  // Prefer certificate embedded in the response; fall back to env var
  let certPem;
  const embeddedCert = extractX509Certificate(xml);
  if (embeddedCert) {
    certPem = derToPem(embeddedCert);
  } else if (SAML_CONFIG.idpCertificate) {
    certPem = SAML_CONFIG.idpCertificate.includes("-----BEGIN")
      ? SAML_CONFIG.idpCertificate
      : derToPem(SAML_CONFIG.idpCertificate.replace(/\s+/g, ""));
  } else {
    return {
      valid:  false,
      reason: "SAMLResponse signature cannot be verified: IdP certificate not configured.",
    };
  }

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
 * Accepts an optional `?RelayState=<url>` query parameter and forwards it
 * to the IdP so the original destination can be restored after authentication.
 */
app.get("/api/auth/saml/login", (req, res) => {
  const { idpSsoUrl } = SAML_CONFIG;

  const relayState = req.query.RelayState || "";
  const redirectUrl = relayState
    ? `${idpSsoUrl}?RelayState=${encodeURIComponent(relayState)}`
    : idpSsoUrl;

  res.redirect(302, redirectUrl);
});

/**
 * POST /api/auth/saml/callback
 *
 * Assertion Consumer Service (ACS) endpoint.
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
app.post("/api/auth/saml/callback", (req, res) => {
  const body = req.body || {};

  // Step 1: SAMLResponse must be present
  const rawB64 = body.SAMLResponse;
  if (!rawB64 || String(rawB64).trim() === "") {
    return res.status(400).json({
      status:  "error",
      message: "Missing SAMLResponse in request body.",
    });
  }

  // Step 2: Base64-decode to obtain the XML string
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

  // Step 3: Verify XML-DSig signature
  const sigResult = verifyXmlSignature(xml);
  if (!sigResult.valid) {
    return res.status(401).json({
      status:  "error",
      message: sigResult.reason || "SAMLResponse signature verification failed.",
    });
  }

  // Step 4: Check SAML Status — must be Success
  const statusCode = extractAttr(xml, "StatusCode", "Value") || "";
  if (!statusCode.includes("status:Success")) {
    return res.status(401).json({
      status:  "error",
      message: `IdP returned a non-success status: ${statusCode || "(none)"}`,
    });
  }

  // Step 5: Extract user attributes from the assertion
  const nameId = extractElement(xml, "NameID") || "";
  const samlAttrs = extractAttributes(xml);

  // Resolve email — try common attribute names and OIDs
  const email = samlAttrs["email"]
    || samlAttrs["mail"]
    || samlAttrs["urn:oid:0.9.2342.19200300.100.1.3"]  // eduPerson mail OID
    || nameId;

  // Resolve display name — try common attribute names and OIDs
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

  // Step 6: Create session and return success
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

app.listen(9090, "0.0.0.0", () => {
  console.log("Carrier app listening on 0.0.0.0:9090");
  console.log("  GET  /health                       — liveness check");
  console.log("  POST /vuln                         — Nextcloud Talk allowlist bypass demo");
  console.log("  GET  /api/auth/saml/metadata       — SAML SP metadata XML");
  console.log("  GET  /api/auth/saml/login          — Initiate SAML SSO login flow");
  console.log("  POST /api/auth/saml/callback       — SAML ACS: validate response & create session");
});
