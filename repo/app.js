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
const crypto = require("crypto");
const zlib = require("zlib");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// ---------------------------------------------------------------------------
// SAML SSO Configuration (built-in Node.js modules only)
// ---------------------------------------------------------------------------

function getSamlConfig() {
  return {
    idpSsoUrl: process.env.SAML_IDP_SSO_URL || "https://idp.example.com/sso/saml",
    idpEntityId: process.env.SAML_IDP_ENTITY_ID || process.env.SAML_IDP_SSO_URL || "https://idp.example.com/sso/saml",
    idpCertificate: process.env.SAML_IDP_CERTIFICATE || "",
    spEntityId: process.env.SAML_SP_ENTITY_ID || "https://nextcloud-talk.example.com/saml/metadata",
    spAcsUrl: process.env.SAML_SP_ACS_URL || "http://localhost:9090/api/auth/saml/callback",
  };
}

function createLoginRequestUrl() {
  var config = getSamlConfig();
  var id = "_" + crypto.randomBytes(16).toString("hex");
  var issueInstant = new Date().toISOString();
  var authnRequest =
    '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"' +
    ' ID="' + id + '" Version="2.0" IssueInstant="' + issueInstant + '"' +
    ' AssertionConsumerServiceURL="' + config.spAcsUrl + '"' +
    ' ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"' +
    ' Destination="' + config.idpSsoUrl + '">' +
    '<saml:Issuer>' + config.spEntityId + '</saml:Issuer>' +
    '<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>' +
    '</samlp:AuthnRequest>';

  return new Promise(function(resolve, reject) {
    zlib.deflateRaw(authnRequest, function(err, deflated) {
      if (err) return reject(err);
      var encoded = deflated.toString("base64");
      var sep = config.idpSsoUrl.indexOf("?") >= 0 ? "&" : "?";
      resolve(config.idpSsoUrl + sep + "SAMLRequest=" + encodeURIComponent(encoded));
    });
  });
}

function generateSpMetadata() {
  var config = getSamlConfig();
  return '<?xml version="1.0" encoding="UTF-8"?>' +
    '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="' + config.spEntityId + '">' +
    '<md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">' +
    '<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>' +
    '<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="' + config.spAcsUrl + '" index="0" isDefault="true"/>' +
    '</md:SPSSODescriptor>' +
    '</md:EntityDescriptor>';
}

function validateXmlSignature(xml) {
  var config = getSamlConfig();
  try {
    var hasSignature = xml.indexOf("<ds:Signature") >= 0 || xml.indexOf("<Signature") >= 0;
    if (!hasSignature) {
      return { valid: false, error: "No XML signature found in SAML response" };
    }
    var sigValueMatch = xml.match(/<(?:ds:)?SignatureValue[^>]*>([\s\S]*?)<\/(?:ds:)?SignatureValue>/);
    if (!sigValueMatch) {
      return { valid: false, error: "No SignatureValue element found" };
    }
    var signedInfoMatch = xml.match(/(<(?:ds:)?SignedInfo[\s\S]*?<\/(?:ds:)?SignedInfo>)/);
    if (!signedInfoMatch) {
      return { valid: false, error: "No SignedInfo element found" };
    }
    if (!config.idpCertificate) {
      return { valid: false, error: "No IdP certificate configured for signature verification" };
    }
    var signatureValue = sigValueMatch[1].replace(/\s+/g, "");
    var signedInfoXml = signedInfoMatch[1];
    if (signedInfoXml.indexOf("xmlns:ds=") < 0 && signedInfoXml.indexOf("xmlns=") < 0) {
      signedInfoXml = signedInfoXml.replace(/(<(?:ds:)?SignedInfo)/, '$1 xmlns:ds="http://www.w3.org/2000/09/xmldsig#"');
    }
    var pemCert = config.idpCertificate.trim();
    if (pemCert.indexOf("-----BEGIN") !== 0) {
      pemCert = "-----BEGIN CERTIFICATE-----\n" + pemCert + "\n-----END CERTIFICATE-----";
    }
    var verifier = crypto.createVerify("RSA-SHA256");
    verifier.update(signedInfoXml);
    var isValid = verifier.verify(pemCert, signatureValue, "base64");
    if (!isValid) {
      return { valid: false, error: "XML signature verification failed" };
    }
    return { valid: true };
  } catch (err) {
    return { valid: false, error: "Signature validation error: " + err.message };
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
 */
app.post("/vuln", (req, res) => {
  const body = req.body || {};

  const actor     = body.actor     || {};
  const senderId  = actor.id   || "";
  const senderName = actor.name || "";
  const allowFrom = body.allowFrom || [];

  const result = resolveNextcloudTalkAllowlistMatch({
    allowFrom,
    senderId,
    senderName,
  });

  res.json({
    allowed:     result.allowed,
    matchSource: result.matchSource ?? null,
    matchKey:    result.matchKey   ?? null,
    input: { senderId, senderName, allowFrom },
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
// SAML SSO Endpoints
// ---------------------------------------------------------------------------

// GET /api/auth/saml/login — redirect to IdP
app.get("/api/auth/saml/login", function(req, res) {
  createLoginRequestUrl()
    .then(function(url) {
      res.redirect(url);
    })
    .catch(function(err) {
      console.error("[SAML] Login redirect failed:", err.message);
      res.status(500).json({ error: "saml_login_failed", message: err.message });
    });
});

// POST /api/auth/saml/callback — validate SAML response
app.post("/api/auth/saml/callback", function(req, res) {
  try {
    var samlResponse = req.body && req.body.SAMLResponse;
    if (!samlResponse) {
      return res.status(400).json({ error: "missing_saml_response", message: "No SAMLResponse found in the POST body." });
    }

    var xml;
    try {
      xml = Buffer.from(samlResponse, "base64").toString("utf-8");
    } catch (e) {
      return res.status(400).json({ error: "invalid_encoding", message: "SAMLResponse is not valid base64." });
    }

    if (xml.indexOf("Response") < 0) {
      return res.status(401).json({ error: "invalid_saml_response", message: "Not a valid SAML response." });
    }

    var sigResult = validateXmlSignature(xml);
    if (!sigResult.valid) {
      return res.status(401).json({ error: "invalid_signature", message: "SAML response signature validation failed.", details: sigResult.error });
    }

    // Extract NameID
    var nameIdMatch = xml.match(/<(?:saml2?:)?NameID[^>]*>([\s\S]*?)<\/(?:saml2?:)?NameID>/);
    var nameID = nameIdMatch ? nameIdMatch[1].trim() : null;

    return res.json({ status: "authenticated", user: { nameID: nameID } });
  } catch (err) {
    console.error("[SAML] Callback error:", err.message);
    return res.status(401).json({ error: "saml_callback_failed", message: err.message });
  }
});

// GET /api/auth/saml/metadata — SP metadata XML
app.get("/api/auth/saml/metadata", function(req, res) {
  try {
    var metadata = generateSpMetadata();
    res.set("Content-Type", "application/xml");
    return res.send(metadata);
  } catch (err) {
    console.error("[SAML] Metadata error:", err.message);
    return res.status(500).json({ error: "saml_metadata_failed", message: err.message });
  }
});

app.listen(9090, "0.0.0.0", () => {
  console.log("Carrier app listening on 0.0.0.0:9090");
});
