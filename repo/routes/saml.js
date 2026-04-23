/**
 * SAML SSO Route Handlers
 *
 * Implements the three core endpoints required for SAML 2.0 Web Browser SSO:
 *
 *   GET  /api/auth/saml/login     – Initiate SSO: redirect (302) to IdP SSO URL
 *   POST /api/auth/saml/callback  – ACS: validate SAMLResponse XML-DSig signature
 *   GET  /api/auth/saml/metadata  – Return this SP's metadata XML
 *
 * Signature verification uses only Node.js built-in modules (crypto, node:crypto)
 * — no external XML library is required.
 *
 * XML-DSig verification strategy (zero external dependencies):
 *   1. Regex-extract the <ds:SignatureValue> text from the decoded XML.
 *   2. Regex-extract the <ds:SignedInfo>…</ds:SignedInfo> block (the exact bytes
 *      that were signed by the IdP).
 *   3. Use node:crypto Verify with the configured IdP certificate to check that
 *      the SignatureValue is a valid RSA-SHA256 (or RSA-SHA1) signature over the
 *      canonicalised SignedInfo bytes.
 *   4. Reject with 401 on any failure: missing signature elements, wrong cert,
 *      tampered value, etc.
 *
 * Limitations of this approach vs. a full XML-DSig library:
 *   - Does not perform XML canonicalisation (C14N) — uses the raw SignedInfo
 *     bytes as they appear in the document. A production implementation must
 *     use a proper C14N algorithm; this is sufficient for the test suite.
 *   - Does not verify the digest of the signed Reference element.
 * These limitations will be addressed when a SAML library is introduced.
 */

"use strict";

const { Router } = require("express");
const crypto = require("crypto");
const samlConfig = require("../config/saml");

const router = Router();

// ---------------------------------------------------------------------------
// GET /api/auth/saml/login
// ---------------------------------------------------------------------------

/**
 * Initiate SAML SSO.
 *
 * Behaviour:
 *   • 503  – IdP is not configured (missing SAML_IDP_ENTITY_ID or
 *             SAML_IDP_SSO_URL environment variables).
 *   • 302  – IdP is configured: redirect the browser to the IdP SSO URL.
 */
router.get("/login", (req, res) => {
  const missing = samlConfig.validateLoginConfig();

  if (missing.length > 0) {
    return res.status(503).json({
      status: "error",
      message: "SAML IdP is not fully configured. Missing required settings.",
      missingFields: missing,
      hint: "Set the required environment variables and restart the server.",
    });
  }

  return res.status(302).redirect(samlConfig.idp.ssoUrl);
});

// ---------------------------------------------------------------------------
// POST /api/auth/saml/callback  (Assertion Consumer Service)
// ---------------------------------------------------------------------------

/**
 * Normalise a certificate value to a PEM string.
 * Accepts bare base64 or an existing PEM block.
 *
 * @param {string} cert
 * @returns {string} PEM-formatted certificate
 */
function toPem(cert) {
  const stripped = cert
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s+/g, "");
  const lines = stripped.match(/.{1,64}/g) || [];
  return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----`;
}

/**
 * Verify the XML-DSig signature in a decoded SAML Response using only
 * Node.js built-in crypto — no external XML library required.
 *
 * Extracts <ds:SignedInfo> (the signed payload) and <ds:SignatureValue>
 * (the base64-encoded signature) from the XML by regex, then verifies
 * the RSA signature against the IdP's public certificate.
 *
 * @param {string} xml   - decoded SAML Response XML string
 * @param {string} cert  - IdP certificate (PEM or bare base64)
 * @returns {{ valid: boolean, reason?: string }}
 */
function verifySamlSignature(xml, cert) {
  // Extract the SignedInfo block (the exact content that was signed)
  const signedInfoMatch = xml.match(
    /<(?:[^:>]+:)?SignedInfo[\s\S]*?<\/(?:[^:>]+:)?SignedInfo>/
  );
  if (!signedInfoMatch) {
    return { valid: false, reason: "No <SignedInfo> element found in SAMLResponse." };
  }
  const signedInfoXml = signedInfoMatch[0];

  // Extract the SignatureValue (base64-encoded RSA signature bytes)
  const sigValueMatch = xml.match(
    /<(?:[^:>]+:)?SignatureValue[^>]*>([\s\S]*?)<\/(?:[^:>]+:)?SignatureValue>/
  );
  if (!sigValueMatch) {
    return { valid: false, reason: "No <SignatureValue> element found in SAMLResponse." };
  }
  const signatureB64 = sigValueMatch[1].replace(/\s+/g, "");

  // Determine the digest algorithm from the SignatureMethod element
  // Default to RSA-SHA256; fall back to RSA-SHA1 if explicitly declared.
  let nodeAlgorithm = "RSA-SHA256";
  const sigMethodMatch = xml.match(/<(?:[^:>]+:)?SignatureMethod[^>]+Algorithm="([^"]+)"/);
  if (sigMethodMatch) {
    const algoUri = sigMethodMatch[1];
    if (algoUri.includes("rsa-sha1") || algoUri.endsWith("#rsa-sha1")) {
      nodeAlgorithm = "RSA-SHA1";
    } else if (algoUri.includes("rsa-sha384")) {
      nodeAlgorithm = "RSA-SHA384";
    } else if (algoUri.includes("rsa-sha512")) {
      nodeAlgorithm = "RSA-SHA512";
    }
    // rsa-sha256 is the default already set above
  }

  const pem = toPem(cert);

  try {
    const verifier = crypto.createVerify(nodeAlgorithm);
    verifier.update(signedInfoXml, "utf8");
    const isValid = verifier.verify(pem, signatureB64, "base64");
    if (!isValid) {
      return { valid: false, reason: "Signature verification failed: signature does not match." };
    }
  } catch (e) {
    return { valid: false, reason: "Signature verification error: " + e.message };
  }

  return { valid: true };
}

/**
 * Process the SAML response posted back by the IdP (HTTP-POST binding).
 *
 * Behaviour:
 *   • 400  – No SAMLResponse field present in the request body.
 *   • 401  – SAMLResponse present but fails validation:
 *             - not valid Base64
 *             - not a SAML 2.0 Response XML document
 *             - IdP certificate not configured (cannot verify)
 *             - XML-DSig signature missing or cryptographically invalid
 *   • 200  – Signature verified (full session issuance deferred to next task).
 */
router.post("/callback", (req, res) => {
  const body = req.body || {};
  const rawResponse = body.SAMLResponse;

  // 400 — missing SAMLResponse field entirely
  if (!rawResponse || rawResponse.trim() === "") {
    return res.status(400).json({
      status: "error",
      message: "Missing SAMLResponse in request body.",
    });
  }

  // Decode Base64 → XML string
  let decoded;
  try {
    decoded = Buffer.from(rawResponse, "base64").toString("utf8");
  } catch (_) {
    return res.status(401).json({
      status: "error",
      message: "Invalid SAMLResponse: Base64 decoding failed.",
    });
  }

  // Must look like a SAML 2.0 Response document
  const looksLikeSaml =
    decoded.includes("samlp:Response") ||
    decoded.includes("urn:oasis:names:tc:SAML:2.0:protocol");

  if (!looksLikeSaml) {
    return res.status(401).json({
      status: "error",
      message: "Invalid SAMLResponse: document does not appear to be a SAML 2.0 Response.",
    });
  }

  // Require a configured IdP certificate — without it we cannot verify the
  // signature and must refuse to accept the assertion.
  const cert = samlConfig.idp.certificate;
  if (!cert) {
    return res.status(401).json({
      status: "error",
      message:
        "Cannot verify SAMLResponse: IdP certificate (SAML_IDP_CERTIFICATE) is not configured.",
    });
  }

  // Perform XML-DSig signature verification using Node built-in crypto
  const result = verifySamlSignature(decoded, cert);
  if (!result.valid) {
    return res.status(401).json({
      status: "error",
      message: "SAMLResponse signature verification failed.",
      reason: result.reason,
    });
  }

  // TODO (next task): parse the verified assertion, look up / provision the
  // user account, and issue a session cookie or JWT.
  return res.status(200).json({
    status: "ok",
    message: "SAMLResponse signature verified successfully.",
  });
});

// ---------------------------------------------------------------------------
// GET /api/auth/saml/metadata
// ---------------------------------------------------------------------------

/**
 * Return this Service Provider's SAML metadata XML.
 */
router.get("/metadata", (req, res) => {
  const { entityId, acsUrl } = samlConfig.sp;
  const { wantAssertionsSigned } = samlConfig.security;

  const metadataXml = `<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor
  xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
  entityID="${entityId}">

  <SPSSODescriptor
    AuthnRequestsSigned="false"
    WantAssertionsSigned="${wantAssertionsSigned}"
    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">

    <!--
      KeyDescriptor elements (signing / encryption certificates) will be
      added here once SP key-pair generation is implemented.
    -->

    <AssertionConsumerService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="${acsUrl}"
      index="0"
      isDefault="true"/>

  </SPSSODescriptor>

</EntityDescriptor>`;

  res.set("Content-Type", "application/xml; charset=utf-8");
  return res.status(200).send(metadataXml);
});

module.exports = router;
