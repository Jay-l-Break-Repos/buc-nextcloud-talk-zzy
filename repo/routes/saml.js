/**
 * SAML SSO Route Handlers
 *
 * Implements the three core endpoints required for SAML 2.0 Web Browser SSO:
 *
 *   GET  /api/auth/saml/login     – Initiate SSO: redirect (302) to IdP SSO URL
 *   POST /api/auth/saml/callback  – ACS: validate SAMLResponse XML-DSig signature
 *   GET  /api/auth/saml/metadata  – Return this SP's metadata XML
 */

"use strict";

const { Router } = require("express");
const { DOMParser } = require("@xmldom/xmldom");
const { SignedXml } = require("xml-crypto");
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
 *             A full implementation will build a signed AuthnRequest and
 *             append it as a query-string parameter (HTTP-Redirect binding).
 *
 * The IdP certificate is NOT required at login time — it is only needed when
 * verifying the assertion that comes back on the /callback endpoint.
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

  // TODO (next task): build a signed AuthnRequest, deflate + Base64-encode it,
  // and append it as the SAMLRequest query parameter before redirecting.
  //
  // Use res.status(302).redirect() rather than res.redirect(302, url) because
  // the two-argument overload was removed in Express 5.
  return res.status(302).redirect(samlConfig.idp.ssoUrl);
});

// ---------------------------------------------------------------------------
// POST /api/auth/saml/callback  (Assertion Consumer Service)
// ---------------------------------------------------------------------------

/**
 * Wrap a bare base-64 certificate string in PEM armour.
 * xml-crypto's SignedXml expects a PEM-formatted public certificate.
 *
 * @param {string} certBase64 - raw base64 (with or without PEM headers)
 * @returns {string} PEM string
 */
function toPem(certBase64) {
  const stripped = certBase64
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s+/g, "");
  const lines = stripped.match(/.{1,64}/g) || [];
  return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----`;
}

/**
 * Verify every XML-DSig <Signature> element inside a decoded SAML Response.
 *
 * @param {string} xml   - decoded SAML Response XML string
 * @param {string} cert  - IdP certificate (PEM or bare base64)
 * @returns {{ valid: boolean, reason?: string }}
 */
function verifySamlSignature(xml, cert) {
  // Parse the XML document
  let doc;
  try {
    doc = new DOMParser().parseFromString(xml, "text/xml");
  } catch (e) {
    return { valid: false, reason: "XML parse error: " + e.message };
  }

  // Locate all <Signature> elements (may appear on the Response or Assertion)
  const sigNodes = doc.getElementsByTagNameNS(
    "http://www.w3.org/2000/09/xmldsig#",
    "Signature"
  );

  if (!sigNodes || sigNodes.length === 0) {
    return {
      valid: false,
      reason: "No XML-DSig <Signature> element found in SAMLResponse.",
    };
  }

  const pem = toPem(cert);

  // Verify each signature node against the IdP public certificate
  for (let i = 0; i < sigNodes.length; i++) {
    const sig = new SignedXml({ publicCert: pem });

    try {
      sig.loadSignature(sigNodes[i]);
      const ok = sig.checkSignature(xml);
      if (!ok) {
        return {
          valid: false,
          reason:
            "Signature verification failed: " +
            (sig.validationErrors || []).join("; "),
        };
      }
    } catch (e) {
      return { valid: false, reason: "Signature check threw: " + e.message };
    }
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
 *
 * Security note: the raw SAMLResponse value is never echoed back in error
 * responses because it may contain sensitive attribute claims.
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
      message:
        "Invalid SAMLResponse: document does not appear to be a SAML 2.0 Response.",
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

  // Perform full XML-DSig signature verification
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
 *
 * Returns a minimal but structurally correct EntityDescriptor document
 * containing the SP entity ID and the Assertion Consumer Service location.
 * A full implementation will add KeyDescriptor elements (SP signing /
 * encryption certificates) once SP key-pair generation is in place.
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
