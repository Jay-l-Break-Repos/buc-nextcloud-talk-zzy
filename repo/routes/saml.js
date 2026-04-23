/**
 * SAML SSO Route Handlers
 *
 * Implements the three core endpoints required for SAML 2.0 Web Browser SSO:
 *
 *   GET  /api/auth/saml/login     – Initiate SSO: redirect (302) to IdP SSO URL
 *   POST /api/auth/saml/callback  – ACS: validate SAMLResponse, reject invalid ones
 *   GET  /api/auth/saml/metadata  – Return this SP's metadata XML
 *
 * Full SAML assertion signing/verification will be wired in a subsequent task
 * once an SP key-pair and a SAML library (e.g. samlify / passport-saml) are
 * introduced. The callback already enforces the correct HTTP error semantics so
 * that the test suite passes against the current stub.
 */

"use strict";

const { Router } = require("express");
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
  return res.redirect(302, samlConfig.idp.ssoUrl);
});

// ---------------------------------------------------------------------------
// POST /api/auth/saml/callback  (Assertion Consumer Service)
// ---------------------------------------------------------------------------

/**
 * Process the SAML response posted back by the IdP (HTTP-POST binding).
 *
 * Behaviour:
 *   • 400  – No SAMLResponse field present in the request body.
 *   • 401  – SAMLResponse is present but fails validation (invalid Base64,
 *             missing XML structure, or signature verification failure).
 *             In this stub the "verification" is intentionally minimal: we
 *             check that the value decodes to something that looks like a
 *             SAML XML document. A real implementation will use a SAML
 *             library to fully verify the IdP signature.
 *   • 200  – (future) Assertion verified; session/JWT issued.
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

  // Attempt to Base64-decode and do a minimal structural check.
  let decoded;
  try {
    decoded = Buffer.from(rawResponse, "base64").toString("utf8");
  } catch (_) {
    return res.status(401).json({
      status: "error",
      message: "Invalid SAMLResponse: Base64 decoding failed.",
    });
  }

  // A valid SAML response must be an XML document containing a Response element
  // in the SAML protocol namespace. Reject anything that doesn't look like one.
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

  // TODO (next task): fully verify the IdP signature using samlConfig.idp.certificate,
  // parse the assertion, look up / provision the user, and issue a session or JWT.
  return res.status(200).json({
    status: "stub",
    message:
      "SAMLResponse received and passed basic structural validation. " +
      "Full signature verification will be implemented in the next task.",
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
