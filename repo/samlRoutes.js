/**
 * SAML SSO Authentication Routes — zero external SAML dependencies
 *
 * Provides three endpoints for SAML 2.0 Single Sign-On using only
 * Node.js built-in modules (crypto, zlib).
 *
 *   GET  /api/auth/saml/login    — Redirects the user to the IdP login page
 *   POST /api/auth/saml/callback — Receives and validates the SAML response
 *   GET  /api/auth/saml/metadata — Returns the SP metadata XML
 *
 * The callback endpoint performs XML digital signature validation against
 * the configured IdP certificate. Invalid or tampered responses are
 * rejected with HTTP 401 Unauthorized.
 */

const express = require("express");
const {
  createLoginRequestUrl,
  generateSpMetadata,
  validateXmlSignature,
  extractSamlAttributes,
} = require("./samlConfig");

const router = express.Router();

// ---------------------------------------------------------------------------
// GET /api/auth/saml/login
//
// Generates a SAML AuthnRequest, deflates and base64-encodes it, then
// redirects the user to the IdP's SSO URL with the SAMLRequest parameter.
// ---------------------------------------------------------------------------
router.get("/login", async (req, res) => {
  try {
    const redirectUrl = await createLoginRequestUrl();
    return res.redirect(redirectUrl);
  } catch (err) {
    console.error("[SAML] Login redirect failed:", err.message);
    return res.status(500).json({
      error: "saml_login_failed",
      message: "Failed to generate SAML login request. Check IdP configuration.",
    });
  }
});

// ---------------------------------------------------------------------------
// POST /api/auth/saml/callback
//
// Assertion Consumer Service (ACS) endpoint.
// The IdP posts the SAML response here after the user authenticates.
//
// Validates the XML digital signature in the SAML response against the
// configured IdP certificate. Returns 401 if validation fails.
// ---------------------------------------------------------------------------
router.post("/callback", express.urlencoded({ extended: false }), async (req, res) => {
  try {
    const samlResponse = req.body && req.body.SAMLResponse;

    if (!samlResponse) {
      return res.status(400).json({
        error: "missing_saml_response",
        message: "No SAMLResponse found in the POST body.",
      });
    }

    // Decode the base64-encoded SAML response
    let xml;
    try {
      xml = Buffer.from(samlResponse, "base64").toString("utf-8");
    } catch (decodeErr) {
      return res.status(400).json({
        error: "invalid_encoding",
        message: "SAMLResponse is not valid base64.",
      });
    }

    // Validate that it contains SAML response structure
    if (!xml.includes("Response")) {
      return res.status(401).json({
        error: "invalid_saml_response",
        message: "The payload is not a valid SAML response document.",
      });
    }

    // Validate the XML digital signature
    const sigResult = validateXmlSignature(xml);
    if (!sigResult.valid) {
      console.error("[SAML] Signature validation failed:", sigResult.error);
      return res.status(401).json({
        error: "invalid_signature",
        message: "SAML response signature validation failed.",
        details: sigResult.error,
      });
    }

    // Signature is valid — extract user attributes
    const { nameID, attributes } = extractSamlAttributes(xml);

    return res.json({
      status: "authenticated",
      message: "SAML response validated and parsed successfully.",
      user: {
        nameID,
        attributes,
      },
    });
  } catch (err) {
    console.error("[SAML] Callback processing failed:", err.message);
    return res.status(401).json({
      error: "saml_callback_failed",
      message: "Failed to process SAML response.",
      details: err.message,
    });
  }
});

// ---------------------------------------------------------------------------
// GET /api/auth/saml/metadata
//
// Returns the Service Provider metadata XML document.
// ---------------------------------------------------------------------------
router.get("/metadata", (req, res) => {
  try {
    const metadata = generateSpMetadata();
    res.set("Content-Type", "application/xml");
    return res.send(metadata);
  } catch (err) {
    console.error("[SAML] Metadata generation failed:", err.message);
    return res.status(500).json({
      error: "saml_metadata_failed",
      message: "Failed to generate SP metadata.",
    });
  }
});

module.exports = router;
