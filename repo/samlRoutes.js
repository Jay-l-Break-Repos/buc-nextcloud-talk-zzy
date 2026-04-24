/**
 * SAML SSO Authentication Routes
 *
 * Provides three endpoints for SAML 2.0 Single Sign-On:
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
  createIdentityProvider,
  createServiceProvider,
  validateXmlSignature,
  getIdpCertificate,
} = require("./samlConfig");

const router = express.Router();

// Lazily initialised SP and IdP instances (created on first request)
let sp = null;
let idp = null;

function ensureProviders() {
  if (!sp) {
    sp = createServiceProvider();
  }
  if (!idp) {
    idp = createIdentityProvider();
  }
}

// ---------------------------------------------------------------------------
// GET /api/auth/saml/login
//
// Generates a SAML AuthnRequest and redirects the user to the IdP's
// Single Sign-On URL with the encoded request as a query parameter.
// ---------------------------------------------------------------------------
router.get("/login", async (req, res) => {
  try {
    ensureProviders();

    // createLoginRequest produces { id, context } where context is the
    // full redirect URL including the SAMLRequest query parameter.
    const { context } = sp.createLoginRequest(idp, "redirect");

    return res.redirect(context);
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
    ensureProviders();

    const samlResponse = req.body.SAMLResponse;

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

    // Validate that it looks like a SAML response
    if (!xml.includes("samlp:Response") && !xml.includes("saml2p:Response") && !xml.includes(":Response")) {
      return res.status(401).json({
        error: "invalid_saml_response",
        message: "The response is not a valid SAML response document.",
      });
    }

    // Check for the presence of a Signature element
    const hasSignature = xml.includes("ds:Signature") || xml.includes("Signature");
    const idpCert = getIdpCertificate();

    // Validate the XML digital signature
    if (hasSignature) {
      if (!idpCert) {
        // No IdP certificate configured — cannot validate signatures
        console.error("[SAML] No IdP certificate configured; cannot validate signature");
        return res.status(401).json({
          error: "signature_validation_failed",
          message: "SAML response contains a signature but no IdP certificate is configured for validation.",
        });
      }

      const sigResult = validateXmlSignature(xml, idpCert);
      if (!sigResult.valid) {
        console.error("[SAML] Signature validation failed:", sigResult.error);
        return res.status(401).json({
          error: "invalid_signature",
          message: "SAML response signature validation failed.",
          details: sigResult.error,
        });
      }
    } else {
      // No signature present — reject unsigned responses
      return res.status(401).json({
        error: "missing_signature",
        message: "SAML response does not contain a digital signature.",
      });
    }

    // Signature is valid — attempt to parse the response via samlify
    let parseResult;
    try {
      parseResult = await sp.parseLoginResponse(idp, "post", { body: req.body });
    } catch (parseErr) {
      console.error("[SAML] Response parsing failed:", parseErr.message);
      return res.status(401).json({
        error: "saml_parse_failed",
        message: "Failed to parse SAML response after signature validation.",
        details: parseErr.message,
      });
    }

    // Extract user attributes from the assertion
    const extract = parseResult.extract || {};
    const nameID = extract.nameID || null;
    const attributes = extract.attributes || {};

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
// This is shared with the IdP administrator so they can configure the
// trust relationship.
// ---------------------------------------------------------------------------
router.get("/metadata", (req, res) => {
  try {
    ensureProviders();

    const metadata = sp.getMetadata();

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
