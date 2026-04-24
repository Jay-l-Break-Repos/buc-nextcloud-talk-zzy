/**
 * SAML SSO Authentication Routes
 *
 * Provides three endpoints for SAML 2.0 Single Sign-On:
 *
 *   GET  /api/auth/saml/login    — Redirects the user to the IdP login page
 *   POST /api/auth/saml/callback — Receives and processes the SAML response (placeholder)
 *   GET  /api/auth/saml/metadata — Returns the SP metadata XML
 *
 * Phase 1: Basic route structure and redirect flow.
 * Full signature validation and user attribute extraction will be added in follow-up phases.
 */

const express = require("express");
const { createIdentityProvider, createServiceProvider } = require("./samlConfig");

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
// Phase 1 — placeholder: acknowledges receipt of the SAML response.
// Full response parsing, signature validation, and user attribute extraction
// will be implemented in a follow-up step.
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

    // Phase 1: Attempt basic parsing via samlify (schema validation is
    // currently set to permissive/skip mode in samlConfig.js).
    // Full validation will be enabled in a follow-up phase.
    const parseResult = await sp.parseLoginResponse(idp, "post", { body: req.body });

    // TODO (Phase 2): Validate signature, extract user attributes,
    //                  create/update local user session, issue JWT, etc.

    return res.json({
      status: "callback_received",
      message: "SAML response received and parsed. Full processing will be implemented in Phase 2.",
      extract: parseResult.extract || null,
    });
  } catch (err) {
    console.error("[SAML] Callback processing failed:", err.message);
    return res.status(500).json({
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
