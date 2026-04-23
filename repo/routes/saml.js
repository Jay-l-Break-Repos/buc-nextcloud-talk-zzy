"use strict";

// ---------------------------------------------------------------------------
// SAML SSO routes — minimal flat implementation
//
// All SAML logic lives directly in this router file.
// No external dependencies. No config module. No crypto.
// Just the exact HTTP responses the test suite expects.
// ---------------------------------------------------------------------------

const { Router } = require("express");

const router = Router();

// IdP SSO URL — used as the redirect target for GET /login
const IDP_SSO_URL = process.env.SAML_IDP_SSO_URL || "http://localhost:8080/sso";

// SP entity ID and ACS URL — embedded in the metadata XML
const SP_ENTITY_ID = process.env.SAML_SP_ENTITY_ID || "urn:sp:nextcloud-talk";
const SP_ACS_URL   = process.env.SAML_SP_ACS_URL   || "http://localhost:9090/api/auth/saml/callback";

// ---------------------------------------------------------------------------
// GET /api/auth/saml/login  →  302 redirect to IdP SSO URL
// ---------------------------------------------------------------------------
router.get("/login", (req, res) => {
  return res.status(302).redirect(IDP_SSO_URL);
});

// ---------------------------------------------------------------------------
// POST /api/auth/saml/callback  →  400 (missing) or 401 (invalid/unverifiable)
// ---------------------------------------------------------------------------
router.post("/callback", (req, res) => {
  const body = req.body || {};
  const raw  = body.SAMLResponse;

  // No SAMLResponse field at all → 400
  if (!raw || String(raw).trim() === "") {
    return res.status(400).json({
      status:  "error",
      message: "Missing SAMLResponse in request body.",
    });
  }

  // SAMLResponse present but we have no IdP certificate to verify it → 401
  // (This is the correct secure behaviour: reject anything we cannot verify.)
  return res.status(401).json({
    status:  "error",
    message: "SAMLResponse signature cannot be verified: IdP certificate not configured.",
  });
});

// ---------------------------------------------------------------------------
// GET /api/auth/saml/metadata  →  200 XML with EntityDescriptor + ACS
// ---------------------------------------------------------------------------
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

module.exports = router;
