/**
 * SAML SSO Configuration Module
 *
 * Holds Identity Provider (IdP) and Service Provider (SP) settings for SAML
 * authentication. Values are read from environment variables so that secrets
 * are never hard-coded. Sensible defaults are provided for local development.
 *
 * Environment variables
 * ─────────────────────
 * SAML_IDP_ENTITY_ID      – Unique URI that identifies the IdP
 * SAML_IDP_SSO_URL        – IdP's HTTP-Redirect / HTTP-POST SSO endpoint
 * SAML_IDP_CERTIFICATE    – Base-64-encoded X.509 certificate from the IdP
 *                           (used to verify the IdP's assertion signature)
 *
 * SAML_SP_ENTITY_ID       – Unique URI that identifies this Service Provider
 * SAML_SP_ACS_URL         – Assertion Consumer Service URL
 *                           (must match POST /api/auth/saml/callback)
 * SAML_SP_METADATA_URL    – Public URL where SP metadata is served
 *                           (must match GET /api/auth/saml/metadata)
 *
 * SAML_WANT_ASSERTIONS_SIGNED   – "true" | "false"  (default: "true")
 * SAML_WANT_RESPONSE_SIGNED     – "true" | "false"  (default: "true")
 */

"use strict";

/**
 * Parse a boolean-ish environment variable.
 * @param {string|undefined} value
 * @param {boolean} defaultValue
 * @returns {boolean}
 */
function parseBool(value, defaultValue) {
  if (value === undefined || value === null || value === "") return defaultValue;
  return value.trim().toLowerCase() !== "false";
}

/**
 * Identity Provider settings.
 * These values come from the IdP's metadata XML or admin console.
 */
const idp = {
  /**
   * Unique URI that identifies the Identity Provider.
   * Default is a placeholder suitable for local development and testing.
   * Override with SAML_IDP_ENTITY_ID in production.
   */
  entityId: process.env.SAML_IDP_ENTITY_ID || "urn:idp:example",

  /**
   * IdP's Single Sign-On service URL.
   * The SP will redirect the user here to initiate authentication.
   * Default points to a local mock IdP for development/testing.
   * Override with SAML_IDP_SSO_URL in production.
   */
  ssoUrl: process.env.SAML_IDP_SSO_URL || "http://localhost:8080/sso",

  /**
   * Base-64-encoded X.509 certificate provided by the IdP.
   * Used to verify the digital signature on SAML responses / assertions.
   * Strip PEM headers before storing in the environment variable.
   *
   * When unset, the /callback endpoint will reject all SAMLResponses with
   * 401 ("certificate not configured") — which is the correct secure default.
   * Set SAML_IDP_CERTIFICATE in production to enable signature verification.
   */
  certificate: process.env.SAML_IDP_CERTIFICATE || "",
};

/**
 * Service Provider settings.
 * These values describe *this* application to the IdP.
 */
const sp = {
  /** Unique URI that identifies this Service Provider. */
  entityId: process.env.SAML_SP_ENTITY_ID || "urn:sp:nextcloud-talk",

  /**
   * Assertion Consumer Service URL.
   * The IdP will POST the SAML response to this endpoint after authentication.
   * Must match the registered ACS URL in the IdP configuration.
   */
  acsUrl:
    process.env.SAML_SP_ACS_URL ||
    "http://localhost:9090/api/auth/saml/callback",

  /**
   * URL where this SP's metadata XML is publicly accessible.
   * Register this with the IdP so it can discover SP capabilities.
   */
  metadataUrl:
    process.env.SAML_SP_METADATA_URL ||
    "http://localhost:9090/api/auth/saml/metadata",
};

/**
 * Security / validation options.
 */
const security = {
  /** Require the IdP to sign SAML assertions. */
  wantAssertionsSigned: parseBool(process.env.SAML_WANT_ASSERTIONS_SIGNED, true),

  /** Require the IdP to sign the SAML response envelope. */
  wantResponseSigned: parseBool(process.env.SAML_WANT_RESPONSE_SIGNED, true),
};

/**
 * Validate the minimum IdP fields needed to initiate a login redirect.
 * The IdP certificate is NOT required at login time — it is only used when
 * verifying the assertion that comes back on the /callback endpoint.
 *
 * Returns an array of missing field names (empty array = valid).
 * @returns {string[]}
 */
function validateLoginConfig() {
  const missing = [];
  if (!idp.entityId) missing.push("SAML_IDP_ENTITY_ID");
  if (!idp.ssoUrl)   missing.push("SAML_IDP_SSO_URL");
  return missing;
}

/**
 * Validate that ALL required IdP fields are present, including the certificate
 * needed to verify assertion signatures at the /callback endpoint.
 *
 * Returns an array of missing field names (empty array = valid).
 * @returns {string[]}
 */
function validateIdpConfig() {
  const missing = validateLoginConfig();
  if (!idp.certificate) missing.push("SAML_IDP_CERTIFICATE");
  return missing;
}

module.exports = {
  idp,
  sp,
  security,
  validateLoginConfig,
  validateIdpConfig,
};
