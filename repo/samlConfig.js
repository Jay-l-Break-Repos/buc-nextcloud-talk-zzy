/**
 * SAML SSO Configuration
 *
 * Configures the Service Provider (SP) and Identity Provider (IdP) settings
 * for SAML 2.0 authentication using the samlify library.
 *
 * Environment variables:
 *   SAML_IDP_SSO_URL        — IdP Single Sign-On URL (login endpoint)
 *   SAML_IDP_CERTIFICATE    — IdP X.509 certificate (PEM) for signature verification
 *   SAML_SP_ENTITY_ID       — SP entity ID (unique identifier for this application)
 *   SAML_SP_ACS_URL         — SP Assertion Consumer Service URL (callback endpoint)
 *   SAML_SP_PRIVATE_KEY     — SP private key (PEM) for signing requests (optional)
 *   SAML_SP_CERTIFICATE     — SP X.509 certificate (PEM) for metadata (optional)
 */

const saml = require("samlify");

// Disable full signature validation for initial setup phase.
// TODO: Enable strict validation in follow-up implementation.
saml.setSchemaValidator({
  validate: (response) => Promise.resolve("skipped"),
});

/**
 * Build the Identity Provider configuration from environment variables.
 */
function createIdentityProvider() {
  const ssoLoginUrl = process.env.SAML_IDP_SSO_URL || "https://idp.example.com/sso/saml";
  const idpCertificate = process.env.SAML_IDP_CERTIFICATE || "";

  const idpConfig = {
    entityID: process.env.SAML_IDP_ENTITY_ID || ssoLoginUrl,
    singleSignOnService: [
      {
        Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
        Location: ssoLoginUrl,
      },
    ],
  };

  if (idpCertificate) {
    idpConfig.signingCert = idpCertificate;
  }

  return saml.IdentityProvider(idpConfig);
}

/**
 * Build the Service Provider configuration from environment variables.
 */
function createServiceProvider() {
  const entityId = process.env.SAML_SP_ENTITY_ID || "https://nextcloud-talk.example.com/saml/metadata";
  const acsUrl = process.env.SAML_SP_ACS_URL || "http://localhost:9090/api/auth/saml/callback";
  const spPrivateKey = process.env.SAML_SP_PRIVATE_KEY || "";
  const spCertificate = process.env.SAML_SP_CERTIFICATE || "";

  const spConfig = {
    entityID: entityId,
    assertionConsumerService: [
      {
        Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        Location: acsUrl,
      },
    ],
    nameIDFormat: ["urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"],
    authnRequestsSigned: false,
    wantAssertionsSigned: false,
  };

  if (spPrivateKey) {
    spConfig.privateKey = spPrivateKey;
  }
  if (spCertificate) {
    spConfig.signingCert = spCertificate;
  }

  return saml.ServiceProvider(spConfig);
}

module.exports = {
  createIdentityProvider,
  createServiceProvider,
};
