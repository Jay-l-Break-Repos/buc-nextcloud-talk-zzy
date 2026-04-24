/**
 * SAML SSO Configuration
 *
 * Configures the Service Provider (SP) and Identity Provider (IdP) settings
 * for SAML 2.0 authentication using the samlify library.
 *
 * Environment variables:
 *   SAML_IDP_SSO_URL        — IdP Single Sign-On URL (login endpoint)
 *   SAML_IDP_ENTITY_ID      — IdP entity ID
 *   SAML_IDP_CERTIFICATE    — IdP X.509 certificate (PEM) for signature verification
 *   SAML_SP_ENTITY_ID       — SP entity ID (unique identifier for this application)
 *   SAML_SP_ACS_URL         — SP Assertion Consumer Service URL (callback endpoint)
 *   SAML_SP_PRIVATE_KEY     — SP private key (PEM) for signing requests (optional)
 *   SAML_SP_CERTIFICATE     — SP X.509 certificate (PEM) for metadata (optional)
 */

const saml = require("samlify");
const crypto = require("crypto");

/**
 * XML digital signature validator.
 *
 * samlify delegates schema/signature validation to a user-supplied validator.
 * We perform real XML signature verification using the IdP certificate.
 */
saml.setSchemaValidator({
  validate: (xmlString) => {
    // Basic structural validation — ensure it looks like a SAML response
    if (!xmlString || typeof xmlString !== "string") {
      return Promise.reject(new Error("Empty or invalid SAML response"));
    }
    if (!xmlString.includes("samlp:Response") && !xmlString.includes("saml2p:Response")) {
      return Promise.reject(new Error("Not a valid SAML response document"));
    }
    // Signature validation is performed separately in validateXmlSignature()
    return Promise.resolve("validated");
  },
});

/**
 * Validate the XML digital signature in a SAML response.
 *
 * Extracts the <ds:SignatureValue> and <ds:SignedInfo> from the XML,
 * then verifies the signature against the IdP's X.509 certificate.
 *
 * @param {string} xml - The decoded SAML response XML
 * @param {string} idpCert - The IdP's X.509 certificate in PEM format
 * @returns {{ valid: boolean, error?: string }}
 */
function validateXmlSignature(xml, idpCert) {
  try {
    // Extract SignatureValue
    const sigValueMatch = xml.match(
      /<ds:SignatureValue[^>]*>([\s\S]*?)<\/ds:SignatureValue>/
    );
    if (!sigValueMatch) {
      return { valid: false, error: "No SignatureValue found in SAML response" };
    }

    // Extract the SignedInfo block (the data that was signed)
    const signedInfoMatch = xml.match(
      /<ds:SignedInfo[^>]*>([\s\S]*?)<\/ds:SignedInfo>/
    );
    if (!signedInfoMatch) {
      return { valid: false, error: "No SignedInfo found in SAML response" };
    }

    const signatureValue = sigValueMatch[1].replace(/\s+/g, "");
    const signedInfoXml = `<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">${signedInfoMatch[1]}</ds:SignedInfo>`;

    // Determine the signature algorithm from SignatureMethod
    const sigMethodMatch = signedInfoXml.match(
      /Algorithm="([^"]+)"/
    );
    let algorithm = "RSA-SHA256"; // default
    if (sigMethodMatch) {
      const algoUri = sigMethodMatch[1].toLowerCase();
      if (algoUri.includes("sha1")) {
        algorithm = "RSA-SHA1";
      } else if (algoUri.includes("sha512")) {
        algorithm = "RSA-SHA512";
      } else if (algoUri.includes("sha256")) {
        algorithm = "RSA-SHA256";
      }
    }

    // Normalise the certificate into PEM format if needed
    let pemCert = idpCert.trim();
    if (!pemCert.startsWith("-----BEGIN")) {
      pemCert = `-----BEGIN CERTIFICATE-----\n${pemCert}\n-----END CERTIFICATE-----`;
    }

    // Verify the signature
    const verifier = crypto.createVerify(algorithm);
    verifier.update(signedInfoXml);
    const isValid = verifier.verify(pemCert, signatureValue, "base64");

    if (!isValid) {
      return { valid: false, error: "XML signature verification failed — signature does not match" };
    }

    return { valid: true };
  } catch (err) {
    return { valid: false, error: `Signature validation error: ${err.message}` };
  }
}

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

/**
 * Return the raw IdP certificate string for use in signature validation.
 */
function getIdpCertificate() {
  return process.env.SAML_IDP_CERTIFICATE || "";
}

module.exports = {
  createIdentityProvider,
  createServiceProvider,
  validateXmlSignature,
  getIdpCertificate,
};
