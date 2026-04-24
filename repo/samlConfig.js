/**
 * SAML SSO Configuration — zero external dependencies
 *
 * Implements SAML 2.0 SP functionality using only Node.js built-in modules
 * (crypto, zlib, querystring). No samlify or other SAML libraries required.
 *
 * Environment variables:
 *   SAML_IDP_SSO_URL        — IdP Single Sign-On URL (login endpoint)
 *   SAML_IDP_ENTITY_ID      — IdP entity ID
 *   SAML_IDP_CERTIFICATE    — IdP X.509 certificate (PEM) for signature verification
 *   SAML_SP_ENTITY_ID       — SP entity ID (unique identifier for this application)
 *   SAML_SP_ACS_URL         — SP Assertion Consumer Service URL (callback endpoint)
 */

const crypto = require("crypto");
const zlib = require("zlib");

// ---------------------------------------------------------------------------
// Configuration helpers
// ---------------------------------------------------------------------------

function getConfig() {
  return {
    idpSsoUrl: process.env.SAML_IDP_SSO_URL || "https://idp.example.com/sso/saml",
    idpEntityId: process.env.SAML_IDP_ENTITY_ID || process.env.SAML_IDP_SSO_URL || "https://idp.example.com/sso/saml",
    idpCertificate: process.env.SAML_IDP_CERTIFICATE || "",
    spEntityId: process.env.SAML_SP_ENTITY_ID || "https://nextcloud-talk.example.com/saml/metadata",
    spAcsUrl: process.env.SAML_SP_ACS_URL || "http://localhost:9090/api/auth/saml/callback",
  };
}

// ---------------------------------------------------------------------------
// AuthnRequest generation (for login redirect)
// ---------------------------------------------------------------------------

/**
 * Generate a SAML 2.0 AuthnRequest XML and return the IdP redirect URL.
 *
 * The AuthnRequest is deflated, base64-encoded, and URL-encoded as the
 * SAMLRequest query parameter on the IdP's SSO URL.
 *
 * @returns {Promise<string>} The full redirect URL
 */
function createLoginRequestUrl() {
  const config = getConfig();
  const id = "_" + crypto.randomBytes(16).toString("hex");
  const issueInstant = new Date().toISOString();

  const authnRequest = [
    '<samlp:AuthnRequest',
    '  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"',
    '  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"',
    `  ID="${id}"`,
    '  Version="2.0"',
    `  IssueInstant="${issueInstant}"`,
    `  AssertionConsumerServiceURL="${config.spAcsUrl}"`,
    '  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"',
    `  Destination="${config.idpSsoUrl}">`,
    `  <saml:Issuer>${config.spEntityId}</saml:Issuer>`,
    '  <samlp:NameIDPolicy',
    '    Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"',
    '    AllowCreate="true"/>',
    '</samlp:AuthnRequest>',
  ].join("\n");

  return new Promise((resolve, reject) => {
    zlib.deflateRaw(authnRequest, (err, deflated) => {
      if (err) return reject(err);
      const encoded = deflated.toString("base64");
      const separator = config.idpSsoUrl.includes("?") ? "&" : "?";
      const url = `${config.idpSsoUrl}${separator}SAMLRequest=${encodeURIComponent(encoded)}`;
      resolve(url);
    });
  });
}

// ---------------------------------------------------------------------------
// SP Metadata generation
// ---------------------------------------------------------------------------

/**
 * Generate the SP metadata XML document.
 *
 * @returns {string} XML metadata
 */
function generateSpMetadata() {
  const config = getConfig();

  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<md:EntityDescriptor',
    '  xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"',
    `  entityID="${config.spEntityId}">`,
    '  <md:SPSSODescriptor',
    '    AuthnRequestsSigned="false"',
    '    WantAssertionsSigned="true"',
    '    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">',
    '    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>',
    '    <md:AssertionConsumerService',
    '      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"',
    `      Location="${config.spAcsUrl}"`,
    '      index="0"',
    '      isDefault="true"/>',
    '  </md:SPSSODescriptor>',
    '</md:EntityDescriptor>',
  ].join("\n");
}

// ---------------------------------------------------------------------------
// XML Signature Validation
// ---------------------------------------------------------------------------

/**
 * Validate the XML digital signature in a SAML response.
 *
 * @param {string} xml - The decoded SAML response XML
 * @returns {{ valid: boolean, error?: string }}
 */
function validateXmlSignature(xml) {
  const config = getConfig();

  try {
    // Must have a Signature element
    const hasSignature = xml.includes("<ds:Signature") || xml.includes("<Signature");
    if (!hasSignature) {
      return { valid: false, error: "No XML signature found in SAML response" };
    }

    // Extract SignatureValue
    const sigValueMatch = xml.match(
      /<(?:ds:)?SignatureValue[^>]*>([\s\S]*?)<\/(?:ds:)?SignatureValue>/
    );
    if (!sigValueMatch) {
      return { valid: false, error: "No SignatureValue element found" };
    }

    // Extract SignedInfo block
    const signedInfoMatch = xml.match(
      /(<(?:ds:)?SignedInfo[\s\S]*?<\/(?:ds:)?SignedInfo>)/
    );
    if (!signedInfoMatch) {
      return { valid: false, error: "No SignedInfo element found" };
    }

    // If no IdP certificate is configured, we cannot verify
    if (!config.idpCertificate) {
      return { valid: false, error: "No IdP certificate configured for signature verification" };
    }

    const signatureValue = sigValueMatch[1].replace(/\s+/g, "");
    const signedInfoXml = signedInfoMatch[1];

    // Ensure the SignedInfo has the xmldsig namespace for canonical form
    let canonicalSignedInfo = signedInfoXml;
    if (!canonicalSignedInfo.includes("xmlns:ds=") && !canonicalSignedInfo.includes("xmlns=")) {
      canonicalSignedInfo = canonicalSignedInfo.replace(
        /(<(?:ds:)?SignedInfo)/,
        '$1 xmlns:ds="http://www.w3.org/2000/09/xmldsig#"'
      );
    }

    // Determine signature algorithm
    const sigMethodMatch = canonicalSignedInfo.match(/Algorithm="([^"]+)"/);
    let algorithm = "RSA-SHA256";
    if (sigMethodMatch) {
      const algoUri = sigMethodMatch[1].toLowerCase();
      if (algoUri.includes("sha1")) algorithm = "RSA-SHA1";
      else if (algoUri.includes("sha512")) algorithm = "RSA-SHA512";
      else if (algoUri.includes("sha256")) algorithm = "RSA-SHA256";
    }

    // Normalise certificate to PEM
    let pemCert = config.idpCertificate.trim();
    if (!pemCert.startsWith("-----BEGIN")) {
      pemCert = "-----BEGIN CERTIFICATE-----\n" + pemCert + "\n-----END CERTIFICATE-----";
    }

    // Verify
    const verifier = crypto.createVerify(algorithm);
    verifier.update(canonicalSignedInfo);
    const isValid = verifier.verify(pemCert, signatureValue, "base64");

    if (!isValid) {
      return { valid: false, error: "XML signature verification failed — signature does not match" };
    }

    return { valid: true };
  } catch (err) {
    return { valid: false, error: "Signature validation error: " + err.message };
  }
}

// ---------------------------------------------------------------------------
// SAML Response Parsing
// ---------------------------------------------------------------------------

/**
 * Extract basic attributes from a decoded SAML response XML.
 *
 * @param {string} xml - The decoded SAML response XML
 * @returns {{ nameID: string|null, attributes: object }}
 */
function extractSamlAttributes(xml) {
  let nameID = null;
  const attributes = {};

  // Extract NameID
  const nameIdMatch = xml.match(/<(?:saml2?:)?NameID[^>]*>([\s\S]*?)<\/(?:saml2?:)?NameID>/);
  if (nameIdMatch) {
    nameID = nameIdMatch[1].trim();
  }

  // Extract Attribute elements
  const attrRegex = /<(?:saml2?:)?Attribute\s+Name="([^"]+)"[^>]*>[\s\S]*?<(?:saml2?:)?AttributeValue[^>]*>([\s\S]*?)<\/(?:saml2?:)?AttributeValue>[\s\S]*?<\/(?:saml2?:)?Attribute>/g;
  let match;
  while ((match = attrRegex.exec(xml)) !== null) {
    attributes[match[1]] = match[2].trim();
  }

  return { nameID, attributes };
}

module.exports = {
  getConfig,
  createLoginRequestUrl,
  generateSpMetadata,
  validateXmlSignature,
  extractSamlAttributes,
};
