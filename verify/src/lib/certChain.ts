/**
 * X.509 certificate chain validation for AWS Nitro Enclaves.
 *
 * The AWS Nitro root CA is embedded directly in this file for security:
 * - No TOFU (trust-on-first-use) problem
 * - No network dependency during verification
 * - Auditable in source code
 * - Fingerprint verified at runtime
 *
 * To verify this root CA independently:
 *   curl -O https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
 *   unzip AWS_NitroEnclaves_Root-G1.zip
 *   openssl x509 -in root.pem -noout -fingerprint -sha256
 *   # Expected: 64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B
 */

import crypto from 'node:crypto';

// AWS Nitro Enclaves Root CA (G1)
// Subject: CN=aws.nitro-enclaves, OU=AWS, O=Amazon, C=US
// Valid: 2019-10-28 to 2049-10-28
// Algorithm: ECDSA P-384 with SHA-384
// Source: https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
const AWS_NITRO_ROOT_CA_PEM = `-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----`;

const EXPECTED_ROOT_FINGERPRINT = '641A0321A3E244EFE456463195D606317ED7CDCC3C1756E09893F3C68F79BB5B';

let rootCaCert: crypto.X509Certificate | null = null;

function getRootCa(): crypto.X509Certificate {
  if (!rootCaCert) {
    rootCaCert = new crypto.X509Certificate(AWS_NITRO_ROOT_CA_PEM);

    // Runtime fingerprint check — defense against supply-chain tampering of the embedded PEM
    const actualFingerprint = rootCaCert.fingerprint256.replace(/:/g, '');
    if (actualFingerprint !== EXPECTED_ROOT_FINGERPRINT) {
      throw new Error(
        `AWS Nitro root CA fingerprint mismatch! ` +
        `Expected: ${EXPECTED_ROOT_FINGERPRINT}, ` +
        `Got: ${actualFingerprint}. ` +
        `The embedded certificate may have been tampered with.`,
      );
    }
  }
  return rootCaCert;
}

/**
 * Verify the certificate chain from a Nitro attestation document.
 *
 * Validates:
 * 1. Each cert was issued by the next (issuer + signature)
 * 2. The last cert roots to the embedded AWS Nitro root CA
 * 3. All certs are within their validity period (notBefore ≤ now ≤ notAfter)
 * 4. Intermediate certs have CA:TRUE basic constraint
 * 5. Leaf cert has digitalSignature key usage (if keyUsage is present)
 *
 * @param leafCertDer - DER-encoded leaf certificate (from payload.certificate)
 * @param cabundle - Array of DER-encoded intermediate certificates (from payload.cabundle)
 */
export function verifyCertificateChain(
  leafCertDer: Buffer,
  cabundle: Buffer[],
): { valid: boolean; error?: string } {
  try {
    const rootCa = getRootCa();
    const now = new Date();

    // Build full chain: leaf + cabundle intermediates
    const certs = [
      new crypto.X509Certificate(leafCertDer),
      ...cabundle.map((der) => new crypto.X509Certificate(der)),
    ];

    // Check validity dates for all certs in the chain
    for (let i = 0; i < certs.length; i++) {
      const cert = certs[i];
      const label = i === 0 ? 'Leaf certificate' : `Intermediate certificate ${i}`;

      // Node's X509Certificate exposes validFrom/validTo as strings, and
      // validFromDate/validToDate as Date objects (Node 20.13+)
      const validFrom = new Date(cert.validFrom);
      const validTo = new Date(cert.validTo);

      if (validFrom > now) {
        return {
          valid: false,
          error: `${label} is not yet valid (validFrom: ${cert.validFrom})`,
        };
      }

      if (validTo < now) {
        return {
          valid: false,
          error: `${label} has expired (validTo: ${cert.validTo})`,
        };
      }
    }

    // Check root CA validity too
    const rootValidTo = new Date(rootCa.validTo);
    if (rootValidTo < now) {
      return {
        valid: false,
        error: `AWS Nitro root CA has expired (validTo: ${rootCa.validTo})`,
      };
    }

    // Leaf cert: check digitalSignature key usage (if present)
    const leafKeyUsage = certs[0].keyUsage;
    if (leafKeyUsage && !leafKeyUsage.includes('digitalSignature')) {
      return {
        valid: false,
        error: `Leaf certificate keyUsage does not include digitalSignature: [${leafKeyUsage.join(', ')}]`,
      };
    }

    // Intermediate certs: check CA basic constraint
    for (let i = 1; i < certs.length; i++) {
      if (!certs[i].ca) {
        return {
          valid: false,
          error: `Intermediate certificate ${i} does not have CA:TRUE basic constraint`,
        };
      }
    }

    // Verify each adjacent pair: cert[i] was issued by cert[i+1]
    for (let i = 0; i < certs.length - 1; i++) {
      const child = certs[i];
      const parent = certs[i + 1];

      if (!child.checkIssued(parent)) {
        return {
          valid: false,
          error: `Certificate ${i} was not issued by certificate ${i + 1} (${child.subject} → ${parent.subject})`,
        };
      }

      if (!child.verify(parent.publicKey)) {
        return {
          valid: false,
          error: `Certificate ${i} signature verification failed against certificate ${i + 1}`,
        };
      }
    }

    // Verify the last cert in chain was issued by the root CA
    const lastCert = certs[certs.length - 1];

    if (!lastCert.checkIssued(rootCa)) {
      return {
        valid: false,
        error: `Last certificate in chain was not issued by AWS Nitro root CA (${lastCert.subject})`,
      };
    }

    if (!lastCert.verify(rootCa.publicKey)) {
      return {
        valid: false,
        error: 'Last certificate signature verification failed against AWS Nitro root CA',
      };
    }

    return { valid: true };
  } catch (err: any) {
    return {
      valid: false,
      error: `Certificate chain verification error: ${err.message}`,
    };
  }
}

/**
 * Get the AWS Nitro root CA as an X509Certificate for external use.
 */
export function getAwsNitroRootCa(): crypto.X509Certificate {
  return getRootCa();
}
