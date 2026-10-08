/**
 * The trust anchor: the AWS Nitro Enclaves root CA (G1), embedded in this file for security:
 * - No TOFU (trust-on-first-use) problem
 * - No network dependency during verification
 * - Auditable in source code
 * - Fingerprint verified at runtime
 *
 * It is its own module so a test can swap the root of trust - and only it - for a synthetic one, the way the
 * main repo's verifier tests do (a document signed by AWS cannot be minted in a test).
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

/** The embedded AWS Nitro root CA, its fingerprint checked on first use. */
export function getAwsNitroRootCa(): crypto.X509Certificate {
  if (!rootCaCert) {
    const cert = new crypto.X509Certificate(AWS_NITRO_ROOT_CA_PEM);

    // Runtime fingerprint check — defense against supply-chain tampering of the embedded PEM
    const actualFingerprint = cert.fingerprint256.replace(/:/g, '');
    if (actualFingerprint !== EXPECTED_ROOT_FINGERPRINT) {
      throw new Error(
        `AWS Nitro root CA fingerprint mismatch! ` +
        `Expected: ${EXPECTED_ROOT_FINGERPRINT}, ` +
        `Got: ${actualFingerprint}. ` +
        `The embedded certificate may have been tampered with.`,
      );
    }
    rootCaCert = cert;
  }
  return rootCaCert;
}
