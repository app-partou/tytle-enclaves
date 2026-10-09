/**
 * X.509 certificate chain validation for AWS Nitro Enclaves (enclave audit P2.1).
 *
 * AWS ("Verifying the root of trust") orders the NSM payload's cabundle root first: [ROOT, INTERM_1, ..., INTERM_N].
 * The path is leaf -> INTERM_N -> ... -> INTERM_1 -> ROOT, and ROOT must BE the trust anchor: equal to it by
 * fingerprint, not merely signed by its key. Every certificate is judged at the document's signed time (the NSM
 * payload's timestamp): AWS's leaf lives about three hours, so judging at "now" refuses every stored document. The
 * anchor itself must also be valid now.
 *
 * The same rules as the main repo's verifier (packages/attestation-core nsmVerification.ts verifyCertChain).
 * Until 2026-10 this file walked [leaf, ROOT, INTERM_1, ...] and judged at "now", so every real document failed.
 */

import crypto from 'node:crypto';
import { getAwsNitroRootCa } from './trustAnchor.js';

export { getAwsNitroRootCa };

export interface ChainResult {
  valid: boolean;
  error?: string;
  /** Issuer / subject name mismatches where the signature holds: reported, never fatal (as in the core). */
  warnings: string[];
}

function validAt(cert: crypto.X509Certificate, at: Date): boolean {
  return new Date(cert.validFrom) <= at && new Date(cert.validTo) >= at;
}

/**
 * Verify the certificate chain of a Nitro attestation document:
 * 1. cabundle[0] is the trust anchor (by SHA-256 fingerprint)
 * 2. every cabundle member is a CA (basicConstraints CA:TRUE), and each is signed by the one before it
 * 3. the leaf is signed by the last cabundle member, is not a CA, and may sign (keyUsage digitalSignature, if present)
 * 4. every certificate is valid at `signedAt`; the anchor is also valid now
 *
 * @param leafCertDer - DER-encoded leaf certificate (from payload.certificate)
 * @param cabundle - DER-encoded CA certificates (from payload.cabundle), root first
 * @param signedAt - the document's signed time (the NSM payload's timestamp)
 * @param anchor - the trust anchor (the embedded AWS Nitro root)
 */
export function verifyCertificateChain(
  leafCertDer: Buffer,
  cabundle: Buffer[],
  signedAt: Date,
  anchor: crypto.X509Certificate = getAwsNitroRootCa(),
): ChainResult {
  const warnings: string[] = [];
  const fail = (error: string): ChainResult => ({ valid: false, error, warnings });
  try {
    if (Number.isNaN(signedAt.getTime())) return fail('The document has no valid signed time');
    if (cabundle.length === 0) return fail('cabundle is empty: a Nitro document always carries the root first');

    const bundle = cabundle.map((der) => new crypto.X509Certificate(der));
    const leaf = new crypto.X509Certificate(leafCertDer);

    if (bundle[0].fingerprint256 !== anchor.fingerprint256) {
      return fail(`cabundle[0] (${bundle[0].fingerprint256}) is not the AWS Nitro root (${anchor.fingerprint256})`);
    }
    for (let i = 0; i < bundle.length; i++) {
      if (!bundle[i].ca) return fail(`cabundle[${i}] is not a CA certificate (basicConstraints CA:TRUE missing)`);
    }
    for (let i = 0; i < bundle.length - 1; i++) {
      if (!bundle[i + 1].verify(bundle[i].publicKey)) return fail(`cabundle[${i + 1}] is not signed by cabundle[${i}]`);
      if (!bundle[i + 1].checkIssued(bundle[i])) warnings.push(`cabundle[${i + 1}] issuer does not match cabundle[${i}] subject`);
    }
    const issuer = bundle[bundle.length - 1];
    if (!leaf.verify(issuer.publicKey)) return fail(`Leaf certificate is not signed by cabundle[${bundle.length - 1}]`);
    if (!leaf.checkIssued(issuer)) warnings.push(`Leaf certificate issuer does not match cabundle[${bundle.length - 1}] subject`);
    if (leaf.ca) return fail('Leaf certificate is a CA certificate (basicConstraints CA:TRUE)');
    const leafKeyUsage = leaf.keyUsage;
    if (leafKeyUsage && !leafKeyUsage.includes('digitalSignature')) {
      return fail(`Leaf certificate keyUsage does not include digitalSignature: [${leafKeyUsage.join(', ')}]`);
    }

    if (!validAt(anchor, new Date())) return fail(`The AWS Nitro root is not valid now (valid ${anchor.validFrom} - ${anchor.validTo})`);
    for (let i = 0; i < bundle.length; i++) {
      if (!validAt(bundle[i], signedAt)) {
        return fail(`cabundle[${i}] is not valid at the signed time ${signedAt.toISOString()} (valid ${bundle[i].validFrom} - ${bundle[i].validTo})`);
      }
    }
    if (!validAt(leaf, signedAt)) {
      return fail(`Leaf certificate is not valid at the signed time ${signedAt.toISOString()} (valid ${leaf.validFrom} - ${leaf.validTo})`);
    }

    return { valid: true, warnings };
  } catch (err: unknown) {
    return fail(`Certificate chain verification error: ${err instanceof Error ? err.message : String(err)}`);
  }
}
