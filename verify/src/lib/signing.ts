/**
 * The operator binding (enclave audit P1.6). PCR0 says WHICH code ran; anyone can build the public EIF and run it in
 * their own AWS account, and their documents carry the same PCR0. Tytle signs its EIFs: an EIF signed with a
 * certificate boots with PCR8 = SHA-384(48 zero bytes || SHA-384(the certificate's DER)) - the register starts at
 * zero and is extended once with the certificate's digest - and signing changes no other PCR. An unsigned EIF (every
 * rebuild, and the enclaves before the 2026-10 release) boots with PCR8 all zeroes. So a PCR8 that is the certificate's
 * says the EIF that ran is one its key signed.
 *
 * scripts/lib/recipe.mjs holds the same formula for the build (pcr8Of); signing.test.ts checks both against the PCR8
 * nitro-cli 1.4.4 printed for a real signed build.
 */

import crypto from 'node:crypto';

/** The PCR8 of an EIF signed with this certificate (PEM), lowercase hex. */
export function pcr8OfCertificate(certificatePem: string): string {
  const digest = crypto.createHash('sha384').update(new crypto.X509Certificate(certificatePem).raw).digest();
  return crypto.createHash('sha384').update(Buffer.concat([Buffer.alloc(48), digest])).digest('hex');
}

/** True for a PCR that holds nothing: absent, or all zeroes (an unsigned EIF's PCR8). */
export function isEmptyPcr(hex: string): boolean {
  return /^0*$/.test(hex);
}
