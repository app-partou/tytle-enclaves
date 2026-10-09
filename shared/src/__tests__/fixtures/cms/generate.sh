#!/usr/bin/env bash
#
# How the CMS fixtures were made (enclave audit P1.7): once, on 2026-10-08, with OpenSSL 3.6, and committed. OpenSSL
# is the independent writer the enclave's reader (shared/src/cms.ts) is tested against: KMS returns the same structure
# (CMS EnvelopedData: the content key wrapped with RSAES-OAEP SHA-256 to the attestation document's RSA key, the secret
# under AES-256-CBC). Every key here is TEST ONLY and trusted nowhere. Running this again makes NEW keys and new files.
set -euo pipefail
cd "$(dirname "$0")"
printf 'sk_test_TESTONLY_not-a-real-stripe-key' > secret.txt

# The recipient: RSA-2048, as the enclave makes one per process (OpenSSL's cms needs a certificate to name it)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out recipient-TESTONLY.key.pem
openssl req -new -x509 -key recipient-TESTONLY.key.pem -out recipient.pem -days 3650 -subj '/CN=tytle-probe-cms-recipient-TESTONLY'
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out other-TESTONLY.key.pem
openssl req -new -x509 -key other-TESTONLY.key.pem -out other.pem -days 3650 -subj '/CN=tytle-probe-cms-other-TESTONLY'

oaep256=(-keyopt rsa_padding_mode:oaep -keyopt rsa_oaep_md:sha256 -keyopt rsa_mgf1_md:sha256)

# What the reader opens: KMS's pair of algorithms, in DER and in streamed BER (indefinite lengths, content in chunks),
# the recipient named by its key identifier (KMS has no certificate to name) or by issuer and serial
openssl cms -encrypt -binary -in secret.txt -aes256 -recip recipient.pem "${oaep256[@]}" -keyid -outform DER -out oaep256-aes256-keyid.der
openssl cms -encrypt -binary -in secret.txt -aes256 -recip recipient.pem "${oaep256[@]}" -keyid -outform DER -stream -out oaep256-aes256-keyid-stream.ber
openssl cms -encrypt -binary -in secret.txt -aes256 -recip recipient.pem "${oaep256[@]}" -outform DER -out oaep256-aes256-issuer.der

# What it refuses, one rule each
openssl cms -encrypt -binary -in secret.txt -aes256 -recip recipient.pem -keyopt rsa_padding_mode:oaep -keyid -outform DER -out oaep-sha1-aes256.der
openssl cms -encrypt -binary -in secret.txt -aes256 -recip recipient.pem -keyid -outform DER -out pkcs1v15-aes256.der
openssl cms -encrypt -binary -in secret.txt -aes128 -recip recipient.pem "${oaep256[@]}" -keyid -outform DER -out oaep256-aes128.der
openssl cms -encrypt -binary -in secret.txt -aes256 -recip recipient.pem "${oaep256[@]}" -recip other.pem "${oaep256[@]}" -keyid -outform DER -out two-recipients.der
