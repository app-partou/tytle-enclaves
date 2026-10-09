#!/bin/bash
# Synthetic certificate chains in the AWS Nitro attestation shape, for the verifier tests.
#
# Run ONCE; the outputs are committed so the test suite needs no OpenSSL. Needs OpenSSL >= 3.4
# (-not_before / -not_after):  OPENSSL=/opt/homebrew/opt/openssl@3/bin/openssl bash generate.sh
#
# Trusted NOWHERE: production pins the embedded AWS Nitro root (src/awsNitroRootCa.ts); these chains
# verify only under the anchor a test injects. The CA private keys are deleted after signing; only
# the leaf keys are kept (a test signs its documents with them).
#
# Shape (docs/ENCLAVE_ATTESTATION_AUDIT_2026_10.md §2, AWS "Verifying the root of trust"):
#   P-384 everywhere, ECDSA-SHA384 signatures; cabundle = [ROOT, INTERMEDIATE] (root first);
#   the leaf lives 3 hours, like the AWS leaf. All chains are pinned to ONE instant so a test can
#   freeze the clock around it: the documents are "signed" at 2026-10-05T12:00:00Z, the leaf is
#   valid 11:00Z-15:00Z, the CAs 2020-2060.
#
#   a/        the main chain: root-a -> int-a -> leaf-a
#   a/direct  a leaf signed by root-a itself (a one-member cabundle)
#   a/noca    int-a-noca (CA:FALSE, still signed by root-a) -> leaf-a-noca
#   a/leafca  leaf-a-ca, a leaf that claims CA:TRUE (signed by int-a)
#   b/        a second, unrelated chain: root-b -> int-b -> leaf-b (a self-signed CA that is not the pin)
#   c/        AWS's real depth: root-c -> int-c-regional -> int-c-zonal -> int-c-instance -> leaf-c,
#             a cabundle of four and five certificates in all. AWS's lower CAs are short-lived too: the
#             zonal CA lives the month (October 2026), the instance CA only the day of the signature, so a
#             verifier that judged them at "now" would refuse the document the next day.
#   c/noca    int-c-instance-noca (CA:FALSE, signed by the zonal CA) -> leaf-c-noca: a non-CA deep in the bundle
#
# Each chain is generated only when its root is absent, so adding a chain never re-keys a committed one
# (the committed static fixture and every test document are signed under them). Added 2026-10-07: c/.
set -euo pipefail
cd "$(dirname "$0")"
OPENSSL="${OPENSSL:-openssl}"
CA_FROM=20200101000000Z
CA_TO=20600101000000Z
LEAF_FROM=20261005110000Z
LEAF_TO=20261005150000Z
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

newkey() { "$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$1"; }

root() { # <name>
  newkey "$TMP/$1.key"
  "$OPENSSL" req -new -x509 -key "$TMP/$1.key" -subj "/CN=synthetic-nitro-$1" -sha384 \
    -not_before "$CA_FROM" -not_after "$CA_TO" -set_serial 1 \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -out "$1.pem"
}

issue() { # <name> <issuer> <serial> <from> <to> <ca:TRUE|FALSE> <keep-key: yes|no>
  local name=$1 issuer=$2 serial=$3 from=$4 to=$5 ca=$6 keep=$7 keyfile
  if [ "$keep" = yes ]; then keyfile="$name-TESTONLY.key.pem"; else keyfile="$TMP/$name.key"; fi
  newkey "$keyfile"
  "$OPENSSL" req -new -key "$keyfile" -subj "/CN=synthetic-nitro-$name" -out "$TMP/$name.csr"
  if [ "$ca" = TRUE ]; then usage="keyCertSign,cRLSign"; else usage="digitalSignature"; fi
  printf 'basicConstraints=critical,CA:%s\nkeyUsage=critical,%s\n' "$ca" "$usage" > "$TMP/$name.ext"
  local issuerkey="$TMP/$issuer.key"
  [ -f "$issuerkey" ] || issuerkey="$issuer-TESTONLY.key.pem"
  "$OPENSSL" x509 -req -in "$TMP/$name.csr" -CA "$issuer.pem" -CAkey "$issuerkey" -sha384 \
    -set_serial "$serial" -not_before "$from" -not_after "$to" -extfile "$TMP/$name.ext" -out "$name.pem"
}

if [ ! -f root-a.pem ]; then
  root root-a
  issue int-a root-a 2 "$CA_FROM" "$CA_TO" TRUE no
  issue leaf-a int-a 3 "$LEAF_FROM" "$LEAF_TO" FALSE yes
  issue leaf-a-direct root-a 4 "$LEAF_FROM" "$LEAF_TO" FALSE yes
  issue int-a-noca root-a 5 "$CA_FROM" "$CA_TO" FALSE no
  issue leaf-a-noca int-a-noca 6 "$LEAF_FROM" "$LEAF_TO" FALSE yes
  issue leaf-a-ca int-a 7 "$LEAF_FROM" "$LEAF_TO" TRUE yes
fi

if [ ! -f root-b.pem ]; then
  root root-b
  issue int-b root-b 2 "$CA_FROM" "$CA_TO" TRUE no
  issue leaf-b int-b 3 "$LEAF_FROM" "$LEAF_TO" FALSE yes
fi

if [ ! -f root-c.pem ]; then
  root root-c
  issue int-c-regional root-c 2 "$CA_FROM" "$CA_TO" TRUE no
  issue int-c-zonal int-c-regional 3 20261001000000Z 20261101000000Z TRUE no
  issue int-c-instance int-c-zonal 4 20261005000000Z 20261006000000Z TRUE no
  issue leaf-c int-c-instance 5 "$LEAF_FROM" "$LEAF_TO" FALSE yes
  issue int-c-instance-noca int-c-zonal 6 20261005000000Z 20261006000000Z FALSE no
  issue leaf-c-noca int-c-instance-noca 7 "$LEAF_FROM" "$LEAF_TO" FALSE yes
fi

echo "generated: $(ls *.pem | tr '\n' ' ')"
