#!/usr/bin/env bash
# Generates a full signing chain for delivery-kit image signing:
#   root CA -> intermediate CA -> leaf signer cert (all ECDSA P256)
#
# Produces:
#   root.key / root.crt              self-signed root CA
#   intermediate.key / .crt          sub-CA signed by root
#   leaf.key / leaf.crt              leaf signer cert (plain PKCS#8 key)
#   leaf.enc.key                     sigstore-encrypted key werf actually loads
#   chain.crt                        intermediate + root (root last)
#
# WERF_SIGN_KEY must point at leaf.enc.key (the "ENCRYPTED DELIVERY-KIT PRIVATE
# KEY" PEM). A plain openssl key is rejected by delivery-kit because it always
# runs sigstore's encrypted.Decrypt on the key bytes.
set -euo pipefail
cd "$(dirname "$0")"

# 1) Root CA
openssl ecparam -name prime256v1 -genkey -noout -out root.key
openssl req -x509 -new -key root.key -sha256 -days 3650 \
  -subj "/O=delivery-kit.dev/CN=delivery-kit-root" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out root.crt

# 2) Intermediate CA
openssl ecparam -name prime256v1 -genkey -noout -out intermediate.key
openssl req -new -key intermediate.key \
  -subj "/O=delivery-kit.dev/CN=delivery-kit-sub" -out intermediate.csr
openssl x509 -req -in intermediate.csr -CA root.crt -CAkey root.key -CAcreateserial \
  -days 1825 -sha256 \
  -extfile <(printf "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nextendedKeyUsage=codeSigning\n") \
  -out intermediate.crt

# 3) Leaf signer cert (plain PKCS#8 key)
openssl ecparam -name prime256v1 -genkey -noout -out leaf.ec.key
openssl pkcs8 -topk8 -nocrypt -in leaf.ec.key -out leaf.key
rm -f leaf.ec.key
openssl req -new -key leaf.key \
  -subj "/O=delivery-kit.dev/CN=delivery-kit-signer" -out leaf.csr
openssl x509 -req -in leaf.csr -CA intermediate.crt -CAkey intermediate.key -CAcreateserial \
  -days 825 -sha256 \
  -extfile <(printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=codeSigning\n") \
  -out leaf.crt

# 4) Verify chain
cat intermediate.crt root.crt > chain.crt
openssl verify -CAfile root.crt -untrusted intermediate.crt leaf.crt

# 5) Wrap leaf.key into the sigstore-encrypted PEM delivery-kit expects.
(cd wrap-key && go run . "$PWD/../leaf.key" "$PWD/../leaf.enc.key")

# 6) Convenience env file (paths resolve relative to the file itself).
cat > sign.env <<'ENV'
_DK_SIGN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
export WERF_SIGN_KEY=$_DK_SIGN_DIR/leaf.enc.key
export WERF_SIGN_CERT=$_DK_SIGN_DIR/leaf.crt
export WERF_SIGN_INTERMEDIATES=$_DK_SIGN_DIR/intermediate.crt
export WERF_VERIFY_ROOTS=$_DK_SIGN_DIR/root.crt
ENV

rm -f ./*.csr ./*.srl
echo "OK: signing material generated in $PWD"
