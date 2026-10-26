#!/usr/bin/env bash
# Generate a CA, a KMIP server certificate and one client certificate per
# client identity, using openssl. Safe to re-run: existing files are kept
# unless FORCE=1.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$here/env.sh"

mkdir -p "$POC_DIR/certs"
cd "$POC_DIR/certs"

if [[ -f ca.pem && -z "${FORCE:-}" ]]; then
  echo "certificates already exist in $POC_DIR/certs (set FORCE=1 to regenerate)"
  exit 0
fi

# CA. Clients and the server both trust this one CA.
openssl req -x509 -newkey rsa:3072 -nodes -days 365 -sha256 \
  -keyout ca.key -out ca.pem -subj "/O=KMIP PoC/CN=KMIP PoC CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

# Server certificate with a SAN for every name or address clients use.
san=""
IFS=',' read -ra hosts <<<"$KMIP_HOSTS"
for h in "${hosts[@]}"; do
  if [[ "$h" =~ ^[0-9.]+$ || "$h" == *:* ]]; then san+="IP:$h,"; else san+="DNS:$h,"; fi
done
san="${san%,}"

openssl req -newkey rsa:3072 -nodes -keyout server.key -out server.csr \
  -subj "/O=KMIP PoC/CN=kmip-server" 2>/dev/null
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -days 365 -sha256 -out server.pem \
  -extfile <(printf "subjectAltName=%s\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyEncipherment\nbasicConstraints=CA:FALSE" "$san") 2>/dev/null

# One client certificate per identity. The common name is what the cert auth
# role matches, and it decides which objects the client can see.
IFS=',' read -ra clients <<<"$KMIP_CLIENTS"
for c in "${clients[@]}"; do
  openssl req -newkey rsa:3072 -nodes -keyout "client-$c.key" -out "client-$c.csr" \
    -subj "/O=KMIP PoC/CN=$c" 2>/dev/null
  openssl x509 -req -in "client-$c.csr" -CA ca.pem -CAkey ca.key -CAcreateserial \
    -days 365 -sha256 -out "client-$c.pem" \
    -extfile <(printf "extendedKeyUsage=clientAuth\nkeyUsage=digitalSignature\nbasicConstraints=CA:FALSE") 2>/dev/null
  # Some clients (mongod) want the certificate and key in one file.
  cat "client-$c.pem" "client-$c.key" >"client-$c-combined.pem"
done

rm -f ./*.csr ca.srl
chmod 600 ./*.key ./*-combined.pem
echo "generated certificates in $POC_DIR/certs:"
ls "$POC_DIR/certs"
