#!/bin/sh
# Per-run throwaway TLS material for the loopback fixture (tls/ is
# gitignored, never committed). A tiny CA signs a leaf for 127.0.0.1:
# rustls/webpki (kharond's sync client, issue #8) rejects a self-signed
# CA:TRUE cert used directly as the server cert (CaUsedAsEndEntity),
# and OpenSSL 3 wants keyUsage on the CA. Clients trust tls/ca.pem;
# Vaultwarden serves tls/cert.pem + tls/key.pem. The leaf also names
# `vaultwarden`, the service name the compose E2E's kharond container
# reaches it by (deploy/compose/e2e, issue #24).
set -eu
cd "$(dirname "$0")"
mkdir -p tls
cd tls
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem \
  -days 2 -subj "/CN=kharon fixture CA" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout key.pem -out leaf.csr \
  -subj "/CN=127.0.0.1" 2>/dev/null
printf 'subjectAltName=IP:127.0.0.1,DNS:vaultwarden\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' > leaf.ext
openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out cert.pem -days 2 -extfile leaf.ext 2>/dev/null
rm -f ca.key leaf.csr leaf.ext ca.srl
echo "tls/: ca.pem (trust this), cert.pem + key.pem (server)"
