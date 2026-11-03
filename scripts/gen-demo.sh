#!/usr/bin/env bash
# Generates a small Fabric-like crypto tree (MSP layout) with openssl so the
# scanner can be demonstrated without committing any key material.
set -euo pipefail

out="${1:-examples/_generated}"
rm -rf "$out"
org="$out/crypto/peerOrganizations/org1.example.com"
peer="$org/peers/peer0.org1.example.com"
mkdir -p "$org/ca" "$peer/msp/cacerts" "$peer/msp/signcerts" "$peer/msp/keystore" "$peer/tls" "$out/legacy"

ec_key() { openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out "$1"; }

# Org CA (ECDSA P-256, 10 years), like cryptogen/fabric-ca would issue.
ec_key "$org/ca/ca_sk"
openssl req -x509 -new -key "$org/ca/ca_sk" -days 3650 -subj "/C=US/O=org1.example.com/CN=ca.org1.example.com" \
  -addext "basicConstraints=critical,CA:TRUE" -out "$peer/msp/cacerts/ca.org1.example.com-cert.pem"

# Peer signing identity.
ec_key "$peer/msp/keystore/priv_sk"
openssl req -new -key "$peer/msp/keystore/priv_sk" -subj "/C=US/O=org1.example.com/OU=peer/CN=peer0.org1.example.com" -out "$out/peer.csr"
openssl x509 -req -in "$out/peer.csr" -CA "$peer/msp/cacerts/ca.org1.example.com-cert.pem" -CAkey "$org/ca/ca_sk" \
  -CAcreateserial -days 3650 -out "$peer/msp/signcerts/peer0.org1.example.com-cert.pem" 2>/dev/null

# Peer TLS key pair.
ec_key "$peer/tls/server.key"
openssl req -new -key "$peer/tls/server.key" -subj "/C=US/O=org1.example.com/CN=peer0.org1.example.com" -out "$out/tls.csr"
openssl x509 -req -in "$out/tls.csr" -CA "$peer/msp/cacerts/ca.org1.example.com-cert.pem" -CAkey "$org/ca/ca_sk" \
  -CAcreateserial -days 3650 -out "$peer/tls/server.crt" 2>/dev/null

# A legacy RSA-2048 CA from an older integration.
openssl genrsa -out "$out/legacy/legacy-ca.key" 2048 2>/dev/null
openssl req -x509 -new -key "$out/legacy/legacy-ca.key" -days 3650 -subj "/O=legacy/CN=legacy-ca" -out "$out/legacy/legacy-ca.pem"

# A connection profile that embeds the CA certificate with escaped newlines.
python3 - "$peer/msp/cacerts/ca.org1.example.com-cert.pem" "$out/connection-org1.json" <<'PY'
import json, sys
pem = open(sys.argv[1]).read()
json.dump({"name": "demo-org1", "certificateAuthorities": {"ca.org1.example.com": {"tlsCACerts": {"pem": [pem]}}}},
          open(sys.argv[2], "w"), indent=2)
PY

find "$out" -name '*.srl' -delete
echo "generated demo crypto tree in $out"
