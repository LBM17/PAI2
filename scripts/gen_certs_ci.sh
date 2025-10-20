#!/usr/bin/env bash
set -euo pipefail

#Este fichero es porq CI es un pesao'

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERTS="$ROOT/certs"
CA_DIR="$CERTS/ca"
SRV_DIR="$CERTS/server"

mkdir -p "$CA_DIR" "$SRV_DIR"

# 1) CA
openssl genrsa -out "$CA_DIR/ca.key" 4096
openssl req -x509 -new -nodes -key "$CA_DIR/ca.key" -sha256 -days 820 \
  -subj "/CN=PAI2-Local-CA" -out "$CA_DIR/ca.pem"

# 2) Server key + CSR + cert firmado por nuestra CA
openssl genrsa -out "$SRV_DIR/server.key" 2048

cat > "$SRV_DIR/server.ext" <<'EOF'
subjectAltName=DNS:localhost,IP:127.0.0.1
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
EOF

openssl req -new -key "$SRV_DIR/server.key" -subj "/CN=localhost" -out "$SRV_DIR/server.csr"

openssl x509 -req -in "$SRV_DIR/server.csr" \
  -CA "$CA_DIR/ca.pem" -CAkey "$CA_DIR/ca.key" -CAcreateserial \
  -out "$SRV_DIR/server.crt" -days 820 -sha256 -extfile "$SRV_DIR/server.ext"

echo "Certificados generados:"
ls -l "$CA_DIR/ca.pem" "$SRV_DIR/server.key" "$SRV_DIR/server.crt"
