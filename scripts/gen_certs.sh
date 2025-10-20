#!/usr/bin/env bash
set -euo pipefail

CA_CN="${CA_CN:-PAI2-Local-CA}"
SERVER_CN="${SERVER_CN:-localhost}"
DAYS_CA="${DAYS_CA:-3650}"
DAYS_SERVER="${DAYS_SERVER:-825}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERTS_DIR="${ROOT_DIR}/certs"
CA_DIR="${CERTS_DIR}/ca"
SRV_DIR="${CERTS_DIR}/server"

mkdir -p "$CA_DIR" "$SRV_DIR"

echo "==> Generando CA (${CA_CN})"
if [[ ! -f "${CA_DIR}/ca.key" ]]; then
  openssl genrsa -out "${CA_DIR}/ca.key" 4096
  chmod 600 "${CA_DIR}/ca.key"
fi
openssl req -x509 -new -nodes -key "${CA_DIR}/ca.key" -sha256 -days "${DAYS_CA}" \
  -subj "/CN=${CA_CN}" -out "${CA_DIR}/ca.pem"

echo "==> Generando clave y CSR del servidor (CN=${SERVER_CN})"
openssl genrsa -out "${SRV_DIR}/server.key" 2048
chmod 600 "${SRV_DIR}/server.key"

openssl req -new -key "${SRV_DIR}/server.key" -out "${SRV_DIR}/server.csr" \
  -subj "/CN=${SERVER_CN}"

# Extensiones para Subject Alternative Name (SAN)
EXT_FILE="${SRV_DIR}/server.ext"
cat > "${EXT_FILE}" <<EOF
subjectAltName = DNS:${SERVER_CN},IP:127.0.0.1,IP:::1
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
EOF

echo "==> Firmando certificado del servidor con nuestra CA"
openssl x509 -req -in "${SRV_DIR}/server.csr" \
  -CA "${CA_DIR}/ca.pem" -CAkey "${CA_DIR}/ca.key" -CAcreateserial \
  -out "${SRV_DIR}/server.crt" -days "${DAYS_SERVER}" -sha256 -extfile "${EXT_FILE}"

# Resumen
echo "==> Resumen del certificado del servidor:"
openssl x509 -in "${SRV_DIR}/server.crt" -noout -subject -issuer -dates
echo "==> Archivos generados:"
ls -1 "${CA_DIR}" "${SRV_DIR}"

echo ""
echo "Listo."
echo "CA pública:    certs/ca/ca.pem"
echo "Servidor key:  certs/server/server.key (privada, NO subir)"
echo "Servidor cert: certs/server/server.crt"
