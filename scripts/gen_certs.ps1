# scripts/gen_certs.ps1
# Requiere: openssl en PATH (Git Bash, ShiningLight, etc.)
$ErrorActionPreference = "Stop"

$CA_CN = $env:CA_CN; if (-not $CA_CN) { $CA_CN = "PAI2-Local-CA" }
$SERVER_CN = $env:SERVER_CN; if (-not $SERVER_CN) { $SERVER_CN = "localhost" }
$DAYS_CA = $env:DAYS_CA; if (-not $DAYS_CA) { $DAYS_CA = 3650 }
$DAYS_SERVER = $env:DAYS_SERVER; if (-not $DAYS_SERVER) { $DAYS_SERVER = 825 }

$ROOT = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$CERTS = Join-Path $ROOT "certs"
$CA = Join-Path $CERTS "ca"
$SRV = Join-Path $CERTS "server"

New-Item -ItemType Directory -Force -Path $CA | Out-Null
New-Item -ItemType Directory -Force -Path $SRV | Out-Null

# --- Mini configuración OpenSSL para evitar el error de openssl.cnf ---
$cfgPath = Join-Path $CERTS "openssl.cnf"
@"
[ req ]
default_bits       = 2048
prompt             = no
distinguished_name = dn

[ dn ]
CN = placeholder
"@ | Out-File -Encoding ASCII $cfgPath

Write-Host "==> Generando CA ($CA_CN)"
if (-not (Test-Path (Join-Path $CA "ca.key"))) {
  & openssl genrsa -out (Join-Path $CA "ca.key") 4096 | Out-Null
}
& openssl req -x509 -new -nodes -key (Join-Path $CA "ca.key") -sha256 -days $DAYS_CA `
  -subj "/CN=$CA_CN" -config $cfgPath -out (Join-Path $CA "ca.pem")

Write-Host "==> Generando clave y CSR del servidor (CN=$SERVER_CN)"
& openssl genrsa -out (Join-Path $SRV "server.key") 2048 | Out-Null
& openssl req -new -key (Join-Path $SRV "server.key") `
  -subj "/CN=$SERVER_CN" -config $cfgPath `
  -out (Join-Path $SRV "server.csr")

# Extensiones (SAN) para el cert del servidor
$extPath = Join-Path $SRV "server.ext"
@"
subjectAltName = DNS:$SERVER_CN,IP:127.0.0.1,IP:::1
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
"@ | Out-File -Encoding ASCII $extPath

Write-Host "==> Firmando certificado del servidor con nuestra CA"
& openssl x509 -req -in (Join-Path $SRV "server.csr") `
  -CA (Join-Path $CA "ca.pem") -CAkey (Join-Path $CA "ca.key") -CAcreateserial `
  -out (Join-Path $SRV "server.crt") -days $DAYS_SERVER -sha256 -extfile $extPath

Write-Host "==> Resumen del certificado del servidor:"
& openssl x509 -in (Join-Path $SRV "server.crt") -noout -subject -issuer -dates

Write-Host "`nListo."
Write-Host "CA pública:    certs/ca/ca.pem"
Write-Host "Servidor key:  certs/server/server.key (privada, NO subir)"
Write-Host "Servidor cert: certs/server/server.crt"
