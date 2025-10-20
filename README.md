# 🛡️ PAI-2 — Road Warrior (TLS + HMAC + Nonce + Mensajes ≤144)

Servidor/cliente TCP sencillo con:

- **TLS 1.3** (certificado autofirmado local).
- **Integridad a nivel aplicación:** HMAC-SHA256 + nonce anti-replay.
- **Usuarios:** register / login (bcrypt).
- **Mensajes:** nueva tabla `messages` con límite de **144 caracteres**.
- **Compatibilidad PAI-1:** endpoint `tx` conservado.
- **SQLite** en `data/` con esquema y WAL.
- **Tests:** handshake, login, mensajes, replay y prueba de carga.

---

## 1️⃣ Requisitos

- **Python 3.12+**
- **PowerShell (Windows)**
- En **Linux/Mac**, ver notas al final.

---

## 2️⃣ Estructura (resumen)

```
pai-ssii/
├─ client/              # Cliente interactivo (TLS + HMAC)
├─ server/              # Servidor TLS, handlers, persistence, logging
├─ common/              # TLS, protocolo, IO, config (.env)
├─ certs/               # CA y server certs (generados)
├─ data/                # Base de datos SQLite (pai2.db)
├─ logs/                # Logs y salidas de pruebas de carga
├─ scripts/             # Gen de certs, checks, load test
├─ test/                # Pytests (handshake, login, mensajes, replay)
├─ .env.example         # Plantilla de variables
└─ README.md
```

---

## 3️⃣ Primer arranque

### 3.1 Crear y activar el virtualenv

```bash
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3.2 Instalar dependencias

Si tienes `requirements.txt`:

```bash
pip install -r requirements.txt
```

Si usas `pyproject.toml`:

```bash
pip install -e .
```

### 3.3 Variables de entorno

Copia `.env.example` → `.env` y ajusta:

```env
ENV=dev
# ≥32 bytes. Puedes usar ASCII largo. (Si usas Base64/hex, se detecta automáticamente)
HMAC_SECRET=pon_aqui_una_clave_larga_de_mas_de_32_bytes

# Base de datos (PAI-2)
DB_URL=sqlite:///pai2.db
DB_PATH=data/pai2.db
```

> **Nota:** `common/config.py` carga `.env` antes de usar HMAC/DB.  
> Si cambias `.env`, **reinicia servidor/cliente**.

### 3.4 Certificados TLS (localhost)

```bash
.\scripts\gen_certs.ps1
```

Se generarán:

- **CA:** `certs/ca/ca.pem`
- **Servidor:**  
  - `certs/server/server.crt`  
  - `certs/server/server.key` *(privada, no subir)*

---

## 4️⃣ Servidor y cliente

### 4.1 Arrancar el servidor

```bash
python -m server.main
```

**Salida esperada:**

```
INFO server.main: DB OK y usuarios seed listos
INFO server.main: Escuchando (TLS) en 127.0.0.1:5050
```

**Variables opcionales:**

```powershell
$env:SERVER_HOST = "127.0.0.1"
$env:SERVER_PORT = "5050"
# Para pruebas de carga locales:
$env:MAX_LOGIN_PER_IP = "400"
```

### 4.2 Cliente interactivo

En otra consola (con venv activo):

```bash
python -m client.main
```

**Menú:**

```
[1] Registrar  [2] Login  [3] Transferir  [4] Logout
[5] Reenviar última TX  [6] Enviar mensaje (≤144)  [0] Salir
```

---

## 5️⃣ Tests (pytest)

Asegúrate de tener el **venv activo**.

### 5.1 Handshake TLS

```bash
python -m pytest -k tls_handshake -q
```

### 5.2 Login y Mensajes (límite 144)

```bash
python -m pytest -k "(login or message)" -q
```

### 5.3 Anti-Replay (HMAC + nonce)

```bash
python -m pytest -k replay -q
```

### 5.4 Todo

```bash
python -m pytest -q
```

---

## 6️⃣ Prueba de carga

> Importante: ejecuta el servidor antes (`python -m server.main`).

El módulo de carga debe ejecutarse como **módulo (-m)** para que resuelva imports,  
y `scripts/__init__.py` debe existir (ya está).

### 6.1 Ligera (50 usuarios × 3 mensajes)

```bash
python -u -m scripts.load_test --users 50 --msgs 3 --workers 20 --ramp-ms 5 --timeout 6 --out run_50x3_r5_t6.json
```

**Salida (ejemplo real tuyo):**

```
ok=43  ko=7  total=50
latencia p50=209.0 ms  p95=610.1 ms
errores: rate-limit de login (127.0.0.1)
```

### 6.2 Densa (300 usuarios × 2 mensajes)

```bash
python -u -m scripts.load_test --users 300 --msgs 2 --workers 100 --ramp-ms 20 --timeout 8 --out run_300x2_r20_t8.json
```

**Salida (ejemplo real tuyo):**

```
ok=275  ko=25  total=300
latencia p50=540.4 ms  p95=1845.1 ms
errores: rate-limit de login (127.0.0.1)
```

**Consejo:**  
Para reducir `KO` por *rate-limit* en local, puedes subir la cuota:

```powershell
$env:MAX_LOGIN_PER_IP = "400"
python -m server.main
```

> Los resultados se guardan en `logs/*.json`.

---

## 7️⃣ Sniffing TLS (Paso 12)

1. Abre **Wireshark** y captura en loopback  
   *(filtro: `tcp.port == 5050` o `tls`)*.
2. Ejecuta cliente: register, login, message.
3. Guarda la captura en:  
   `captures/run_tls_localhost.pcapng`.

**Verifica:**  
Solo se ven `ClientHello` / `ServerHello` y **TLS Application Data**  
(sin texto en claro).

---

## 8️⃣ Limpieza / Reset DB

Parar servidor/cliente.

Borrar base de datos y reiniciar:

```bash
Remove-Item .\data\pai2.db -ErrorAction Ignore
python -m server.main
```

---

## 9️⃣ Problemas típicos / Soluciones

### ❌ `ModuleNotFoundError: No module named 'common'`

Ejecuta scripts como módulos:

```bash
python -m scripts.load_test
# (y no python scripts/load_test.py)
```

### ❌ KO de login en carga

Rate-limit por compartir `127.0.0.1`.  
Usa `--ramp-ms`, `--timeout` mayores y/o ajusta `MAX_LOGIN_PER_IP`.

### ⚠️ Handshake abortado ocasional en carga

Benigno; el servidor lo registra y continúa.

---
