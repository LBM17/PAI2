# PAI — Integridad en almacenamiento y transmisión (SSII)

Proyecto docente para implementar un sistema **cliente/servidor** con **sockets**, **autenticación**, verificación de **integridad en transmisión** mediante **HMAC + nonce** y **almacenamiento seguro de credenciales**.

## Requisitos
- **Python** ≥ 3.10 (probado con 3.12)
- **Git**
- (Opcional) **VS Code** + extensión *Python*

## Dependencias (requirements.txt)
- **bcrypt** — Hash seguro de contraseñas (salting + cost).
- **python-dotenv** — Carga variables desde `.env`.
- **pytest** — Pruebas unitarias.
- **black** — Formateador de código.
- **isort** — Orden de imports.
- **flake8** — Linter.

**Módulos estándar usados**: `socket`, `hmac`, `hashlib`, `secrets`, `json`, `logging`, `sqlite3`, `os`, `typing`.

## Instalación rápida
```bash
# Dentro de la carpeta del repo
python -m venv .venv

# Activa el entorno virtual
# Git Bash:
source .venv/Scripts/activate
# PowerShell:
# .venv\Scripts\Activate.ps1

# Instala dependencias
pip install -r requirements.txt

# Variables locales
cp .env.example .env
# edita .env y pon un HMAC_SECRET robusto
```
## Ejecutar y probar

```bash
# Tests
pytest -q

# Servidor (placeholder)
python server/main.py

# Cliente (placeholder)
python client/main.py
```
## Estructura del proyecto 
```bash
.
├─ client/                 # Cliente CLI
│  └─ main.py              # Entry point (carga .env)
├─ server/                 # Servidor (sockets)
│  └─ main.py              # Entry point (carga .env)
├─ common/                 # Código compartido
│  └─ __init__.py          # (añade utils: HMAC, nonce, JSON canónico, etc.)
├─ tests/                  # Pruebas con pytest
│  └─ test_smoke.py        # Test de humo inicial
├─ informe/                # Documentación y capturas (PDF final ignorado en git)
├─ logs/                   # Logs de ejecución (ignorado en git)
├─ .github/
│  └─ workflows/ci.yml     # (Opcional) CI: black + isort + flake8 + pytest
├─ .vscode/                # (Opcional) Ajustes de VS Code
├─ .env.example            # Plantilla variables de entorno
├─ .env                    # Variables locales (NO subir a git)
├─ requirements.txt        # Dependencias del proyecto
├─ .gitignore              # Ignora .venv/, .env, __pycache__/, logs/, etc.
└─ README.md               # Este documento
```

## ¿Para qué sirve cada carpeta/archivo?

**client/:** lógica del cliente (login, envío de transferencias firmadas).

**server/:** servidor de sockets; valida HMAC/nonce, credenciales y reglas de negocio.

**common/:** utilidades compartidas (firma/verificación, generación de nonce, serialización JSON determinista, etc.).

**tests/:** pruebas (login OK/KO, MITM alterando campos ⇒ HMAC falla, replay ⇒ nonce repetido rechazado).

**informe/:** memoria de la práctica y evidencias.

**logs/:** ficheros de log (excluidos del repo).

**.github/workflows/ci.yml**: pipeline opcional con formato/lint/tests.

**.vscode/:** configuración del entorno de desarrollo.

**.env.example / .env:** plantilla y variables locales reales.

**requirements.txt:** lista de dependencias con versiones.

Comandos útiles
# Formatear
python -m black .

# Ordenar imports
python -m isort .

# Lint
python -m flake8 .

# Ejecutar tests
pytest -q
