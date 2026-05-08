"""
Secrets Scanner — Detección de secretos y credenciales expuestas en disco.

Analiza periódicamente el sistema en busca de información sensible que no
debería estar accesible en texto plano:

  1. Variables de entorno del proceso con nombres sensibles
     (API keys, tokens, contraseñas) — T1552.007
  2. Archivos de configuración peligrosos en rutas de usuario
     (.env, id_rsa, *.pem, credentials.xml, .aws/credentials, etc.) — T1552.001
  3. Contenido de archivos pequeños expuestos que contengan patrones
     de secretos conocidos (AWS AKIA, claves PEM, tokens Bearer) — T1552.001

El escáner NO lee archivos mayores de 512 KB para evitar impacto en rendimiento.
Ejecuta un análisis completo al arrancar y luego cada 5 minutos.
"""

import os
import re
import time
import threading
from datetime import datetime
from pathlib import Path
from typing import Callable

from utils.logger import get_logger

logger = get_logger("SecretsScanner")

# ── Configuración ─────────────────────────────────────────────────────────────
_POLL_INTERVAL        = 300       # segundos entre análisis completos
_MAX_FILE_SIZE_BYTES  = 512_000   # no leer archivos > 512 KB
_MAX_SNIPPET_LEN      = 80        # caracteres del secreto mostrados en la alerta

# ── Archivos peligrosos por nombre/extensión ──────────────────────────────────
# Tuplas (patrón glob, descripción, MITRE, severidad)
_DANGEROUS_FILES: list[tuple[str, str, str, int]] = [
    # Claves SSH privadas
    ("id_rsa",            "Clave privada SSH (RSA)",         "T1552.004", 9),
    ("id_ed25519",        "Clave privada SSH (Ed25519)",     "T1552.004", 9),
    ("id_ecdsa",          "Clave privada SSH (ECDSA)",       "T1552.004", 9),
    ("*.pem",             "Certificado / clave privada PEM", "T1552.004", 8),
    ("*.p12",             "Keystore PKCS#12",                "T1552.004", 8),
    ("*.pfx",             "Certificado con clave privada",   "T1552.004", 8),
    ("*.key",             "Archivo de clave privada",        "T1552.004", 7),
    # Configuración con credenciales
    (".env",              "Archivo de variables de entorno", "T1552.001", 8),
    (".env.local",        "Archivo .env local",              "T1552.001", 8),
    (".env.production",   "Archivo .env de producción",      "T1552.001", 9),
    ("credentials.xml",   "Credenciales XML (Jenkins/CI)",   "T1552.001", 8),
    ("secrets.yml",       "Secretos YAML",                   "T1552.001", 8),
    ("secrets.yaml",      "Secretos YAML",                   "T1552.001", 8),
    # AWS / Cloud
    ("credentials",       "Credenciales AWS/cloud",          "T1552.005", 9),
    # Bases de datos locales
    ("*.sqlite",          "Base de datos SQLite local",      "T1005",     5),
    ("*.db",              "Base de datos local",             "T1005",     5),
]

# Directorios de usuario que se escanean
_USERNAME = os.environ.get("USERNAME", "")
_SCAN_DIRS: list[Path] = [
    Path(rf"C:\Users\{_USERNAME}\Desktop"),
    Path(rf"C:\Users\{_USERNAME}\Documents"),
    Path(rf"C:\Users\{_USERNAME}\Downloads"),
    Path(rf"C:\Users\{_USERNAME}\.ssh"),
    Path(rf"C:\Users\{_USERNAME}\.aws"),
    Path(rf"C:\Users\{_USERNAME}\.config"),
    Path(rf"C:\Users\{_USERNAME}\AppData\Roaming"),
    Path(r"C:\inetpub\wwwroot"),
    Path(r"C:\xampp\htdocs"),
]

# ── Patrones de secretos dentro del contenido de archivos ────────────────────
# Tuplas (nombre, regex compilado, severidad, MITRE)
_SECRET_PATTERNS: list[tuple[str, re.Pattern, int, str]] = [
    ("AWS Access Key",
     re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE),
     9, "T1552.005"),

    ("AWS Secret Key",
     re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"]([A-Za-z0-9/+=]{40})['\"]"),
     9, "T1552.005"),

    ("Clave privada PEM",
     re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
     9, "T1552.004"),

    ("GitHub Personal Access Token",
     re.compile(r"ghp_[A-Za-z0-9]{36}"),
     8, "T1552.001"),

    ("GitLab Personal Access Token",
     re.compile(r"glpat-[A-Za-z0-9\-_]{20}"),
     8, "T1552.001"),

    ("Bearer Token",
     re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE),
     7, "T1528"),

    ("Google API Key",
     re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
     8, "T1552.001"),

    ("Azure Client Secret",
     re.compile(r"(?i)client.secret['\"\s:=]+([A-Za-z0-9~._\-]{34,40})"),
     8, "T1552.001"),

    ("Contraseña en texto plano",
     re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{8,})['\"]?"),
     6, "T1552.001"),

    ("Token genérico",
     re.compile(r"(?i)(api_key|api_token|auth_token|secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9\-_]{20,})['\"]?"),
     6, "T1552.001"),
]

# ── Variables de entorno sensibles ───────────────────────────────────────────
_SENSITIVE_ENV_PATTERNS = re.compile(
    r"(?i)(password|passwd|secret|api.?key|token|auth|credential|private.?key"
    r"|aws_secret|azure_client|gcp_|stripe_|twilio_|sendgrid_)",
)


# ─────────────────────────────────────────────────────────────────────────────
def _truncate(text: str, max_len: int = _MAX_SNIPPET_LEN) -> str:
    """Recorta el texto y añade '...' si supera el límite."""
    return text[:max_len] + ("..." if len(text) > max_len else "")


class SecretsScanner:
    """Escáner de secretos y credenciales expuestas en disco y entorno."""

    def __init__(self, callback: Callable[[dict], None]):
        self._callback = callback
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

        # Conjuntos de rutas ya alertadas para no generar duplicados
        self._alerted_files: set[str] = set()
        self._alerted_env_vars: set[str] = set()

    # ── Ciclo de vida ─────────────────────────────────────────────────────────
    def start(self):
        # Primer análisis en un hilo aparte para no bloquear el arranque
        self._thread = threading.Thread(target=self._run_loop,
                                        name="SecretsScanner", daemon=True)
        self._thread.start()
        logger.info("SecretsScanner iniciado (intervalo %ds).", _POLL_INTERVAL)

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("SecretsScanner detenido.")

    # ── Bucle principal ───────────────────────────────────────────────────────
    def _run_loop(self):
        # Ejecutar inmediatamente al arrancar
        self._run_full_scan()
        # Luego repetir cada _POLL_INTERVAL segundos
        while not self._stop_event.wait(_POLL_INTERVAL):
            self._run_full_scan()

    def _run_full_scan(self):
        logger.debug("Iniciando análisis de secretos expuestos...")
        self._scan_environment_variables()
        self._scan_filesystem()
        logger.debug("Análisis de secretos completado.")

    # ── 1. Variables de entorno ───────────────────────────────────────────────
    def _scan_environment_variables(self):
        for var_name, var_value in os.environ.items():
            if not _SENSITIVE_ENV_PATTERNS.search(var_name):
                continue
            if var_name in self._alerted_env_vars:
                continue
            # Ignorar valores vacíos o claramente de ruta del sistema
            if not var_value or len(var_value) < 8:
                continue
            if var_value.startswith(("C:\\Windows", "C:\\Program")):
                continue

            self._alerted_env_vars.add(var_name)
            logger.warning("Variable de entorno sensible expuesta: %s", var_name)
            self._callback({
                "timestamp": datetime.now().isoformat(),
                "source": "SecretsScanner",
                "type": "exposed_env_secret",
                "severity": 6,
                "confidence": 80,
                "description": (
                    f"Variable de entorno con nombre sensible detectada: "
                    f"'{var_name}' contiene un valor potencialmente secreto."
                ),
                "details": {
                    "variable": var_name,
                    "value_preview": _truncate(var_value, 20) + "***",
                },
                "mitre_technique": "T1552.007",
                "mitre_tactic": "Credential Access",
            })

    # ── 2. Sistema de archivos ────────────────────────────────────────────────
    def _scan_filesystem(self):
        for scan_dir in _SCAN_DIRS:
            if not scan_dir.exists():
                continue
            try:
                self._scan_directory(scan_dir)
            except PermissionError:
                pass

    def _scan_directory(self, directory: Path):
        try:
            entries = list(directory.iterdir())
        except PermissionError:
            return

        for entry in entries:
            if self._stop_event.is_set():
                return
            try:
                if entry.is_symlink():
                    continue
                if entry.is_dir():
                    # Recursión solo un nivel adicional (no bucear demasiado)
                    if entry.name not in {".git", "__pycache__", "node_modules",
                                          "venv", ".venv", "site-packages"}:
                        self._scan_directory(entry)
                elif entry.is_file():
                    self._check_file(entry)
            except (PermissionError, OSError):
                continue

    def _check_file(self, file_path: Path):
        path_str = str(file_path)

        # ── Comprobar si el nombre/extensión coincide con un archivo peligroso
        for pattern, description, mitre, severity in _DANGEROUS_FILES:
            if self._glob_match(file_path.name, pattern):
                if path_str not in self._alerted_files:
                    self._alerted_files.add(path_str)
                    logger.warning("Archivo sensible encontrado: %s", path_str)
                    self._callback({
                        "timestamp": datetime.now().isoformat(),
                        "source": "SecretsScanner",
                        "type": "sensitive_file_found",
                        "severity": severity,
                        "confidence": 85,
                        "description": (
                            f"{description} encontrado en ubicación accesible: "
                            f"{path_str}"
                        ),
                        "details": {
                            "file": path_str,
                            "file_type": description,
                        },
                        "mitre_technique": mitre,
                        "mitre_tactic": "Credential Access",
                    })
                break  # No seguir comprobando más patrones para este archivo

        # ── Buscar patrones de secretos dentro del contenido del archivo
        self._scan_file_content(file_path)

    def _scan_file_content(self, file_path: Path):
        """Lee el archivo y busca patrones de secretos en su contenido."""
        try:
            stat = file_path.stat()
            if stat.st_size == 0 or stat.st_size > _MAX_FILE_SIZE_BYTES:
                return
        except OSError:
            return

        # Solo analizar archivos de texto plano
        text_extensions = {
            ".txt", ".env", ".cfg", ".conf", ".config", ".ini",
            ".json", ".yaml", ".yml", ".xml", ".toml",
            ".py", ".js", ".ts", ".sh", ".bat", ".ps1",
            ".properties", ".pem", ".key", ".log", "",
        }
        if file_path.suffix.lower() not in text_extensions:
            return

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return

        for secret_name, pattern, severity, mitre in _SECRET_PATTERNS:
            match = pattern.search(content)
            if not match:
                continue

            alert_key = f"{file_path}::{secret_name}"
            if alert_key in self._alerted_files:
                continue

            self._alerted_files.add(alert_key)
            snippet = _truncate(match.group(0))
            logger.warning("Secreto detectado en archivo: %s → %s", file_path, secret_name)
            self._callback({
                "timestamp": datetime.now().isoformat(),
                "source": "SecretsScanner",
                "type": "secret_in_file",
                "severity": severity,
                "confidence": 88,
                "description": (
                    f"{secret_name} detectado en el archivo: {file_path}"
                ),
                "details": {
                    "file": str(file_path),
                    "secret_type": secret_name,
                    "snippet": snippet,
                },
                "mitre_technique": mitre,
                "mitre_tactic": "Credential Access",
            })

    @staticmethod
    def _glob_match(filename: str, pattern: str) -> bool:
        """Comprueba si un nombre de archivo coincide con un patrón glob simple."""
        if pattern.startswith("*"):
            return filename.lower().endswith(pattern[1:].lower())
        return filename.lower() == pattern.lower()
