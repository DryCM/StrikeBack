"""
SecretsManager — Gestión segura de credenciales mediante Windows Credential Manager.

Las claves API (Groq, VirusTotal) se almacenan en el llavero del sistema operativo
(DPAPI / Credential Manager), no en config.py en texto plano.

Cumplimiento:
  - OWASP A02: Cryptographic Failures → secretos fuera del código
  - NIST SP 800-57: gestión del ciclo de vida de claves
  - CIS Control 3.11: Encrypt sensitive data at rest

Flujo:
  1. Al primer arranque, si config.py tiene keys → migrarlas al Credential Manager y
     borrarlas del fichero.
  2. En arranques sucesivos, leer desde el Credential Manager.
  3. Fallback: si el Credential Manager no está disponible (entorno sin UI),
     se usa config.py como respaldo (con advertencia).

Uso:
    from utils.secrets_manager import get_secret, store_secret
    api_key = get_secret("AI_API_KEY")
"""

import os
import sys
from utils.logger import get_logger

logger = get_logger("SecretsManager")

_APP_PREFIX = "StrikeBack/"

# ─────────────────────────────────────────────────────────────────────────────
def _win_cred_available() -> bool:
    try:
        import win32cred  # pywin32
        return True
    except ImportError:
        return False


def store_secret(name: str, value: str) -> bool:
    """
    Almacena una clave en Windows Credential Manager.
    Retorna True si tuvo éxito, False si no está disponible.
    """
    if not value or not _win_cred_available():
        return False
    try:
        import win32cred
        win32cred.CredWrite({
            "Type":           win32cred.CRED_TYPE_GENERIC,
            "TargetName":     _APP_PREFIX + name,
            "UserName":       "strikeback",
            "CredentialBlob": value,          # win32cred espera str, no bytes
            "Persist":        win32cred.CRED_PERSIST_LOCAL_MACHINE,
            "Comment":        f"StrikeBack - {name}",
        }, 0)
        logger.info(f"[SecretsManager] '{name}' almacenada en Windows Credential Manager.")
        return True
    except Exception as exc:
        logger.warning(f"[SecretsManager] No se pudo almacenar '{name}': {exc}")
        return False


def get_secret(name: str, fallback: str = "") -> str:
    """
    Recupera una clave del Windows Credential Manager.
    Si no está disponible o no existe, retorna fallback.
    """
    if not _win_cred_available():
        return fallback
    try:
        import win32cred
        cred = win32cred.CredRead(_APP_PREFIX + name, win32cred.CRED_TYPE_GENERIC)
        blob = cred.get("CredentialBlob")
        if isinstance(blob, bytes):
            # win32cred almacena strings Python como UTF-16LE en Windows
            try:
                return blob.decode("utf-16-le").rstrip("\x00")
            except UnicodeDecodeError:
                return blob.decode("utf-8").rstrip("\x00")
        if isinstance(blob, str):
            return blob.rstrip("\x00")
        return str(blob) if blob else fallback
    except Exception:
        return fallback


def delete_secret(name: str) -> bool:
    """Elimina una clave del Credential Manager."""
    if not _win_cred_available():
        return False
    try:
        import win32cred
        win32cred.CredDelete(_APP_PREFIX + name, win32cred.CRED_TYPE_GENERIC)
        logger.info(f"[SecretsManager] '{name}' eliminada del Credential Manager.")
        return True
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
_MANAGED_KEYS = ("AI_API_KEY", "VIRUSTOTAL_API_KEY")

def migrate_from_config() -> int:
    """
    Migra las keys de config.py al Credential Manager (primera vez).
    Retorna el número de keys migradas con éxito.
    """
    import config as _config
    migrated = 0

    for key_name in _MANAGED_KEYS:
        value = getattr(_config, key_name, "")
        if not value or value in ("TU_API_KEY_AQUI", ""):
            continue

        # Si ya está en el Credential Manager, no sobreescribir
        if get_secret(key_name):
            logger.debug(f"[SecretsManager] '{key_name}' ya existe en Credential Manager.")
            continue

        if store_secret(key_name, value):
            migrated += 1
            logger.info(f"[SecretsManager] '{key_name}' migrada a Credential Manager.")

    return migrated


def load_secrets_into_config():
    """
    Carga las keys del Credential Manager en config (en memoria).
    Llamar una vez al arrancar, antes de iniciar monitores.
    """
    import config as _config

    for key_name in _MANAGED_KEYS:
        stored = get_secret(key_name)
        if stored:
            setattr(_config, key_name, stored)
            logger.debug(f"[SecretsManager] '{key_name}' cargada desde Credential Manager.")
        # Si no está en el CM, mantener el valor de config.py (fallback)
