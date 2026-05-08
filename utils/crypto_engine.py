"""
CryptoEngine — Cifrado AES-256-GCM para datos en reposo.

Cumplimiento:
  - INCIBE: Protección de datos sensibles en almacenamiento local
  - MASVS V2: Data Storage and Privacy (MSTG-STORAGE-1, MSTG-STORAGE-2)
  - NIST SP 800-132: PBKDF2-HMAC-SHA256 con 600 000 iteraciones mínimas
  - OWASP: A02 Cryptographic Failures — uso de AES-256-GCM (AEAD)

Arquitectura:
  - Clave maestra de 256 bits generada aleatoriamente (os.urandom)
  - Clave maestra cifrada con clave derivada de la máquina (PBKDF2) → data/.keystore
  - Por campo: salt[16] + nonce[12] distintos → no reutilización de claves
  - Formato almacenado: ENC:<base64(salt+nonce+ciphertext+tag)>
  - Retrocompatible: campos no cifrados se devuelven tal cual

Campos cifrados en la BD:
  description, details, ai_impact, ai_actions, ai_summary
"""

import base64
import os
import socket
import threading
from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from utils.logger import get_logger

logger = get_logger("CryptoEngine")

# ── Constantes ────────────────────────────────────────────────────────────────
_KEYSTORE_PATH      = Path("data/.keystore")
_ENC_PREFIX         = "ENC:"
_PBKDF2_ITERATIONS  = 600_000          # NIST SP 800-132 §5.3
_SALT_LEN           = 16               # 128-bit salt
_NONCE_LEN          = 12               # 96-bit nonce (GCM estándar)
_KEY_LEN            = 32               # AES-256
_KS_AAD             = b"strikeback-keystore-v1"
_FIELD_AAD          = b"strikeback-field-v1"


class CryptoEngine:
    """
    Motor de cifrado AES-256-GCM con clave vinculada a la máquina.

    Thread-safe. Obtener la instancia singleton con get_crypto_engine().
    """

    def __init__(self):
        self._lock        = threading.Lock()
        self._master_key: bytes | None = None

    # ── Identificación de máquina ─────────────────────────────────────────────
    def _get_machine_secret(self) -> bytes:
        """
        Combina MachineGuid (Windows), hostname y usuario para un identificador
        estable y único de la máquina actual. Sin datos de red.
        """
        parts: list[str] = []

        # 1. MachineGuid del registro
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography",
            )
            guid, _ = winreg.QueryValueEx(key, "MachineGuid")
            winreg.CloseKey(key)
            parts.append(guid)
        except Exception:
            pass

        # 2. Hostname
        parts.append(socket.gethostname())

        # 3. Usuario actual (GetUserNameW)
        try:
            import ctypes
            buf  = ctypes.create_unicode_buffer(256)
            size = ctypes.c_ulong(256)
            ctypes.windll.advapi32.GetUserNameW(buf, ctypes.byref(size))
            parts.append(buf.value)
        except Exception:
            pass

        return "|".join(filter(None, parts)).encode("utf-8")

    # ── Derivación de clave ────────────────────────────────────────────────────
    def _derive_key(self, password: bytes, salt: bytes) -> bytes:
        """PBKDF2-HMAC-SHA256 con 600 000 iteraciones → clave AES-256."""
        kdf = PBKDF2HMAC(
            algorithm  = hashes.SHA256(),
            length     = _KEY_LEN,
            salt       = salt,
            iterations = _PBKDF2_ITERATIONS,
            backend    = default_backend(),
        )
        return kdf.derive(password)

    # ── Keystore ──────────────────────────────────────────────────────────────
    def _load_or_create_master_key(self) -> bytes:
        """
        Carga la clave maestra del keystore cifrado, o la genera si no existe.
        El keystore está cifrado con una clave derivada de la identidad de la
        máquina → ilegible en otro sistema.
        """
        machine_secret = self._get_machine_secret()

        if _KEYSTORE_PATH.exists():
            try:
                raw           = _KEYSTORE_PATH.read_bytes()
                # Diseño: wrap_salt[16] | nonce[12] | encrypted_master_key+tag
                wrap_salt     = raw[:_SALT_LEN]
                nonce         = raw[_SALT_LEN : _SALT_LEN + _NONCE_LEN]
                cipher_blob   = raw[_SALT_LEN + _NONCE_LEN:]
                wrapping_key  = self._derive_key(machine_secret, wrap_salt)
                master_key    = AESGCM(wrapping_key).decrypt(nonce, cipher_blob, _KS_AAD)
                logger.info("Clave maestra cargada desde keystore cifrado.")
                return master_key
            except Exception as exc:
                logger.warning(f"Keystore ilegible ({exc}), regenerando…")

        # Generar clave maestra nueva
        master_key  = os.urandom(_KEY_LEN)
        wrap_salt   = os.urandom(_SALT_LEN)
        nonce       = os.urandom(_NONCE_LEN)
        wrapping_key = self._derive_key(machine_secret, wrap_salt)
        cipher_blob  = AESGCM(wrapping_key).encrypt(nonce, master_key, _KS_AAD)

        _KEYSTORE_PATH.parent.mkdir(parents=True, exist_ok=True)
        _KEYSTORE_PATH.write_bytes(wrap_salt + nonce + cipher_blob)

        # Restringir permisos NTFS al usuario actual (MASVS MSTG-STORAGE-2)
        self._restrict_file_permissions(_KEYSTORE_PATH)

        logger.info("Nueva clave maestra AES-256 generada y almacenada en keystore.")
        return master_key

    @staticmethod
    def _restrict_file_permissions(path: Path) -> None:
        """Aplica DACL restrictivo: solo el usuario propietario tiene acceso."""
        try:
            import ctypes
            import win32security
            import win32api
            import ntsecuritycon as ntcon

            proc_token = win32security.OpenProcessToken(
                win32api.GetCurrentProcess(), 0x0008  # TOKEN_QUERY
            )
            user_sid = win32security.GetTokenInformation(
                proc_token, win32security.TokenUser
            )[0]

            dacl = win32security.ACL()
            dacl.AddAccessAllowedAce(
                win32security.ACL_REVISION, ntcon.FILE_ALL_ACCESS, user_sid
            )

            sd = win32security.GetFileSecurity(
                str(path), win32security.DACL_SECURITY_INFORMATION
            )
            sd.SetSecurityDescriptorDacl(True, dacl, False)
            win32security.SetFileSecurity(
                str(path), win32security.DACL_SECURITY_INFORMATION, sd
            )
        except Exception:
            pass  # Continuar sin DACL personalizado si pywin32 no está disponible

    # ── API pública ───────────────────────────────────────────────────────────
    def get_master_key(self) -> bytes:
        """Retorna la clave maestra cargada de forma thread-safe (lazy init)."""
        with self._lock:
            if self._master_key is None:
                self._master_key = self._load_or_create_master_key()
            return self._master_key

    def encrypt(self, plaintext: str) -> str:
        """
        Cifra un string con AES-256-GCM.

        Formato: ENC:<base64(salt[16] + nonce[12] + ciphertext + tag[16])>

        Idempotente: si ya empieza con 'ENC:' no re-cifra.
        Retorna el valor original si es vacío o None.
        """
        if not plaintext:
            return plaintext
        if plaintext.startswith(_ENC_PREFIX):
            return plaintext

        master_key = self.get_master_key()
        salt       = os.urandom(_SALT_LEN)
        data_key   = self._derive_key(master_key, salt)
        nonce      = os.urandom(_NONCE_LEN)
        cipher_tag = AESGCM(data_key).encrypt(nonce, plaintext.encode("utf-8"), _FIELD_AAD)

        blob = base64.b64encode(salt + nonce + cipher_tag).decode("ascii")
        return _ENC_PREFIX + blob

    def decrypt(self, value: str) -> str:
        """
        Descifra un campo AES-256-GCM.

        Retrocompatible: si el valor no empieza con 'ENC:' lo devuelve tal cual.
        """
        if not value or not value.startswith(_ENC_PREFIX):
            return value

        try:
            raw        = base64.b64decode(value[len(_ENC_PREFIX):])
            salt       = raw[:_SALT_LEN]
            nonce      = raw[_SALT_LEN : _SALT_LEN + _NONCE_LEN]
            cipher_tag = raw[_SALT_LEN + _NONCE_LEN:]

            master_key = self.get_master_key()
            data_key   = self._derive_key(master_key, salt)
            plaintext  = AESGCM(data_key).decrypt(nonce, cipher_tag, _FIELD_AAD)
            return plaintext.decode("utf-8")

        except Exception as exc:
            logger.warning(f"Error de descifrado en campo (posible corrupción): {exc}")
            return value  # Retornar tal cual → no silenciar datos

    def encrypt_json(self, obj) -> str:
        """Serializa a JSON y cifra."""
        import json
        return self.encrypt(json.dumps(obj, ensure_ascii=False))

    def decrypt_json(self, value: str):
        """Descifra y deserializa JSON. Retrocompatible con JSON plano."""
        import json
        plain = self.decrypt(value)
        try:
            return json.loads(plain)
        except Exception:
            return plain


# ── Singleton thread-safe ─────────────────────────────────────────────────────
_engine: "CryptoEngine | None" = None
_engine_lock = threading.Lock()


def get_crypto_engine() -> CryptoEngine:
    """Retorna la instancia singleton del motor de cifrado (lazy init)."""
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = CryptoEngine()
    return _engine
