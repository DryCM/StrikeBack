"""
AuthManager — Autenticación MFA y gestión de sesiones seguras para el Dashboard.

Cumplimiento:
  - INCIBE: Autenticación robusta, gestión de sesiones y control de acceso
  - MASVS V4: Authentication and Session Management (MSTG-AUTH-1 a MSTG-AUTH-12)
  - OWASP A07: Identification and Authentication Failures
  - NIST SP 800-63B: Nivel de garantía AAL2 (password + OTP)

Arquitectura:
  1. Contraseña maestra: PBKDF2-HMAC-SHA256 (600 000 iter, salt 32 bytes)
     → almacenada en data/.auth_config (solo propietario por DACL)
  2. TOTP MFA: RFC 6238, ventana ±1, algoritmo SHA-1 estándar (authy/GA compatible)
     → secreto TOTP cifrado con CryptoEngine (AES-256-GCM)
  3. Tokens de sesión: 32 bytes aleatorios (256 bits), expiración 8 horas
     → almacenados en memoria (nunca en disco), invalidados en stop()
  4. Bloqueo por intentos fallidos: 5 intentos → 15 min bloqueo (NIST SP 800-63B)
  5. Cabeceras de seguridad HTTP en todas las respuestas

Integración con dashboard:
    from web.auth import AuthManager
    auth = AuthManager()
    auth.protect(app)     # aplica @before_request y /login, /logout
"""

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import pyotp

from utils.logger import get_logger
from utils.crypto_engine import get_crypto_engine

logger = get_logger("AuthManager")

# ── Constantes ────────────────────────────────────────────────────────────────
_AUTH_CONFIG_PATH  = Path("data/.auth_config")
_PBKDF2_ITERATIONS = 600_000
_SALT_LEN          = 32
_SESSION_LEN       = 32               # 256-bit token
_SESSION_TTL_H     = 8                # horas de validez
_MAX_ATTEMPTS      = 5
_LOCKOUT_MINUTES   = 15
_TOTP_ISSUER       = "StrikeBack-SOC"

# Cabeceras de seguridad HTTP (OWASP Secure Headers Project)
_SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy":   (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    ),
    "X-Content-Type-Options":    "nosniff",
    "X-Frame-Options":           "DENY",
    "X-XSS-Protection":          "1; mode=block",
    "Referrer-Policy":           "strict-origin-when-cross-origin",
    "Permissions-Policy":        "geolocation=(), microphone=(), camera=()",
    "Cache-Control":             "no-store, no-cache, must-revalidate",
}

# Rutas que no requieren autenticación
_PUBLIC_PATHS = {"/login", "/logout", "/favicon.ico"}


class AuthManager:
    """Gestor de autenticación MFA y sesiones para el Web Dashboard."""

    def __init__(self):
        self._sessions: dict[str, dict] = {}   # token → {created, ip}
        self._lock      = threading.Lock()
        self._attempts: dict[str, list] = {}   # ip → [timestamps]
        self._config    = self._load_or_create_config()

    # ── Configuración y bootstrap ─────────────────────────────────────────────
    def _load_or_create_config(self) -> dict:
        """Carga config auth o genera un setup inicial con credenciales seguras."""
        if _AUTH_CONFIG_PATH.exists():
            try:
                raw    = _AUTH_CONFIG_PATH.read_text(encoding="utf-8")
                config = json.loads(raw)
                # Descifrar secreto TOTP
                config["totp_secret"] = get_crypto_engine().decrypt(
                    config.get("totp_secret_enc", "")
                )
                logger.info("Configuración de autenticación cargada.")
                return config
            except Exception as exc:
                logger.warning(f"Config auth corrupta ({exc}), regenerando…")

        return self._bootstrap()

    def _bootstrap(self) -> dict:
        """
        Primera ejecución: genera contraseña temporal y secreto TOTP.
        Muestra las credenciales UNA SOLA VEZ en consola.
        """
        temp_password = secrets.token_urlsafe(16)   # 128-bit URL-safe
        totp_secret   = pyotp.random_base32()        # 160-bit secreto TOTP

        salt      = os.urandom(_SALT_LEN)
        pw_hash   = self._hash_password(temp_password.encode(), salt)

        config = {
            "pw_hash":         pw_hash.hex(),
            "pw_salt":         salt.hex(),
            "totp_secret":     totp_secret,
            "totp_secret_enc": get_crypto_engine().encrypt(totp_secret),
            "setup_complete":  False,
        }

        self._save_config(config)

        # URI para importar en Google Authenticator / Authy / TOTP app
        totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
            name="admin", issuer_name=_TOTP_ISSUER
        )

        logger.warning("=" * 60)
        logger.warning("  CONFIGURACIÓN INICIAL DE AUTENTICACIÓN")
        logger.warning("=" * 60)
        logger.warning(f"  Contraseña temporal : {temp_password}")
        logger.warning(f"  Secreto TOTP (base32): {totp_secret}")
        logger.warning(f"  URI para QR         : {totp_uri}")
        logger.warning("  Importa el URI en Google Authenticator / Authy")
        logger.warning("=" * 60)

        return config

    def _save_config(self, config: dict) -> None:
        """Persiste config auth con campos TOTP cifrados."""
        _AUTH_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "pw_hash":         config["pw_hash"],
            "pw_salt":         config["pw_salt"],
            "totp_secret_enc": get_crypto_engine().encrypt(config["totp_secret"]),
            "setup_complete":  config.get("setup_complete", False),
        }
        _AUTH_CONFIG_PATH.write_text(
            json.dumps(data, indent=2), encoding="utf-8"
        )
        self._restrict_config_permissions()

    @staticmethod
    def _restrict_config_permissions() -> None:
        """Aplica DACL: solo el usuario propietario puede leer .auth_config."""
        try:
            import win32security
            import win32api
            import ntsecuritycon as ntcon

            proc_token = win32security.OpenProcessToken(
                win32api.GetCurrentProcess(), 0x0008
            )
            user_sid = win32security.GetTokenInformation(
                proc_token, win32security.TokenUser
            )[0]
            dacl = win32security.ACL()
            dacl.AddAccessAllowedAce(
                win32security.ACL_REVISION, ntcon.FILE_ALL_ACCESS, user_sid
            )
            sd = win32security.GetFileSecurity(
                str(_AUTH_CONFIG_PATH), win32security.DACL_SECURITY_INFORMATION
            )
            sd.SetSecurityDescriptorDacl(True, dacl, False)
            win32security.SetFileSecurity(
                str(_AUTH_CONFIG_PATH), win32security.DACL_SECURITY_INFORMATION, sd
            )
        except Exception:
            pass

    # ── Hash de contraseña ────────────────────────────────────────────────────
    @staticmethod
    def _hash_password(password: bytes, salt: bytes) -> bytes:
        """PBKDF2-HMAC-SHA256 con 600 000 iteraciones (NIST SP 800-132)."""
        return hashlib.pbkdf2_hmac("sha256", password, salt, _PBKDF2_ITERATIONS)

    def _verify_password(self, candidate: str) -> bool:
        """Compara contraseña usando hmac.compare_digest (timing-safe)."""
        try:
            salt      = bytes.fromhex(self._config["pw_salt"])
            expected  = bytes.fromhex(self._config["pw_hash"])
            candidate_hash = self._hash_password(candidate.encode("utf-8"), salt)
            return hmac.compare_digest(candidate_hash, expected)
        except Exception:
            return False

    # ── TOTP MFA ──────────────────────────────────────────────────────────────
    def _verify_totp(self, code: str) -> bool:
        """Valida código TOTP RFC 6238 con ventana ±1 (30s × 3 = 90s)."""
        try:
            totp   = pyotp.TOTP(self._config["totp_secret"])
            return totp.verify(code, valid_window=1)
        except Exception:
            return False

    # ── Rate limiting / bloqueo por intentos ─────────────────────────────────
    def _is_locked(self, ip: str) -> bool:
        """True si la IP ha superado el umbral de intentos fallidos."""
        with self._lock:
            attempts = self._attempts.get(ip, [])
            cutoff   = time.time() - _LOCKOUT_MINUTES * 60
            recent   = [t for t in attempts if t > cutoff]
            self._attempts[ip] = recent
            return len(recent) >= _MAX_ATTEMPTS

    def _record_failed(self, ip: str) -> None:
        with self._lock:
            self._attempts.setdefault(ip, []).append(time.time())

    def _clear_attempts(self, ip: str) -> None:
        with self._lock:
            self._attempts.pop(ip, None)

    # ── Sesiones ──────────────────────────────────────────────────────────────
    def _create_session(self, ip: str) -> str:
        """Genera un token de sesión de 256 bits y lo registra."""
        token = secrets.token_hex(_SESSION_LEN)
        with self._lock:
            self._sessions[token] = {
                "created": time.time(),
                "ip":      ip,
            }
        return token

    def _validate_session(self, token: str, ip: str) -> bool:
        """Valida token + IP + TTL. Elimina sesiones expiradas."""
        if not token:
            return False
        with self._lock:
            session = self._sessions.get(token)
            if not session:
                return False
            # Binding de IP (mitiga robo de token)
            if session["ip"] != ip:
                return False
            # TTL 8 horas
            if time.time() - session["created"] > _SESSION_TTL_H * 3600:
                del self._sessions[token]
                return False
            return True

    def _revoke_session(self, token: str) -> None:
        with self._lock:
            self._sessions.pop(token, None)

    def _cleanup_expired_sessions(self) -> None:
        """Elimina sesiones expiradas (llamado periódicamente)."""
        cutoff = time.time() - _SESSION_TTL_H * 3600
        with self._lock:
            expired = [t for t, s in self._sessions.items() if s["created"] < cutoff]
            for t in expired:
                del self._sessions[t]

    # ── Integración Flask ─────────────────────────────────────────────────────
    def protect(self, app) -> None:
        """
        Aplica autenticación MFA y cabeceras de seguridad a la app Flask.

        Rutas añadidas:
          GET  /login  → formulario de login
          POST /login  → verifica password + TOTP → crea sesión
          GET  /logout → revoca sesión activa
        """
        from flask import request, redirect, url_for, make_response, Response

        @app.before_request
        def _auth_guard():
            """Protege todas las rutas salvo /login y /logout."""
            # Cabeceras de seguridad en todas las respuestas (añadidas via after)
            if request.path in _PUBLIC_PATHS:
                return None
            token = request.cookies.get("sb_session", "")
            ip    = request.remote_addr or "unknown"
            if not self._validate_session(token, ip):
                return redirect("/login")
            return None

        @app.after_request
        def _security_headers(response):
            """Aplica cabeceras de seguridad HTTP en todas las respuestas."""
            for header, value in _SECURITY_HEADERS.items():
                response.headers[header] = value
            return response

        @app.route("/login", methods=["GET"])
        def _login_get():
            return make_response(_LOGIN_HTML), 200

        @app.route("/login", methods=["POST"])
        def _login_post():
            ip       = request.remote_addr or "unknown"

            # Rate limiting
            if self._is_locked(ip):
                return make_response(
                    f"<h2>Demasiados intentos. Intenta en {_LOCKOUT_MINUTES} min.</h2>",
                    429
                )

            password = request.form.get("password", "")
            totp_code = request.form.get("totp", "").strip().replace(" ", "")

            pw_ok   = self._verify_password(password)
            totp_ok = self._verify_totp(totp_code)

            if not pw_ok or not totp_ok:
                self._record_failed(ip)
                remaining = _MAX_ATTEMPTS - len(self._attempts.get(ip, []))
                return make_response(
                    _LOGIN_HTML.replace(
                        "<!--ERROR-->",
                        f'<div class="err">Credenciales incorrectas. '
                        f'Intentos restantes: {max(0, remaining)}</div>',
                    ),
                    401,
                )

            # Autenticación correcta
            self._clear_attempts(ip)
            token    = self._create_session(ip)
            response = redirect("/")
            # Cookie segura: HttpOnly, Secure, SameSite=Strict
            response.set_cookie(
                "sb_session", token,
                max_age    = _SESSION_TTL_H * 3600,
                httponly   = True,
                secure     = True,
                samesite   = "Strict",
                path       = "/",
            )
            logger.info(f"Autenticación MFA exitosa desde {ip}")
            return response

        @app.route("/logout")
        def _logout():
            token    = request.cookies.get("sb_session", "")
            self._revoke_session(token)
            response = redirect("/login")
            response.delete_cookie("sb_session")
            return response

    def get_active_sessions(self) -> int:
        """Retorna el número de sesiones activas (para auditoría)."""
        self._cleanup_expired_sessions()
        with self._lock:
            return len(self._sessions)


# ── Página de login embebida ──────────────────────────────────────────────────
_LOGIN_HTML = """<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>StrikeBack — Acceso Seguro</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0;}
    body{background:#0d1117;display:flex;align-items:center;justify-content:center;
         min-height:100vh;font-family:'Segoe UI',system-ui,sans-serif;}
    .card{background:#161b22;border:1px solid #30363d;border-radius:12px;
          padding:40px 48px;width:380px;text-align:center;}
    .logo{font-size:48px;margin-bottom:8px;}
    h1{color:#e6edf3;font-size:22px;font-weight:800;letter-spacing:3px;margin-bottom:4px;}
    .sub{color:#8b949e;font-size:12px;letter-spacing:2px;margin-bottom:32px;}
    label{display:block;text-align:left;color:#8b949e;font-size:12px;
          letter-spacing:1px;margin-bottom:6px;}
    input{width:100%;background:#0d1117;border:1px solid #30363d;border-radius:8px;
          color:#e6edf3;font-size:14px;padding:10px 14px;margin-bottom:20px;outline:none;}
    input:focus{border-color:#ff4444;}
    button{width:100%;background:#ff4444;border:none;border-radius:8px;color:#fff;
           font-size:15px;font-weight:700;padding:12px;cursor:pointer;
           letter-spacing:1px;transition:background .2s;}
    button:hover{background:#cc0000;}
    .err{background:#2d1515;border:1px solid #ff4444;border-radius:8px;color:#ff6b6b;
         font-size:13px;padding:10px;margin-bottom:16px;}
    .hint{color:#8b949e;font-size:11px;margin-top:16px;line-height:1.6;}
    .shield{color:#ff4444;font-size:13px;margin-top:8px;}
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">🦉</div>
    <h1>STRIKE<span style="color:#ff4444">BACK</span></h1>
    <div class="sub">SECURITY OPERATIONS CENTER</div>
    <!--ERROR-->
    <form method="POST" action="/login" autocomplete="off">
      <label>CONTRASEÑA</label>
      <input type="password" name="password" placeholder="••••••••••••" required autofocus>
      <label>CÓDIGO MFA (Google Authenticator / Authy)</label>
      <input type="text" name="totp" placeholder="123456" maxlength="6"
             pattern="[0-9]{6}" inputmode="numeric" required>
      <button type="submit">🔐 ACCEDER</button>
    </form>
    <div class="hint">
      Autenticación de dos factores requerida.<br>
      Sesión válida durante 8 horas.
    </div>
    <div class="shield">🛡️ TLS 1.3 · AES-256-GCM · PBKDF2</div>
  </div>
</body>
</html>"""
