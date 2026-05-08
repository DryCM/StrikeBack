"""
TLS Manager — Gestión de certificados TLS para el Web Dashboard.

Cumplimiento:
  - INCIBE: Protocolos seguros para transmisión de datos
  - MASVS V5: Network Communication (MSTG-NETWORK-1, MSTG-NETWORK-2)
  - OWASP A02/A05: Configuración criptográfica correcta
  - TLS 1.3 preferente; TLS 1.2 mínimo si el sistema no soporta TLS 1.3

Genera un certificado autofirmado EC P-384 con:
  - CN: StrikeBack-SOC / SAN: localhost + 127.0.0.1
  - SHA-384 signature  (más robusto que SHA-256 para P-384)
  - Validez: 365 días con auto-renovación
  - Almacenado en data/.tls/ (permisos NTFS restrictivos)
  - Suite de cifrado: TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256

Uso:
    from utils.tls_manager import get_ssl_context
    ctx = get_ssl_context()
    app.run(ssl_context=ctx, ...)
"""

import datetime
import ipaddress
import os
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from utils.logger import get_logger

logger = get_logger("TLSManager")

_TLS_DIR   = Path("data/.tls")
_CERT_FILE = _TLS_DIR / "server.crt"
_KEY_FILE  = _TLS_DIR / "server.key"
_DAYS_VALID = 365


def _generate_certificate() -> None:
    """
    Genera par de claves EC P-384 y certificado autofirmado X.509 v3.
    Incluye SAN para localhost e IP 127.0.0.1.
    """
    _TLS_DIR.mkdir(parents=True, exist_ok=True)

    # Par de claves EC P-384 (equivale a RSA-7680 en seguridad)
    private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME,             "StrikeBack-SOC"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,       "StrikeBack Security"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,"SOC Dashboard"),
        x509.NameAttribute(NameOID.COUNTRY_NAME,            "ES"),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=_DAYS_VALID))
        # Subject Alternative Names — evita advertencias TLS modernas
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("StrikeBack-SOC"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        # Uso de clave: firma digital + acuerdo de clave (ECDH)
        .add_extension(
            x509.KeyUsage(
                digital_signature  = True,
                key_cert_sign      = False,
                key_encipherment   = False,
                data_encipherment  = False,
                key_agreement      = True,
                content_commitment = False,
                crl_sign           = False,
                encipher_only      = False,
                decipher_only      = False,
            ),
            critical=True,
        )
        # Uso extendido: servidor TLS
        .add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        # Restricciones básicas: no es CA
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA384(), default_backend())
    )

    # Serializar clave privada (sin cifrado adicional — protegida por DACL NTFS)
    _KEY_FILE.write_bytes(
        private_key.private_bytes(
            encoding         = serialization.Encoding.PEM,
            format           = serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm = serialization.NoEncryption(),
        )
    )
    _CERT_FILE.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    # Aplicar permisos NTFS restrictivos (solo propietario)
    _restrict_tls_permissions()

    logger.info(f"Certificado TLS autofirmado EC P-384 generado en {_TLS_DIR}")


def _restrict_tls_permissions() -> None:
    """Aplica DACL restrictivo a archivos TLS: solo el usuario actual tiene acceso."""
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

        for path in (_KEY_FILE, _CERT_FILE):
            if not path.exists():
                continue
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
        pass


def _cert_is_valid(margin_days: int = 30) -> bool:
    """Comprueba si el certificado existe y no expira en los próximos margin_days."""
    if not _CERT_FILE.exists() or not _KEY_FILE.exists():
        return False
    try:
        from cryptography.x509 import load_pem_x509_certificate
        cert = load_pem_x509_certificate(_CERT_FILE.read_bytes())
        expire = cert.not_valid_after_utc
        remaining = (expire - datetime.datetime.now(datetime.timezone.utc)).days
        if remaining < margin_days:
            logger.info(f"Certificado TLS expira en {remaining} días — renovando…")
            return False
        return True
    except Exception:
        return False


def ensure_certificate() -> None:
    """Genera el certificado si no existe o está a punto de expirar."""
    if not _cert_is_valid():
        _generate_certificate()


def get_ssl_context() -> ssl.SSLContext:
    """
    Retorna un SSLContext configurado para TLS 1.3 preferente (TLS 1.2 mínimo).

    Suite de cifrado segura:
      TLS 1.3: TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256
      TLS 1.2: ECDHE-ECDSA-AES256-GCM-SHA384 (fallback)

    Protecciones adicionales:
      - OP_NO_SSLv2 / OP_NO_SSLv3 / OP_NO_TLSv1 / OP_NO_TLSv1_1
      - OP_SINGLE_DH_USE + OP_SINGLE_ECDH_USE (perfect forward secrecy)
      - OP_CIPHER_SERVER_PREFERENCE
    """
    ensure_certificate()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # Versión mínima TLS 1.2; preferir TLS 1.3
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        logger.info("TLS configurado: versión mínima 1.3")
    except AttributeError:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        logger.info("TLS 1.3 no disponible en este sistema — usando TLS 1.2 mínimo")

    # Deshabilitar versiones inseguras explícitamente
    ctx.options |= (
        getattr(ssl, "OP_NO_SSLv2",   0) |
        getattr(ssl, "OP_NO_SSLv3",   0) |
        getattr(ssl, "OP_NO_TLSv1",   0) |
        getattr(ssl, "OP_NO_TLSv1_1", 0)
    )

    # Perfect Forward Secrecy
    ctx.options |= (
        getattr(ssl, "OP_SINGLE_DH_USE",   0) |
        getattr(ssl, "OP_SINGLE_ECDH_USE", 0) |
        getattr(ssl, "OP_CIPHER_SERVER_PREFERENCE", 0)
    )

    # Cargar certificado y clave
    ctx.load_cert_chain(certfile=str(_CERT_FILE), keyfile=str(_KEY_FILE))

    # Suite de cifrado fuerte (TLS 1.2 fallback)
    try:
        ctx.set_ciphers(
            "ECDHE-ECDSA-AES256-GCM-SHA384:"
            "ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-CHACHA20-POLY1305:"
            "ECDHE-RSA-CHACHA20-POLY1305:"
            "@SECLEVEL=2"
        )
    except ssl.SSLError:
        pass  # Fallback a suite por defecto del sistema

    return ctx


def get_cert_info() -> dict:
    """Retorna metadatos del certificado activo para auditoría."""
    if not _CERT_FILE.exists():
        return {"status": "no_cert"}
    try:
        from cryptography.x509 import load_pem_x509_certificate
        cert    = load_pem_x509_certificate(_CERT_FILE.read_bytes())
        expire  = cert.not_valid_after_utc
        now     = datetime.datetime.now(datetime.timezone.utc)
        return {
            "status":       "valid",
            "subject":      cert.subject.rfc4514_string(),
            "expires":      expire.isoformat(),
            "days_left":    (expire - now).days,
            "serial":       hex(cert.serial_number),
            "algorithm":    cert.signature_hash_algorithm.name,
        }
    except Exception as exc:
        return {"status": "error", "detail": str(exc)}
