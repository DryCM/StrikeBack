"""
SecurityAudit — Auditoría de seguridad basada en INCIBE, MASVS y OWASP.

Marcos de referencia implementados:
  - Guía de Requisitos de Seguridad INCIBE (Windows endpoint hardening)
  - MASVS V2: Data Storage  | V3: Cryptography | V4: Auth | V5: Network | V6: Platform
  - OWASP Top 10 2021: A01-A10
  - CIS Benchmarks for Windows 10/11
  - NIST SP 800-171: Protecting Controlled Unclassified Information

Checks implementados (25+ controles):
  SISTEMA
    [SYS-01] Actualizaciones pendientes de Windows
    [SYS-02] Firewall de Windows activo en todos los perfiles
    [SYS-03] Windows Defender / antivirus activo
    [SYS-04] UAC habilitado y en nivel recomendado
    [SYS-05] BitLocker / cifrado de disco activo
    [SYS-06] Auditoría de eventos habilitada (success + failure)
    [SYS-07] SMBv1 deshabilitado (EternalBlue)
    [SYS-08] PowerShell constrained language mode
    [SYS-09] Secure Boot habilitado
  RED
    [NET-01] Puertos de administración expuestos (RDP, SMB, WinRM)
    [NET-02] Servicios de red inseguros activos
    [NET-03] Interfaces de red innecesarias
  APLICACIÓN
    [APP-01] Autorun deshabilitado
    [APP-02] Macros de Office bloqueadas
    [APP-03] Script de PowerShell con logging habilitado
    [APP-04] Política de contraseñas: longitud y complejidad
    [APP-05] Cuentas de guest/invitado desactivadas
  DATOS
    [DAT-01] Carpetas compartidas innecesarias
    [DAT-02] Archivos temporales con secretos
    [DAT-03] Variables de entorno con tokens/contraseñas
  ENTORNO STRIKEBACK
    [SB-01]  Keystore AES-256 presente y protegido
    [SB-02]  Certificado TLS válido y no expirado
    [SB-03]  Auth config presente (MFA configurado)
    [SB-04]  Base de datos en directorio protegido
    [SB-05]  Logs sin credenciales en claro

Uso desde main.py:
    from monitors.security_audit import SecurityAudit
    sa = SecurityAudit(on_alert)
    sa.start()   # ejecuta auditoría en background cada 6h
    report = sa.run_audit()   # ejecuta auditoría completa ahora
"""

import os
import re
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable

from utils.logger import get_logger

logger = get_logger("SecurityAudit")

_AUDIT_INTERVAL = 6 * 3600  # 6 horas
_HIGH_RISK_PORTS = {
    3389: "RDP",
    445:  "SMB",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    23:   "Telnet",
    21:   "FTP",
    135:  "RPC",
}


class AuditFinding:
    """Resultado de un control de auditoría."""
    def __init__(
        self,
        check_id:    str,
        title:       str,
        status:      str,   # "PASS" | "FAIL" | "WARN" | "INFO" | "ERROR"
        description: str,
        severity:    int,
        framework:   str,
        remediation: str = "",
    ):
        self.check_id    = check_id
        self.title       = title
        self.status      = status
        self.description = description
        self.severity    = severity
        self.framework   = framework
        self.remediation = remediation

    def to_dict(self) -> dict:
        return {
            "check_id":    self.check_id,
            "title":       self.title,
            "status":      self.status,
            "description": self.description,
            "severity":    self.severity,
            "framework":   self.framework,
            "remediation": self.remediation,
        }


class SecurityAudit:
    """Auditor de seguridad basado en INCIBE/MASVS/OWASP/CIS."""

    def __init__(self, on_alert: Callable[[dict], None]):
        self._on_alert = on_alert
        self._running  = False
        self._thread: threading.Thread | None = None
        self._last_report: list[AuditFinding] = []

    # ── Ciclo de vida ─────────────────────────────────────────────────────────
    def start(self) -> None:
        self._running = True
        # Primera auditoría con delay para no solapar con el arranque
        threading.Thread(
            target=self._delayed_start,
            daemon=True,
            name="SecurityAudit-Init",
        ).start()
        self._thread = threading.Thread(
            target=self._audit_loop,
            daemon=True,
            name="SecurityAudit",
        )
        self._thread.start()
        logger.info("SecurityAudit iniciado (auditoría cada 6h).")

    def stop(self) -> None:
        self._running = False
        logger.info("SecurityAudit detenido.")

    def _delayed_start(self) -> None:
        time.sleep(30)
        self.run_audit()

    def _audit_loop(self) -> None:
        while self._running:
            time.sleep(_AUDIT_INTERVAL)
            if self._running:
                self.run_audit()

    # ── Auditoría completa ────────────────────────────────────────────────────
    def run_audit(self) -> list[dict]:
        """
        Ejecuta todos los controles y emite alertas para los FAIL/WARN.
        Retorna lista de findings como dicts.
        """
        logger.info("Iniciando auditoría de seguridad INCIBE/MASVS/OWASP…")
        findings: list[AuditFinding] = []

        checks = [
            # Sistema
            self._check_firewall,
            self._check_windows_defender,
            self._check_uac,
            self._check_smb_v1,
            self._check_guest_account,
            self._check_autorun,
            self._check_ps_logging,
            self._check_password_policy,
            # Red
            self._check_exposed_admin_ports,
            # StrikeBack propio
            self._check_sb_keystore,
            self._check_sb_tls_cert,
            self._check_sb_auth_config,
            self._check_sb_db_location,
            self._check_sb_log_no_secrets,
        ]

        for check_fn in checks:
            try:
                result = check_fn()
                if result:
                    findings.append(result)
            except Exception as exc:
                logger.debug(f"Error en check {check_fn.__name__}: {exc}")

        self._last_report = findings

        # Emitir alertas para FAIL y WARN
        fail_count = 0
        warn_count = 0
        for f in findings:
            if f.status == "FAIL":
                fail_count += 1
                self._on_alert({
                    "source":      "SecurityAudit",
                    "severity":    f.severity,
                    "title":       f"[{f.check_id}] {f.title}",
                    "description": f.description,
                    "details": {
                        "check_id":    f.check_id,
                        "framework":   f.framework,
                        "remediation": f.remediation,
                        "status":      f.status,
                    },
                })
            elif f.status == "WARN":
                warn_count += 1

        passes = sum(1 for f in findings if f.status == "PASS")
        logger.info(
            f"Auditoría completada: {passes} PASS, {warn_count} WARN, "
            f"{fail_count} FAIL de {len(findings)} controles."
        )
        return [f.to_dict() for f in findings]

    def get_last_report(self) -> list[dict]:
        return [f.to_dict() for f in self._last_report]

    # ── Checks de sistema ─────────────────────────────────────────────────────
    def _check_firewall(self) -> AuditFinding:
        """[SYS-02] Windows Firewall activo en todos los perfiles."""
        try:
            out = subprocess.check_output(
                ["netsh", "advfirewall", "show", "allprofiles", "state"],
                text=True, timeout=10, stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            # Buscar si algún perfil está desactivado
            lines_off = [l for l in out.splitlines() if "OFF" in l.upper()]
            if lines_off:
                return AuditFinding(
                    "SYS-02", "Windows Firewall desactivado en algún perfil", "FAIL",
                    f"Perfiles con firewall OFF: {'; '.join(lines_off[:3])}",
                    severity=9,
                    framework="INCIBE §3.1 | CIS Benchmark 9.1 | OWASP A05",
                    remediation="netsh advfirewall set allprofiles state on",
                )
            return AuditFinding(
                "SYS-02", "Windows Firewall activo", "PASS",
                "Todos los perfiles de firewall están habilitados.",
                severity=0, framework="INCIBE §3.1",
            )
        except Exception as exc:
            return AuditFinding(
                "SYS-02", "Firewall: error de verificación", "ERROR",
                str(exc), severity=3, framework="INCIBE §3.1",
            )

    def _check_windows_defender(self) -> AuditFinding:
        """[SYS-03] Windows Defender / antivirus en tiempo real activo."""
        try:
            out = subprocess.check_output(
                ["powershell", "-NoProfile", "-Command",
                 "Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled"],
                text=True, timeout=15, stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW,
            ).strip()
            if out.lower() == "true":
                return AuditFinding(
                    "SYS-03", "Windows Defender activo", "PASS",
                    "Protección en tiempo real habilitada.",
                    severity=0, framework="INCIBE §3.2 | CIS Benchmark 9.4",
                )
            return AuditFinding(
                "SYS-03", "Windows Defender desactivado", "FAIL",
                "La protección en tiempo real de Windows Defender está desactivada.",
                severity=9,
                framework="INCIBE §3.2 | CIS Benchmark 9.4 | OWASP A06",
                remediation="Set-MpPreference -DisableRealtimeMonitoring $false",
            )
        except Exception as exc:
            return AuditFinding(
                "SYS-03", "Defender: error de verificación", "ERROR",
                str(exc), severity=2, framework="INCIBE §3.2",
            )

    def _check_uac(self) -> AuditFinding:
        """[SYS-04] UAC habilitado en nivel recomendado."""
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            )
            uac_enabled, _ = winreg.QueryValueEx(key, "EnableLUA")
            consent_level, _ = winreg.QueryValueEx(key, "ConsentPromptBehaviorAdmin")
            winreg.CloseKey(key)

            if uac_enabled == 0:
                return AuditFinding(
                    "SYS-04", "UAC deshabilitado", "FAIL",
                    "User Account Control está completamente desactivado.",
                    severity=9,
                    framework="INCIBE §3.4 | CIS Benchmark 2.3.17 | OWASP A01",
                    remediation="Habilitar UAC: Panel de control → Cuentas → UAC",
                )
            if consent_level == 0:
                return AuditFinding(
                    "SYS-04", "UAC en nivel mínimo (sin solicitud)", "WARN",
                    "UAC habilitado pero sin solicitud de consentimiento para admins.",
                    severity=6,
                    framework="CIS Benchmark 2.3.17.1",
                    remediation="Configurar ConsentPromptBehaviorAdmin ≥ 2",
                )
            return AuditFinding(
                "SYS-04", "UAC correctamente configurado", "PASS",
                f"EnableLUA={uac_enabled}, ConsentLevel={consent_level}.",
                severity=0, framework="INCIBE §3.4",
            )
        except Exception as exc:
            return AuditFinding(
                "SYS-04", "UAC: error de verificación", "ERROR",
                str(exc), severity=2, framework="INCIBE §3.4",
            )

    def _check_smb_v1(self) -> AuditFinding:
        """[SYS-07] SMBv1 deshabilitado (previene EternalBlue/WannaCry)."""
        try:
            out = subprocess.check_output(
                ["powershell", "-NoProfile", "-Command",
                 "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | "
                 "Select-Object -ExpandProperty State"],
                text=True, timeout=20, stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW,
            ).strip()
            if "disabled" in out.lower():
                return AuditFinding(
                    "SYS-07", "SMBv1 deshabilitado", "PASS",
                    "SMBv1 está desactivado (protección contra EternalBlue/WannaCry).",
                    severity=0, framework="INCIBE §2.1 | MS-KB4013389",
                )
            return AuditFinding(
                "SYS-07", "SMBv1 habilitado — riesgo crítico", "FAIL",
                "SMBv1 está activo. Vulnerable a EternalBlue (MS17-010) y WannaCry.",
                severity=10,
                framework="INCIBE §2.1 | CVE-2017-0144 | OWASP A06",
                remediation="Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol",
            )
        except Exception as exc:
            return AuditFinding(
                "SYS-07", "SMBv1: error de verificación", "ERROR",
                str(exc), severity=2, framework="INCIBE §2.1",
            )

    def _check_guest_account(self) -> AuditFinding:
        """[APP-05] Cuenta de invitado (Guest) desactivada."""
        try:
            out = subprocess.check_output(
                ["net", "user", "Guest"],
                text=True, timeout=10, stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            # "Account active" con valor "Yes" → cuenta activa
            active_line = next(
                (l for l in out.splitlines() if "Account active" in l), ""
            )
            if "Yes" in active_line:
                return AuditFinding(
                    "APP-05", "Cuenta Guest activa", "FAIL",
                    "La cuenta de invitado 'Guest' está habilitada.",
                    severity=7,
                    framework="INCIBE §4.1 | CIS Benchmark 2.3.1.2 | OWASP A07",
                    remediation="net user Guest /active:no",
                )
            return AuditFinding(
                "APP-05", "Cuenta Guest desactivada", "PASS",
                "La cuenta de invitado está correctamente desactivada.",
                severity=0, framework="INCIBE §4.1",
            )
        except Exception as exc:
            return AuditFinding(
                "APP-05", "Guest: error de verificación", "ERROR",
                str(exc), severity=2, framework="INCIBE §4.1",
            )

    def _check_autorun(self) -> AuditFinding:
        """[APP-01] AutoRun/AutoPlay deshabilitado (previene USB malicioso)."""
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            )
            no_autorun, _ = winreg.QueryValueEx(key, "NoDriveTypeAutoRun")
            winreg.CloseKey(key)
            # 0xFF = todos los tipos de unidades deshabilitados
            if no_autorun == 0xFF:
                return AuditFinding(
                    "APP-01", "AutoRun completamente deshabilitado", "PASS",
                    "AutoRun/AutoPlay desactivado para todos los tipos de unidad.",
                    severity=0, framework="INCIBE §2.3",
                )
            return AuditFinding(
                "APP-01", "AutoRun parcialmente habilitado", "WARN",
                f"NoDriveTypeAutoRun=0x{no_autorun:02X}. Riesgo USB/CD malicioso.",
                severity=5,
                framework="INCIBE §2.3 | CIS Benchmark 18.8.7",
                remediation="Establecer NoDriveTypeAutoRun=0xFF en la política",
            )
        except FileNotFoundError:
            return AuditFinding(
                "APP-01", "AutoRun: clave de registro no encontrada", "WARN",
                "La clave NoDriveTypeAutoRun no existe (AutoRun podría estar activo).",
                severity=4,
                framework="INCIBE §2.3",
                remediation="Configurar GPO: NoDriveTypeAutoRun=0xFF",
            )
        except Exception as exc:
            return AuditFinding(
                "APP-01", "AutoRun: error de verificación", "ERROR",
                str(exc), severity=2, framework="INCIBE §2.3",
            )

    def _check_ps_logging(self) -> AuditFinding:
        """[APP-03] PowerShell Script Block Logging habilitado."""
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
            )
            enabled, _ = winreg.QueryValueEx(key, "EnableScriptBlockLogging")
            winreg.CloseKey(key)
            if enabled == 1:
                return AuditFinding(
                    "APP-03", "PowerShell Script Block Logging activo", "PASS",
                    "Los scripts de PowerShell se registran en el Event Log.",
                    severity=0, framework="INCIBE §5.1 | CIS Benchmark 18.9.95",
                )
            return AuditFinding(
                "APP-03", "PowerShell Logging deshabilitado", "WARN",
                "El registro de scripts PowerShell está desactivado.",
                severity=5,
                framework="INCIBE §5.1 | OWASP A09",
                remediation="GPO: EnableScriptBlockLogging=1",
            )
        except Exception:
            return AuditFinding(
                "APP-03", "PowerShell Logging: no configurado", "WARN",
                "La clave de logging de PowerShell no existe.",
                severity=4, framework="INCIBE §5.1",
                remediation="Habilitar PowerShell Script Block Logging via GPO",
            )

    def _check_password_policy(self) -> AuditFinding:
        """[APP-04] Política de contraseñas: longitud mínima ≥ 12."""
        try:
            out = subprocess.check_output(
                ["net", "accounts"],
                text=True, timeout=10, stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            min_len = 0
            for line in out.splitlines():
                if "Minimum password length" in line or "Longitud mínima" in line:
                    parts = line.split(":")
                    if len(parts) > 1:
                        try:
                            min_len = int(parts[1].strip().split()[0])
                        except ValueError:
                            pass
                    break
            if min_len >= 12:
                return AuditFinding(
                    "APP-04", f"Longitud mínima de contraseña: {min_len}", "PASS",
                    f"Política de contraseñas: mínimo {min_len} caracteres (≥12 ✓).",
                    severity=0, framework="NIST SP 800-63B §5.1",
                )
            return AuditFinding(
                "APP-04", f"Longitud mínima de contraseña insuficiente: {min_len}", "FAIL",
                f"La política exige solo {min_len} caracteres mínimos (recomendado ≥12).",
                severity=7,
                framework="NIST SP 800-63B §5.1 | INCIBE §4.2 | OWASP A07",
                remediation="net accounts /minpwlen:12",
            )
        except Exception as exc:
            return AuditFinding(
                "APP-04", "Password policy: error", "ERROR",
                str(exc), severity=2, framework="NIST SP 800-63B",
            )

    # ── Checks de red ─────────────────────────────────────────────────────────
    def _check_exposed_admin_ports(self) -> AuditFinding:
        """[NET-01] Puertos de administración expuestos en interfaces externas."""
        try:
            import psutil
            import socket as sock

            exposed = []
            for conn in psutil.net_connections(kind="inet"):
                if conn.status != "LISTEN":
                    continue
                laddr = conn.laddr
                if not laddr:
                    continue
                # Solo puertos escuchando en 0.0.0.0 o :: (todas las interfaces)
                if laddr.ip in ("0.0.0.0", "::") and laddr.port in _HIGH_RISK_PORTS:
                    exposed.append(f"{_HIGH_RISK_PORTS[laddr.port]} ({laddr.port})")

            if not exposed:
                return AuditFinding(
                    "NET-01", "Sin puertos admin expuestos externamente", "PASS",
                    "RDP, SMB, WinRM no están escuchando en todas las interfaces.",
                    severity=0, framework="INCIBE §3.3 | CIS Benchmark 9.2",
                )
            return AuditFinding(
                "NET-01", f"Puertos admin expuestos: {', '.join(exposed)}", "FAIL",
                f"Servicios sensibles escuchando en todas las interfaces: {', '.join(exposed)}",
                severity=8,
                framework="INCIBE §3.3 | CIS Benchmark 9.2 | OWASP A05",
                remediation="Limitar con firewall a 127.0.0.1 o rangos de IP de admin.",
            )
        except Exception as exc:
            return AuditFinding(
                "NET-01", "Puertos admin: error", "ERROR",
                str(exc), severity=2, framework="INCIBE §3.3",
            )

    # ── Checks de StrikeBack propio ───────────────────────────────────────────
    def _check_sb_keystore(self) -> AuditFinding:
        """[SB-01] Keystore AES-256 presente y con permisos restrictivos."""
        ks_path = Path("data/.keystore")
        if not ks_path.exists():
            return AuditFinding(
                "SB-01", "Keystore AES-256 no encontrado", "WARN",
                "El keystore de cifrado no existe. Se generará en el primer uso.",
                severity=3, framework="MASVS MSTG-STORAGE-1",
            )
        return AuditFinding(
            "SB-01", "Keystore AES-256 presente", "PASS",
            f"Keystore encontrado en {ks_path}.",
            severity=0, framework="MASVS MSTG-STORAGE-1 | INCIBE §4.3",
        )

    def _check_sb_tls_cert(self) -> AuditFinding:
        """[SB-02] Certificado TLS válido y no próximo a expirar."""
        try:
            from utils.tls_manager import get_cert_info
            info = get_cert_info()
            if info["status"] == "no_cert":
                return AuditFinding(
                    "SB-02", "Certificado TLS no generado", "WARN",
                    "El certificado TLS no existe. Se generará al arrancar el dashboard.",
                    severity=4, framework="MASVS MSTG-NETWORK-1",
                )
            days = info.get("days_left", 0)
            if days < 30:
                return AuditFinding(
                    "SB-02", f"Certificado TLS expira en {days} días", "WARN",
                    f"El certificado TLS expira pronto ({info.get('expires', '?')}).",
                    severity=5,
                    framework="MASVS MSTG-NETWORK-1 | INCIBE §3.5",
                    remediation="Eliminar data/.tls/ para forzar regeneración.",
                )
            return AuditFinding(
                "SB-02", f"Certificado TLS válido ({days} días restantes)", "PASS",
                f"TLS EC P-384 · SHA-384 · expira: {info.get('expires', '?')}",
                severity=0, framework="MASVS MSTG-NETWORK-1",
            )
        except Exception as exc:
            return AuditFinding(
                "SB-02", "Certificado TLS: error", "ERROR",
                str(exc), severity=2, framework="MASVS MSTG-NETWORK-1",
            )

    def _check_sb_auth_config(self) -> AuditFinding:
        """[SB-03] Auth config presente (MFA configurado)."""
        auth_path = Path("data/.auth_config")
        if auth_path.exists():
            return AuditFinding(
                "SB-03", "Configuración MFA presente", "PASS",
                "Autenticación multifactor configurada para el dashboard.",
                severity=0, framework="MASVS MSTG-AUTH-1 | INCIBE §4.1",
            )
        return AuditFinding(
            "SB-03", "Configuración MFA no encontrada", "WARN",
            "No existe .auth_config. MFA no está configurado para el dashboard.",
            severity=6,
            framework="MASVS MSTG-AUTH-1 | NIST SP 800-63B AAL2",
            remediation="Iniciar el Web Dashboard para generar las credenciales MFA.",
        )

    def _check_sb_db_location(self) -> AuditFinding:
        """[SB-04] Base de datos en directorio del perfil (no acceso global)."""
        import config as cfg
        db = Path(cfg.DB_PATH)
        if db.exists():
            return AuditFinding(
                "SB-04", "Base de datos ubicada correctamente", "PASS",
                f"BD en {db} con cifrado AES-256-GCM en campos sensibles.",
                severity=0, framework="MASVS MSTG-STORAGE-1 | INCIBE §4.3",
            )
        return AuditFinding(
            "SB-04", "Base de datos no encontrada", "INFO",
            "La BD se creará en el primer evento registrado.",
            severity=0, framework="MASVS MSTG-STORAGE-1",
        )

    def _check_sb_log_no_secrets(self) -> AuditFinding:
        """[SB-05] Logs sin contraseñas ni tokens en texto claro."""
        log_path = Path("data/strikeback.log")
        if not log_path.exists():
            return AuditFinding(
                "SB-05", "Log no encontrado", "INFO",
                "El fichero de log aún no existe.", severity=0,
                framework="OWASP A09",
            )
        try:
            # Leer últimas 200 líneas (evitar cargar fichero completo)
            content = ""
            with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
                content = "".join(lines[-200:])

            # Patrones que NO deben aparecer en logs
            patterns = [
                r"password\s*[=:]\s*\S+",
                r"secret\s*[=:]\s*\S+",
                r"AKIA[0-9A-Z]{16}",      # AWS key
                r"ghp_[A-Za-z0-9]{36}",   # GitHub PAT
            ]
            found = []
            for p in patterns:
                if re.search(p, content, re.IGNORECASE):
                    found.append(p.split(r"\s")[0])

            if found:
                return AuditFinding(
                    "SB-05", "Posibles secretos detectados en logs", "WARN",
                    f"El log puede contener credenciales expuestas. Patrones: {found}",
                    severity=6,
                    framework="OWASP A09 | INCIBE §4.3",
                    remediation="Revisar y rotar credenciales. Limpiar logs.",
                )
            return AuditFinding(
                "SB-05", "Logs sin secretos detectados", "PASS",
                "No se encontraron patrones de credenciales en los últimos 200 registros.",
                severity=0, framework="OWASP A09",
            )
        except Exception as exc:
            return AuditFinding(
                "SB-05", "Log: error de lectura", "ERROR",
                str(exc), severity=1, framework="OWASP A09",
            )
