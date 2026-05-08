"""
Auto-Respuesta Activa — StrikeBack.

Cuando se detecta una amenaza crítica, actúa ANTES de que el atacante
complete el objetivo. No solo alerta: defiende.

Acciones disponibles:
  1. KILL PROCESS       — mata el proceso malicioso inmediatamente
  2. BLOCK C2 IP        — añade regla de bloqueo en Windows Firewall
  3. QUARANTINE FILE    — mueve archivos ransomware a carpeta aislada
  4. VSS SNAPSHOT       — crea copia de seguridad de volumen al arrancar
  5. ISOLATE NETWORK    — (emergencia) corta todas las conexiones externas

Umbrales configurables en config.py:
  AUTO_KILL_THRESHOLD_SEVERITY   = 9
  AUTO_KILL_THRESHOLD_CONFIDENCE = 90
"""

import os
import shutil
import subprocess
import threading
import ctypes
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

import config
from utils.logger import get_logger

logger = get_logger("AutoResponse")


def _is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


class AutoResponse:
    """
    Se engancha al pipeline de amenazas y ejecuta respuestas defensivas
    cuando severity + confidence superan los umbrales configurados.

    Uso en main.py:
        self.auto_response = AutoResponse(notify_callback=self._on_raw_threat)
        self.auto_response.start()
        # luego, en _on_raw_threat:
        self.auto_response.handle(threat)
    """

    def __init__(self, notify_callback: Optional[Callable] = None):
        self._notify    = notify_callback   # para emitir amenaza de "acción tomada"
        self._lock      = threading.Lock()
        self._blocked_ips:    set[str] = set()
        self._killed_pids:    set[int] = set()
        self._quarantined:    list[str] = []
        self._is_admin        = _is_admin()
        self._vss_created     = False

    # ─────────────────────────────────────────────────────────────────────────
    def start(self):
        os.makedirs(config.QUARANTINE_DIR, exist_ok=True)
        if not config.AUTO_RESPONSE_ENABLED:
            logger.info("[AutoResponse] Desactivado en config.")
            return

        if not self._is_admin:
            logger.warning(
                "[AutoResponse] Sin privilegios de administrador. "
                "Kill/Firewall/VSS pueden fallar. Reinicia como admin."
            )

        if config.AUTO_VSS_SNAPSHOT_ON_START and self._is_admin:
            self._create_vss_snapshot()

        logger.info("[AutoResponse] Activo — umbral sev≥%d conf≥%d%%",
                    config.AUTO_KILL_THRESHOLD_SEVERITY,
                    config.AUTO_KILL_THRESHOLD_CONFIDENCE)

    # ─────────────────────────────────────────────────────────────────────────
    def handle(self, threat: dict):
        """
        Punto de entrada principal. Llamar con cada amenaza detectada.
        Decide qué acciones tomar según tipo y severidad.
        """
        if not config.AUTO_RESPONSE_ENABLED:
            return

        sev  = threat.get("severity", 0)
        conf = threat.get("confidence", 0)
        src  = threat.get("source", "")
        det  = threat.get("details", {})

        # ── 1. Matar proceso malicioso ────────────────────────────────────
        if (sev >= config.AUTO_KILL_THRESHOLD_SEVERITY and
                conf >= config.AUTO_KILL_THRESHOLD_CONFIDENCE):
            pid  = det.get("pid")
            name = det.get("process") or det.get("name") or ""
            if pid and name:
                self._kill_process(pid, name, threat)

        # ── 2. Bloquear IP C2 en Firewall ─────────────────────────────────
        if config.AUTO_BLOCK_C2_IPS and src in ("NetworkMonitor", "ThreatIntel"):
            remote_ip = det.get("remote_ip") or det.get("ip")
            if remote_ip and sev >= 8:
                self._block_ip(remote_ip, threat)

        # ── 3. Cuarentena de archivos ransomware ──────────────────────────
        if config.AUTO_QUARANTINE_RANSOMWARE and src in ("FileSystemMonitor", "HoneypotMonitor"):
            file_path = det.get("path") or det.get("honeypot_path")
            title = threat.get("title", "")
            is_ransomware = (
                any(ext in title for ext in config.RANSOMWARE_EXTENSIONS) or
                "ransomware" in title.lower() or
                "señuelo" in title.lower()
            )
            if file_path and is_ransomware and sev >= 8:
                self._quarantine_file(file_path, threat)

        # ── 4. Aislamiento de red (solo si severidad = 10 + es C2 activo) ─
        if sev == 10 and "C2" in threat.get("title", "") and conf >= 95:
            pid = det.get("pid")
            if pid:
                self._isolate_process_network(pid, threat)

    # ─────────────────────────────────────────────────────────────────────────
    def _kill_process(self, pid: int, name: str, threat: dict):
        """Termina un proceso malicioso si no está en la whitelist."""
        with self._lock:
            if pid in self._killed_pids:
                return
            if name.lower() in config.AUTO_RESPONSE_PROCESS_WHITELIST:
                logger.warning(f"[AutoResponse] KILL BLOQUEADO — {name} está en whitelist")
                return

        try:
            import psutil
            proc = psutil.Process(pid)
            proc.kill()
            with self._lock:
                self._killed_pids.add(pid)

            msg = f"PROCESO ELIMINADO: {name} (PID {pid})"
            logger.critical(f"[AutoResponse] ✓ {msg}")
            self._emit_action(threat, "KILL_PROCESS", msg,
                              f"Proceso '{name}' terminado por StrikeBack (sev {threat.get('severity')}/10)")

        except Exception as e:
            logger.error(f"[AutoResponse] Error matando PID {pid} ({name}): {e}")

    # ─────────────────────────────────────────────────────────────────────────
    def _block_ip(self, ip: str, threat: dict):
        """Añade regla de bloqueo en Windows Firewall (entrada + salida)."""
        with self._lock:
            if ip in self._blocked_ips:
                return
            # No bloquear IPs locales/privadas
            if ip.startswith(("127.", "192.168.", "10.", "172.16.", "0.")):
                return
            self._blocked_ips.add(ip)

        rule_name = f"StrikeBack_Block_{ip.replace('.', '_')}"
        _NO_WIN = subprocess.CREATE_NO_WINDOW
        for direction in ("in", "out"):
            try:
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "add", "rule",
                     f"name={rule_name}_{direction}",
                     "action=block",
                     f"dir={direction}",
                     f"remoteip={ip}",
                     "enable=yes"],
                    capture_output=True, text=True, timeout=10,
                    creationflags=_NO_WIN,
                )
            except Exception as e:
                logger.error(f"[AutoResponse] Error bloqueando {ip} {direction}: {e}")

        msg = f"IP BLOQUEADA en Firewall: {ip}"
        logger.critical(f"[AutoResponse] ✓ {msg}")
        self._emit_action(threat, "BLOCK_IP", msg,
                          f"IP {ip} bloqueada (entrada+salida) en Windows Firewall")

    # ─────────────────────────────────────────────────────────────────────────
    def _quarantine_file(self, file_path: str, threat: dict):
        """Mueve el archivo a la carpeta de cuarentena aislada."""
        src = Path(file_path)
        if not src.exists():
            return

        dst_dir = Path(config.QUARANTINE_DIR)
        dst_dir.mkdir(parents=True, exist_ok=True)
        # Nombre con timestamp para evitar colisiones
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        dst   = dst_dir / f"{stamp}_{src.name}.quarantine"

        try:
            shutil.move(str(src), str(dst))
            with self._lock:
                self._quarantined.append(str(dst))

            msg = f"ARCHIVO EN CUARENTENA: {src.name} → {dst}"
            logger.critical(f"[AutoResponse] ✓ {msg}")
            self._emit_action(threat, "QUARANTINE_FILE", msg,
                              f"'{src.name}' aislado en data\\quarantine\\")

        except Exception as e:
            logger.error(f"[AutoResponse] Error poniendo en cuarentena {file_path}: {e}")

    # ─────────────────────────────────────────────────────────────────────────
    def _isolate_process_network(self, pid: int, threat: dict):
        """
        Aísla el proceso de red usando Windows Firewall (bloquea PID específico).
        Técnica: regla de firewall por nombre de ejecutable.
        """
        try:
            import psutil
            proc = psutil.Process(pid)
            exe  = proc.exe()
        except Exception:
            return

        rule_name = f"StrikeBack_Isolate_PID{pid}"
        try:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name={rule_name}",
                 "action=block", "dir=out",
                 f"program={exe}",
                 "enable=yes"],
                capture_output=True, text=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            msg = f"PROCESO AISLADO DE RED: {os.path.basename(exe)} (PID {pid})"
            logger.critical(f"[AutoResponse] ✓ {msg}")
            self._emit_action(threat, "ISOLATE_NETWORK", msg,
                              f"Conexiones salientes de PID {pid} bloqueadas")
        except Exception as e:
            logger.error(f"[AutoResponse] Error aislando PID {pid}: {e}")

    # ─────────────────────────────────────────────────────────────────────────
    def _create_vss_snapshot(self):
        """
        Crea un VSS snapshot del volumen C: al arrancar.
        Si llega ransomware, se puede restaurar desde aquí.
        """
        try:
            result = subprocess.run(
                ["wmic", "shadowcopy", "call", "create",
                 "Volume=C:\\\\"],
                capture_output=True, text=True, timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            if "ReturnValue = 0" in result.stdout or result.returncode == 0:
                self._vss_created = True
                logger.info("[AutoResponse] ✓ VSS Snapshot creado en C: (restauración disponible)")
            else:
                logger.warning(f"[AutoResponse] VSS snapshot falló: {result.stderr[:100]}")
        except Exception as e:
            logger.warning(f"[AutoResponse] No se pudo crear VSS snapshot: {e}")

    # ─────────────────────────────────────────────────────────────────────────
    def _emit_action(self, original_threat: dict, action: str, title: str, desc: str):
        """Emite una amenaza/evento de 'acción tomada' al dashboard."""
        if not self._notify:
            return
        self._notify({
            "source":      "AutoResponse",
            "title":       f"🛡 {title}",
            "description": desc,
            "severity":    original_threat.get("severity", 9),
            "confidence":  100,
            "timestamp":   datetime.now().isoformat(),
            "details": {
                "action":           action,
                "original_source":  original_threat.get("source"),
                "original_title":   original_threat.get("title"),
                "auto_response":    True,
            },
        })

    # ─────────────────────────────────────────────────────────────────────────
    def get_stats(self) -> dict:
        with self._lock:
            return {
                "killed_processes":     len(self._killed_pids),
                "blocked_ips":          len(self._blocked_ips),
                "quarantined_files":    len(self._quarantined),
                "vss_snapshot_created": self._vss_created,
                "admin":                self._is_admin,
            }
