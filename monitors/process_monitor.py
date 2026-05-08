"""
Monitor de procesos — detecta malware, keyloggers y comportamiento anómalo.
"""
import threading
import os
from datetime import datetime
from typing import Callable, Optional
import psutil

import config
from utils.logger import get_logger

logger = get_logger("ProcessMonitor")


def _calc_confidence(name: str, exe: str, base: int) -> int:
    """
    Calcula un porcentaje de confianza (0-100) para la detección.
    Penaliza si el nombre solo coincide parcialmente o no tiene exe en disco.
    """
    score = base
    # Coincidencia exacta (sin extensión) sube confianza
    name_no_ext = os.path.splitext(name)[0].lower()
    if name_no_ext in config.ATTACK_TOOL_SIGNATURES:
        score = min(score + 10, 100)
    # Proceso con exe verificado en disco
    if exe and os.path.isfile(exe):
        score = min(score + 5, 100)
    # Sin exe en disco baja confianza (podría ser proceso legítimo renombrado)
    elif not exe:
        score = max(score - 15, 30)
    return score


class ProcessMonitor:
    """
    Escanea procesos en ejecución y detecta herramientas de ataque
    mediante firmas MITRE ATT&CK completas y análisis heurístico.
    """

    def __init__(self, threat_callback: Callable):
        self.threat_callback = threat_callback
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._seen_pids: set = set()
        self._alerted_pids: set = set()
        self.name = "Procesos"
        self._snapshot: list = []

    # ------------------------------------------------------------------
    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True, name="ProcessMon")
        self._thread.start()
        logger.info("Monitor de procesos iniciado.")

    def stop(self):
        self._stop_event.set()

    # ------------------------------------------------------------------
    def _run(self):
        while not self._stop_event.is_set():
            try:
                self._scan()
            except Exception as e:
                logger.error(f"Error en escaneo de procesos: {e}")
            self._stop_event.wait(timeout=config.PROCESS_SCAN_INTERVAL)

    # ------------------------------------------------------------------
    def _scan(self):
        snapshot = []
        new_pids = set()

        for proc in psutil.process_iter(
            ["pid", "name", "exe", "cmdline", "cpu_percent", "memory_info",
             "username", "ppid", "create_time", "status"]
        ):
            try:
                info     = proc.info
                pid      = info["pid"]
                name     = (info["name"] or "").lower()
                name_clean = os.path.splitext(name)[0]
                exe      = info.get("exe") or ""
                cmdline  = " ".join(info.get("cmdline") or []).lower()

                new_pids.add(pid)
                is_new = pid not in self._seen_pids

                mem_mb = info["memory_info"].rss // (1024 * 1024) if info.get("memory_info") else 0
                snapshot.append({
                    "pid":    pid,
                    "name":   info["name"] or "?",
                    "cpu":    info.get("cpu_percent", 0),
                    "mem_mb": mem_mb,
                    "status": info.get("status", ""),
                    "user":   info.get("username", ""),
                })

                # --- Regla 1: Firma de herramienta de ataque conocida ---
                # Coincidencia EXACTA de nombre (sin extensión) para evitar falsos positivos
                # por substring (ej. "john" en "johndoe.exe", "beacon" en otros procesos).
                # El cmdline sí usa subcadena pero requiere firma de â6+ chars.
                matched_sig = None
                for sig_name, (sev, mitre, category) in config.ATTACK_TOOL_SIGNATURES.items():
                    name_match = (name_clean == sig_name)
                    cmd_match  = (len(sig_name) >= 6 and sig_name in cmdline)
                    if name_match or cmd_match:
                        matched_sig = (sig_name, sev, mitre, category)
                        break

                if matched_sig and pid not in self._alerted_pids:
                    sig_name, sev, mitre, category = matched_sig
                    # Base reducida para evitar que cualquier coincidencia llegue al 95-98%
                    # Fórmula: 55 + sev*3  →  sev=7 → 76%,  sev=9 → 82%,  sev=10 → 85%
                    confidence = _calc_confidence(name, exe, 55 + sev * 3)
                    confidence = min(confidence, 97)
                    self._emit_threat(
                        pid=pid, severity=sev,
                        title=f"[{mitre}] Herramienta de ataque: {info['name']}",
                        description=(
                            f"Proceso '{info['name']}' (PID {pid}) coincide con firma "
                            f"'{sig_name}' — categoría: {category}. "
                            f"Ruta: {exe or 'sin ruta en disco'}"
                        ),
                        details={
                            "pid": pid, "name": info["name"], "exe": exe,
                            "mitre": mitre, "category": category,
                            "matched_sig": sig_name, "confidence": confidence,
                        },
                        confidence=confidence,
                    )

                # --- Regla 2: Proceso sin ruta en disco (process hollowing) ---
                if is_new and not exe and name not in ("system", "idle", "registry", ""):
                    if pid not in self._alerted_pids:
                        confidence = 60
                        self._emit_threat(
                            pid=pid, severity=7,
                            title=f"[T1055] Proceso fantasma — posible hollowing: {info['name']}",
                            description=(
                                f"Proceso '{info['name']}' (PID {pid}) sin imagen en disco. "
                                f"Técnica T1055 - Process Hollowing o inyección de código."
                            ),
                            details={"pid": pid, "name": info["name"], "confidence": confidence},
                            confidence=confidence,
                        )

                # --- Regla 3: Ejecutable desde directorio temporal ---
                if exe and is_new:
                    suspicious_dirs = [
                        r"\temp\\", r"\tmp\\", r"\appdata\local\temp\\",
                        r"\downloads\\", r"\recycle", r"\users\public\\",
                        r"\perflogs\\",
                    ]
                    exe_lower = exe.lower()
                    for sdir in suspicious_dirs:
                        if sdir in exe_lower and exe_lower.endswith(".exe"):
                            if pid not in self._alerted_pids:
                                confidence = 75
                                self._emit_threat(
                                    pid=pid, severity=7,
                                    title=f"[T1059] Ejecutable lanzado desde directorio temporal",
                                    description=(
                                        f"Proceso '{info['name']}' (PID {pid}) ejecutándose desde "
                                        f"ruta de alto riesgo: {exe}"
                                    ),
                                    details={"pid": pid, "name": info["name"], "exe": exe,
                                             "confidence": confidence},
                                    confidence=confidence,
                                )
                            break

                # --- Regla 4: PowerShell con flags de evasión ---
                if "powershell" in name_clean:
                    evasion_flags = [
                        ("-enc", "T1059.001 - PowerShell Encoded Command", 85),
                        ("-encodedcommand", "T1059.001 - PowerShell Encoded Command", 88),
                        ("-windowstyle hidden", "T1564 - Hidden Window", 80),
                        ("bypass", "T1059.001 - ExecutionPolicy Bypass", 82),
                        ("downloadstring", "T1105 - Remote File Download", 90),
                        ("iex ", "T1059.001 - Invoke-Expression", 78),
                        ("invoke-expression", "T1059.001 - Invoke-Expression", 80),
                        ("webclient", "T1105 - Remote File Download", 85),
                        ("bitsadmin", "T1197 - BITS Jobs abuse", 80),
                    ]
                    for flag, label, conf in evasion_flags:
                        if flag in cmdline and pid not in self._alerted_pids:
                            self._emit_threat(
                                pid=pid, severity=8,
                                title=f"[{label.split(' - ')[0]}] PowerShell sospechoso: {flag}",
                                description=(
                                    f"PowerShell (PID {pid}) ejecutado con parámetros de evasión: '{flag}'. "
                                    f"Técnica: {label}. Cmdline: {cmdline[:120]}"
                                ),
                                details={"pid": pid, "cmdline": cmdline[:300],
                                         "flag": flag, "confidence": conf},
                                confidence=conf,
                            )
                            break

                # --- Regla 5: wscript/cscript ejecutando scripts -----
                if name_clean in ("wscript", "cscript") and cmdline:
                    if any(ext in cmdline for ext in [".vbs", ".js", ".wsf", ".hta"]):
                        if pid not in self._alerted_pids:
                            confidence = 72
                            self._emit_threat(
                                pid=pid, severity=7,
                                title=f"[T1059.005] Script engine ejecutando archivo sospechoso",
                                description=(
                                    f"{info['name']} (PID {pid}) ejecutando script: {cmdline[:150]}"
                                ),
                                details={"pid": pid, "cmdline": cmdline[:300],
                                         "confidence": confidence},
                                confidence=confidence,
                            )

                # --- Regla 6: CPU excesivo (cryptominer) ---------------
                cpu = info.get("cpu_percent", 0) or 0
                if cpu > config.CPU_THRESHOLD_PERCENT and pid not in self._alerted_pids:
                    confidence = min(50 + int(cpu - config.CPU_THRESHOLD_PERCENT), 90)
                    self._emit_threat(
                        pid=pid, severity=6,
                        title=f"[T1496] CPU excesivo — posible cryptominer: {info['name']} ({cpu:.0f}%)",
                        description=(
                            f"'{info['name']}' (PID {pid}) usa {cpu:.0f}% de CPU. "
                            f"Patrón consistente con cryptomining (XMRig, etc.)."
                        ),
                        details={"pid": pid, "name": info["name"], "cpu": cpu,
                                 "confidence": confidence},
                        confidence=confidence,
                    )

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        self._seen_pids = new_pids
        self._snapshot  = snapshot

    # ------------------------------------------------------------------
    def get_top_processes(self, n: int = 15) -> list[dict]:
        return sorted(self._snapshot, key=lambda x: x["cpu"], reverse=True)[:n]

    # ------------------------------------------------------------------
    def _emit_threat(self, pid: int, severity: int, title: str,
                     description: str, details: dict, confidence: int = 70):
        self._alerted_pids.add(pid)
        threat = {
            "source":      "Procesos",
            "severity":    severity,
            "title":       title,
            "description": description,
            "details":     details,
            "confidence":  confidence,
            "timestamp":   datetime.now().isoformat(),
        }
        logger.warning(f"[AMENAZA {confidence}%] {title}")
        self.threat_callback(threat)



class ProcessMonitor:
    """
    Escanea procesos en ejecución y detecta:
    - Nombres de procesos maliciosos conocidos
    - Procesos con uso de CPU/RAM excesivo
    - Procesos ejecutándose desde ubicaciones sospechosas
    - Inyección de procesos (proceso sin imagen en disco)
    """

    def __init__(self, threat_callback: Callable):
        self.threat_callback = threat_callback
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._seen_pids: set = set()
        self._alerted_pids: set = set()
        self.name = "Procesos"
        self._snapshot: list = []

    # ------------------------------------------------------------------
    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True, name="ProcessMon")
        self._thread.start()
        logger.info("Monitor de procesos iniciado.")

    def stop(self):
        self._stop_event.set()

    # ------------------------------------------------------------------
    def _run(self):
        while not self._stop_event.is_set():
            try:
                self._scan()
            except Exception as e:
                logger.error(f"Error en escaneo de procesos: {e}")
            self._stop_event.wait(timeout=config.PROCESS_SCAN_INTERVAL)

    # ------------------------------------------------------------------
    def _scan(self):
        snapshot = []
        new_pids = set()

        for proc in psutil.process_iter(
            ["pid", "name", "exe", "cmdline", "cpu_percent", "memory_info",
             "username", "ppid", "create_time", "status"]
        ):
            try:
                info = proc.info
                pid  = info["pid"]
                name = (info["name"] or "").lower()
                exe  = info.get("exe") or ""

                new_pids.add(pid)
                is_new = pid not in self._seen_pids

                # Captura para dashboard
                mem_mb = info["memory_info"].rss // (1024 * 1024) if info.get("memory_info") else 0
                snapshot.append({
                    "pid":    pid,
                    "name":   info["name"] or "?",
                    "cpu":    info.get("cpu_percent", 0),
                    "mem_mb": mem_mb,
                    "status": info.get("status", ""),
                    "user":   info.get("username", ""),
                })

                # --- Regla 1: Nombre sospechoso ---
                for bad in config.SUSPICIOUS_PROCESS_NAMES:
                    if bad in name and pid not in self._alerted_pids:
                        self._emit_threat(
                            pid=pid, severity=9,
                            title=f"Proceso malicioso detectado: {info['name']}",
                            description=(
                                f"Se encontró el proceso '{info['name']}' (PID {pid}) asociado "
                                f"a herramientas de hacking/RAT. Ruta: {exe or 'desconocida'}"
                            ),
                            details={"pid": pid, "name": info["name"], "exe": exe},
                        )
                        break

                # --- Regla 2: Proceso sin ruta en disco (hollow process) ---
                if is_new and not exe and name not in ("system", "idle", "registry"):
                    if pid not in self._alerted_pids:
                        self._emit_threat(
                            pid=pid, severity=7,
                            title=f"Proceso fantasma (sin exe): {info['name']}",
                            description=(
                                f"El proceso '{info['name']}' (PID {pid}) no tiene imagen en disco. "
                                f"Puede indicar process hollowing o inyección de código."
                            ),
                            details={"pid": pid, "name": info["name"]},
                        )

                # --- Regla 3: Proceso desde ubicación sospechosa ---
                if exe and is_new:
                    suspicious_dirs = [r"\temp\\", r"\tmp\\", r"\appdata\local\temp\\",
                                       r"\downloads\\", r"\recycle"]
                    exe_lower = exe.lower()
                    for sdir in suspicious_dirs:
                        if sdir in exe_lower and exe_lower.endswith(".exe"):
                            if pid not in self._alerted_pids:
                                self._emit_threat(
                                    pid=pid, severity=7,
                                    title=f"Ejecutable lanzado desde directorio temporal",
                                    description=(
                                        f"Proceso '{info['name']}' (PID {pid}) ejecutándose desde "
                                        f"directorio temporal: {exe}. Técnica común de malware."
                                    ),
                                    details={"pid": pid, "name": info["name"], "exe": exe},
                                )
                            break

                # --- Regla 4: CPU excesivo ---
                cpu = info.get("cpu_percent", 0) or 0
                if cpu > config.CPU_THRESHOLD_PERCENT and pid not in self._alerted_pids:
                    self._emit_threat(
                        pid=pid, severity=5,
                        title=f"Proceso con CPU excesivo: {info['name']} ({cpu:.0f}%)",
                        description=(
                            f"'{info['name']}' (PID {pid}) usa {cpu:.0f}% de CPU. "
                            f"Puede indicar cryptominer o bucle infinito malicioso."
                        ),
                        details={"pid": pid, "name": info["name"], "cpu": cpu},
                    )

                # --- Regla 5: RAM excesiva ---
                if mem_mb > config.HIGH_MEMORY_MB and pid not in self._alerted_pids:
                    self._emit_threat(
                        pid=pid, severity=4,
                        title=f"Proceso con RAM excesiva: {info['name']} ({mem_mb} MB)",
                        description=(
                            f"'{info['name']}' (PID {pid}) usa {mem_mb} MB de RAM. "
                            f"Puede indicar memory scraping o fuga de memoria maliciosa."
                        ),
                        details={"pid": pid, "name": info["name"], "mem_mb": mem_mb},
                    )

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        self._seen_pids = new_pids
        self._snapshot  = snapshot

    # ------------------------------------------------------------------
    def get_top_processes(self, n: int = 15) -> list[dict]:
        """Top procesos por CPU para el dashboard."""
        return sorted(self._snapshot, key=lambda x: x["cpu"], reverse=True)[:n]

    # ------------------------------------------------------------------
    def _emit_threat(self, pid: int, severity: int, title: str,
                     description: str, details: dict):
        self._alerted_pids.add(pid)
        threat = {
            "source":      "Procesos",
            "severity":    severity,
            "title":       title,
            "description": description,
            "details":     details,
            "timestamp":   datetime.now().isoformat(),
        }
        logger.warning(f"[AMENAZA] {title}")
        self.threat_callback(threat)
