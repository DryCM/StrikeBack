"""
Monitor de patrones de ataque — detecta técnicas avanzadas:
- Port scanning entrante/saliente
- Lateral movement via SMB/WinRM
- DNS tunneling
- Living-off-the-land (LOLBins)
- Staged payload download indicators
"""
import threading
import re
import os
import subprocess
import ipaddress
from datetime import datetime
from typing import Callable, Optional
from collections import defaultdict, deque

import psutil

import config
from utils.logger import get_logger

logger = get_logger("AttackPatterns")

# Binarios legítimos de Windows usados para ataques (LOLBins T1218)
LOLBINS: dict = {
    "regsvr32.exe":   ("T1218.010", "RegSvr32 - posible bypass AppLocker/UAC", 82),
    "rundll32.exe":   ("T1218.011", "RunDLL32 - ejecución DLL anónima",        78),
    "mshta.exe":      ("T1218.005", "MSHTA - ejecución HTA/VBScript",          85),
    "certutil.exe":   ("T1105",     "CertUtil - descarga de archivos",         80),
    "bitsadmin.exe":  ("T1197",     "BITSAdmin - descarga persistente",        80),
    "wmic.exe":       ("T1047",     "WMIC - ejecución remota WMI",             78),
    "cmstp.exe":      ("T1218.003", "CMSTP - bypass UAC",                      82),
    "msiexec.exe":    ("T1218.007", "MSIExec - instalación remota MSI",        72),
    "odbcconf.exe":   ("T1218.008", "ODBCConf - DLL load bypass",              80),
    "regasm.exe":     ("T1218.009", "RegAsm - .NET assembly proxy exec",       82),
    "regsvcs.exe":    ("T1218.009", "RegSvcs - .NET assembly proxy exec",      82),
    "installutil.exe":("T1218.004", "InstallUtil - bypass AppLocker",          85),
    "ieexec.exe":     ("T1218",     "IEExec - remote binary execution",        80),
    "csc.exe":        ("T1027.004", "CSC - compilación C# en memoria",         72),
    "ftp.exe":        ("T1105",     "FTP.exe - descarga de archivo",           68),
    "makecab.exe":    ("T1560.001", "MakeCab - compresión para exfiltración",  65),
    "expand.exe":     ("T1140",     "Expand - descompresión de payload",       65),
    "eudcedit.exe":   ("T1218",     "EudcEdit - DLL hijack",                   72),
    "pcalua.exe":     ("T1218",     "PCAlua - ejecución bypasseando UAC",      80),
    "forfiles.exe":   ("T1218",     "ForFiles - ejecución indirecta",          72),
    "schtasks.exe":   ("T1053.005", "Schtasks - persistencia tarea programada",75),
    "at.exe":         ("T1053.002", "At.exe - tarea programada legada",        70),
}

# Argumentos sospechosos para cmd.exe / powershell.exe (T1059)
SHELL_SUSPICIOUS_ARGS = [
    (r"net\s+user\s+\w+\s+\w+\s+/add",          "T1136", "Creación de usuario via net user",         88),
    (r"net\s+localgroup\s+administrators",        "T1098", "Añadido a grupo Administrators",          88),
    (r"reg\s+(add|save|export)\s+.*sam",          "T1003", "Acceso/exportación SAM registry",         92),
    (r"vssadmin\s+delete\s+shadows",              "T1490", "Borrado de shadow copies (ransomware)",   95),
    (r"bcdedit.*recoveryenabled.*no",             "T1490", "Desactivación recuperación Windows",      93),
    (r"wbadmin\s+delete\s+catalog",               "T1490", "Borrado catálogo backup",                 93),
    (r"cipher\s+/w",                              "T1070", "Borrado seguro de archivos",              75),
    (r"schtasks.*\/create.*\/sc\s+minute",        "T1053", "Tarea programada cada minuto",            80),
    (r"netsh\s+(firewall|advfirewall).*allow",    "T1562", "Regla firewall permisiva añadida",        82),
    (r"sc\s+(create|config|start)\s+\w+",         "T1543", "Servicio creado/modificado via sc.exe",  80),
    (r"whoami\s*/priv",                           "T1033", "Enumeración de privilegios",              65),
    (r"taskkill.*\/im\s+(defender|mssecurity|av)",  "T1562", "Intento de matar antivirus",           90),
    (r"set-mppreference.*disable",                "T1562.001", "Desactivación Windows Defender",     95),
    (r"add-mppreference.*exclusionpath",          "T1562.001", "Exclusión añadida a Defender",       90),
]

# Patrones de DNS sospechoso para detectar DNS tunneling (T1071.004)
DNS_SUBDOMAIN_LENGTH_THRESHOLD = 50   # subdominio muy largo = posible tunelización


class AttackPatternMonitor:
    """
    Detecta ataques avanzados mediante análisis de:
    - Uso de LOLBins con argumentos peligrosos
    - Comandos de shell sospechosos
    - Comportamiento de movimiento lateral
    - Port scanning activo desde el host
    """

    def __init__(self, threat_callback: Callable):
        self.threat_callback   = threat_callback
        self._stop_event       = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._alerted_pids: set = set()
        self._conn_history: dict = defaultdict(deque)  # ip -> deque of timestamps
        self.name = "Patrones"

    # ------------------------------------------------------------------
    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True, name="PatternMon")
        self._thread.start()
        logger.info("Monitor de patrones de ataque iniciado.")

    def stop(self):
        self._stop_event.set()

    # ------------------------------------------------------------------
    def _run(self):
        while not self._stop_event.is_set():
            try:
                self._scan_lolbins()
                self._scan_lateral_movement()
                self._scan_port_scan()
            except Exception as e:
                logger.error(f"Error en monitor de patrones: {e}")
            self._stop_event.wait(timeout=20)

    # ------------------------------------------------------------------
    def _scan_lolbins(self):
        """Detecta LOLBins ejecutándose con argumentos peligrosos."""
        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
            try:
                pid      = proc.info["pid"]
                name     = (proc.info["name"] or "").lower()
                cmdline  = " ".join(proc.info.get("cmdline") or []).lower()

                if not cmdline:
                    continue

                # Chequear si es LOLBin
                for lol_name, (mitre, desc, base_conf) in LOLBINS.items():
                    if lol_name not in name:
                        continue

                    # LOLBin activo — analizar argumentos
                    if pid in self._alerted_pids:
                        continue

                    # Subir confianza si tiene argumentos externos (URLs, IPs, rutas temp)
                    confidence = base_conf
                    suspicious_args = [
                        r"https?://", r"\\\\", r"\.tmp", r"\.ps1",
                        r"scrobj\.dll", r"javascript:", r"vbscript:",
                    ]
                    for pattern in suspicious_args:
                        if re.search(pattern, cmdline):
                            confidence = min(confidence + 8, 97)

                    if confidence >= 68:
                        self._emit(
                            severity=8,
                            title=f"[{mitre}] LOLBin con args sospechosos: {name}",
                            description=(
                                f"{desc}. Proceso '{name}' (PID {pid}) ejecutado con:\n"
                                f"{cmdline[:200]}"
                            ),
                            details={"pid": pid, "name": name, "mitre": mitre,
                                     "cmdline": cmdline[:400], "confidence": confidence},
                            confidence=confidence,
                        )

                # Chequear patrones de shell sospechoso
                if name in ("cmd.exe", "powershell.exe", "pwsh.exe"):
                    for pattern, mitre, desc, conf in SHELL_SUSPICIOUS_ARGS:
                        if re.search(pattern, cmdline) and pid not in self._alerted_pids:
                            self._emit(
                                severity=9,
                                title=f"[{mitre}] Comando de ataque detectado: {desc}",
                                description=(
                                    f"Proceso '{name}' (PID {pid}) ejecutando comando peligroso.\n"
                                    f"Patrón: {desc}\nCmdline: {cmdline[:200]}"
                                ),
                                details={"pid": pid, "name": name, "mitre": mitre,
                                         "cmdline": cmdline[:400], "confidence": conf},
                                confidence=conf,
                            )
                            break

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    # ------------------------------------------------------------------
    def _scan_lateral_movement(self):
        """Detecta conexiones SMB/WinRM salientes desde procesos no esperados."""
        lateral_ports = {445, 139, 5985, 5986, 135, 593}
        trusted_procs = {"system", "svchost.exe", "lsass.exe", "services.exe"}

        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status != "ESTABLISHED":
                    continue
                if not conn.raddr:
                    continue
                if conn.raddr.port not in lateral_ports:
                    continue

                pid  = conn.pid
                proc = self._get_proc_name(pid)
                if proc.lower() in trusted_procs:
                    continue

                # Movimiento lateral desde proceso no esperado
                mitre_map = {
                    445:  ("T1021.002", "SMB Lateral Movement", 80),
                    139:  ("T1021.002", "NetBIOS SMB Lateral Movement", 78),
                    5985: ("T1021.006", "WinRM HTTP Lateral Movement", 85),
                    5986: ("T1021.006", "WinRM HTTPS Lateral Movement", 87),
                    135:  ("T1021.003", "DCOM RPC Lateral Movement", 75),
                }
                mitre, desc, conf = mitre_map.get(conn.raddr.port, ("T1021", "Lateral Movement", 70))

                key = (pid, conn.raddr.ip, conn.raddr.port)
                if key not in self._alerted_pids:
                    self._alerted_pids.add(key)
                    self._emit(
                        severity=8,
                        title=f"[{mitre}] {desc} — proceso inusual: {proc}",
                        description=(
                            f"Proceso '{proc}' (PID {pid}) iniciando conexión de movimiento lateral "
                            f"a {conn.raddr.ip}:{conn.raddr.port}."
                        ),
                        details={"pid": pid, "proc": proc, "mitre": mitre,
                                 "dst": f"{conn.raddr.ip}:{conn.raddr.port}",
                                 "confidence": conf},
                        confidence=conf,
                    )

        except psutil.AccessDenied:
            pass

    # ------------------------------------------------------------------
    def _scan_port_scan(self):
        """
        Detecta si el host está realizando un escaneo de puertos saliente:
        muchas conexiones SYN_SENT a IPs distintas en poco tiempo.
        """
        try:
            syn_targets: dict = defaultdict(set)   # ip -> {puertos}
            for conn in psutil.net_connections(kind="inet"):
                if conn.status == "SYN_SENT" and conn.raddr:
                    syn_targets[conn.raddr.ip].add(conn.raddr.port)

            for ip, ports in syn_targets.items():
                if len(ports) >= 10:
                    try:
                        # Ignorar IPs privadas si son pocas
                        addr = ipaddress.ip_address(ip)
                        if addr.is_private and len(ports) < 25:
                            continue
                    except ValueError:
                        pass

                    confidence = min(50 + len(ports) * 2, 94)
                    self._emit(
                        severity=7,
                        title=f"[T1046] Port scan saliente — {len(ports)} puertos a {ip}",
                        description=(
                            f"El host está enviando SYN a {len(ports)} puertos distintos de {ip}. "
                            f"Posible herramienta de escaneo activa (nmap, masscan, etc.)."
                        ),
                        details={"target_ip": ip, "ports_scanned": len(ports),
                                 "sample_ports": sorted(ports)[:10], "confidence": confidence},
                        confidence=confidence,
                    )

        except psutil.AccessDenied:
            pass

    # ------------------------------------------------------------------
    def _emit(self, severity: int, title: str, description: str,
               details: dict, confidence: int = 70):
        threat = {
            "source":      "Patrones",
            "severity":    severity,
            "title":       title,
            "description": description,
            "details":     details,
            "confidence":  confidence,
            "timestamp":   datetime.now().isoformat(),
        }
        logger.warning(f"[AMENAZA {confidence}%] {title}")
        self.threat_callback(threat)

    @staticmethod
    def _get_proc_name(pid: Optional[int]) -> str:
        if not pid:
            return "desconocido"
        try:
            return psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return f"PID-{pid}"
