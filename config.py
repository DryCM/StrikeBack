# =============================================================================
# StrikeBack - Configuración
# =============================================================================
# Las claves API NO se guardan aquí.
# Se leen (por orden de prioridad):
#   1. Windows Credential Manager  (utils/secrets_manager.py)
#   2. Variables de entorno         STRIKEBACK_AI_API_KEY / STRIKEBACK_VT_API_KEY
#   3. Placeholder vacío            (la función queda desactivada)
#
# Para registrar las claves por primera vez:
#   python -c "from utils.secrets_manager import store_secret; store_secret('AI_API_KEY','TU_KEY'); store_secret('VIRUSTOTAL_API_KEY','TU_KEY')"

import os as _os

# --- API de IA (elige un proveedor) ---
# Groq (gratis, muy rápido): https://console.groq.com
AI_API_KEY  = _os.environ.get("STRIKEBACK_AI_API_KEY", "")
AI_BASE_URL = "https://api.groq.com/openai/v1"   # Groq por defecto
AI_MODEL    = "llama-3.3-70b-versatile"            # Modelo de análisis

# Para OpenAI usa:
# AI_BASE_URL = "https://api.openai.com/v1"
# AI_MODEL    = "gpt-4o-mini"

# --- VirusTotal (opcional, gratis: 4 req/min) ---
# https://www.virustotal.com/gui/my-apikey
VIRUSTOTAL_API_KEY = _os.environ.get("STRIKEBACK_VT_API_KEY", "")  # Deja vacío para desactivar

# --- Monitoreo de Red ---
NETWORK_SCAN_INTERVAL    = 30    # segundos entre escaneos

# Puertos con firma de ataque: puerto -> (severidad, descripción, MITRE)
SUSPICIOUS_PORT_SIGNATURES: dict = {
    # RAT / Backdoor
    4444:  (9,  "Metasploit meterpreter default",         "T1219"),
    4445:  (9,  "Metasploit payload alternativo",         "T1219"),
    1337:  (8,  "Elite/hacker port - RAT común",          "T1219"),
    31337: (9,  "Elite / Back Orifice RAT",                "T1219"),
    5555:  (7,  "Android Debug Bridge / RAT",             "T1219"),
    6666:  (8,  "IRC botnet / RAT",                       "T1219"),
    9999:  (7,  "Puerto RAT genérico",                    "T1219"),
    1234:  (7,  "Puerto RAT genérico",                    "T1219"),
    4321:  (7,  "Puerto RAT genérico",                    "T1219"),
    12345: (8,  "NetBus RAT",                             "T1219"),
    54321: (8,  "Puerto RAT inverso",                     "T1219"),
    666:   (8,  "Backdoor puerto clásico",                "T1219"),
    # C2 Frameworks
    8443:  (7,  "Cobalt Strike HTTPS C2 común",           "T1219"),
    50050: (10, "Cobalt Strike Team Server",              "T1219"),
    2222:  (7,  "Cobalt Strike / backdoor SSH alt",       "T1021"),
    # Tunneling
    4989:  (8,  "Chisel reverse tunnel",                  "T1572"),
    8080:  (5,  "HTTP proxy / tunneling",                 "T1572"),
    # Credential / SMB attack
    445:   (5,  "SMB — objetivo de EternalBlue/WannaCry", "T1021"),
    139:   (5,  "NetBIOS SMB",                            "T1021"),
    # Remote execution
    5985:  (6,  "WinRM HTTP — lateral movement",          "T1021"),
    5986:  (6,  "WinRM HTTPS — lateral movement",         "T1021"),
    # Known malware ports
    6667:  (9,  "IRC botnet C2",                          "T1071"),
    6668:  (9,  "IRC botnet C2",                          "T1071"),
    6669:  (9,  "IRC botnet C2",                          "T1071"),
    65535: (8,  "Puerto máximo — técnica de evasión",     "T1219"),
    # Crypto-miner pools
    3333:  (8,  "Monero mining pool (xmr.pool.minergate)", "T1496"),
    5555:  (8,  "Crypto miner pool alternativo",          "T1496"),
    7777:  (7,  "Crypto miner pool alternativo",          "T1496"),
    14444: (9,  "XMRig miner por defecto",                "T1496"),
    14433: (9,  "XMRig miner SSL",                       "T1496"),
    3032:  (8,  "NiceHash miner",                         "T1496"),
}
# Conjunto simple para lookup rápido
SUSPICIOUS_PORTS = set(SUSPICIOUS_PORT_SIGNATURES.keys())

BLOCKED_COUNTRIES = []   # ['RU', 'CN'] — futuro uso con GeoIP

# Patrones de payload sospechoso en URLs/User-Agents (network level)
ATTACK_PAYLOAD_PATTERNS = [
    # SQL Injection
    r"(?i)(union\s+select|select\s+from|drop\s+table|insert\s+into|exec\s*\(|xp_cmdshell)",
    # XSS
    r"(?i)(<script|javascript:|onerror=|onload=|eval\(|document\.cookie)",
    # Path Traversal
    r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/)",
    # Command Injection
    r"(?i)(;.*?(id|whoami|uname|cat\s+/etc|ls\s+-la)|`[^`]+`|\$\([^)]+\))",
    # SSRF
    r"(?i)(file://|dict://|gopher://|ftp://localhost|http://127\.0\.0\.1|http://169\.254)",
    # Common CVE exploit strings
    r"(?i)(log4j|jndi:|javax\.naming|com\.sun\.jndi)",
    r"(?i)(shellshock|\(\)\s*\{|cgi-bin/.*\?.*=\(\))",
]

# --- Monitoreo de Procesos ---
PROCESS_SCAN_INTERVAL    = 60    # segundos (era 30 — reducido para menos ruido)
CPU_THRESHOLD_PERCENT    = 95    # Alerta si proceso usa >X% CPU  (era 85)
HIGH_MEMORY_MB           = 4000  # Alerta si proceso usa >X MB    (era 2000)

# Firmas de herramientas de ataque con nombre y categoría MITRE ATT&CK
# Formato: "nombre_proceso": (severidad, "TXXXX", "categoría")
ATTACK_TOOL_SIGNATURES: dict = {
    # ── Credential Dumping ────────────────────────────────────────────
    "mimikatz":      (10, "T1003", "Credential Dumping"),
    "wce":           (10, "T1003", "Credential Dumping"),
    "pwdump":        (10, "T1003", "Credential Dumping"),
    "fgdump":        (10, "T1003", "Credential Dumping"),
    "gsecdump":      (10, "T1003", "Credential Dumping"),
    "lazagne":       (10, "T1003", "Credential Dumping"),
    "crackmapexec":  (9,  "T1003", "Credential Dumping"),
    "secretsdump":   (10, "T1003", "Credential Dumping"),
    "lsassy":        (10, "T1003", "Credential Dumping"),
    "pypykatz":      (10, "T1003", "Credential Dumping"),
    "nanodump":      (10, "T1003", "Credential Dumping"),

    # ── RAT / C2 ─────────────────────────────────────────────────────
    "meterpreter":   (10, "T1219", "Remote Access Tool"),
    "remcos":        (10, "T1219", "Remote Access Tool"),
    "njrat":         (10, "T1219", "Remote Access Tool"),
    "darkcomet":     (10, "T1219", "Remote Access Tool"),
    "quasar":        (10, "T1219", "Remote Access Tool"),
    "asyncrat":      (10, "T1219", "Remote Access Tool"),
    "nanocore":      (10, "T1219", "Remote Access Tool"),
    "xworm":         (10, "T1219", "Remote Access Tool"),
    "dcrat":         (10, "T1219", "Remote Access Tool"),
    "venom":         (9,  "T1219", "Remote Access Tool"),
    "cobalt":        (10, "T1219", "C2 Framework"),
    "cobalt strike": (10, "T1219", "C2 Framework"),
    "cobaltstrike":  (10, "T1219", "C2 Framework"),
    "beacon":        (10, "T1219", "C2 Framework"),
    "sliver":        (10, "T1219", "C2 Framework"),
    "havoc":         (10, "T1219", "C2 Framework"),
    "brute ratel":   (10, "T1219", "C2 Framework"),
    "empire":        (10, "T1059", "C2 Framework / PS"),

    # ── Network / Port Scan ──────────────────────────────────────────
    "nmap":          (7,  "T1046", "Network Scanning"),
    "masscan":       (8,  "T1046", "Network Scanning"),
    "zmap":          (8,  "T1046", "Network Scanning"),
    "netdiscover":   (7,  "T1046", "Network Discovery"),
    "arp-scan":      (7,  "T1016", "Network Discovery"),
    "nbtscan":       (6,  "T1135", "Network Share Discovery"),
    "enum4linux":    (8,  "T1087", "Account Enumeration"),
    "responder":     (10, "T1557", "MITM / Credential Capture"),
    "ettercap":      (9,  "T1557", "MITM"),
    "bettercap":     (9,  "T1557", "MITM"),
    "arpspoof":      (8,  "T1557", "ARP Spoofing"),

    # ── Exploitation ─────────────────────────────────────────────────
    "metasploit":    (10, "T1203", "Exploitation Framework"),
    "msfconsole":    (10, "T1203", "Exploitation Framework"),
    "msfvenom":      (10, "T1587", "Payload Generation"),
    "exploitdb":     (8,  "T1203", "Exploitation"),
    "sqlmap":        (9,  "T1190", "SQL Injection"),
    "sqlninja":      (9,  "T1190", "SQL Injection"),
    "havij":         (9,  "T1190", "SQL Injection"),
    "beef":          (9,  "T1189", "XSS / Browser Exploitation"),

    # ── Password Attack ──────────────────────────────────────────────
    "hydra":         (9,  "T1110", "Brute Force"),
    "medusa":        (9,  "T1110", "Brute Force"),
    "thc-hydra":     (9,  "T1110", "Brute Force"),
    "john":          (8,  "T1110", "Password Cracking"),
    "hashcat":       (8,  "T1110", "Password Cracking"),
    "aircrack":      (8,  "T1110", "WiFi Cracking"),
    "wifite":        (8,  "T1110", "WiFi Cracking"),
    "fern":          (8,  "T1110", "WiFi Cracking"),
    "cowpatty":      (8,  "T1110", "WiFi Cracking"),
    "crunch":        (6,  "T1110", "Wordlist Generation"),
    "cewl":          (6,  "T1589", "Wordlist Generation"),

    # ── Privilege Escalation ─────────────────────────────────────────
    "winpeas":       (9,  "T1078", "Privilege Escalation"),
    "linpeas":       (9,  "T1078", "Privilege Escalation"),
    "beroot":        (9,  "T1078", "Privilege Escalation"),
    "wesng":         (8,  "T1068", "Exploit - Local Privilege Escalation"),
    "getsystem":     (10, "T1068", "Privilege Escalation"),

    # ── Lateral Movement ─────────────────────────────────────────────
    "psexec":        (9,  "T1021", "Lateral Movement"),
    "impacket":      (9,  "T1021", "Lateral Movement / Credential Access"),
    "bloodhound":    (9,  "T1069", "AD Enumeration / Privilege Escalation Path"),
    "rubeus":        (10, "T1558", "Kerberos Attacks (AS-REP/TGT/Pass-the-Ticket)"),
    "certify":       (9,  "T1649", "AD CS Certificate Abuse (ESC privesc)"),
    "wmiexec":       (9,  "T1021", "Lateral Movement WMI"),
    "smbexec":       (9,  "T1021", "Lateral Movement SMB"),
    "atexec":        (8,  "T1021", "Lateral Movement"),
    "dcomexec":      (9,  "T1021", "Lateral Movement DCOM"),
    "evil-winrm":    (9,  "T1021", "Lateral Movement WinRM"),

    # ── Persistence ──────────────────────────────────────────────────
    "regshot":       (7,  "T1547", "Registry Persistence"),
    "autoruns":      (5,  "T1547", "Autorun Inspection"),

    # ── Sniffing / Traffic Analysis ──────────────────────────────────
    "wireshark":     (6,  "T1040", "Network Sniffing"),
    "tcpdump":       (6,  "T1040", "Network Sniffing"),
    "tshark":        (6,  "T1040", "Network Sniffing"),
    "dsniff":        (8,  "T1040", "Network Sniffing"),
    "urlsnarf":      (8,  "T1040", "Traffic Analysis"),
    "ssldump":       (7,  "T1040", "SSL Inspection"),

    # ── Tunneling / Exfiltration ─────────────────────────────────────
    "netcat":        (9,  "T1071", "Network Tunneling"),
    "ncat":          (9,  "T1071", "Network Tunneling"),
    "socat":         (8,  "T1071", "Network Tunneling"),
    "chisel":        (9,  "T1572", "Protocol Tunneling"),
    "frpc":          (8,  "T1572", "Protocol Tunneling"),
    "ngrok":         (7,  "T1572", "Reverse Tunnel"),
    "cloudflared":   (7,  "T1572", "Reverse Tunnel"),
    "ligolo":        (9,  "T1572", "Protocol Tunneling"),

    # ── Keylogger / Spyware ──────────────────────────────────────────
    "keylogger":     (10, "T1056", "Keylogging"),
    "revealer":      (9,  "T1056", "Keylogging"),
    "spyrix":        (9,  "T1056", "Spyware"),

    # ── Recon ────────────────────────────────────────────────────────
    "maltego":       (7,  "T1596", "OSINT Recon"),
    "recon-ng":      (7,  "T1596", "OSINT Recon"),
    "theharvester":  (7,  "T1589", "Email/DNS Recon"),
    "dnsenum":       (7,  "T1018", "DNS Recon"),
    "dnsrecon":      (7,  "T1018", "DNS Recon"),
    "sublist3r":     (7,  "T1018", "Subdomain Recon"),
    "amass":         (7,  "T1018", "Subdomain Recon"),
    "shodan":        (8,  "T1596", "Internet Scanning"),
    "censys":        (7,  "T1596", "Internet Scanning"),

    # ── Web Attack ───────────────────────────────────────────────────
    "nikto":         (8,  "T1190", "Web Vulnerability Scan"),
    "wpscan":        (8,  "T1190", "WordPress Scan"),
    "gobuster":      (7,  "T1083", "Directory Brute Force"),
    "dirbuster":     (7,  "T1083", "Directory Brute Force"),
    "feroxbuster":   (7,  "T1083", "Directory Brute Force"),
    "burpsuite":     (7,  "T1190", "Web Proxy/Fuzzing"),
    "zaproxy":       (7,  "T1190", "Web Vulnerability Scan"),
    "wfuzz":         (8,  "T1110", "Web Fuzzing"),
    "ffuf":          (7,  "T1083", "Web Fuzzing"),

    # ── Steganography / Obfuscation ───────────────────────────────────
    "steghide":      (6,  "T1027", "Steganography"),
    "openstego":     (6,  "T1027", "Steganography"),

    # ── Process Injection ────────────────────────────────────────────
    "procdump":      (8,  "T1055", "Process Dump/Injection"),
    "processhacker": (7,  "T1055", "Process Inspection"),
    "pe-sieve":      (7,  "T1055", "Process Hollowing Detection"),
}

# Para búsqueda rápida por nombre de proceso (se genera al importar)
SUSPICIOUS_PROCESS_NAMES = set(ATTACK_TOOL_SIGNATURES.keys())

# --- Monitoreo de Sistema de Archivos ---
WATCH_PATHS = [
    r"C:\Users\Jaime\Desktop",
    r"C:\Users\Jaime\Documents",
    r"C:\Users\Jaime\Downloads",
]

# Extensiones de archivos de desarrollo/código fuente:
# NO se cuentan para el detector de ráfaga ransomware (evita falsos positivos al editar código).
# El ransomware actúa sobre documentos/fotos/datos, no sobre fuentes .py/.js/.etc
BURST_IGNORE_EXTENSIONS: set = {
    ".py", ".pyw", ".pyc", ".pyo",   # Python
    ".js", ".ts", ".jsx", ".tsx",    # JavaScript/TypeScript
    ".java", ".kt", ".scala",         # JVM
    ".cs", ".vb",                      # .NET
    ".c", ".cpp", ".h", ".hpp",       # C/C++
    ".rs", ".go", ".rb", ".php",      # Otros lenguajes
    ".html", ".htm", ".css", ".scss", # Web
    ".json", ".yaml", ".yml",          # Config
    ".xml", ".toml", ".ini", ".cfg",  # Config 2
    ".md", ".rst", ".txt",             # Texto/docs
    ".sh", ".bash",                    # Scripts
    ".sql",                            # Bases de datos
    ".ipynb",                          # Jupyter
    ".r", ".m", ".mat",               # R/MATLAB
}
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".wsf", ".hta", ".scr", ".pif", ".com", ".cpl", ".msi",
    ".reg", ".lnk"
}
RANSOMWARE_EXTENSIONS = {
    ".locked", ".encrypted", ".crypto", ".crypt", ".cryp1",
    ".zepto", ".zcrypt", ".cerber", ".locky", ".aaa", ".abc",
    ".zzz", ".xyz", ".micro", ".vvv", ".ccc", ".xxx",
    ".ttt", ".mp3", ".torrentlocker", ".wallet",
    ".wcry", ".wncry", ".wnry",   # WannaCry
    ".ryuk",                        # Ryuk
    ".revil", ".sodinokibi",        # REvil
    ".maze", ".conti",              # Maze/Conti
    ".blackmatter", ".darkside",    # DarkSide
    ".lockbit",                     # LockBit
    ".hive",                        # Hive
    ".alphv", ".blackcat",          # BlackCat/ALPHV
    ".cuba",                        # Cuba Ransomware
    ".clop", ".cl0p",               # Clop
}

# --- MITRE ATT&CK Coverage Map ---
# Define las categorías que StrikeBack monitorea y qué % de técnicas cubre
ATTACK_COVERAGE: dict = {
    "Reconocimiento (TA0043)":          {"monitored": True,  "techniques": 7,  "covered": 6},
    "Desarrollo de recursos (TA0042)":  {"monitored": True,  "techniques": 5,  "covered": 3},
    "Acceso inicial (TA0001)":          {"monitored": True,  "techniques": 9,  "covered": 7},
    "Ejecución (TA0002)":               {"monitored": True,  "techniques": 12, "covered": 9},
    "Persistencia (TA0003)":            {"monitored": True,  "techniques": 19, "covered": 11},
    "Escalada de privilegios (TA0004)": {"monitored": True,  "techniques": 13, "covered": 10},
    "Evasión de defensas (TA0005)":     {"monitored": True,  "techniques": 42, "covered": 18},
    "Acceso a credenciales (TA0006)":   {"monitored": True,  "techniques": 16, "covered": 14},
    "Descubrimiento (TA0007)":          {"monitored": True,  "techniques": 29, "covered": 20},
    "Movimiento lateral (TA0008)":      {"monitored": True,  "techniques": 9,  "covered": 8},
    "Recolección (TA0009)":             {"monitored": True,  "techniques": 17, "covered": 8},
    "Comando y control (TA0011)":       {"monitored": True,  "techniques": 16, "covered": 13},
    "Exfiltración (TA0010)":            {"monitored": True,  "techniques": 9,  "covered": 5},
    "Impacto (TA0040)":                 {"monitored": True,  "techniques": 13, "covered": 11},
}

# --- Monitoreo de Event Log (Windows) ---
EVENTLOG_SCAN_INTERVAL   = 60    # segundos
MAX_FAILED_LOGINS        = 5     # Alertar tras X intentos fallidos en 5 min

# --- IA y Análisis ---
AI_MAX_CALLS_PER_MINUTE  = 10    # Rate limit para no quemar créditos
AI_THREAT_QUEUE_SIZE     = 50    # Cola máxima de amenazas pendientes
AI_SEVERITY_THRESHOLD    = 8     # (1-10) Umbral para notificación inmediata (era 6)
AI_WORKER_THREADS        = 2     # Workers paralelos del analizador IA
AI_MODEL_FALLBACK        = "llama-3.1-8b-instant"   # Modelo de respaldo si falla el principal
AI_DEDUP_WINDOW_SECONDS  = 90    # Ventana de deduplicación (no re-analizar misma clase)

# Fiabilidad mínima para mostrar una amenaza en el dashboard.
# Alertas con confidence < este valor se descartan silenciosamente.
MIN_CONFIDENCE_TO_ALERT  = 80    # %  (0 = mostrar todo)

# --- Base de Datos ---
DB_PATH = r"data\strikeback.db"

# --- Logging ---
LOG_PATH  = r"data\strikeback.log"
LOG_LEVEL = "INFO"   # DEBUG | INFO | WARNING | ERROR

# --- Auto-Respuesta Activa ---
# ADVERTENCIA: activa acciones defensivas automáticas (matar procesos, bloquear IPs)
# Si no tienes admin, algunas acciones fallarán silenciosamente
AUTO_RESPONSE_ENABLED          = True   # Activar respuesta automática
AUTO_KILL_THRESHOLD_SEVERITY   = 9      # Matar proceso si severidad >= este valor
AUTO_KILL_THRESHOLD_CONFIDENCE = 90     # Y confianza >= este valor
AUTO_BLOCK_C2_IPS              = True   # Bloquear IPs C2 en Windows Firewall
AUTO_QUARANTINE_RANSOMWARE     = True   # Mover archivos ransomware a cuarentena
AUTO_VSS_SNAPSHOT_ON_START     = True   # Crear VSS snapshot al arrancar (requiere admin)
QUARANTINE_DIR                 = r"data\quarantine"  # Carpeta de cuarentena

# Procesos del sistema que NUNCA se deben matar (whitelist)
AUTO_RESPONSE_PROCESS_WHITELIST = {
    "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "svchost.exe", "explorer.exe",
    "taskmgr.exe", "python.exe", "python3.14.exe", "strikeback.exe",
}

# --- Notificaciones Windows ---
SHOW_TRAY_ICON           = True
TOAST_NOTIFICATIONS      = True
TOAST_DURATION           = 10   # segundos

# --- IPs conocidas maliciosas (lista base, se amplía con VirusTotal) ---
# No incluir 0.0.0.0 ni IPs reservadas: generan falsos positivos con psutil.
KNOWN_MALICIOUS_IPS: set = set()  # se llena en runtime desde threat feeds

# --- Directorios del sistema a ignorar en filesystem monitor ---
IGNORE_PATHS = {
    r"C:\Windows\Temp",
    r"C:\Windows\SoftwareDistribution",
    r"C:\Users\Jaime\AppData\Local\Temp",
    r"C:\Users\Jaime\Desktop\StrikeBack",   # auto-exclusión: no monitorearse a sí mismo
    r"C:\Users\Jaime\AppData\Local\Programs\Microsoft VS Code",
    r"C:\Users\Jaime\AppData\Roaming\Code",  # VS Code workspace/cache
    r".venv",                                 # entornos virtuales Python
    r"__pycache__",                           # bytecode Python
    r"\.git",                                 # repositorios git
}
