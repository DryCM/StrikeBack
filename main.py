"""
StrikeBack — Agente IA de Ciberseguridad para Windows
=====================================================
Punto de entrada principal. Orquesta todos los monitores,
el analizador IA, la base de datos, el tray icon y el dashboard.

Uso:
    python main.py
"""
import sys
import os
import threading
import signal
import ctypes
from datetime import datetime

# ─── Fijar encoding UTF-8 en consola Windows ────────────────────────────────
try:
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    if hasattr(sys.stderr, 'reconfigure'):
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

# Verificar Python 3.10+
if sys.version_info < (3, 10):
    print("ERROR: Se requiere Python 3.10 o superior.")
    sys.exit(1)

# ─── Setup de paths ───────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ─── Comprobación de entorno ──────────────────────────────────────────────────
def _check_environment():
    """Verifica que el setup se ejecutó y todas las dependencias están disponibles."""
    missing = []
    required = ["rich", "psutil", "watchdog", "openai", "pystray", "PIL", "win32evtlog"]
    for mod in required:
        try:
            __import__(mod)
        except ImportError:
            missing.append(mod)

    if missing:
        print("=" * 60)
        print("  ERROR: Entorno no configurado correctamente.")
        print("=" * 60)
        print(f"\nMódulos faltantes: {', '.join(missing)}")
        print("\nEjecuta primero: Setup_StrikeBack.exe")
        print("(se encuentra en la carpeta dist\\ o en el directorio raíz)")
        print("=" * 60)
        input("\nPresiona ENTER para salir...")
        sys.exit(1)

_check_environment()
os.chdir(BASE_DIR)
os.makedirs("data", exist_ok=True)

# ─── Imports internos ─────────────────────────────────────────────────────────
import config
from monitors import NetworkMonitor, ProcessMonitor, FileSystemMonitor, EventLogMonitor
from monitors.attack_patterns import AttackPatternMonitor
from monitors.ai_attack_monitor import AIAttackMonitor
from monitors.honeypot import HoneypotMonitor
from monitors.credential_guard import CredentialGuard
from monitors.registry_monitor import RegistryMonitor
from monitors.injection_detector import InjectionDetector
from monitors.yara_scanner import YaraScanner
from monitors.auto_response import AutoResponse
from ai.threat_analyzer import ThreatAnalyzer
from utils.database import Database
from utils.alerts import Alerts
from utils.tray import TrayApp
from utils.threat_intel import ThreatIntel
from utils.report_generator import generate_report
from utils.secrets_manager import migrate_from_config, load_secrets_into_config
from utils.logger import get_logger
from web.dashboard import WebDashboard
from cli.dashboard import Dashboard

# GUI nativa (PyQt6) — import opcional para no romper entornos headless
try:
    from PyQt6.QtWidgets import QApplication
    from PyQt6.QtCore import Qt
    from ui.main_window import MainWindow
    _QT_AVAILABLE = True
except ImportError:
    _QT_AVAILABLE = False

logger = get_logger("Main")

# ── Cargar claves desde Windows Credential Manager (antes de cualquier módulo) ─
try:
    migrated = migrate_from_config()
    if migrated:
        logger.info(f"[SecretsManager] {migrated} key(s) migrada(s) al Credential Manager.")
    load_secrets_into_config()
except Exception as _sm_exc:
    logger.warning(f"[SecretsManager] No disponible, usando config.py: {_sm_exc}")


# ─── Verificar privilegios de administrador ────────────────────────────────
def _check_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


# ─── StrikeBack Core ──────────────────────────────────────────────────────────
class StrikeBack:
    def __init__(self, qt_app: "QApplication | None" = None):
        self.db           = Database()
        self.alerts       = Alerts()
        self.dashboard    = Dashboard()
        self._stop_event  = threading.Event()
        self._qt_app      = qt_app
        self._main_window: "MainWindow | None" = None

        # Mapa threat_id -> amenaza sin analizar (para actualizar con análisis IA)
        self._pending_ids: dict = {}
        self._pending_lock = threading.Lock()

        # Inicializar monitores
        self.net_monitor      = NetworkMonitor(self._on_raw_threat)
        self.proc_monitor     = ProcessMonitor(self._on_raw_threat)
        self.fs_monitor       = FileSystemMonitor(self._on_raw_threat)
        self.evlog_monitor    = EventLogMonitor(self._on_raw_threat)
        self.pattern_monitor  = AttackPatternMonitor(self._on_raw_threat)
        self.ai_attack_monitor = AIAttackMonitor(self._on_raw_threat)
        self.honeypot_monitor   = HoneypotMonitor(self._on_raw_threat)
        self.credential_guard   = CredentialGuard(self._on_raw_threat)
        self.registry_monitor   = RegistryMonitor(self._on_raw_threat)
        self.injection_detector = InjectionDetector(self._on_raw_threat)
        self.yara_scanner       = YaraScanner(self._on_raw_threat)
        self.auto_response      = AutoResponse(notify_callback=self._on_raw_threat)
        self.threat_intel     = ThreatIntel()
        self.web_dashboard    = WebDashboard(db_path=config.DB_PATH)

        # Analizador IA (resultado enriquecido llega a _on_ai_result)
        self.ai_analyzer  = ThreatAnalyzer(self._on_ai_result)

        # Tray icon
        self.tray = TrayApp(
            on_exit = self.shutdown,
            on_scan = self._force_scan,
        )

        # Pasar referencias al dashboard
        self.dashboard.network_monitor = self.net_monitor
        self.dashboard.process_monitor = self.proc_monitor
        self.dashboard.db              = self.db

    # ──────────────────────────────────────────────────────────────────────────
    def start(self):
        """Inicia todos los componentes y el dashboard."""
        self._print_banner()

        # Iniciar componentes en orden
        self.ai_analyzer.start()
        self.threat_intel.start()
        self.net_monitor.start()
        self.proc_monitor.start()
        self.fs_monitor.start()
        self.evlog_monitor.start()
        self.pattern_monitor.start()
        self.ai_attack_monitor.start()
        self.honeypot_monitor.start()
        self.credential_guard.start()
        self.registry_monitor.start()
        self.injection_detector.start()
        self.yara_scanner.start()
        self.auto_response.start()
        self.web_dashboard.start(open_browser=False)
        self.tray.start()

        logger.info("StrikeBack iniciado. Todos los monitores activos.")

        if self._qt_app is not None and _QT_AVAILABLE:
            # Crear y mostrar la ventana nativa
            def _open_web():
                import webbrowser
                webbrowser.open("https://127.0.0.1:8443")

            self._main_window = MainWindow(
                on_scan      = self._force_scan,
                on_report    = lambda: generate_report(),
                on_open_web  = _open_web,
                db_path      = config.DB_PATH,
            )
            self._main_window.set_monitors_status(12, 12)
            self._main_window.show()

            # Qt loop bloquea hasta cerrar la ventana
            ret = self._qt_app.exec()
            self.shutdown()
            sys.exit(ret)
        else:
            # Fallback: dashboard terminal
            try:
                self.dashboard.run()
            except KeyboardInterrupt:
                pass
            finally:
                self.shutdown()

    # ──────────────────────────────────────────────────────────────────────────
    def shutdown(self):
        """Para todos los componentes limpiamente."""
        if self._stop_event.is_set():
            return
        self._stop_event.set()

        self.dashboard.stop()
        self.net_monitor.stop()
        self.proc_monitor.stop()
        self.fs_monitor.stop()
        self.evlog_monitor.stop()
        self.pattern_monitor.stop()
        self.registry_monitor.stop()
        self.injection_detector.stop()
        self.yara_scanner.stop()
        self.credential_guard.stop()
        self.honeypot_monitor.stop()
        self.ai_analyzer.stop()
        self.web_dashboard.stop()
        self.tray.stop()

        # Generar informe HTML final al cerrar
        try:
            report_path = generate_report()
            if report_path:
                logger.info("Informe de sesión generado: %s", report_path)
                print(f"\n  Informe exportado → {report_path}")
        except Exception as exc:
            logger.warning("No se pudo generar el informe: %s", exc)

        self.db.close()

        logger.info("StrikeBack detenido.")
        sys.exit(0)

    # ──────────────────────────────────────────────────────────────────────────
    def _on_raw_threat(self, threat: dict):
        """Callback invocado por los monitores cuando detectan algo sospechoso."""
        # 0. Filtro de fiabilidad mínima — descartar alertas de baja confianza
        conf = threat.get("confidence", 100)
        if conf < config.MIN_CONFIDENCE_TO_ALERT:
            return

        # 1. Guardar en DB inmediatamente
        threat_id = self.db.save_threat(threat)
        threat["_db_id"] = threat_id

        # 2. Actualizar dashboard terminal (solo si Qt no está activo)
        if not _QT_AVAILABLE:
            self.dashboard.add_threat(threat)

        # 2b. Actualizar ventana nativa Qt
        if self._main_window is not None:
            self._main_window.push_threat(threat)

        # 3. Enviar al Web Dashboard en tiempo real
        self.web_dashboard.push_threat(threat)

        # 3. Auto-respuesta activa (matar proceso, bloquear IP, cuarentena)
        self.auto_response.handle(threat)

        # 4. Notificación Windows si es suficientemente grave
        self.alerts.notify(
            title    = threat.get("title", "Amenaza detectada"),
            message  = threat.get("description", ""),
            severity = threat.get("severity", 5),
        )

        # 4. Actualizar contador del tray icon
        stats = self.db.get_stats()
        self.tray.update_threat_count(stats["total"])

        # 5. Enriquecer con VirusTotal en background (no bloquea el pipeline)
        if config.VIRUSTOTAL_API_KEY:
            self._enrich_vt_async(threat, threat_id)

        # 6. Encolar para análisis IA (solo si severidad mínima > 3)
        if threat.get("severity", 0) >= 4:
            with self._pending_lock:
                self._pending_ids[threat_id] = threat
            self.ai_analyzer.submit(threat)

        logger.info(
            f"[{threat.get('source','?')}] Sev={threat.get('severity','?')} — {threat.get('title','?')}"
        )

    # ──────────────────────────────────────────────────────────────────────────
    def _enrich_vt_async(self, threat: dict, threat_id: int):
        """Consulta VirusTotal en un hilo daemon para no bloquear el pipeline."""
        def _run():
            try:
                vt_result = None
                source = threat.get("source", "")

                # Enriquecer IPs (NetworkMonitor genera amenazas con "ip")
                ip = threat.get("ip") or threat.get("details", {}).get("ip") if isinstance(threat.get("details"), dict) else None
                if ip and source in ("NetworkMonitor", "AttackPatterns"):
                    vt_result = self.threat_intel.check_ip_vt(ip)
                    if vt_result and vt_result.get("malicious"):
                        # Subir severidad si VT confirma la IP como maliciosa
                        new_sev = min(10, threat.get("severity", 5) + 2)
                        self.db.update_field(threat_id, "severity", new_sev)
                        self.db.update_field(threat_id, "vt_result", str(vt_result))
                        logger.warning(
                            f"[VT] IP {ip} maliciosa ({vt_result['engines']}/{vt_result['total']} engines). "
                            f"Sev elevada a {new_sev}."
                        )

                # Enriquecer hashes de archivos (YaraScanner / FileSystemMonitor)
                file_path = threat.get("file_path") or (threat.get("details", {}).get("path") if isinstance(threat.get("details"), dict) else None)
                if file_path and source in ("YaraScanner", "FileSystemMonitor"):
                    vt_result = self.threat_intel.check_hash_vt(file_path)
                    if vt_result and vt_result.get("malicious"):
                        new_sev = min(10, threat.get("severity", 5) + 3)
                        self.db.update_field(threat_id, "severity", new_sev)
                        self.db.update_field(threat_id, "vt_result", str(vt_result))
                        logger.warning(
                            f"[VT] Archivo malicioso: {file_path} "
                            f"({vt_result['engines']}/{vt_result['total']} engines). "
                            f"Sev elevada a {new_sev}."
                        )
            except Exception as exc:
                logger.debug(f"[VT] Error en enriquecimiento async: {exc}")

        t = threading.Thread(target=_run, daemon=True, name="VT-Enrich")
        t.start()

    # ──────────────────────────────────────────────────────────────────────────
    def _on_ai_result(self, threat: dict):
        """Callback cuando el analizador IA termina con una amenaza."""
        threat_id = threat.get("_db_id")

        if threat_id:
            # Actualizar en DB con el análisis IA
            self.db.update_ai_analysis(threat_id, threat)

            # Actualizar la fila en la ventana nativa Qt (⏳ → ✓ IA / ✗ F.P.)
            if self._main_window is not None:
                self._main_window.update_threat_ai(threat)

            # Actualizar en el dashboard terminal (solo si Qt no está activo)
            if not _QT_AVAILABLE:
                with self.dashboard._lock:
                    for i, t in enumerate(self.dashboard._recent_threats):
                        if t.get("_db_id") == threat_id:
                            self.dashboard._recent_threats[i] = threat
                            break

            # Si la IA confirma amenaza grave, notificar de nuevo con contexto
            ai      = threat.get("ai_analysis") or {}
            urgency = ai.get("urgency", "low")
            sev_ia  = ai.get("confirmed_severity", 0)
            # Notificar si la urgencia es inmediata, o alta con sev >= 8
            should_notify = (
                ai.get("is_threat") and (
                    urgency == "immediate" or
                    (urgency == "high" and sev_ia >= 8)
                )
            )
            if should_notify:
                summary    = ai.get("summary", "")
                mitre      = ai.get("mitre_technique", "")
                kcs        = ai.get("kill_chain_stage", "")
                camp_flag  = " 🚨 CAMPAÑA" if ai.get("campaign_indicator") else ""
                actions    = ai.get("actions", [])
                action_str = " | ".join(actions[:2]) if actions else ""
                urgency_label = {"immediate": "⚠ INMEDIATA", "high": "ALTA"}.get(urgency, "")

                self.alerts.notify(
                    title    = f"[{urgency_label}] IA: {threat.get('title', '')}{camp_flag}",
                    message  = f"{summary}\n{mitre} {kcs}\nAcción: {action_str}",
                    severity = sev_ia,
                )

        with self._pending_lock:
            self._pending_ids.pop(threat_id, None)

    # ──────────────────────────────────────────────────────────────────────────
    def _force_scan(self):
        """Fuerza un escaneo inmediato desde el tray icon."""
        logger.info("Escaneo manual iniciado desde tray icon.")
        try:
            self.net_monitor._scan()
            self.proc_monitor._scan()
        except Exception as e:
            logger.error(f"Error en escaneo manual: {e}")

    # ──────────────────────────────────────────────────────────────────────────
    @staticmethod
    def _print_banner():
        """Solo se muestra en modo consola (no en modo GUI Qt)."""
        if _QT_AVAILABLE:
            return  # En modo GUI el banner no tiene sentido
        is_admin = _check_admin()
        admin_str = "[OK] Administrador" if is_admin else "[!] Sin privilegios admin (Event Log limitado)"

        print("\n" + "=" * 60)
        print("  STRIKEBACK -- Agente IA de Ciberseguridad")
        print("=" * 60)
        print(f"  Hora de inicio : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Privilegios    : {admin_str}")
        print(f"  API IA         : {config.AI_BASE_URL}")
        print(f"  Modelo         : {config.AI_MODEL}")
        print(f"  Firmas proceso : {len(config.ATTACK_TOOL_SIGNATURES)} herramientas (Kali/Metasploit/RAT/etc.)")
        print(f"  Firmas puerto  : {len(config.SUSPICIOUS_PORT_SIGNATURES)} puertos de ataque")
        print(f"  Extensiones RW : {len(config.RANSOMWARE_EXTENSIONS)} familias de ransomware")
        print(f"  Cobertura ATT&K: {len(config.ATTACK_COVERAGE)} tacticas MITRE monitoreadas")
        print(f"  Base de datos  : {config.DB_PATH}")
        print(f"  Log            : {config.LOG_PATH}")
        print("=" * 60)

        if not is_admin:
            print("\n  RECOMENDACION: Ejecuta como Administrador para acceder")
            print("  al Event Log de Windows (deteccion de ataques completa).\n")

        if not config.AI_API_KEY:
            print("\n  ATENCION: Configura tu API key (Windows Credential Manager)")
            print("  El analisis IA estara desactivado hasta entonces.\n")

        print("  Iniciando monitores...\n")


# ─── Entry point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Modo: generar informe bajo demanda sin arrancar el agente
    if "--report" in sys.argv:
        path = generate_report()
        if path:
            print(f"Informe generado: {path}")
        else:
            print("Error al generar el informe.")
        sys.exit(0)

    # Configurar signal para cierre limpio en Windows
    # Qt requiere QApplication antes de cualquier QWidget
    qt_app = None
    if _QT_AVAILABLE:
        # Atributo necesario en Windows para DPI correcto
        try:
            QApplication.setAttribute(Qt.ApplicationAttribute.AA_EnableHighDpiScaling, True)
        except Exception:
            pass
        qt_app = QApplication(sys.argv)
        qt_app.setApplicationName("StrikeBack")
        qt_app.setOrganizationName("StrikeBack Security")

    app = StrikeBack(qt_app=qt_app)

    def _sigint_handler(sig, frame):
        app.shutdown()

    signal.signal(signal.SIGINT,  _sigint_handler)
    signal.signal(signal.SIGTERM, _sigint_handler)

    app.start()
