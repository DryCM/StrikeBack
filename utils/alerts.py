"""
Alertas Windows — notificaciones toast y sonidos del sistema.
"""
import threading
from utils.logger import get_logger
import config

logger = get_logger("Alerts")


class Alerts:
    """Envía notificaciones toast de Windows cuando se detecta una amenaza."""

    def __init__(self):
        self._toaster = None
        self._available = False
        self._lock = threading.Lock()

        if not config.TOAST_NOTIFICATIONS:
            return

        try:
            from win10toast import ToastNotifier
            self._toaster = ToastNotifier()
            self._available = True
            logger.info("Notificaciones toast de Windows activadas.")
        except ImportError:
            try:
                # Fallback: usar ctypes directamente (Windows 10/11)
                import ctypes
                self._ctypes = ctypes
                self._available = True
                self._use_ctypes = True
                logger.info("Notificaciones via ctypes activadas.")
            except Exception:
                logger.warning("win10toast no disponible. Notificaciones desactivadas.")

    # ------------------------------------------------------------------
    def notify(self, title: str, message: str, severity: int = 5):
        """Envía notificación toast si la severidad lo justifica."""
        if not self._available or not config.TOAST_NOTIFICATIONS:
            return

        # Solo notificar amenazas relevantes para no saturar
        if severity < config.AI_SEVERITY_THRESHOLD:
            return

        icon_map = {range(1, 5): "info", range(5, 8): "warning", range(8, 11): "error"}
        icon = next((v for k, v in icon_map.items() if severity in k), "warning")

        prefix = {
            "error":   "🔴 CRÍTICO",
            "warning": "🟡 ALERTA",
            "info":    "🔵 INFO",
        }.get(icon, "⚠️")

        full_title   = f"StrikeBack — {prefix}"
        short_msg    = message[:200] if len(message) > 200 else message

        thread = threading.Thread(
            target  = self._send,
            args    = (full_title, short_msg),
            daemon  = True,
        )
        thread.start()

    # ------------------------------------------------------------------
    def _send(self, title: str, message: str):
        with self._lock:
            try:
                if self._toaster:
                    self._toaster.show_toast(
                        title,
                        message,
                        duration  = config.TOAST_DURATION,
                        threaded  = False,
                    )
                elif hasattr(self, "_use_ctypes"):
                    # Fallback simple: MessageBox (bloquea si el usuario no cierra)
                    # Solo para severidad crítica
                    pass
            except Exception as e:
                logger.debug(f"Error enviando notificación: {e}")
