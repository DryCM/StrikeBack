"""
Tray icon de Windows — escudo en la barra de sistema con menú contextual.
"""
import threading
import os
import sys
from typing import Callable, Optional

from utils.logger import get_logger
import config

logger = get_logger("TrayApp")


def _build_icon_image():
    """Crea un ícono de escudo programáticamente con Pillow."""
    from PIL import Image, ImageDraw, ImageFont

    size = 64
    img  = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Fondo del escudo (azul oscuro)
    shield_color = (15, 52, 96)
    # Forma de escudo simplificada (rectángulo + semicírculo inferior)
    draw.rounded_rectangle([6, 4, 58, 44], radius=8, fill=shield_color)
    draw.pieslice([6, 24, 58, 60], start=0, end=180, fill=shield_color)

    # "S" blanca en el centro
    try:
        draw.text((20, 12), "SB", fill=(0, 212, 255), font=None)
    except Exception:
        draw.rectangle([26, 16, 38, 40], fill=(0, 212, 255))

    return img


def _build_alert_icon_image():
    """Ícono rojo para estado de alerta."""
    from PIL import Image, ImageDraw

    size = 64
    img  = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    draw.rounded_rectangle([6, 4, 58, 44], radius=8, fill=(180, 0, 0))
    draw.pieslice([6, 24, 58, 60], start=0, end=180, fill=(180, 0, 0))
    draw.text((20, 12), "!", fill=(255, 255, 0), font=None)

    return img


class TrayApp:
    """
    Ícono en la bandeja del sistema de Windows.
    Menú derecho: ver estado, escanear ahora, salir.
    """

    def __init__(self, on_exit: Callable, on_scan: Optional[Callable] = None):
        self.on_exit  = on_exit
        self.on_scan  = on_scan
        self._icon    = None
        self._thread: Optional[threading.Thread] = None
        self._threat_count = 0

    # ------------------------------------------------------------------
    def start(self):
        if not config.SHOW_TRAY_ICON:
            return
        try:
            import pystray
            from pystray import MenuItem, Menu
        except ImportError:
            logger.warning("pystray no disponible. Tray icon desactivado.")
            return

        self._thread = threading.Thread(target=self._run, daemon=True, name="TrayApp")
        self._thread.start()

    def stop(self):
        if self._icon:
            try:
                self._icon.stop()
            except Exception:
                pass

    # ------------------------------------------------------------------
    def _run(self):
        try:
            import pystray
            from pystray import MenuItem, Menu

            icon_image = _build_icon_image()

            menu = Menu(
                MenuItem("StrikeBack — Protegiendo tu PC", lambda: None, enabled=False),
                Menu.SEPARATOR,
                MenuItem("Escanear ahora",  self._on_scan_click),
                MenuItem("Ver amenazas",    self._on_view_click),
                Menu.SEPARATOR,
                MenuItem("Salir",           self._on_exit_click),
            )

            self._icon = pystray.Icon(
                name  = "StrikeBack",
                icon  = icon_image,
                title = "StrikeBack — Activo",
                menu  = menu,
            )
            self._icon.run()

        except Exception as e:
            logger.error(f"Error en tray icon: {e}")

    # ------------------------------------------------------------------
    def update_threat_count(self, count: int):
        """Actualiza el tooltip del tray con el conteo de amenazas."""
        self._threat_count = count
        if self._icon:
            try:
                if count > 0:
                    self._icon.title = f"StrikeBack — {count} amenaza(s) detectada(s)"
                    self._icon.icon  = _build_alert_icon_image()
                else:
                    self._icon.title = "StrikeBack — Todo en orden"
                    self._icon.icon  = _build_icon_image()
            except Exception:
                pass

    # ------------------------------------------------------------------
    def _on_scan_click(self, icon, item):
        if self.on_scan:
            threading.Thread(target=self.on_scan, daemon=True).start()

    def _on_view_click(self, icon, item):
        # Abrir el archivo de log con el bloc de notas
        try:
            os.startfile(config.LOG_PATH)
        except Exception:
            pass

    def _on_exit_click(self, icon, item):
        icon.stop()
        self.on_exit()
