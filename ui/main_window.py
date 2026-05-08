"""
StrikeBack — Ventana principal nativa (PyQt6)

Layout:
  ┌──────────────────────────────────────────────────────────┐
  │  🛡 STRIKEBACK  ● LIVE   [Escanear] [Informe] [Web]      │  ← Toolbar
  ├──────────────────────────────────────────────────────────┤
  │  [ Total ]  [ Críticas ]  [ IA Analizadas ]  [ VT OK ]   │  ← KPI cards
  ├──────────────────────────────────────────────────────────┤
  │  Filtro: [___________]  Severidad: [TODAS ▼]             │  ← Filtros
  ├──────────────────────────────────────────────────────────┤
  │  Timestamp │ Sev │ Monitor │ Descripción │ MITRE │ IA │ VT│  ← Tabla
  │  ...                                                     │
  ├──────────────────────────────────────────────────────────┤
  │  15 monitores activos │ Última actualización: 12:34:56   │  ← Status bar
  └──────────────────────────────────────────────────────────┘
"""

from __future__ import annotations
import json, threading
from datetime import datetime
from typing import Callable, Optional

from PyQt6.QtCore import (
    Qt, QObject, pyqtSignal, QTimer, QThread,
)
from PyQt6.QtGui import (
    QColor, QFont, QIcon, QPalette, QBrush,
)
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTableWidget, QTableWidgetItem, QHeaderView,
    QFrame, QLineEdit, QComboBox, QSplitter, QTextEdit, QDialog,
    QDialogButtonBox, QScrollArea, QStatusBar, QSizePolicy,
    QAbstractItemView, QToolBar, QProgressBar,
)

try:
    from ai.threat_analyzer import KILL_CHAIN_LABELS, _KC_SHORT
except ImportError:
    KILL_CHAIN_LABELS = {}
    _KC_SHORT         = {}

# ─── Paleta de colores (idéntica a la web) ────────────────────────────────────
_BG      = "#0d1117"
_SURF    = "#161b22"
_SURF2   = "#1c2128"
_BORDER  = "#30363d"
_TEXT    = "#e6edf3"
_MUTED   = "#8b949e"
_RED     = "#ff4444"
_ORANGE  = "#ff6d00"
_YELLOW  = "#ffd600"
_GREEN   = "#3fb950"
_BLUE    = "#58a6ff"
_PURPLE  = "#8b5cf6"
_CAMPAIGN_ROW_BG = "#2d1800"   # fondo naranja oscuro para filas de campaña

_GLOBAL_CSS = f"""
QWidget {{
    background-color: {_BG};
    color: {_TEXT};
    font-family: 'Segoe UI', sans-serif;
    font-size: 13px;
}}
QMainWindow {{
    background-color: {_BG};
}}
QToolBar {{
    background-color: {_SURF};
    border-bottom: 1px solid {_BORDER};
    spacing: 6px;
    padding: 4px 8px;
}}
QStatusBar {{
    background-color: {_SURF};
    color: {_MUTED};
    border-top: 1px solid {_BORDER};
    font-size: 11px;
    padding: 2px 8px;
}}
QTableWidget {{
    background-color: {_SURF};
    gridline-color: {_BORDER};
    border: 1px solid {_BORDER};
    border-radius: 6px;
    selection-background-color: {_SURF2};
    selection-color: {_TEXT};
    outline: 0;
}}
QTableWidget::item {{
    padding: 6px 10px;
    border: none;
}}
QTableWidget::item:selected {{
    background-color: {_SURF2};
    color: {_TEXT};
}}
QHeaderView::section {{
    background-color: {_SURF2};
    color: {_MUTED};
    padding: 7px 10px;
    border: none;
    border-bottom: 1px solid {_BORDER};
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.5px;
    text-transform: uppercase;
}}
QLineEdit {{
    background-color: {_SURF2};
    border: 1px solid {_BORDER};
    border-radius: 6px;
    padding: 6px 10px;
    color: {_TEXT};
}}
QLineEdit:focus {{
    border-color: {_BLUE};
}}
QComboBox {{
    background-color: {_SURF2};
    border: 1px solid {_BORDER};
    border-radius: 6px;
    padding: 6px 10px;
    color: {_TEXT};
    min-width: 130px;
}}
QComboBox::drop-down {{
    border: none;
    padding-right: 8px;
}}
QComboBox QAbstractItemView {{
    background-color: {_SURF2};
    border: 1px solid {_BORDER};
    selection-background-color: {_SURF};
    color: {_TEXT};
}}
QPushButton {{
    background-color: transparent;
    border: 1px solid {_BORDER};
    border-radius: 6px;
    padding: 6px 14px;
    color: {_MUTED};
    font-size: 12px;
}}
QPushButton:hover {{
    border-color: {_RED};
    color: {_RED};
}}
QPushButton.primary {{
    background-color: {_RED};
    border-color: {_RED};
    color: white;
    font-weight: 600;
}}
QPushButton.primary:hover {{
    background-color: #e03030;
    border-color: #e03030;
    color: white;
}}
QScrollBar:vertical {{
    background: {_SURF};
    width: 8px;
    border-radius: 4px;
}}
QScrollBar::handle:vertical {{
    background: {_BORDER};
    border-radius: 4px;
    min-height: 20px;
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QFrame#kpi-row {{
    background: transparent;
}}
QFrame#separator {{
    background-color: {_BORDER};
    max-height: 1px;
}}
"""


def _sev_color(s: int) -> str:
    if s >= 9: return _RED
    if s >= 7: return _ORANGE
    if s >= 5: return _YELLOW
    if s >= 3: return _BLUE
    return _MUTED

def _sev_label(s: int) -> str:
    if s >= 9: return "CRÍTICA"
    if s >= 7: return "ALTA"
    if s >= 5: return "MEDIA"
    if s >= 3: return "BAJA"
    return "INFO"


# ─── Emisor de señales (thread-safe) ─────────────────────────────────────────
class _Emitter(QObject):
    threat_arrived    = pyqtSignal(dict)
    stats_updated     = pyqtSignal(dict)
    threat_ai_updated = pyqtSignal(dict)   # resultado IA: actualiza fila existente


# ─── KPI Card ─────────────────────────────────────────────────────────────────
class KpiCard(QFrame):
    def __init__(self, title: str, value: str = "0", color: str = _BLUE, parent=None):
        super().__init__(parent)
        self._color = color
        self.setFixedHeight(82)
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {_SURF};
                border: 1px solid {_BORDER};
                border-radius: 8px;
            }}
            QFrame:hover {{
                border-color: {color};
            }}
        """)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 12, 16, 12)
        lay.setSpacing(4)

        self._val_lbl = QLabel(value)
        self._val_lbl.setStyleSheet(f"color: {color}; font-size: 26px; font-weight: 700; border:none; background:transparent;")

        self._title_lbl = QLabel(title)
        self._title_lbl.setStyleSheet(f"color: {_MUTED}; font-size: 11px; letter-spacing: 1px; text-transform: uppercase; border:none; background:transparent;")

        lay.addWidget(self._val_lbl)
        lay.addWidget(self._title_lbl)

    def set_value(self, v):
        self._val_lbl.setText(str(v))


# ─── Diálogo de detalle de amenaza ───────────────────────────────────────────
class ThreatDetailDialog(QDialog):
    def __init__(self, threat: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Detalle de Amenaza")
        self.setMinimumSize(620, 480)
        self.setStyleSheet(_GLOBAL_CSS)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 20, 20, 20)
        lay.setSpacing(12)

        s = threat.get("severity", 0)
        color = _sev_color(s)

        # Cabecera
        hdr = QLabel(f"{threat.get('title', 'Amenaza')}")
        hdr.setStyleSheet(f"font-size: 16px; font-weight: 700; color: {color}; background: transparent;")
        lay.addWidget(hdr)

        sep = QFrame(); sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet(f"background: {_BORDER}; max-height: 1px; border: none;")
        lay.addWidget(sep)

        # Contenido
        txt = QTextEdit()
        txt.setReadOnly(True)
        txt.setStyleSheet(f"background: {_SURF2}; border: 1px solid {_BORDER}; border-radius: 6px; padding: 10px; font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 12px;")

        lines = []
        lines.append(f"Timestamp   : {threat.get('timestamp','')}")
        lines.append(f"Monitor     : {threat.get('source','')}")
        lines.append(f"Severidad   : {s} — {_sev_label(s)}")
        lines.append(f"Descripción : {threat.get('description','')}")
        lines.append(f"Detalles    : {threat.get('details','')}")
        lines.append("")
        ai = threat.get("ai_analysis") or {}
        if ai:
            lines.append("── Análisis IA ─────────────────────────────────────")
            camp = "  ⚠ CAMPAÑA ACTIVA" if ai.get("campaign_indicator") else ""
            lines.append(f"¿Es amenaza?   : {'SÍ' if ai.get('is_threat') else 'NO'}{camp}")
            urgency_map = {"immediate": "⚠ INMEDIATA", "high": "Alta",
                           "medium": "Media", "low": "Baja"}
            urgency_str = urgency_map.get(ai.get("urgency", ""), ai.get("urgency", "–"))
            lines.append(f"Severidad IA   : {ai.get('confirmed_severity', '–')}  |  Urgencia: {urgency_str}")
            lines.append(f"MITRE Técnica  : {ai.get('mitre_technique', '–')}")
            lines.append(f"MITRE Táctica  : {ai.get('mitre_tactic', '–')}")
            kcs       = ai.get("kill_chain_stage") or ""
            kcs_label = KILL_CHAIN_LABELS.get(kcs, kcs) if kcs else "–"
            lines.append(f"Fase Kill Chain: {kcs_label}")
            related = ai.get("related_to_previous", False)
            lines.append(f"Relacionado    : {'SÍ — posible cadena de ataque' if related else 'No'}")
            lines.append(f"Impacto        : {ai.get('impact', '–')}")
            lines.append(f"Resumen        : {ai.get('summary', '–')}")
            acciones = ai.get("actions", [])
            if acciones:
                lines.append("Acciones       :")
                for idx, accion in enumerate(acciones, 1):
                    lines.append(f"  {idx}. {accion}")
            fp_reason = ai.get("false_positive_reason")
            if fp_reason:
                lines.append(f"F.P. Razón     : {fp_reason}")
            ai_model = threat.get("ai_model", "")
            if ai_model:
                lines.append(f"Modelo IA      : {ai_model}")
        vt_raw = threat.get("vt_result")
        if vt_raw:
            try:
                vt = json.loads(vt_raw)
                lines.append("")
                lines.append("── VirusTotal ──────────────────────────────")
                lines.append(f"Malicioso     : {'SÍ ⚠' if vt.get('malicious') else 'No'}")
                lines.append(f"Detecciones   : {vt.get('malicious',0)}/{vt.get('total',vt.get('engines',0))}")
                if vt.get("country"):
                    lines.append(f"País          : {vt.get('country')}")
            except Exception:
                pass

        txt.setPlainText("\n".join(lines))
        lay.addWidget(txt)

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btns.setStyleSheet(f"background: transparent;")
        btns.rejected.connect(self.accept)
        lay.addWidget(btns)


# ─── Ventana principal ────────────────────────────────────────────────────────
class MainWindow(QMainWindow):
    def __init__(
        self,
        on_scan: Optional[Callable] = None,
        on_report: Optional[Callable] = None,
        on_open_web: Optional[Callable] = None,
        db_path: str = "",
    ):
        super().__init__()
        self._on_scan      = on_scan
        self._on_report    = on_report
        self._on_open_web  = on_open_web
        self._db_path      = db_path
        self._all_threats: list[dict] = []
        self._filter_text  = ""
        self._filter_sev   = 0

        self._emitter = _Emitter()
        self._emitter.threat_arrived.connect(self._add_threat_row)
        self._emitter.stats_updated.connect(self._update_kpis)
        self._emitter.threat_ai_updated.connect(self._on_ai_update)

        self._build_ui()
        self._load_from_db()

        # Refresco automático de KPIs cada 10 s
        self._kpi_timer = QTimer(self)
        self._kpi_timer.timeout.connect(self._refresh_stats)
        self._kpi_timer.start(10_000)

    # ── Construcción de la UI ─────────────────────────────────────────────────
    def _build_ui(self):
        self.setWindowTitle("StrikeBack — Agente IA de Ciberseguridad")
        self.setMinimumSize(1100, 680)
        self.resize(1300, 780)
        self.setStyleSheet(_GLOBAL_CSS)

        # ── Toolbar ──────────────────────────────────────────────────────────
        tb = QToolBar("Principal")
        tb.setMovable(False)
        tb.setFloatable(False)
        self.addToolBar(tb)

        # Logo / brand
        brand = QLabel("  🛡 <b>STRIKE</b><span style='color:#ff4444'>BACK</span>")
        brand.setStyleSheet(f"font-size: 15px; color: {_TEXT}; background: transparent; padding: 0 8px;")
        brand.setTextFormat(Qt.TextFormat.RichText)
        tb.addWidget(brand)

        # LIVE badge
        self._live_lbl = QLabel("  ● LIVE")
        self._live_lbl.setStyleSheet(f"color: {_GREEN}; font-size: 11px; letter-spacing: 2px; background: transparent;")
        tb.addWidget(self._live_lbl)

        spacer = QWidget(); spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        tb.addWidget(spacer)

        # Clock
        self._clock_lbl = QLabel()
        self._clock_lbl.setStyleSheet(f"color: {_MUTED}; font-size: 11px; font-family: monospace; background: transparent; padding: 0 8px;")
        self._update_clock()
        tb.addWidget(self._clock_lbl)
        clock_timer = QTimer(self); clock_timer.timeout.connect(self._update_clock); clock_timer.start(1000)

        tb.addSeparator()

        btn_scan = QPushButton("⟳  Escanear")
        btn_scan.setToolTip("Fuerza escaneo de red y procesos")
        btn_scan.clicked.connect(self._do_scan)
        tb.addWidget(btn_scan)

        btn_report = QPushButton("📄  Informe")
        btn_report.setToolTip("Genera informe HTML de la sesión")
        btn_report.clicked.connect(self._do_report)
        tb.addWidget(btn_report)

        btn_web = QPushButton("🌐  Web")
        btn_web.setToolTip("Abre el dashboard web en el navegador")
        btn_web.clicked.connect(self._do_open_web)
        tb.addWidget(btn_web)

        # ── Central widget ───────────────────────────────────────────────────
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(12, 12, 12, 8)
        root.setSpacing(10)

        # ── KPI row ──────────────────────────────────────────────────────────
        kpi_row = QHBoxLayout()
        kpi_row.setSpacing(10)
        self._kpi_total    = KpiCard("AMENAZAS TOTALES",  "0", _RED)
        self._kpi_critical = KpiCard("CRÍTICAS / ALTAS",  "0", _ORANGE)
        self._kpi_ai       = KpiCard("ANALIZADAS POR IA", "0", _PURPLE)
        self._kpi_vt       = KpiCard("VT ENRIQUECIDAS",   "0", _BLUE)
        for card in (self._kpi_total, self._kpi_critical, self._kpi_ai, self._kpi_vt):
            kpi_row.addWidget(card)
        root.addLayout(kpi_row)

        # ── Filtros ──────────────────────────────────────────────────────────
        filter_row = QHBoxLayout()
        filter_row.setSpacing(8)

        filter_lbl = QLabel("Filtro:")
        filter_lbl.setStyleSheet(f"color: {_MUTED}; background: transparent;")
        filter_row.addWidget(filter_lbl)

        self._filter_edit = QLineEdit()
        self._filter_edit.setPlaceholderText("Buscar por descripción, monitor, MITRE…")
        self._filter_edit.textChanged.connect(self._apply_filter)
        filter_row.addWidget(self._filter_edit, stretch=1)

        sev_lbl = QLabel("Severidad:")
        sev_lbl.setStyleSheet(f"color: {_MUTED}; background: transparent;")
        filter_row.addWidget(sev_lbl)

        self._sev_combo = QComboBox()
        self._sev_combo.addItems(["Todas", "≥ Info (1+)", "≥ Baja (3+)", "≥ Media (5+)", "≥ Alta (7+)", "≥ Crítica (9+)"])
        self._sev_combo.currentIndexChanged.connect(self._on_sev_filter)
        filter_row.addWidget(self._sev_combo)

        root.addLayout(filter_row)

        # ── Tabla de amenazas ─────────────────────────────────────────────────
        self._table = QTableWidget()
        self._table.setColumnCount(9)
        self._table.setHorizontalHeaderLabels(["Timestamp", "Sev", "Fiab.", "Monitor", "Descripción", "MITRE", "IA", "VT", "ID"])
        self._table.verticalHeader().setVisible(False)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(False)
        self._table.setSortingEnabled(True)
        self._table.doubleClicked.connect(self._on_row_double_click)
        self._table.setShowGrid(True)

        hdr = self._table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)  # Timestamp
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)  # Sev
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)  # Fiab.
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)  # Monitor
        hdr.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)            # Descripción
        hdr.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)  # MITRE
        hdr.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)  # IA
        hdr.setSectionResizeMode(7, QHeaderView.ResizeMode.ResizeToContents)  # VT
        hdr.setSectionResizeMode(8, QHeaderView.ResizeMode.Fixed)              # ID (oculto)
        self._table.setColumnHidden(8, True)

        root.addWidget(self._table, stretch=1)

        # ── Status bar ───────────────────────────────────────────────────────
        sb = QStatusBar()
        self.setStatusBar(sb)
        self._status_monitors = QLabel("Iniciando…")
        self._status_monitors.setStyleSheet(f"color: {_MUTED}; background: transparent;")
        self._status_last = QLabel("")
        self._status_last.setStyleSheet(f"color: {_MUTED}; background: transparent;")
        sb.addWidget(self._status_monitors)
        sb.addPermanentWidget(self._status_last)

    # ── Helpers UI ────────────────────────────────────────────────────────────
    def _update_clock(self):
        self._clock_lbl.setText(datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))

    def _do_scan(self):
        if self._on_scan:
            threading.Thread(target=self._on_scan, daemon=True).start()

    def _do_report(self):
        if self._on_report:
            threading.Thread(target=self._on_report, daemon=True).start()

    def _do_open_web(self):
        if self._on_open_web:
            self._on_open_web()

    # ── Recepción de amenazas (thread-safe via señal) ─────────────────────────
    def push_threat(self, threat: dict):
        """Llamado desde hilos de monitores. Thread-safe."""
        self._emitter.threat_arrived.emit(threat)

    def _add_threat_row(self, threat: dict):
        """Ejecutado en el hilo principal Qt."""
        self._all_threats.insert(0, threat)
        if len(self._all_threats) > 2000:
            self._all_threats.pop()
        self._insert_row(threat, position=0)
        self._update_status()

    def _insert_row(self, threat: dict, position: int = -1):
        s = threat.get("severity", 0)
        # Verificar filtro
        if not self._passes_filter(threat):
            return

        row = position if position >= 0 else self._table.rowCount()
        self._table.setSortingEnabled(False)
        self._table.insertRow(row)

        color = _sev_color(s)
        label = _sev_label(s)

        ts = (threat.get("timestamp") or "").replace("T", " ")[:19]
        sev_txt = f"{label} ({s})"
        conf    = threat.get("confidence", 0)
        conf_txt = f"{conf}%"
        monitor = threat.get("source") or "–"
        desc    = (threat.get("description") or "")[:120]
        mitre   = threat.get("ai_mitre") or (threat.get("ai_analysis") or {}).get("mitre_technique") or "–"

        # ── Estado IA: pendiente / confirmado / falso positivo ──────────────
        ai_analyzed  = threat.get("ai_analyzed", False)
        ai_analysis  = threat.get("ai_analysis") or {}
        # Datos procedentes de la DB (columnas ai_is_threat, ai_severity)
        if not ai_analysis and threat.get("ai_is_threat") is not None:
            ai_analyzed = True
            ai_analysis = {"is_threat": bool(threat.get("ai_is_threat")),
                           "confirmed_severity": threat.get("ai_severity"),
                           "mitre_technique": threat.get("ai_mitre"),
                           "summary": threat.get("ai_summary") or ""}
        ai_is_threat = ai_analysis.get("is_threat", True)

        if ai_analyzed or ai_analysis:
            kcs       = ai_analysis.get("kill_chain_stage") or ""
            kcs_short = _KC_SHORT.get(kcs, "")
            if not ai_is_threat:
                ai_text  = "✗ F.P."
                ai_color = _MUTED
            elif kcs_short:
                ai_text  = f"✓ {kcs_short}"
                ai_color = _PURPLE
            else:
                ai_text  = "✓ IA"
                ai_color = _PURPLE
        elif s >= 4:
            ai_text  = "⏳"       # pendiente de verificación por la IA
            ai_color = _YELLOW
        else:
            ai_text  = "–"
            ai_color = _MUTED

        vt_txt = "–"
        vt_raw = threat.get("vt_result")
        if vt_raw:
            try:
                vt = json.loads(vt_raw)
                mal = vt.get("malicious", 0)
                tot = vt.get("total", vt.get("engines", 0))
                vt_txt = f"⚠ {mal}/{tot}" if mal > 0 else f"✓ 0/{tot}"
            except Exception:
                pass

        db_id = str(threat.get("_db_id") or threat.get("id") or "")

        def _item(text: str, align=Qt.AlignmentFlag.AlignVCenter) -> QTableWidgetItem:
            it = QTableWidgetItem(text)
            it.setForeground(QBrush(QColor(_TEXT)))
            it.setTextAlignment(align | Qt.AlignmentFlag.AlignLeft)
            return it

        sev_item = QTableWidgetItem(sev_txt)
        sev_item.setForeground(QBrush(QColor(color)))
        sev_item.setTextAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)

        # Columna Fiabilidad: verde >=80%, amarillo >=60%, rojo <60%
        conf_item = QTableWidgetItem(conf_txt)
        conf_color = _GREEN if conf >= 80 else (_YELLOW if conf >= 60 else _RED)
        conf_item.setForeground(QBrush(QColor(conf_color)))
        conf_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        vt_item = QTableWidgetItem(vt_txt)
        vt_color = _RED if vt_txt.startswith("⚠") else (_GREEN if vt_txt.startswith("✓") else _MUTED)
        vt_item.setForeground(QBrush(QColor(vt_color)))
        vt_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        ai_item = QTableWidgetItem(ai_text)
        ai_item.setForeground(QBrush(QColor(ai_color)))
        ai_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        self._table.setItem(row, 0, _item(ts))
        self._table.setItem(row, 1, sev_item)
        self._table.setItem(row, 2, conf_item)
        self._table.setItem(row, 3, _item(monitor))
        self._table.setItem(row, 4, _item(desc))
        self._table.setItem(row, 5, _item(mitre))
        self._table.setItem(row, 6, ai_item)
        self._table.setItem(row, 7, vt_item)
        self._table.setItem(row, 8, _item(db_id))

        # Altura de fila
        self._table.setRowHeight(row, 34)

        # Fila de campaña: fondo naranja oscuro para destacarla
        if (threat.get("source") == "AIAnalyzer" and
                "CAMPAÑA" in (threat.get("title") or "").upper()):
            bg = QBrush(QColor(_CAMPAIGN_ROW_BG))
            for col in range(self._table.columnCount() - 1):
                item = self._table.item(row, col)
                if item:
                    item.setBackground(bg)

        self._table.setSortingEnabled(True)

    def _passes_filter(self, threat: dict) -> bool:
        s = threat.get("severity", 0)
        if s < self._filter_sev:
            return False
        if self._filter_text:
            haystack = " ".join([
                str(threat.get("description") or ""),
                str(threat.get("source") or ""),
                str(threat.get("title") or ""),
                str(threat.get("ai_mitre") or ""),
            ]).lower()
            if self._filter_text.lower() not in haystack:
                return False
        return True

    def _apply_filter(self, text: str):
        self._filter_text = text
        self._rebuild_table()

    def _on_sev_filter(self, idx: int):
        thresholds = [0, 1, 3, 5, 7, 9]
        self._filter_sev = thresholds[idx]
        self._rebuild_table()

    def _rebuild_table(self):
        self._table.setSortingEnabled(False)
        self._table.setRowCount(0)
        for t in self._all_threats:
            self._insert_row(t)
        self._table.setSortingEnabled(True)

    def _on_row_double_click(self, index):
        row = index.row()
        db_id_item = self._table.item(row, 8)
        if not db_id_item:
            return
        db_id = db_id_item.text()
        threat = next((t for t in self._all_threats
                       if str(t.get("_db_id") or t.get("id") or "") == db_id), None)
        if threat:
            dlg = ThreatDetailDialog(threat, self)
            dlg.exec()

    # ── Actualización de la IA en tiempo real ────────────────────────────────
    def update_threat_ai(self, threat: dict):
        """Thread-safe: llamar desde _on_ai_result en main.py."""
        self._emitter.threat_ai_updated.emit(threat)

    def _on_ai_update(self, threat: dict):
        """Ejecutado en el hilo Qt cuando llega el resultado de la IA."""
        db_id = str(threat.get("_db_id") or threat.get("id") or "")
        if not db_id:
            return

        # Actualizar la copia en memoria
        for i, t in enumerate(self._all_threats):
            if str(t.get("_db_id") or t.get("id") or "") == db_id:
                self._all_threats[i] = threat
                break

        # Actualizar la fila visible en la tabla
        for row in range(self._table.rowCount()):
            id_item = self._table.item(row, 8)
            if id_item and id_item.text() == db_id:
                self._apply_ai_to_row(row, threat)
                break

    def _apply_ai_to_row(self, row: int, threat: dict):
        """
        Actualiza las celdas IA, Severidad y MITRE de una fila ya existente
        con el resultado del análisis IA.
        """
        ai = threat.get("ai_analysis") or {}
        is_threat  = ai.get("is_threat", True)
        conf_sev   = ai.get("confirmed_severity")
        mitre      = ai.get("mitre_technique") or threat.get("ai_mitre") or "–"

        # Col 6: IA — mostrar kill chain + veredicto con color
        kcs       = ai.get("kill_chain_stage") or ""
        kcs_short = _KC_SHORT.get(kcs, "")
        if not is_threat:
            ai_text  = "✗ F.P."
            ai_color = _MUTED
        elif kcs_short:
            ai_text  = f"✓ {kcs_short}"
            ai_color = _PURPLE
        else:
            ai_text  = "✓ IA"
            ai_color = _PURPLE
        ai_item = QTableWidgetItem(ai_text)
        ai_item.setForeground(QBrush(QColor(ai_color)))
        ai_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self._table.setItem(row, 6, ai_item)

        # Col 5: MITRE — la IA puede identificar la técnica
        mitre_item = QTableWidgetItem(mitre)
        mitre_item.setForeground(QBrush(QColor(_TEXT if is_threat else _MUTED)))
        mitre_item.setTextAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
        self._table.setItem(row, 5, mitre_item)

        # Col 1: Sev — actualizar si la IA corrigió la severidad
        if conf_sev is not None:
            label = _sev_label(conf_sev)
            clr   = _sev_color(conf_sev) if is_threat else _MUTED
            sev_item = QTableWidgetItem(f"{label} ({conf_sev})")
            sev_item.setForeground(QBrush(QColor(clr)))
            sev_item.setTextAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
            self._table.setItem(row, 1, sev_item)

        # Si la IA dice FALSO POSITIVO — atenuar toda la fila
        if not is_threat:
            for col in range(self._table.columnCount() - 1):  # no tocar la columna ID
                item = self._table.item(row, col)
                if item:
                    item.setForeground(QBrush(QColor(_MUTED)))

    # ── Carga inicial desde DB ─────────────────────────────────────────────────
    def _load_from_db(self):
        if not self._db_path:
            return
        try:
            import sqlite3
            from pathlib import Path
            from utils.crypto_engine import get_crypto_engine
            if not Path(self._db_path).exists():
                return
            crypto = get_crypto_engine()
            conn = sqlite3.connect(self._db_path, timeout=5, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM threats ORDER BY timestamp DESC LIMIT 500"
            ).fetchall()
            conn.close()

            enc_fields = ("description", "details", "ai_impact", "ai_actions", "ai_summary")
            self._table.setSortingEnabled(False)
            for r in rows:
                t = dict(r)
                for f in enc_fields:
                    if t.get(f):
                        try:
                            t[f] = crypto.decrypt(t[f])
                        except Exception:
                            pass
                # Mapear columnas DB a formato interno
                ai = {}
                if t.get("ai_analyzed"):
                    ai = {
                        "is_threat":         t.get("ai_is_threat"),
                        "confirmed_severity": t.get("ai_severity"),
                        "mitre_technique":    t.get("ai_mitre"),
                        "impact":             t.get("ai_impact"),
                        "summary":            t.get("ai_summary"),
                        "actions":            (t.get("ai_actions") or "").split("|"),
                    }
                    t["ai_analysis"] = ai
                self._all_threats.append(t)
                self._insert_row(t)
            self._table.setSortingEnabled(True)
            self._refresh_stats()
        except Exception as exc:
            self._status_monitors.setText(f"Error cargando DB: {exc}")

    # ── KPIs ──────────────────────────────────────────────────────────────────
    def _refresh_stats(self):
        if not self._db_path:
            return
        try:
            import sqlite3
            from pathlib import Path
            if not Path(self._db_path).exists():
                return
            conn = sqlite3.connect(self._db_path, timeout=3, check_same_thread=False)
            total      = conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
            critical   = conn.execute("SELECT COUNT(*) FROM threats WHERE severity >= 7").fetchone()[0]
            ai_done    = conn.execute("SELECT COUNT(*) FROM threats WHERE ai_analyzed=1").fetchone()[0]
            vt_done    = conn.execute("SELECT COUNT(*) FROM threats WHERE vt_result IS NOT NULL AND vt_result != ''").fetchone()[0]
            conn.close()
            self._emitter.stats_updated.emit({
                "total": total, "critical": critical,
                "ai": ai_done, "vt": vt_done,
            })
        except Exception:
            pass

    def _update_kpis(self, stats: dict):
        self._kpi_total.set_value(stats.get("total", 0))
        self._kpi_critical.set_value(stats.get("critical", 0))
        self._kpi_ai.set_value(stats.get("ai", 0))
        self._kpi_vt.set_value(stats.get("vt", 0))

    def _update_status(self):
        now = datetime.now().strftime("%H:%M:%S")
        rows = self._table.rowCount()
        self._status_last.setText(f"Última actualización: {now}")
        self._status_monitors.setText(f"Mostrando {rows} amenazas")

    def set_monitors_status(self, active: int, total: int):
        self._status_monitors.setText(f"{active}/{total} monitores activos")

    # ── Ciclo de vida ──────────────────────────────────────────────────────────
    def closeEvent(self, event):
        """Al cerrar la ventana, notificar al agente para parar todo."""
        event.accept()
