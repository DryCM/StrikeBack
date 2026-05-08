"""
Report Generator — Generación de informes HTML ejecutivos sobre amenazas detectadas.

Produce un informe HTML completo y autónomo (sin dependencias externas)
que incluye:
  - Resumen ejecutivo con KPIs principales
  - Gráfica de distribución de severidad (Chart.js embebido)
  - Gráfica de amenazas por fuente / monitor
  - Línea de tiempo de las últimas 48 horas
  - Tabla detallada de todas las amenazas con análisis IA
  - Estilo corporativo oscuro coherente con el dashboard de StrikeBack

El informe se genera bajo demanda o automáticamente al cerrar StrikeBack.
Destino: data/reports/strikeback_report_YYYYMMDD_HHMMSS.html
"""

import os
import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import config
from utils.logger import get_logger

logger = get_logger("ReportGenerator")

_REPORTS_DIR = Path("data") / "reports"

# ─────────────────────────────────────────────────────────────────────────────
# Paleta de colores coherente con el dashboard
# ─────────────────────────────────────────────────────────────────────────────
_SEV_COLORS = {
    10: "#ff1744",
    9:  "#f50057",
    8:  "#ff6d00",
    7:  "#ffd600",
    6:  "#76ff03",
    5:  "#00e5ff",
    4:  "#2979ff",
    3:  "#651fff",
    2:  "#b0bec5",
    1:  "#546e7a",
}

_SEV_LABELS = {
    10: "CRÍTICO",
    9:  "CRÍTICO",
    8:  "ALTO",
    7:  "ALTO",
    6:  "MEDIO",
    5:  "MEDIO",
    4:  "BAJO",
    3:  "BAJO",
    2:  "INFO",
    1:  "INFO",
}


def _sev_color(sev: int) -> str:
    return _SEV_COLORS.get(max(1, min(10, sev)), "#b0bec5")


def _sev_label(sev: int) -> str:
    return _SEV_LABELS.get(max(1, min(10, sev)), "INFO")


# ─────────────────────────────────────────────────────────────────────────────
def _load_threats(db_path: str) -> list[dict]:
    """Lee todas las amenazas de la base de datos SQLite."""
    if not Path(db_path).exists():
        return []
    try:
        conn = sqlite3.connect(db_path, timeout=5)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM threats ORDER BY timestamp DESC"
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except sqlite3.Error as exc:
        logger.error("Error leyendo base de datos: %s", exc)
        return []


# ─────────────────────────────────────────────────────────────────────────────
def _build_html(threats: list[dict], generated_at: str) -> str:
    """Construye el HTML completo del informe."""

    total       = len(threats)
    critical    = sum(1 for t in threats if t.get("severity", 0) >= 8)
    high        = sum(1 for t in threats if 6 <= t.get("severity", 0) <= 7)
    medium      = sum(1 for t in threats if 4 <= t.get("severity", 0) <= 5)
    low         = sum(1 for t in threats if t.get("severity", 0) <= 3)
    ai_analyzed = sum(1 for t in threats if t.get("ai_analyzed"))

    # Distribución por severidad para Chart.js
    sev_counts = {}
    for t in threats:
        s = t.get("severity", 0)
        sev_counts[s] = sev_counts.get(s, 0) + 1

    chart_sev_labels = json.dumps([f"Sev {k}" for k in sorted(sev_counts)])
    chart_sev_data   = json.dumps([sev_counts[k] for k in sorted(sev_counts)])
    chart_sev_colors = json.dumps([_sev_color(k) for k in sorted(sev_counts)])

    # Distribución por fuente
    src_counts: dict[str, int] = {}
    for t in threats:
        src = t.get("source", "Desconocido")
        src_counts[src] = src_counts.get(src, 0) + 1

    chart_src_labels = json.dumps(list(src_counts.keys()))
    chart_src_data   = json.dumps(list(src_counts.values()))
    chart_src_colors = json.dumps([
        "#ff1744", "#ff6d00", "#ffd600", "#76ff03", "#00e5ff",
        "#2979ff", "#651fff", "#f50057", "#b0bec5", "#546e7a",
    ][:len(src_counts)])

    # Línea de tiempo — amenazas por hora de las últimas 48h
    now = datetime.now()
    hours_48: dict[str, int] = {}
    for i in range(47, -1, -1):
        h = (now - timedelta(hours=i)).strftime("%d/%m %H:00")
        hours_48[h] = 0

    for t in threats:
        try:
            ts = datetime.fromisoformat(t["timestamp"])
            if (now - ts).total_seconds() <= 172800:  # 48h
                h = ts.strftime("%d/%m %H:00")
                if h in hours_48:
                    hours_48[h] += 1
        except (ValueError, KeyError):
            pass

    chart_time_labels = json.dumps(list(hours_48.keys()))
    chart_time_data   = json.dumps(list(hours_48.values()))

    # ── Filas de la tabla de amenazas ─────────────────────────────────────────
    rows_html = ""
    for t in threats[:200]:  # Límite: 200 filas para rendimiento del navegador
        sev       = t.get("severity", 0)
        color     = _sev_color(sev)
        label     = _sev_label(sev)
        ts        = t.get("timestamp", "")[:19].replace("T", " ")
        source    = t.get("source", "–")
        title     = t.get("title") or t.get("description", "")[:80]
        desc      = t.get("description", "")
        mitre     = t.get("ai_mitre") or "–"
        ai_sum    = t.get("ai_summary") or "–"
        ai_badge  = (
            '<span class="badge badge-ai">IA</span>'
            if t.get("ai_analyzed") else ""
        )

        rows_html += f"""
        <tr>
          <td class="mono">{ts}</td>
          <td><span class="sev-badge" style="background:{color}">{label} ({sev})</span></td>
          <td>{source} {ai_badge}</td>
          <td class="desc-cell" title="{_esc(desc)}">{_esc(title[:100])}</td>
          <td class="mono">{mitre}</td>
          <td class="ai-cell">{_esc(str(ai_sum)[:120])}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>StrikeBack — Informe de Seguridad {generated_at[:10]}</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
  <style>
    :root {{
      --bg:       #0d1117;
      --surface:  #161b22;
      --border:   #30363d;
      --text:     #e6edf3;
      --muted:    #8b949e;
      --accent:   #ff4444;
      --accent2:  #ff6d00;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: var(--bg); color: var(--text);
      font-family: 'Segoe UI', system-ui, sans-serif;
      font-size: 14px; line-height: 1.6;
    }}
    /* ── Header ── */
    .header {{
      background: linear-gradient(135deg, #1a0505 0%, #0d1117 60%);
      border-bottom: 2px solid var(--accent);
      padding: 24px 40px;
      display: flex; align-items: center; justify-content: space-between;
    }}
    .header-logo {{
      display: flex; align-items: center; gap: 16px;
    }}
    .logo-icon {{
      width: 52px; height: 52px; background: var(--accent);
      border-radius: 12px; display: flex; align-items: center;
      justify-content: center; font-size: 28px;
    }}
    h1 {{ font-size: 22px; font-weight: 700; letter-spacing: 2px; }}
    h1 span {{ color: var(--accent); }}
    .header-meta {{ text-align: right; color: var(--muted); font-size: 12px; }}
    .header-meta strong {{ color: var(--text); }}
    /* ── Layout ── */
    .container {{ max-width: 1400px; margin: 0 auto; padding: 32px 40px; }}
    /* ── KPIs ── */
    .kpi-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 16px; margin-bottom: 32px;
    }}
    .kpi-card {{
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 10px; padding: 20px 24px;
      border-top: 3px solid var(--accent-kpi, var(--accent));
    }}
    .kpi-value {{
      font-size: 42px; font-weight: 800;
      color: var(--accent-kpi, var(--accent));
      line-height: 1;
    }}
    .kpi-label {{ color: var(--muted); font-size: 12px; margin-top: 6px; text-transform: uppercase; letter-spacing: 1px; }}
    /* ── Charts ── */
    .chart-grid {{
      display: grid;
      grid-template-columns: 1fr 1fr 2fr;
      gap: 20px; margin-bottom: 32px;
    }}
    @media (max-width: 1000px) {{ .chart-grid {{ grid-template-columns: 1fr; }} }}
    .chart-card {{
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 10px; padding: 20px;
    }}
    .chart-card h3 {{
      font-size: 13px; color: var(--muted); text-transform: uppercase;
      letter-spacing: 1px; margin-bottom: 16px;
    }}
    .chart-wrap {{ position: relative; height: 220px; }}
    /* ── Tabla ── */
    .section-title {{
      font-size: 16px; font-weight: 700; letter-spacing: 1px;
      margin-bottom: 16px; padding-bottom: 8px;
      border-bottom: 1px solid var(--border);
    }}
    .table-wrap {{ overflow-x: auto; }}
    table {{
      width: 100%; border-collapse: collapse;
      font-size: 13px;
    }}
    thead th {{
      background: #1c2128; color: var(--muted);
      font-size: 11px; text-transform: uppercase; letter-spacing: 1px;
      padding: 10px 14px; text-align: left;
      border-bottom: 1px solid var(--border);
      position: sticky; top: 0;
    }}
    tbody tr {{ border-bottom: 1px solid #21262d; transition: background 0.15s; }}
    tbody tr:hover {{ background: #1c2128; }}
    tbody td {{ padding: 10px 14px; vertical-align: top; }}
    .mono {{ font-family: 'Consolas', monospace; font-size: 12px; color: var(--muted); }}
    .sev-badge {{
      display: inline-block; padding: 2px 8px;
      border-radius: 4px; font-size: 11px; font-weight: 700;
      color: #000; white-space: nowrap;
    }}
    .badge-ai {{
      background: #1a3a5c; color: #58a6ff;
      font-size: 10px; font-weight: 700; border-radius: 3px;
      padding: 1px 5px; margin-left: 4px; vertical-align: middle;
    }}
    .desc-cell {{ max-width: 280px; }}
    .ai-cell {{ max-width: 220px; color: var(--muted); font-size: 12px; }}
    /* ── Footer ── */
    footer {{
      border-top: 1px solid var(--border); margin-top: 48px;
      padding: 24px 40px; text-align: center;
      color: var(--muted); font-size: 12px;
    }}
    footer strong {{ color: var(--text); }}
  </style>
</head>
<body>

<!-- ══════════════ HEADER ══════════════ -->
<div class="header">
  <div class="header-logo">
    <div class="logo-icon">🦉</div>
    <div>
      <h1>STRIKE<span>BACK</span></h1>
      <div style="color:var(--muted);font-size:12px;letter-spacing:1px">
        CYBERSECURITY INTELLIGENCE REPORT
      </div>
    </div>
  </div>
  <div class="header-meta">
    <div>Generado el <strong>{generated_at}</strong></div>
    <div>Período analizado: <strong>Histórico completo</strong></div>
    <div>Clasificación: <strong style="color:var(--accent)">CONFIDENCIAL</strong></div>
  </div>
</div>

<!-- ══════════════ CONTENIDO ══════════════ -->
<div class="container">

  <!-- KPIs -->
  <div class="kpi-grid">
    <div class="kpi-card" style="--accent-kpi:#ff4444">
      <div class="kpi-value">{total}</div>
      <div class="kpi-label">Eventos totales</div>
    </div>
    <div class="kpi-card" style="--accent-kpi:#ff1744">
      <div class="kpi-value">{critical}</div>
      <div class="kpi-label">Críticos / Altos (≥8)</div>
    </div>
    <div class="kpi-card" style="--accent-kpi:#ffd600">
      <div class="kpi-value">{high}</div>
      <div class="kpi-label">Severidad media-alta (6–7)</div>
    </div>
    <div class="kpi-card" style="--accent-kpi:#76ff03">
      <div class="kpi-value">{medium}</div>
      <div class="kpi-label">Severidad media (4–5)</div>
    </div>
    <div class="kpi-card" style="--accent-kpi:#2979ff">
      <div class="kpi-value">{low}</div>
      <div class="kpi-label">Severidad baja (1–3)</div>
    </div>
    <div class="kpi-card" style="--accent-kpi:#58a6ff">
      <div class="kpi-value">{ai_analyzed}</div>
      <div class="kpi-label">Analizados con IA</div>
    </div>
  </div>

  <!-- Gráficas -->
  <div class="chart-grid">
    <div class="chart-card">
      <h3>Distribución por severidad</h3>
      <div class="chart-wrap">
        <canvas id="chartSev"></canvas>
      </div>
    </div>
    <div class="chart-card">
      <h3>Eventos por monitor</h3>
      <div class="chart-wrap">
        <canvas id="chartSrc"></canvas>
      </div>
    </div>
    <div class="chart-card">
      <h3>Actividad — últimas 48 horas</h3>
      <div class="chart-wrap">
        <canvas id="chartTime"></canvas>
      </div>
    </div>
  </div>

  <!-- Tabla de amenazas -->
  <div class="section-title">Registro detallado de eventos ({min(total, 200)} de {total})</div>
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Timestamp</th>
          <th>Severidad</th>
          <th>Monitor</th>
          <th>Descripción</th>
          <th>MITRE</th>
          <th>Análisis IA</th>
        </tr>
      </thead>
      <tbody>
        {rows_html}
      </tbody>
    </table>
  </div>

</div><!-- /container -->

<!-- ══════════════ FOOTER ══════════════ -->
<footer>
  <strong>StrikeBack Cybersecurity Agent</strong> &nbsp;|&nbsp;
  Informe generado automáticamente el {generated_at} &nbsp;|&nbsp;
  Clasificación: CONFIDENCIAL — Solo para uso interno
</footer>

<!-- ══════════════ CHARTS ══════════════ -->
<script>
const defaultFont = {{ family: "'Segoe UI', system-ui, sans-serif", size: 12 }};
Chart.defaults.color = '#8b949e';
Chart.defaults.font  = defaultFont;

// 1. Distribución severidad — Doughnut
new Chart(document.getElementById('chartSev'), {{
  type: 'doughnut',
  data: {{
    labels: {chart_sev_labels},
    datasets: [{{
      data: {chart_sev_data},
      backgroundColor: {chart_sev_colors},
      borderWidth: 0,
      hoverOffset: 6,
    }}]
  }},
  options: {{
    responsive: true, maintainAspectRatio: false,
    plugins: {{
      legend: {{ position: 'right', labels: {{ boxWidth: 12, padding: 10 }} }}
    }}
  }}
}});

// 2. Por fuente — Bar horizontal
new Chart(document.getElementById('chartSrc'), {{
  type: 'bar',
  data: {{
    labels: {chart_src_labels},
    datasets: [{{
      label: 'Eventos',
      data: {chart_src_data},
      backgroundColor: {chart_src_colors},
      borderRadius: 4,
      borderWidth: 0,
    }}]
  }},
  options: {{
    indexAxis: 'y',
    responsive: true, maintainAspectRatio: false,
    plugins: {{ legend: {{ display: false }} }},
    scales: {{
      x: {{ grid: {{ color: '#21262d' }}, ticks: {{ stepSize: 1 }} }},
      y: {{ grid: {{ display: false }} }}
    }}
  }}
}});

// 3. Línea de tiempo — Line
new Chart(document.getElementById('chartTime'), {{
  type: 'line',
  data: {{
    labels: {chart_time_labels},
    datasets: [{{
      label: 'Amenazas detectadas',
      data: {chart_time_data},
      borderColor: '#ff4444',
      backgroundColor: 'rgba(255,68,68,0.08)',
      tension: 0.4,
      fill: true,
      pointRadius: 2,
      borderWidth: 2,
    }}]
  }},
  options: {{
    responsive: true, maintainAspectRatio: false,
    plugins: {{ legend: {{ display: false }} }},
    scales: {{
      x: {{
        grid: {{ color: '#21262d' }},
        ticks: {{
          maxTicksLimit: 12,
          maxRotation: 45,
          font: {{ size: 10 }}
        }}
      }},
      y: {{
        grid: {{ color: '#21262d' }},
        ticks: {{ stepSize: 1 }},
        beginAtZero: true,
      }}
    }}
  }}
}});
</script>
</body>
</html>"""


def _esc(text: str) -> str:
    """Escapa caracteres HTML para inserción segura en el informe."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


# ─────────────────────────────────────────────────────────────────────────────
def generate_report(db_path: Optional[str] = None,
                    output_dir: Optional[str] = None) -> Optional[str]:
    """
    Genera el informe HTML y devuelve la ruta del archivo creado.

    Args:
        db_path:    Ruta a strikeback.db. Por defecto usa config.DB_PATH.
        output_dir: Directorio de salida. Por defecto data/reports/.

    Returns:
        Ruta absoluta al informe generado, o None si hubo un error.
    """
    db_path    = db_path    or config.DB_PATH
    output_dir = output_dir or str(_REPORTS_DIR)

    Path(output_dir).mkdir(parents=True, exist_ok=True)

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename     = f"strikeback_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    output_path  = Path(output_dir) / filename

    threats = _load_threats(db_path)
    html    = _build_html(threats, generated_at)

    try:
        output_path.write_text(html, encoding="utf-8")
        logger.info("Informe generado: %s (%d amenazas)", output_path, len(threats))
        return str(output_path.resolve())
    except OSError as exc:
        logger.error("Error al escribir el informe: %s", exc)
        return None
