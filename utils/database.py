"""
Base de datos SQLite — almacena amenazas históricas y estadísticas.

Cifrado en reposo (AES-256-GCM):
  Los campos sensibles (description, details, ai_impact, ai_actions, ai_summary)
  se cifran antes de persistir y se descifran al leer. Los campos de búsqueda
  (source, severity, title, mitre) se mantienen en claro para permitir consultas
  eficientes sin exponer contenido sensible.
  Cumple: INCIBE §4.3, MASVS MSTG-STORAGE-1, OWASP A02.
"""
import sqlite3
import json
import threading
import os
from datetime import datetime
from typing import Optional

import config
from utils.logger import get_logger
from utils.crypto_engine import get_crypto_engine

logger = get_logger("Database")


class Database:
    """Thread-safe wrapper de SQLite."""

    def __init__(self):
        os.makedirs(os.path.dirname(config.DB_PATH), exist_ok=True)
        self._local = threading.local()
        self._init_schema()

    # ------------------------------------------------------------------
    def _conn(self) -> sqlite3.Connection:
        """Cada hilo tiene su propia conexión (thread-local)."""
        if not hasattr(self._local, "conn"):
            self._local.conn = sqlite3.connect(
                config.DB_PATH,
                check_same_thread=False,
                timeout=10,
            )
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    # ------------------------------------------------------------------
    def _init_schema(self):
        conn = self._conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS threats (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT    NOT NULL,
                source      TEXT    NOT NULL,
                severity    INTEGER NOT NULL,
                title       TEXT    NOT NULL,
                description TEXT,
                details     TEXT,
                ai_analyzed INTEGER DEFAULT 0,
                ai_is_threat INTEGER,
                ai_severity INTEGER,
                ai_mitre    TEXT,
                ai_impact   TEXT,
                ai_actions  TEXT,
                ai_summary  TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threats(timestamp);
            CREATE INDEX IF NOT EXISTS idx_threats_severity  ON threats(severity DESC);
            CREATE INDEX IF NOT EXISTS idx_threats_source    ON threats(source);
        """)
        # Migración: añadir vt_result si no existe (compatibilidad con DBs antiguas)
        try:
            conn.execute("ALTER TABLE threats ADD COLUMN vt_result TEXT")
            conn.commit()
        except Exception:
            pass  # Columna ya existe
        conn.commit()
        logger.info("Esquema de base de datos listo.")

    # ------------------------------------------------------------------
    @staticmethod
    def _enc(value) -> str | None:
        """Cifra un valor si no es None/vacío."""
        if value is None:
            return None
        return get_crypto_engine().encrypt(str(value))

    @staticmethod
    def _dec(value) -> str | None:
        """Descifra un valor; retorna None si la entrada es None."""
        if value is None:
            return None
        return get_crypto_engine().decrypt(str(value))

    def _decrypt_row(self, row: dict) -> dict:
        """Descifra los campos sensibles de una fila leída de la BD."""
        row["description"] = self._dec(row.get("description"))
        row["details"]     = self._dec(row.get("details"))
        row["ai_impact"]   = self._dec(row.get("ai_impact"))
        row["ai_actions"]  = self._dec(row.get("ai_actions"))
        row["ai_summary"]  = self._dec(row.get("ai_summary"))
        return row

    # ------------------------------------------------------------------
    def save_threat(self, threat: dict) -> int:
        """Guarda una amenaza con campos sensibles cifrados (AES-256-GCM)."""
        ai         = threat.get("ai_analysis") or {}
        ai_actions = json.dumps(ai.get("actions", []), ensure_ascii=False) if ai else None

        cursor = self._conn().execute(
            """INSERT INTO threats
               (timestamp, source, severity, title, description, details,
                ai_analyzed, ai_is_threat, ai_severity, ai_mitre, ai_impact,
                ai_actions, ai_summary)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                threat.get("timestamp", datetime.now().isoformat()),
                threat.get("source", "?"),
                threat.get("severity", 5),
                threat.get("title", "?"),
                self._enc(threat.get("description", "")),
                self._enc(json.dumps(threat.get("details", {}), ensure_ascii=False)),
                1 if threat.get("ai_analyzed") else 0,
                1 if ai.get("is_threat") else (0 if ai else None),
                ai.get("confirmed_severity"),
                ai.get("mitre_technique"),
                self._enc(ai.get("impact")),
                self._enc(ai_actions),
                self._enc(ai.get("summary")),
            ),
        )
        self._conn().commit()
        return cursor.lastrowid

    # ------------------------------------------------------------------
    def update_ai_analysis(self, threat_id: int, threat: dict):
        """Actualiza el análisis IA de una amenaza con campos sensibles cifrados."""
        ai         = threat.get("ai_analysis") or {}
        ai_actions = json.dumps(ai.get("actions", []), ensure_ascii=False)

        self._conn().execute(
            """UPDATE threats SET
               ai_analyzed=1, ai_is_threat=?, ai_severity=?,
               ai_mitre=?, ai_impact=?, ai_actions=?, ai_summary=?
               WHERE id=?""",
            (
                1 if ai.get("is_threat") else 0,
                ai.get("confirmed_severity"),
                ai.get("mitre_technique"),
                self._enc(ai.get("impact")),
                self._enc(ai_actions),
                self._enc(ai.get("summary")),
                threat_id,
            ),
        )
        self._conn().commit()

    # ------------------------------------------------------------------
    def get_recent_threats(self, limit: int = 50) -> list[dict]:
        rows = self._conn().execute(
            "SELECT * FROM threats ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
        return [self._decrypt_row(dict(r)) for r in rows]

    def get_stats(self) -> dict:
        conn = self._conn()
        total    = conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
        critical = conn.execute("SELECT COUNT(*) FROM threats WHERE severity >= 8").fetchone()[0]
        by_source = dict(conn.execute(
            "SELECT source, COUNT(*) FROM threats GROUP BY source"
        ).fetchall())
        return {"total": total, "critical": critical, "by_source": by_source}

    # ------------------------------------------------------------------
    def update_field(self, threat_id: int, field: str, value):
        """
        Actualiza un campo individual de una amenaza existente.
        Campos permitidos: severity, vt_result (whitelist contra SQLi).
        """
        _ALLOWED = {"severity", "vt_result"}
        if field not in _ALLOWED:
            logger.warning(f"update_field: campo '{field}' no permitido.")
            return
        self._conn().execute(
            f"UPDATE threats SET {field}=? WHERE id=?",
            (value, threat_id),
        )
        self._conn().commit()

    def close(self):
        if hasattr(self._local, "conn"):
            self._local.conn.close()
