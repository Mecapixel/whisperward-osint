#!/usr/bin/env python3
"""
WhisperWard OSINT - Database Manager
Phase 5 update: get_all_cases() returns latest_risk + peak_risk
Phase 5 update: get_case_risk() added for dossier page
"""
import sqlite3
import json
import hashlib
import uuid
from pathlib import Path
from typing import Optional, List, Dict, Any


class DatabaseManager:
    def __init__(self, db_path: str = "whisperward.db"):
        self.db_path = db_path
        self.conn = None

    def get_connection(self):
        if self.conn is None:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row
        return self.conn

    def init(self):
        schema_path = Path("database/schema.sql")
        if not schema_path.exists():
            raise FileNotFoundError(f"Schema file not found: {schema_path}")
        conn = self.get_connection()
        with open(schema_path, 'r') as f:
            conn.executescript(f.read())
        conn.commit()
        print("Database initialized successfully.")

    def create_case(self, name: str, description: str = "", analyst: str = "Meca Dismukes") -> str:
        case_id = f"CASE-{uuid.uuid4().hex[:8].upper()}"
        conn = self.get_connection()
        conn.execute(
            "INSERT INTO cases (case_id, case_name, description, analyst_name) VALUES (?, ?, ?, ?)",
            (case_id, name, description, analyst)
        )
        conn.commit()
        return case_id

    def add_target(self, case_id: str, platform: str, username: str, notes: str = ""):
        conn = self.get_connection()
        conn.execute(
            "INSERT INTO targets (case_id, platform, username, notes) VALUES (?, ?, ?, ?)",
            (case_id, platform.lower(), username, notes)
        )
        conn.commit()

    def get_case_targets(self, case_id: str) -> List[Dict]:
        conn = self.get_connection()
        cursor = conn.execute("SELECT * FROM targets WHERE case_id = ?", (case_id,))
        return [dict(row) for row in cursor.fetchall()]

    def save_artifact(self, target_id: int, module_name: str, artifact_type: str,
                      raw_data: Any, processed_data: Any = None, file_path: str = None) -> int:
        sha256 = hashlib.sha256(json.dumps(raw_data, default=str).encode()).hexdigest()
        conn = self.get_connection()
        cursor = conn.execute(
            "INSERT INTO artifacts (target_id, module_name, artifact_type, raw_data, processed_data, file_path, sha256) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (target_id, module_name, artifact_type,
             json.dumps(raw_data, default=str),
             json.dumps(processed_data, default=str) if processed_data else None,
             file_path, sha256)
        )
        conn.commit()
        return cursor.lastrowid

    def get_text_for_analysis(self, case_id: str) -> str:
        conn = self.get_connection()
        cursor = conn.execute(
            "SELECT raw_data FROM artifacts WHERE target_id IN (SELECT target_id FROM targets WHERE case_id = ?)",
            (case_id,)
        )
        texts = []
        for row in cursor.fetchall():
            data = json.loads(row['raw_data'])
            if isinstance(data, dict):
                texts.append(str(data.get('bio', '') or data.get('description', '')))
        return "\n\n".join(filter(None, texts)) or "No text content available."

    def save_analysis(self, target_id: int, results: Dict):
        """Persist analysis results including risk_score and timestamp."""
        conn = self.get_connection()
        conn.execute(
            "INSERT INTO analysis_results (target_id, analysis_type, findings, risk_score, analyst_notes) VALUES (?, ?, ?, ?, ?)",
            (target_id,
             results.get('analysis_type', 'behavioral'),
             json.dumps(results.get('findings', {})),
             results.get('risk_score', 0.0),
             results.get('notes', ''))
        )
        conn.commit()

    def get_case_summary(self, case_id: str) -> Dict:
        conn = self.get_connection()
        targets = conn.execute(
            "SELECT COUNT(*) as count FROM targets WHERE case_id = ?",
            (case_id,)
        ).fetchone()['count']
        artifacts = conn.execute(
            "SELECT COUNT(*) as count FROM artifacts WHERE target_id IN (SELECT target_id FROM targets WHERE case_id = ?)",
            (case_id,)
        ).fetchone()['count']
        platforms = conn.execute(
            "SELECT platform, COUNT(*) as count FROM targets WHERE case_id = ? GROUP BY platform",
            (case_id,)
        ).fetchall()
        return {
            "total_targets": targets,
            "artifacts_count": artifacts,
            "platforms": {p['platform']: p['count'] for p in platforms}
        }

    def get_case_risk(self, case_id: str) -> Dict:
        """Get latest and peak risk scores for a case (used by dossier page)."""
        cursor = self.get_connection().execute("""
            SELECT
                MAX(ar.risk_score)    AS peak_risk,
                COUNT(ar.risk_score)  AS analysis_count
            FROM targets t
            LEFT JOIN analysis_results ar ON ar.target_id = t.target_id
            WHERE t.case_id = ?
        """, (case_id,))
        row = cursor.fetchone()
        if not row or row["peak_risk"] is None:
            return {"latest_risk": None, "peak_risk": None, "analysis_count": 0}

        cursor2 = self.get_connection().execute("""
            SELECT ar.risk_score
            FROM targets t
            JOIN analysis_results ar ON ar.target_id = t.target_id
            WHERE t.case_id = ?
            ORDER BY ar.completed_at DESC
            LIMIT 1
        """, (case_id,))
        latest_row = cursor2.fetchone()
        return {
            "latest_risk": latest_row["risk_score"] if latest_row else None,
            "peak_risk": row["peak_risk"],
            "analysis_count": row["analysis_count"]
        }

    def get_all_cases(self):
        """
        Get all cases for the dashboard.
        Returns: case_id, case_name, analyst_name, created_at, target_count,
        primary_platform, latest_risk, peak_risk, analyzed_at, analysis_count
        """
        cursor = self.get_connection().execute("""
            WITH case_targets AS (
                SELECT case_id, COUNT(*) AS target_count
                FROM targets
                GROUP BY case_id
            ),
            case_platform AS (
                SELECT case_id, platform AS primary_platform
                FROM (
                    SELECT case_id, platform, COUNT(*) AS pc,
                           ROW_NUMBER() OVER (PARTITION BY case_id ORDER BY COUNT(*) DESC) AS rn
                    FROM targets
                    GROUP BY case_id, platform
                )
                WHERE rn = 1
            ),
            case_analysis AS (
                SELECT
                    t.case_id,
                    MAX(ar.risk_score)    AS peak_risk,
                    COUNT(ar.risk_score)  AS analysis_count,
                    MAX(ar.completed_at)  AS analyzed_at
                FROM targets t
                LEFT JOIN analysis_results ar ON ar.target_id = t.target_id
                GROUP BY t.case_id
            ),
            latest_analysis AS (
                SELECT case_id, risk_score AS latest_risk
                FROM (
                    SELECT t.case_id, ar.risk_score, ar.completed_at,
                           ROW_NUMBER() OVER (PARTITION BY t.case_id ORDER BY ar.completed_at DESC) AS rn
                    FROM targets t
                    JOIN analysis_results ar ON ar.target_id = t.target_id
                )
                WHERE rn = 1
            )
            SELECT
                c.case_id,
                c.case_name,
                c.analyst_name,
                c.created_at,
                COALESCE(ct.target_count, 0)   AS target_count,
                cp.primary_platform             AS primary_platform,
                la.latest_risk                  AS latest_risk,
                ca.peak_risk                    AS peak_risk,
                ca.analyzed_at                  AS analyzed_at,
                COALESCE(ca.analysis_count, 0)  AS analysis_count
            FROM cases c
            LEFT JOIN case_targets    ct ON ct.case_id = c.case_id
            LEFT JOIN case_platform   cp ON cp.case_id = c.case_id
            LEFT JOIN latest_analysis la ON la.case_id = c.case_id
            LEFT JOIN case_analysis   ca ON ca.case_id = c.case_id
            ORDER BY
                (la.latest_risk IS NULL),
                la.latest_risk DESC,
                c.created_at DESC
        """)
        return [dict(row) for row in cursor.fetchall()]

    def get_case(self, case_id: str):
        """Get single case by ID."""
        cursor = self.get_connection().execute(
            "SELECT * FROM cases WHERE case_id = ?", (case_id,)
        )
        row = cursor.fetchone()
        return dict(row) if row else None

    def close(self):
        if self.conn:
            self.conn.close()