#!/usr/bin/env python3
"""
WhisperWard OSINT - Database Manager
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
        conn.execute("INSERT INTO cases (case_id, case_name, description, analyst_name) VALUES (?, ?, ?, ?)",
                     (case_id, name, description, analyst))
        conn.commit()
        return case_id

    def add_target(self, case_id: str, platform: str, username: str, notes: str = ""):
        conn = self.get_connection()
        conn.execute("INSERT INTO targets (case_id, platform, username, notes) VALUES (?, ?, ?, ?)",
                     (case_id, platform.lower(), username, notes))
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
            (target_id, module_name, artifact_type, json.dumps(raw_data, default=str),
             json.dumps(processed_data, default=str) if processed_data else None, file_path, sha256))
        conn.commit()
        return cursor.lastrowid

    def get_text_for_analysis(self, case_id: str) -> str:
        conn = self.get_connection()
        cursor = conn.execute(
            "SELECT raw_data FROM artifacts WHERE target_id IN (SELECT target_id FROM targets WHERE case_id = ?)",
            (case_id,))
        texts = []
        for row in cursor.fetchall():
            data = json.loads(row['raw_data'])
            if isinstance(data, dict):
                texts.append(str(data.get('bio', '') or data.get('description', '')))
        return "\n\n".join(filter(None, texts)) or "No text content available."

    def save_analysis(self, target_id: int, results: Dict):
        conn = self.get_connection()
        conn.execute(
            "INSERT INTO analysis_results (target_id, analysis_type, findings, risk_score, analyst_notes) VALUES (?, ?, ?, ?, ?)",
            (target_id, results.get('analysis_type', 'behavioral'),
             json.dumps(results.get('findings', {})), results.get('risk_score', 0.0), results.get('notes', '')))
        conn.commit()

    def get_case_summary(self, case_id: str) -> Dict:
        conn = self.get_connection()
        targets = conn.execute("SELECT COUNT(*) as count FROM targets WHERE case_id = ?", (case_id,)).fetchone()['count']
        artifacts = conn.execute(
            "SELECT COUNT(*) as count FROM artifacts WHERE target_id IN (SELECT target_id FROM targets WHERE case_id = ?)",
            (case_id,)).fetchone()['count']
        platforms = conn.execute(
            "SELECT platform, COUNT(*) as count FROM targets WHERE case_id = ? GROUP BY platform",
            (case_id,)).fetchall()
        return {"total_targets": targets, "artifacts_count": artifacts,
                "platforms": {p['platform']: p['count'] for p in platforms}}

    def close(self):
        if self.conn:
            self.conn.close()