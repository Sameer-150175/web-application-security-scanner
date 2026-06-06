import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, render_template, request

from service import PROJECT_NAME, analyze

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = Path(os.environ.get("APP_DB_PATH", DATA_DIR / "app.sqlite"))

def get_db():
    DATA_DIR.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            payload TEXT NOT NULL,
            result TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    return conn

def create_app():
    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False

    @app.get("/")
    def dashboard():
        conn = get_db()
        rows = conn.execute("SELECT id, result, created_at FROM findings ORDER BY id DESC LIMIT 10").fetchall()
        findings = [dict(id=row["id"], result=json.loads(row["result"]), created_at=row["created_at"]) for row in rows]
        return render_template("dashboard.html", project_name=PROJECT_NAME, findings=findings)

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok", "project": PROJECT_NAME})

    @app.post("/api/analyze")
    def api_analyze():
        payload = request.get_json(silent=True) or {}
        result = analyze(payload)
        conn = get_db()
        conn.execute(
            "INSERT INTO findings(payload, result, created_at) VALUES (?, ?, ?)",
            (json.dumps(payload), json.dumps(result), datetime.utcnow().isoformat() + "Z")
        )
        conn.commit()
        return jsonify(result), 201

    @app.get("/api/findings")
    def api_findings():
        conn = get_db()
        rows = conn.execute("SELECT id, payload, result, created_at FROM findings ORDER BY id DESC LIMIT 100").fetchall()
        return jsonify([
            {
                "id": row["id"],
                "payload": json.loads(row["payload"]),
                "result": json.loads(row["result"]),
                "created_at": row["created_at"]
            }
            for row in rows
        ])

    return app

if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=os.environ.get("FLASK_DEBUG") == "1")
