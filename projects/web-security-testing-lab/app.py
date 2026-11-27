"""Local-only web security teaching lab. Never expose this app to a network."""

from __future__ import annotations

import os
import sqlite3
import tempfile
from pathlib import Path

from flask import Flask, abort, g, redirect, render_template, request, url_for

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("LAB_SECRET_KEY", "local-training-only-change-me"),
    DATABASE=str(Path(tempfile.gettempdir()) / "web_security_testing_lab.sqlite3"),
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS demo_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL
)
"""


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        connection = sqlite3.connect(app.config["DATABASE"])
        connection.row_factory = sqlite3.Row
        g.db = connection
    return g.db


@app.teardown_appcontext
def close_db(_error: BaseException | None) -> None:
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def initialize_database() -> None:
    with sqlite3.connect(app.config["DATABASE"]) as connection:
        connection.execute(SCHEMA)
        count = connection.execute("SELECT COUNT(*) FROM demo_users").fetchone()[0]
        if count == 0:
            connection.executemany(
                "INSERT INTO demo_users (username, role) VALUES (?, ?)",
                [("alice", "analyst"), ("bob", "developer"), ("casey", "student")],
            )


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; object-src 'none'; base-uri 'self'"
    return response


@app.get("/")
def index():
    return render_template("index.html")


@app.route("/sql-injection", methods=["GET", "POST"])
def sql_injection():
    term = request.form.get("term", "") if request.method == "POST" else ""
    vulnerable_rows = []
    safe_rows = []
    error = None

    if request.method == "POST":
        # Intentionally vulnerable: user input is interpolated into SQL.
        # This is restricted to the local, fictional training database.
        try:
            query = (
                "SELECT username, role FROM demo_users "
                f"WHERE username LIKE '%{term}%'"
            )
            vulnerable_rows = get_db().execute(query).fetchall()
        except sqlite3.Error as exc:
            error = f"SQLite error: {exc}"

        # Safe comparison: query values are passed separately from SQL syntax.
        safe_rows = get_db().execute(
            "SELECT username, role FROM demo_users WHERE username LIKE ?",
            (f"%{term}%",),
        ).fetchall()

    return render_template(
        "sql_injection.html",
        term=term,
        vulnerable_rows=vulnerable_rows,
        safe_rows=safe_rows,
        error=error,
    )


@app.route("/xss", methods=["GET", "POST"])
def xss():
    submitted = request.form.get("message", "") if request.method == "POST" else ""
    # This is the intentionally unsafe lesson output. The template uses |safe.
    return render_template(
        "xss.html",
        submitted=submitted,
    )


@app.errorhandler(404)
def not_found(_error):
    return render_template("404.html"), 404


if __name__ == "__main__":
    initialize_database()
    # Loopback binding is deliberate: this training app must stay on this machine.
    app.run(host="127.0.0.1", port=5000, debug=False)
