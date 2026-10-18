"""
Zorem
A local, private monthly-budget app.

Run:  python app.py            (this computer only, http://127.0.0.1:5000)
      python app.py --lan      (also reachable from phones on the same Wi-Fi)
"""
import argparse
import json
import os
import re
import secrets
import socket
import sqlite3
import time
from functools import wraps

from flask import (Flask, abort, g, jsonify, redirect, render_template,
                   request, send_from_directory, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "data")
DB_PATH = os.path.join(DATA, "kis.sqlite3")
os.makedirs(DATA, exist_ok=True)

NAME_RX = re.compile(r"^[A-Za-z0-9_-]{1,120}$")   # document names: settings, calendar, m-2026-10, m-b1x2-2026-10
USER_RX = re.compile(r"^[\w.@-]{2,40}$", re.UNICODE)
MAX_DOC_BYTES = 512 * 1024


def secret_key() -> str:
    path = os.path.join(DATA, "secret.key")
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(secrets.token_hex(32))
    with open(path) as f:
        return f.read().strip()


app = Flask(__name__, static_folder="static", template_folder="templates")
app.config.update(
    SECRET_KEY=secret_key(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 60,   # stay signed in for 60 days
    MAX_CONTENT_LENGTH=20 * 1024 * 1024,
)


# ---------------------------------------------------------------- database
def db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT UNIQUE NOT NULL COLLATE NOCASE,
            pw_hash    TEXT NOT NULL,
            created_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS docs (
            user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name       TEXT NOT NULL,
            body       TEXT NOT NULL,
            updated_at REAL NOT NULL,
            PRIMARY KEY (user_id, name)
        );
        """
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------- auth
def login_required(api=False):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            if not session.get("uid"):
                if api:
                    return jsonify(error="not_signed_in"), 401
                return redirect(url_for("login"))
            return fn(*a, **kw)
        return wrapper
    return deco


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        row = db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if row and check_password_hash(row["pw_hash"], password):
            session.clear()
            session.permanent = True
            session["uid"] = row["id"]
            session["username"] = row["username"]
            return redirect(url_for("index"))
        error = "שם המשתמש או הסיסמה לא נכונים"
    return render_template("login.html", mode="login", error=error)


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm") or ""
        if not USER_RX.match(username):
            error = "שם משתמש צריך להיות 2-40 תווים, בלי רווחים"
        elif len(password) < 6:
            error = "הסיסמה צריכה להיות באורך 6 תווים לפחות"
        elif password != confirm:
            error = "הסיסמאות לא תואמות"
        else:
            try:
                cur = db().execute(
                    "INSERT INTO users (username, pw_hash, created_at) VALUES (?, ?, ?)",
                    (username, generate_password_hash(password, method="pbkdf2:sha256"), time.time()),
                )
                db().commit()
                session.clear()
                session.permanent = True
                session["uid"] = cur.lastrowid
                session["username"] = username
                return redirect(url_for("index"))
            except sqlite3.IntegrityError:
                error = "שם המשתמש הזה כבר תפוס"
    return render_template("login.html", mode="register", error=error)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------- app shell
@app.route("/")
@login_required()
def index():
    return send_from_directory(app.static_folder, "index.html", max_age=0)


@app.route("/sw.js")
def service_worker():
    resp = send_from_directory(app.static_folder, "sw.js", max_age=0)
    resp.headers["Service-Worker-Allowed"] = "/"
    return resp


@app.route("/manifest.webmanifest")
def manifest():
    return send_from_directory(app.static_folder, "manifest.webmanifest", mimetype="application/manifest+json")


# ---------------------------------------------------------------- API (every call is scoped to the signed-in user)
def check_name(name: str):
    if not NAME_RX.match(name):
        abort(400)


def require_json():
    # A JSON body can't be sent by a plain cross-site form, which blocks CSRF on writes.
    if request.mimetype != "application/json":
        abort(415)


@app.get("/api/me")
@login_required(api=True)
def me():
    return jsonify(id=session["uid"], username=session["username"])


@app.get("/api/doc/<name>")
@login_required(api=True)
def get_doc(name):
    check_name(name)
    row = db().execute("SELECT body FROM docs WHERE user_id = ? AND name = ?", (session["uid"], name)).fetchone()
    if not row:
        return jsonify(error="not_found"), 404
    return app.response_class(row["body"], mimetype="application/json")


@app.put("/api/doc/<name>")
@login_required(api=True)
def put_doc(name):
    check_name(name)
    require_json()
    raw = request.get_data(as_text=True)
    if len(raw.encode()) > MAX_DOC_BYTES:
        return jsonify(error="too_large"), 413
    try:
        body = json.loads(raw)
    except ValueError:
        abort(400)
    if not isinstance(body, dict):
        abort(400)
    db().execute(
        "INSERT INTO docs (user_id, name, body, updated_at) VALUES (?, ?, ?, ?) "
        "ON CONFLICT(user_id, name) DO UPDATE SET body = excluded.body, updated_at = excluded.updated_at",
        (session["uid"], name, json.dumps(body, ensure_ascii=False), time.time()),
    )
    db().commit()
    return jsonify(ok=True)


@app.delete("/api/doc/<name>")
@login_required(api=True)
def delete_doc(name):
    check_name(name)
    db().execute("DELETE FROM docs WHERE user_id = ? AND name = ?", (session["uid"], name))
    db().commit()
    return jsonify(ok=True)


@app.post("/api/password")
@login_required(api=True)
def change_password():
    require_json()
    data = request.get_json(silent=True) or {}
    row = db().execute("SELECT pw_hash FROM users WHERE id = ?", (session["uid"],)).fetchone()
    if not row or not check_password_hash(row["pw_hash"], data.get("current", "")):
        return jsonify(error="wrong_password"), 403
    if len(data.get("new", "")) < 6:
        return jsonify(error="too_short"), 400
    db().execute("UPDATE users SET pw_hash = ? WHERE id = ?", (generate_password_hash(data["new"], method="pbkdf2:sha256"), session["uid"]))
    db().commit()
    return jsonify(ok=True)


@app.after_request
def security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    return resp


def lan_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Zorem – local budget app")
    ap.add_argument("--lan", action="store_true", help="allow phones on the same Wi-Fi to connect")
    ap.add_argument("--port", type=int, default=5000)
    args = ap.parse_args()
    init_db()
    host = "0.0.0.0" if args.lan else "127.0.0.1"
    print("\n  Zorem is running  ·  האפליקציה פועלת")
    print(f"  במחשב הזה:   http://127.0.0.1:{args.port}")
    if args.lan:
        print(f"  בטלפון (באותה רשת Wi-Fi):   http://{lan_ip()}:{args.port}")
    print("  לעצירה: Ctrl+C\n")
    try:
        from waitress import serve  # production-grade server, if installed
        serve(app, host=host, port=args.port)
    except ImportError:
        app.run(host=host, port=args.port, debug=False)
