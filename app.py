"""
Flow
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
import threading
import time
from functools import wraps

from flask import (Flask, abort, g, jsonify, redirect, render_template,
                   request, send_from_directory, session, url_for)
from flask.sessions import SecureCookieSessionInterface
from werkzeug.middleware.proxy_fix import ProxyFix
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


class AdaptiveSessionInterface(SecureCookieSessionInterface):
    """Mark the sign-in cookie Secure whenever the request came over https.
    Plain http (this computer or the home Wi-Fi) keeps working, because there a Secure cookie would be dropped."""
    def get_cookie_secure(self, app):
        return request.is_secure


app.session_interface = AdaptiveSessionInterface()

# Behind an https proxy (nginx, Caddy, Cloudflare tunnel...) set TRUST_PROXY=1, so the app sees the real
# visitor address (for the attempt limit) and knows the visit was https (for the Secure cookie).
if os.environ.get("TRUST_PROXY") == "1":
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)


# ---------------------------------------------------------------- database
def db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA secure_delete = ON")   # deleted data is overwritten, not left behind in the file
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
    # recovery code (stored hashed, like the password); added later, so older databases get the column here
    cols = {r[1] for r in conn.execute("PRAGMA table_info(users)")}
    if "recovery_hash" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN recovery_hash TEXT")
    conn.commit()
    conn.close()


# ---------------------------------------------------------------- recovery codes
# 16 characters from an alphabet without look-alikes (no 0/O, 1/I/L), shown as XXXX-XXXX-XXXX-XXXX (~80 bits)
CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"


def new_recovery_code() -> str:
    raw = "".join(secrets.choice(CODE_ALPHABET) for _ in range(16))
    return "-".join(raw[i:i + 4] for i in range(0, 16, 4))


def normalize_code(code: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", (code or "").upper())


def hash_secret(value: str) -> str:
    return generate_password_hash(value, method="pbkdf2:sha256")


def set_recovery_code(user_id: int) -> str:
    """Create a fresh code for the user, store only its hash, and return the plain code to show once."""
    code = new_recovery_code()
    db().execute("UPDATE users SET recovery_hash = ? WHERE id = ?", (hash_secret(normalize_code(code)), user_id))
    db().commit()
    return code


# ---------------------------------------------------------------- failed-attempt limit
# After 5 wrong tries for the same username, or from the same address, that key is blocked for 15 minutes
# (counted from the 5th failure). Kept in memory, so a server restart clears it.
FAILS: dict = {}     # key -> times of recent failures
BLOCKS: dict = {}    # key -> time the block ends
FAIL_LIMIT, FAIL_WINDOW = 5, 15 * 60
FAILS_LOCK = threading.Lock()


def attempt_keys(kind: str, username: str) -> tuple:
    return (f"{kind}:u:{username.strip().lower()}", f"{kind}:ip:{request.remote_addr or ''}")


def blocked_for(*keys) -> int:
    """Seconds left on the longest active block among the keys (0 = not blocked)."""
    now, left = time.time(), 0
    with FAILS_LOCK:
        for k in keys:
            until = BLOCKS.get(k, 0)
            if until > now:
                left = max(left, int(until - now) + 1)
            else:
                BLOCKS.pop(k, None)
    return left


def too_many_fails(*keys) -> bool:
    return blocked_for(*keys) > 0


def note_fail(*keys):
    now = time.time()
    with FAILS_LOCK:
        for k in keys:
            recent = [t for t in FAILS.get(k, []) if now - t < FAIL_WINDOW] + [now]
            if len(recent) >= FAIL_LIMIT:
                BLOCKS[k] = now + FAIL_WINDOW   # 15 minutes from the 5th failure
                FAILS.pop(k, None)
            else:
                FAILS[k] = recent
        # drop stale entries so the dictionaries don't grow forever
        if len(FAILS) > 10000:
            for k in [k for k, v in FAILS.items() if now - v[-1] >= FAIL_WINDOW]:
                del FAILS[k]


def clear_fails(*keys):
    with FAILS_LOCK:
        for k in keys:
            FAILS.pop(k, None)


def blocked_message(seconds: int) -> str:
    minutes = max(1, -(-seconds // 60))
    when = "בעוד דקה" if minutes == 1 else f"בעוד {minutes} דקות"
    return f"היו יותר מדי ניסיונות שגויים, אז הכניסה נחסמה זמנית לביטחונך. אפשר לנסות שוב {when}."


DUMMY_HASH = hash_secret("not-a-real-code")


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
        keys = attempt_keys("login", username)
        wait = blocked_for(*keys)
        if wait:
            # while blocked, the password isn't checked at all, even a correct one
            return render_template("login.html", mode="login", error=blocked_message(wait)), 429
        row = db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        # check a hash even for unknown users, so response time doesn't reveal which names exist
        ok = check_password_hash(row["pw_hash"] if row else DUMMY_HASH, password) and row is not None
        if ok:
            clear_fails(keys[0])
            session.clear()
            session.permanent = True
            session["uid"] = row["id"]
            session["username"] = row["username"]
            return redirect(url_for("index"))
        note_fail(*keys)
        wait = blocked_for(*keys)
        error = blocked_message(wait) if wait else "שם המשתמש או הסיסמה לא נכונים"
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
                code = new_recovery_code()
                cur = db().execute(
                    "INSERT INTO users (username, pw_hash, recovery_hash, created_at) VALUES (?, ?, ?, ?)",
                    (username, hash_secret(password), hash_secret(normalize_code(code)), time.time()),
                )
                db().commit()
                session.clear()
                session.permanent = True
                session["uid"] = cur.lastrowid
                session["username"] = username
                # the code is shown once, right here, and never stored in plain text
                return render_template("login.html", mode="code", code=code, reason="new")
            except sqlite3.IntegrityError:
                error = "שם המשתמש הזה כבר תפוס"
    return render_template("login.html", mode="register", error=error)


@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    error = None
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        code = normalize_code(request.form.get("code"))
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm") or ""
        keys = attempt_keys("forgot", username)
        wait = blocked_for(*keys)
        if wait:
            return render_template("login.html", mode="forgot", error=blocked_message(wait)), 429
        elif len(password) < 6:
            error = "הסיסמה צריכה להיות באורך 6 תווים לפחות"
        elif password != confirm:
            error = "הסיסמאות לא תואמות"
        else:
            row = db().execute("SELECT id, username, recovery_hash FROM users WHERE username = ?", (username,)).fetchone()
            stored = row["recovery_hash"] if row and row["recovery_hash"] else DUMMY_HASH
            ok = check_password_hash(stored, code) and row is not None and bool(row["recovery_hash"])
            if not ok:
                note_fail(*keys)
                wait = blocked_for(*keys)
                # same message whether the user exists or not
                error = blocked_message(wait) if wait else "שם המשתמש או קוד השחזור לא נכונים"
            else:
                clear_fails(keys[0])
                db().execute("UPDATE users SET pw_hash = ? WHERE id = ?", (hash_secret(password), row["id"]))
                db().commit()
                # a used code is retired: the user gets a new one, shown once
                new_code = set_recovery_code(row["id"])
                session.clear()
                session.permanent = True
                session["uid"] = row["id"]
                session["username"] = row["username"]
                return render_template("login.html", mode="code", code=new_code, reason="reset")
    return render_template("login.html", mode="forgot", error=error)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("index"))


# ---------------------------------------------------------------- app shell
@app.route("/")
def index():
    # visitors who aren't signed in see the welcome page; signed-in users get the app
    if not session.get("uid"):
        return render_template("welcome.html")
    return send_from_directory(app.static_folder, "index.html", max_age=0)


@app.route("/robots.txt")
def robots():
    body = "User-agent: *\nAllow: /$\nAllow: /login\nAllow: /register\nDisallow: /api/\n"
    return app.response_class(body, mimetype="text/plain")


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
    row = db().execute("SELECT recovery_hash FROM users WHERE id = ?", (session["uid"],)).fetchone()
    return jsonify(id=session["uid"], username=session["username"], has_recovery=bool(row and row["recovery_hash"]))


@app.post("/api/recovery")
@login_required(api=True)
def make_recovery():
    """Create a new recovery code for the signed-in user. Asks for the current password first."""
    require_json()
    data = request.get_json(silent=True) or {}
    keys = ("rec:" + str(session["uid"]),)
    if too_many_fails(*keys):
        return jsonify(error="too_many"), 429
    row = db().execute("SELECT pw_hash FROM users WHERE id = ?", (session["uid"],)).fetchone()
    if not row or not check_password_hash(row["pw_hash"], data.get("password", "")):
        note_fail(*keys)
        return jsonify(error="wrong_password"), 403
    return jsonify(code=set_recovery_code(session["uid"]))


@app.post("/api/account/delete")
@login_required(api=True)
def delete_account():
    """Permanently delete the signed-in user and everything they saved. Asks for the current password."""
    require_json()
    data = request.get_json(silent=True) or {}
    uid = session["uid"]
    keys = ("del:" + str(uid),)
    if too_many_fails(*keys):
        return jsonify(error="too_many"), 429
    row = db().execute("SELECT pw_hash FROM users WHERE id = ?", (uid,)).fetchone()
    if not row or not check_password_hash(row["pw_hash"], data.get("password", "")):
        note_fail(*keys)
        return jsonify(error="wrong_password"), 403
    conn = db()
    with conn:   # one transaction: either everything is deleted or nothing is
        conn.execute("DELETE FROM docs WHERE user_id = ?", (uid,))
        conn.execute("DELETE FROM users WHERE id = ?", (uid,))
    session.clear()
    return jsonify(ok=True)


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
    if request.path in ("/register", "/forgot", "/api/recovery"):
        resp.headers["Cache-Control"] = "no-store"   # pages that may show a recovery code
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
    ap = argparse.ArgumentParser(description="Flow – local budget app")
    ap.add_argument("--lan", action="store_true", help="allow phones on the same Wi-Fi to connect")
    ap.add_argument("--port", type=int, default=5000)
    args = ap.parse_args()
    init_db()
    host = "0.0.0.0" if args.lan else "127.0.0.1"
    print("\n  Flow is running  ·  האפליקציה פועלת")
    print(f"  במחשב הזה:   http://127.0.0.1:{args.port}")
    if args.lan:
        print(f"  בטלפון (באותה רשת Wi-Fi):   http://{lan_ip()}:{args.port}")
    print("  לעצירה: Ctrl+C\n")
    try:
        from waitress import serve  # production-grade server, if installed
        serve(app, host=host, port=args.port)
    except ImportError:
        app.run(host=host, port=args.port, debug=False)
