import os, json, sqlite3, hashlib, secrets, time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

ROOT = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(ROOT, "arrow_escape.db")
HOST, PORT = "127.0.0.1", 8080
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
INITIAL_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

def connect():
    db = sqlite3.connect(DB, timeout=10)
    db.row_factory = sqlite3.Row
    return db

def password_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 200000)
    return salt, digest.hex()

def init_db():
    with connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS admins(
          username TEXT PRIMARY KEY, salt TEXT NOT NULL, digest TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS scores(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          player TEXT NOT NULL, level INTEGER NOT NULL,
          score INTEGER NOT NULL, created INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions(
          token_hash TEXT PRIMARY KEY, expires INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS score_order ON scores(level DESC, score DESC);
        """)
        row = db.execute("SELECT username FROM admins WHERE username=?", (ADMIN_USER,)).fetchone()
        if not row:
            if len(INITIAL_PASSWORD) < 12:
                raise SystemExit("Set ADMIN_PASSWORD to a password of at least 12 characters before starting.")
            salt, digest = password_hash(INITIAL_PASSWORD)
            db.execute("INSERT INTO admins VALUES(?,?,?)", (ADMIN_USER, salt, digest))
    print("SQLite database ready:", DB)

def verify_admin(username, password):
    with connect() as db:
        row = db.execute("SELECT * FROM admins WHERE username=?", (username,)).fetchone()
    if not row:
        return False
    salt, digest = password_hash(password, row["salt"])
    return secrets.compare_digest(digest, row["digest"])

def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()

def admin_session(handler):
    cookie = handler.headers.get("Cookie", "")
    token = ""
    for item in cookie.split(";"):
        if item.strip().startswith("arrow_admin="):
            token = item.strip().split("=", 1)[1]
    if not token:
        return False
    with connect() as db:
        row = db.execute("SELECT expires FROM sessions WHERE token_hash=?", (token_hash(token),)).fetchone()
    return bool(row and row["expires"] > int(time.time()))

class Handler(BaseHTTPRequestHandler):
    def reply(self, status, obj, extra=None):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def body(self):
        n = int(self.headers.get("Content-Length", "0"))
        if n > 10000:
            raise ValueError("Request too large")
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            try:
                with open(os.path.join(ROOT, "index.html"), "rb") as f:
                    data = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except OSError:
                self.reply(404, {"error": "index.html not found"})
            return

        if path == "/api/leaderboard":
            with connect() as db:
                rows = db.execute(
                    "SELECT player,level,score,created FROM scores ORDER BY level DESC,score DESC,created ASC LIMIT 50"
                ).fetchall()
            self.reply(200, {"scores": [dict(r) for r in rows]})
            return

        if path == "/api/admin/me":
            self.reply(200, {"authenticated": admin_session(self)})
            return

        if path == "/api/admin/data":
            if not admin_session(self):
                self.reply(401, {"error": "Admin login required"})
                return
            with connect() as db:
                rows = db.execute(
                    "SELECT id,player,level,score,created FROM scores ORDER BY created DESC LIMIT 200"
                ).fetchall()
                count = db.execute("SELECT COUNT(*) AS n FROM scores").fetchone()["n"]
            self.reply(200, {"scores": [dict(r) for r in rows], "total": count})
            return

        self.reply(404, {"error": "Not found"})

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            data = self.body()
        except Exception:
            self.reply(400, {"error": "Invalid request"})
            return

        if path == "/api/admin/login":
            username = str(data.get("username", ""))[:80]
            password = str(data.get("password", ""))
            if not verify_admin(username, password):
                time.sleep(0.5)
                self.reply(401, {"error": "Incorrect username or password"})
                return
            token = secrets.token_urlsafe(32)
            with connect() as db:
                db.execute("DELETE FROM sessions WHERE expires < ?", (int(time.time()),))
                db.execute("INSERT INTO sessions VALUES(?,?)",
                           (token_hash(token), int(time.time()) + 8 * 60 * 60))
            self.reply(200, {"ok": True}, {
                "Set-Cookie": "arrow_admin=" + token + "; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800"
            })
            return

        if path == "/api/admin/logout":
            cookie = self.headers.get("Cookie", "")
            token = next((x.strip().split("=",1)[1] for x in cookie.split(";")
                          if x.strip().startswith("arrow_admin=")), "")
            with connect() as db:
                if token:
                    db.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash(token),))
            self.reply(200, {"ok": True}, {
                "Set-Cookie": "arrow_admin=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
            })
            return

        if path.startswith("/api/admin/"):
            if not admin_session(self):
                self.reply(401, {"error": "Admin login required"})
                return

            if path == "/api/admin/reset":
                with connect() as db:
                    db.execute("DELETE FROM scores")
                self.reply(200, {"ok": True, "message": "Leaderboard cleared"})
                return

            if path == "/api/admin/password":
                old = str(data.get("old_password", ""))
                new = str(data.get("new_password", ""))
                if not verify_admin(ADMIN_USER, old):
                    self.reply(403, {"error": "Current password is incorrect"})
                    return
                if len(new) < 12:
                    self.reply(400, {"error": "New password must be at least 12 characters"})
                    return
                salt, digest = password_hash(new)
                with connect() as db:
                    db.execute("UPDATE admins SET salt=?,digest=? WHERE username=?",
                               (salt, digest, ADMIN_USER))
                    db.execute("DELETE FROM sessions")
                self.reply(200, {"ok": True, "message": "Password changed. Please log in again."},
                           {"Set-Cookie": "arrow_admin=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"})
                return
            self.reply(404, {"error": "Unknown admin action"})
            return

        if path == "/api/score":
            player = str(data.get("player", "Player")).strip()[:20] or "Player"
            try:
                level = int(data.get("level", 0))
                score = int(data.get("score", 0))
            except (ValueError, TypeError):
                self.reply(400, {"error": "Invalid score"})
                return
            if not 1 <= level <= 10000 or not 0 <= score <= 100000000:
                self.reply(400, {"error": "Score out of range"})
                return
            with connect() as db:
                db.execute("INSERT INTO scores(player,level,score,created) VALUES(?,?,?,?)",
                           (player, level, score, int(time.time())))
            self.reply(201, {"ok": True})
            return

        self.reply(404, {"error": "Not found"})

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args))

if __name__ == "__main__":
    init_db()
    print("Arrow Escape server: http://127.0.0.1:" + str(PORT))
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
