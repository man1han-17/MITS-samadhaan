#!/usr/bin/env python3
"""MITS Samadhan local web application (Python standard library + SQLite)."""
from __future__ import annotations

import hashlib
import hmac
import html
import json
import email.policy
from email.parser import BytesParser
import mimetypes
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
from datetime import datetime, timezone
from getpass import getpass
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("MITS_DATA_DIR", str(ROOT))).expanduser()
DB_PATH = DATA_DIR / "samadhan.db"
UPLOAD_DIR = DATA_DIR / "uploads"
HOST = os.environ.get("HOST", os.environ.get("MITS_HOST", "127.0.0.1"))
PORT = int(os.environ.get("PORT", os.environ.get("MITS_PORT", "8000")))
SETUP_KEY = os.environ.get("MITS_SETUP_KEY", "")
SECURE_COOKIE = os.environ.get("MITS_SECURE_COOKIE", "0").lower() in {"1", "true", "yes"}
MAX_REQUEST = 32 * 1024 * 1024
MAX_FILE = 5 * 1024 * 1024
MAX_FILES = 6
ITERATIONS = 260_000
COOKIE = "mits_session"
DB_LOCK = threading.RLock()

STATUSES = {"Submitted", "Under Review", "Rejected", "Accepted", "Assigned", "In Progress", "Resolved", "Confirmed"}
CATEGORIES = {"Electricity", "Water leakage", "AC", "Projector", "Furniture", "Other"}
URGENCIES = {"Normal", "Urgent", "Emergency / safety issue"}
ALLOWED_FILE_TYPES = {"image/jpeg", "image/png", "image/gif", "image/webp", "video/mp4", "video/quicktime", "video/webm"}
FILE_EXTENSIONS = {"image/jpeg":".jpg", "image/png":".png", "image/gif":".gif", "image/webp":".webp", "video/mp4":".mp4", "video/quicktime":".mov", "video/webm":".webm"}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect() -> sqlite3.Connection:
    db = sqlite3.connect(DB_PATH, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    return db


def init_db() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    UPLOAD_DIR.mkdir(exist_ok=True)
    with DB_LOCK, connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
          id TEXT PRIMARY KEY COLLATE NOCASE, name TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('Student','Faculty','Management')),
          salt BLOB NOT NULL, password_hash BLOB NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
          token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          expires_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS complaints (
          id TEXT PRIMARY KEY, reporter_id TEXT NOT NULL REFERENCES users(id), reporter_name TEXT NOT NULL,
          category TEXT NOT NULL, location_type TEXT NOT NULL CHECK(location_type IN ('Campus','Hostel')),
          place TEXT NOT NULL, block TEXT NOT NULL DEFAULT '', floor TEXT NOT NULL, room TEXT NOT NULL,
          description TEXT NOT NULL, urgency TEXT NOT NULL, status TEXT NOT NULL,
          estimate TEXT NOT NULL DEFAULT '', assignee TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '',
          reason TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS attachments (
          id INTEGER PRIMARY KEY AUTOINCREMENT, complaint_id TEXT NOT NULL REFERENCES complaints(id) ON DELETE CASCADE,
          original_name TEXT NOT NULL, stored_name TEXT NOT NULL, content_type TEXT NOT NULL, size INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit (
          id INTEGER PRIMARY KEY AUTOINCREMENT, complaint_id TEXT NOT NULL REFERENCES complaints(id) ON DELETE CASCADE,
          actor_id TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_complaints_status ON complaints(status);
        CREATE INDEX IF NOT EXISTS idx_complaints_created ON complaints(created_at);
        CREATE INDEX IF NOT EXISTS idx_audit_complaint ON audit(complaint_id, id);
        """)


def password_hash(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)


def create_account(user_id: str, name: str, role: str, password: str) -> None:
    salt = secrets.token_bytes(16)
    with DB_LOCK, connect() as db:
        db.execute("INSERT INTO users(id,name,role,salt,password_hash,created_at) VALUES(?,?,?,?,?,?)",
                   (user_id.strip(), name.strip(), role, salt, password_hash(password, salt), now_iso()))


def create_initial_management() -> None:
    with connect() as db:
        if db.execute("SELECT 1 FROM users WHERE role='Management' LIMIT 1").fetchone():
            return
    print("\nFirst-time MITS Samadhan setup: create the management account.")
    while True:
        user_id = input("Management ID: ").strip()
        name = input("Management display name: ").strip()
        password = getpass("Management password (minimum 10 characters): ")
        confirm = getpass("Confirm password: ")
        if not user_id or not name:
            print("ID and name are required.")
        elif len(password) < 10:
            print("Use at least 10 characters for the password.")
        elif password != confirm:
            print("Passwords did not match.")
        else:
            create_account(user_id, name, "Management", password)
            print("Management account created. Starting the website now.")
            return


class Handler(SimpleHTTPRequestHandler):
    server_version = "MITS-Samadhan/1.0"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def log_message(self, fmt, *args):
        print("[%s] %s" % (self.log_date_time_string(), fmt % args))

    def json_response(self, status: int, payload: dict, headers: dict | None = None):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if headers:
            for key, value in headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length > MAX_REQUEST:
            raise ValueError("Request is too large.")
        try:
            value = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError as exc:
            raise ValueError("Invalid JSON request.") from exc
        if not isinstance(value, dict):
            raise ValueError("Expected a JSON object.")
        return value

    def read_multipart(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > MAX_REQUEST:
            raise ValueError("Upload is empty or larger than 32 MB.")
        content_type = self.headers.get("Content-Type", "")
        if not content_type.lower().startswith("multipart/form-data"):
            raise ValueError("Expected a multipart form upload.")
        body = self.rfile.read(length)
        message = BytesParser(policy=email.policy.default).parsebytes(
            b"Content-Type: " + content_type.encode("ascii", "replace") + b"\r\nMIME-Version: 1.0\r\n\r\n" + body
        )
        if not message.is_multipart():
            raise ValueError("Upload form could not be read.")
        fields, files = {}, []
        for part in message.iter_parts():
            name = part.get_param("name", header="content-disposition")
            if not name:
                continue
            payload = part.get_payload(decode=True) or b""
            filename = part.get_filename()
            if filename is not None:
                files.append((name, filename, part.get_content_type(), payload))
            else:
                charset = part.get_content_charset() or "utf-8"
                fields[name] = payload.decode(charset, "replace")
        return fields, files

    def user(self):
        raw = self.headers.get("Cookie", "")
        token = ""
        for part in raw.split(";"):
            key, sep, value = part.strip().partition("=")
            if sep and key == COOKIE:
                token = value
                break
        if not token:
            return None
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        with DB_LOCK, connect() as db:
            row = db.execute("SELECT u.id,u.name,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?",
                             (token_hash, int(time.time()))).fetchone()
            return dict(row) if row else None

    def require_user(self, roles: set[str] | None = None):
        user = self.user()
        if not user:
            self.json_response(401, {"error": "Please sign in."})
            return None
        if roles and user["role"] not in roles:
            self.json_response(403, {"error": "You do not have access to this action."})
            return None
        return user

    def audit(self, db, complaint_id: str, actor: str, action: str, detail: str = ""):
        db.execute("INSERT INTO audit(complaint_id,actor_id,action,detail,created_at) VALUES(?,?,?,?,?)",
                   (complaint_id, actor, action, detail[:2000], now_iso()))

    def do_GET(self):
        path = urlparse(self.path).path
        if path.startswith("/uploads/") or path in {"/samadhan.db", "/samadhan.db-shm", "/samadhan.db-wal", "/server.py", "/.gitignore"}:
            return self.json_response(404, {"error": "Not found."})
        if path == "/api/me":
            user = self.user()
            return self.json_response(200, {"user": user})
        if path == "/api/setup-status":
            with DB_LOCK, connect() as db:
                exists = db.execute("SELECT 1 FROM users WHERE role='Management' LIMIT 1").fetchone() is not None
            return self.json_response(200, {"management_exists": exists, "setup_key_required": bool(SETUP_KEY and not exists)})
        if path == "/api/complaints":
            user = self.require_user()
            if not user: return
            query = self.path.partition("?")[2]
            from urllib.parse import parse_qs
            filters = parse_qs(query)
            where, values = [], []
            if user["role"] != "Management":
                where.append("c.reporter_id=?"); values.append(user["id"])
            for param, column in [("status", "c.status"), ("category", "c.category"), ("urgency", "c.urgency")]:
                val = filters.get(param, [""])[0]
                if val: where.append(column + "=?"); values.append(val)
            date = filters.get("date", [""])[0]
            if date and re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
                where.append("substr(c.created_at,1,10)=?"); values.append(date)
            q = filters.get("q", [""])[0].strip()
            if q:
                where.append("(c.id LIKE ? OR c.description LIKE ? OR c.place LIKE ? OR c.block LIKE ? OR c.reporter_name LIKE ?)")
                values.extend(["%"+q+"%"]*5)
            sql = "SELECT c.* FROM complaints c" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY CASE WHEN c.urgency='Emergency / safety issue' THEN 0 ELSE 1 END, c.created_at DESC"
            with DB_LOCK, connect() as db:
                rows = db.execute(sql, values).fetchall()
                result = []
                for row in rows:
                    c = dict(row)
                    c["files"] = [dict(x) for x in db.execute("SELECT id,original_name,content_type,size FROM attachments WHERE complaint_id=?", (c["id"],))]
                    result.append(c)
            return self.json_response(200, {"complaints": result})
        match = re.fullmatch(r"/api/complaints/([A-Za-z0-9_-]+)/audit", path)
        if match:
            user = self.require_user()
            if not user: return
            complaint_id = match.group(1)
            with DB_LOCK, connect() as db:
                c = db.execute("SELECT reporter_id FROM complaints WHERE id=?", (complaint_id,)).fetchone()
                if not c: return self.json_response(404, {"error": "Complaint not found."})
                if user["role"] != "Management" and c["reporter_id"] != user["id"]:
                    return self.json_response(403, {"error": "You do not have access to this complaint."})
                rows = db.execute("SELECT actor_id,action,detail,created_at FROM audit WHERE complaint_id=? ORDER BY id DESC", (complaint_id,)).fetchall()
                return self.json_response(200, {"audit": [dict(x) for x in rows]})
        match = re.fullmatch(r"/api/files/(\d+)", path)
        if match:
            user = self.require_user()
            if not user: return
            with DB_LOCK, connect() as db:
                row = db.execute("SELECT a.original_name,a.stored_name,a.content_type,c.reporter_id FROM attachments a JOIN complaints c ON c.id=a.complaint_id WHERE a.id=?", (int(match.group(1)),)).fetchone()
            if not row: return self.json_response(404, {"error": "File not found."})
            if user["role"] != "Management" and row["reporter_id"] != user["id"]:
                return self.json_response(403, {"error": "You do not have access to this file."})
            path_on_disk = UPLOAD_DIR / row["stored_name"]
            try: payload = path_on_disk.read_bytes()
            except OSError: return self.json_response(404, {"error": "File is unavailable."})
            self.send_response(200); self.send_header("Content-Type", row["content_type"]); self.send_header("Content-Length", str(len(payload)))
            self.send_header("Content-Disposition", "inline; filename*=UTF-8''" + __import__('urllib.parse').parse.quote(row["original_name"]))
            self.send_header("X-Content-Type-Options", "nosniff"); self.end_headers(); self.wfile.write(payload); return
        if path == "/" or path == "/index.html":
            self.path = "/index.html"
        return super().do_GET()

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            if path == "/api/register": return self.register()
            if path == "/api/login": return self.login()
            if path == "/api/logout": return self.logout()
            if path == "/api/complaints": return self.create_complaint()
            match = re.fullmatch(r"/api/complaints/([A-Za-z0-9_-]+)/action", path)
            if match: return self.complaint_action(match.group(1))
            return self.json_response(404, {"error": "Not found."})
        except ValueError as exc:
            return self.json_response(400, {"error": str(exc)})
        except sqlite3.IntegrityError:
            return self.json_response(409, {"error": "That ID is already registered."})
        except Exception as exc:
            print("Request error:", repr(exc))
            return self.json_response(500, {"error": "The server could not complete that request."})

    def register(self):
        data = self.read_json()
        user_id = str(data.get("id", "")).strip()
        name = str(data.get("name", "")).strip()
        role = str(data.get("role", ""))
        password = str(data.get("password", ""))
        if not re.fullmatch(r"[A-Za-z0-9._-]{3,48}", user_id): raise ValueError("ID must be 3–48 letters, numbers, dots, underscores, or hyphens.")
        if not name or len(name) > 96: raise ValueError("Enter a name up to 96 characters.")
        if role not in {"Student", "Faculty", "Management"}: raise ValueError("Choose a valid account type.")
        if len(password) < 10: raise ValueError("Use a password with at least 10 characters.")
        if role == "Management":
            if SETUP_KEY and not hmac.compare_digest(str(data.get("setup_key", "")), SETUP_KEY):
                return self.json_response(403, {"error": "Enter the deployment setup key to create the first management account."})
            with DB_LOCK, connect() as db:
                if db.execute("SELECT 1 FROM users WHERE role='Management' LIMIT 1").fetchone():
                    raise ValueError("The first management account is already set up. Register as a student or faculty member.")
                create_account(user_id, name, role, password)
        else:
            create_account(user_id, name, role, password)
        return self.login_with_credentials(user_id, password)

    def login(self):
        data = self.read_json()
        return self.login_with_credentials(str(data.get("id", "")).strip(), str(data.get("password", "")))

    def login_with_credentials(self, user_id: str, password: str):
        with DB_LOCK, connect() as db:
            row = db.execute("SELECT * FROM users WHERE id=? COLLATE NOCASE", (user_id,)).fetchone()
            if not row or not hmac.compare_digest(row["password_hash"], password_hash(password, row["salt"])):
                return self.json_response(401, {"error": "ID or password is incorrect."})
            token = secrets.token_urlsafe(32)
            db.execute("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)",
                       (hashlib.sha256(token.encode()).hexdigest(), row["id"], int(time.time()) + 60*60*24*7))
        secure = "; Secure" if SECURE_COOKIE else ""
        cookie = f"{COOKIE}={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={60*60*24*7}{secure}"
        return self.json_response(200, {"user": {"id": row["id"], "name": row["name"], "role": row["role"]}}, {"Set-Cookie": cookie})

    def logout(self):
        raw = self.headers.get("Cookie", "")
        token = next((p.strip().split("=",1)[1] for p in raw.split(";") if p.strip().startswith(COOKIE+"=")), "")
        if token:
            with DB_LOCK, connect() as db: db.execute("DELETE FROM sessions WHERE token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),))
        secure = "; Secure" if SECURE_COOKIE else ""
        return self.json_response(200, {"ok": True}, {"Set-Cookie": f"{COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0{secure}"})

    def create_complaint(self):
        user = self.require_user({"Student", "Faculty"})
        if not user: return
        fields, uploaded = self.read_multipart()
        def val(key): return str(fields.get(key, "")).strip()
        category, location_type, urgency = val("category"), val("locationType"), val("urgency")
        place, floor, room = val("place"), val("floor"), val("room")
        block, description = val("block"), val("description")
        if category not in CATEGORIES: raise ValueError("Choose a valid category.")
        if location_type not in {"Campus", "Hostel"}: raise ValueError("Choose Campus or Hostel.")
        if urgency not in URGENCIES: raise ValueError("Choose a valid urgency.")
        if not all([place, floor, room, description]): raise ValueError("Location and description fields are required.")
        if location_type == "Hostel" and not block: raise ValueError("Enter the hostel block.")
        if len(description) > 2000: raise ValueError("Description is too long (maximum 2000 characters).")
        files = [f for f in uploaded if f[0] == "attachments" and f[1]]
        if len(files) > MAX_FILES: raise ValueError("Attach at most 6 files.")
        for _, filename, content_type, payload in files:
            if content_type not in ALLOWED_FILE_TYPES: raise ValueError("Unsupported attachment type. Use an image or video file.")
            if len(payload) > MAX_FILE: raise ValueError("Each attachment must be 5 MB or smaller.")
            if len(filename) > 255: raise ValueError("Attachment filename is too long.")
        complaint_id = "MS-" + datetime.now().strftime("%Y") + "-" + secrets.token_hex(4).upper()
        now = now_iso()
        stored = []
        try:
            for _, filename, content_type, payload in files:
                original_name = Path(filename.replace("\\", "/")).name
                ext = FILE_EXTENSIONS[content_type]
                stored_name = secrets.token_hex(16) + ext
                (UPLOAD_DIR / stored_name).write_bytes(payload)
                stored.append((original_name[:255], stored_name, content_type, len(payload)))
            with DB_LOCK, connect() as db:
                db.execute("INSERT INTO complaints(id,reporter_id,reporter_name,category,location_type,place,block,floor,room,description,urgency,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                           (complaint_id,user["id"],user["name"],category,location_type,place,block,floor,room,description,urgency,"Submitted",now,now))
                for original, stored_name, content_type, size in stored:
                    db.execute("INSERT INTO attachments(complaint_id,original_name,stored_name,content_type,size) VALUES(?,?,?,?,?)", (complaint_id,original,stored_name,content_type,size))
                self.audit(db, complaint_id, user["id"], "Submitted", "Complaint registered")
        except Exception:
            for _, stored_name, _, _ in stored:
                try: (UPLOAD_DIR / stored_name).unlink()
                except OSError: pass
            raise
        return self.json_response(201, {"id": complaint_id})

    def complaint_action(self, complaint_id: str):
        user = self.require_user()
        if not user: return
        data = self.read_json()
        action = str(data.get("action", ""))
        detail = str(data.get("detail", "")).strip()
        with DB_LOCK, connect() as db:
            c = db.execute("SELECT * FROM complaints WHERE id=?", (complaint_id,)).fetchone()
            if not c: return self.json_response(404, {"error": "Complaint not found."})
            management = user["role"] == "Management"
            if not management and c["reporter_id"] != user["id"]:
                return self.json_response(403, {"error": "You can only update your own complaint."})
            status = c["status"]
            update = {"updated_at": now_iso()}
            audit_action = action
            if management:
                if action == "review" and status == "Submitted": update.update(status="Under Review", note="Your complaint is being reviewed."); detail="Management started verification."
                elif action == "accept" and status in {"Submitted", "Under Review"}: update.update(status="Accepted", note="Your complaint has been accepted."); detail="Complaint verified and accepted."
                elif action == "reject" and status in {"Submitted", "Under Review"} and detail: update.update(status="Rejected", reason=detail)
                elif action == "estimate" and status in {"Accepted", "Assigned"} and detail: update.update(estimate=detail)
                elif action == "assign" and status in {"Accepted", "Assigned"} and detail:
                    assignee = str(data.get("assignee", "")).strip()
                    if not assignee: raise ValueError("Enter the responsible person or team.")
                    update.update(status="Assigned", assignee=assignee[:96], estimate=detail)
                    detail = "Assigned to " + assignee[:96] + "; estimate: " + detail
                elif action == "progress" and status in {"Assigned", "In Progress"} and detail: update.update(status="In Progress", note=detail)
                elif action == "resolve" and status == "In Progress" and detail: update.update(status="Resolved", note=detail)
                else: return self.json_response(409, {"error": "That action is not allowed for the complaint's current status."})
            else:
                if action == "confirm" and status == "Resolved": update.update(status="Confirmed", note="Reporter confirmed the issue is fixed."); detail="Reporter confirmed the repair."
                elif action == "reopen" and status == "Resolved" and detail: update.update(status="In Progress", note=detail)
                elif action == "resubmit" and status == "Rejected":
                    description = str(data.get("description", "")).strip()
                    place = str(data.get("place", "")).strip()
                    floor = str(data.get("floor", "")).strip()
                    room = str(data.get("room", "")).strip()
                    if not description or not place or not floor or not room: raise ValueError("Corrected description and location are required.")
                    update.update(status="Submitted", reason="", description=description[:2000], place=place[:96], floor=floor[:96], room=room[:96], note="Corrected complaint resubmitted for review.")
                    detail="Reporter corrected and resubmitted the complaint."
                else: return self.json_response(409, {"error": "That action is not allowed for the complaint's current status."})
            fields = ",".join(f"{key}=?" for key in update)
            db.execute(f"UPDATE complaints SET {fields} WHERE id=?", (*update.values(), complaint_id))
            self.audit(db, complaint_id, user["id"], audit_action, detail)
        return self.json_response(200, {"ok": True})

    def do_HEAD(self):
        return super().do_HEAD()


def main() -> None:
    init_db()
    if "--setup" in sys.argv:
        create_initial_management()
        return
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"MITS Samadhan is running on {HOST}:{PORT}")
    print("On first visit, create the management account in the website.")
    print(f"Press Ctrl+C to stop. Data is stored in {DB_PATH}; uploaded files are in {UPLOAD_DIR}/.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
