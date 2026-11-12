"""Call Coaching & Performance client app. FastAPI + Postgres (SQLite locally)."""
import base64, hashlib, hmac, json, os, re, secrets, time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, File, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel
from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, Integer, LargeBinary, String, Text, create_engine
from sqlalchemy.orm import Session as DB, declarative_base, sessionmaker
from sqlalchemy.orm.attributes import flag_modified

HERE = Path(__file__).parent
def _db_env():
    """Find the database address even if the variable name is typed in a different case or uses an older Railway name."""
    env = {k.upper(): (v or "").strip() for k, v in os.environ.items()}
    for k in ("DATABASE_URL", "DATABASE_PRIVATE_URL", "DATABASE_PUBLIC_URL", "POSTGRES_URL"):
        if env.get(k):
            return env[k]
    if env.get("PGHOST") and env.get("PGUSER"):
        return f"postgresql://{env['PGUSER']}:{env.get('PGPASSWORD', '')}@{env['PGHOST']}:{env.get('PGPORT', '5432')}/{env.get('PGDATABASE', 'railway')}"
    return ""


DB_VARS_SEEN = sorted(f"{k}{'' if (v or '').strip() else ' (empty)'}" for k, v in os.environ.items() if re.search(r"database|^pg|postgres", k, re.I))
url = _db_env()
if url.startswith("postgres://"):
    url = url.replace("postgres://", "postgresql+psycopg://", 1)
elif url.startswith("postgresql://"):
    url = url.replace("postgresql://", "postgresql+psycopg://", 1)
ON_RAILWAY = any(os.environ.get(k) for k in ("RAILWAY_ENVIRONMENT", "RAILWAY_ENVIRONMENT_NAME", "RAILWAY_PROJECT_ID"))
# On Railway the app must use Postgres. Without it, it would write to a throwaway file that every deploy wipes.
DB_MISSING = ON_RAILWAY and not url
if DB_MISSING:
    print("ERROR: DATABASE_URL is empty. Set it to ${{ Postgres.DATABASE_URL }} on this service. The app is refusing to save anything until then.", flush=True)
url = url or os.environ.get("LOCAL_DB", "sqlite:///callapp.db")
engine = create_engine(url, connect_args={"check_same_thread": False} if url.startswith("sqlite") else {}, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


def now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Client(Base):
    __tablename__ = "clients"
    id = Column(Integer, primary_key=True)
    name = Column(String(120), default="")
    phone = Column(String(10), unique=True, nullable=True)
    code = Column(String(6), nullable=True)
    code_tries = Column(Integer, default=0)
    password_hash = Column(String(300), nullable=True)
    data = Column(JSON, default=dict)
    created = Column(DateTime, default=now)


class Sess(Base):
    __tablename__ = "sessions"
    id = Column(Integer, primary_key=True)
    client_id = Column(Integer, ForeignKey("clients.id", ondelete="CASCADE"), index=True)
    date = Column(String(10), index=True)
    minutes = Column(Integer)
    length = Column(Integer, default=60)
    title = Column(String(80), default="Session")
    done = Column(Boolean, default=False)
    repeat = Column(Boolean, default=False)


class CheckIn(Base):
    __tablename__ = "checkins"
    id = Column(Integer, primary_key=True)
    client_id = Column(Integer, ForeignKey("clients.id", ondelete="CASCADE"), index=True)
    answers = Column(JSON, default=dict)
    reply = Column(Text, default="")
    replied_at = Column(DateTime, nullable=True)
    created = Column(DateTime, default=now)


class FileRow(Base):
    __tablename__ = "files"
    id = Column(Integer, primary_key=True)
    client_id = Column(Integer, ForeignKey("clients.id", ondelete="CASCADE"), index=True)
    name = Column(String(200))
    mime = Column(String(100))
    blob = Column(LargeBinary)
    created = Column(DateTime, default=now)


class Setting(Base):
    __tablename__ = "settings"
    key = Column(String(50), primary_key=True)
    value = Column(JSON)


Base.metadata.create_all(engine)

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


def db():
    s = SessionLocal()
    try:
        yield s
    finally:
        s.close()


def get_setting(s: DB, key, default=None):
    row = s.get(Setting, key)
    return row.value if row else default


def set_setting(s: DB, key, value):
    row = s.get(Setting, key)
    if row:
        row.value = value
    else:
        s.add(Setting(key=key, value=value))
    s.commit()


def secret_key() -> bytes:
    env = os.environ.get("SECRET_KEY", "")
    if env:
        return env.encode()
    s = SessionLocal()
    try:
        val = get_setting(s, "secret")
        if not val:
            val = secrets.token_hex(32)
            set_setting(s, "secret", val)
        return val.encode()
    finally:
        s.close()


SECRET = secret_key()
COOKIE = "call_session"
FAILS: dict = {}


def too_many(key: str) -> bool:
    t = time.time()
    FAILS[key] = [x for x in FAILS.get(key, []) if t - x < 900]
    return len(FAILS[key]) >= 8


def failed(key: str):
    FAILS.setdefault(key, []).append(time.time())


def hash_pw(pw: str) -> str:
    salt = secrets.token_bytes(16)
    d = hashlib.scrypt(pw.encode(), salt=salt, n=2 ** 14, r=8, p=1)
    return salt.hex() + "$" + d.hex()


def check_pw(pw: str, stored: Optional[str]) -> bool:
    if not stored:
        return False
    salt, d = stored.split("$")
    return hmac.compare_digest(hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=2 ** 14, r=8, p=1).hex(), d)


def make_token(payload: dict) -> str:
    raw = base64.urlsafe_b64encode(json.dumps({**payload, "exp": int(time.time()) + 30 * 86400}).encode()).decode()
    return raw + "." + hmac.new(SECRET, raw.encode(), hashlib.sha256).hexdigest()


def read_token(tok: Optional[str]):
    if not tok or "." not in tok:
        return None
    raw, sig = tok.rsplit(".", 1)
    if not hmac.compare_digest(sig, hmac.new(SECRET, raw.encode(), hashlib.sha256).hexdigest()):
        return None
    p = json.loads(base64.urlsafe_b64decode(raw))
    return p if p.get("exp", 0) > time.time() else None


def set_login(resp: Response, req: Request, payload: dict):
    secure = req.headers.get("x-forwarded-proto", req.url.scheme) == "https"
    resp.set_cookie(COOKIE, make_token(payload), httponly=True, samesite="lax", secure=secure, max_age=30 * 86400, path="/")


def current(req: Request, s: DB = Depends(db)):
    p = read_token(req.cookies.get(COOKIE))
    if not p:
        return None
    if p.get("role") == "admin":
        return {"role": "admin"}
    c = s.get(Client, p.get("id"))
    if not c or not c.password_hash or c.password_hash[-8:] != p.get("v"):
        return None
    return {"role": "client", "client": c}


def need_admin(me=Depends(current)):
    if not me or me["role"] != "admin":
        raise HTTPException(401, "Please sign in.")
    return me


def need_client(me=Depends(current)):
    if not me or me["role"] != "client":
        raise HTTPException(401, "Please sign in.")
    return me["client"]


def clean_phone(v: str) -> str:
    d = re.sub(r"\D", "", v or "")
    if len(d) == 11 and d.startswith("1"):
        d = d[1:]
    return d


def new_code() -> str:
    return f"{secrets.randbelow(10 ** 6):06d}"


def sess_json(x: Sess, with_client=False):
    out = {"id": x.id, "date": x.date, "minutes": x.minutes, "length": x.length, "title": x.title, "done": x.done, "repeat": x.repeat}
    if with_client:
        out["client_id"] = x.client_id
    return out


def checkin_json(x: CheckIn, with_client=False):
    out = {"id": x.id, "answers": x.answers or {}, "reply": x.reply or "", "created": x.created.isoformat(), "replied_at": x.replied_at.isoformat() if x.replied_at else None}
    if with_client:
        out["client_id"] = x.client_id
    return out


def file_json(x: FileRow, with_client=False):
    out = {"id": x.id, "name": x.name, "created": x.created.date().isoformat()}
    if with_client:
        out["client_id"] = x.client_id
    return out


DEFAULT_WAIVER = """TRAINING AGREEMENT AND RELEASE OF LIABILITY
Call Coaching & Performance and Nicholas Call ("Nick")

Please read this carefully. It limits your right to bring a claim if you are hurt.

1. Risks of exercise. Exercise, personal training, cardio, mobility work and nutrition changes carry risks, including muscle and joint injuries, illness, heart problems, and in rare cases serious injury or death. You choose to take part and you accept these risks.

2. Your health. You confirm your health answers are true. You will tell Nick about any injury, condition or medication that may affect your training, and update him if anything changes. You should check with your doctor before starting or changing an exercise or nutrition program. Stop and tell Nick if you feel pain, dizziness or anything unusual.

3. Not medical care. Coaching, workouts and nutrition plans are general fitness guidance. They are not medical advice, diagnosis, treatment or physical therapy.

4. Training at Crunch. In-person training takes place at Crunch Fitness Cordova. You must keep an active Crunch membership and follow Crunch's rules. Your Crunch membership agreement and waiver still apply to your use of the gym. This agreement is separate and also applies to your coaching with Nick.

5. Online training. If you train online, you choose where, when and with what equipment you train, and you are responsible for keeping your setup and training safe.

6. Release of liability. To the fullest extent Tennessee law allows, you release Call Coaching & Performance and Nicholas Call from claims for injury, illness, death or property damage connected to your coaching, workouts or nutrition plan, including claims based on ordinary negligence. This release does not cover gross negligence, reckless or intentional conduct, or anything else the law does not allow to be released.

7. Your agreement. You confirm you are at least 18 years old, that you have read and understand this agreement, and that you are accepting it voluntarily. Tennessee law applies."""


def public_settings(s: DB):
    out = {"venmo": "NickCall2003", "cashapp": "determlned", "apple": "9013590305", "phone": "9013590305", "location": "Crunch Fitness Cordova", "waiver": DEFAULT_WAIVER}
    out.update(get_setting(s, "app", {}) or {})
    out["waiver"] = out.get("waiver") or DEFAULT_WAIVER
    return out


# ---------- pages ----------
@app.middleware("http")
async def headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    return resp


@app.get("/", response_class=HTMLResponse)
def index():
    return HTMLResponse((HERE / "index.html").read_text(encoding="utf-8"), headers={"Cache-Control": "no-cache"})


@app.get("/logo.png")
def logo():
    return FileResponse(HERE / "logo.png", media_type="image/png")


@app.get("/link-preview.jpg")
def link_preview():
    return FileResponse(HERE / "link-preview.jpg", media_type="image/jpeg")


@app.get("/manifest.webmanifest")
def manifest():
    return JSONResponse({"name": "Call Coaching", "short_name": "Call", "start_url": "/", "display": "standalone", "background_color": "#0a0e14", "theme_color": "#0a0e14", "icons": [{"src": "/logo.png", "sizes": "192x192", "type": "image/png"}]})


@app.middleware("http")
async def block_without_db(request: Request, call_next):
    if DB_MISSING and request.url.path.startswith("/api/"):
        return JSONResponse({"detail": "The app isn't connected to its database right now, so nothing was changed. Nick: set DATABASE_URL in Railway."}, status_code=503)
    return await call_next(request)


@app.get("/health")
def health():
    out = {"ok": not DB_MISSING, "db": "missing" if DB_MISSING else ("postgres" if url.startswith("postgresql") else "sqlite")}
    if DB_MISSING:
        out["variables_seen"] = DB_VARS_SEEN
    return out


# ---------- auth ----------
class LoginIn(BaseModel):
    phone: str = ""
    password: str = ""


class JoinIn(BaseModel):
    phone: str
    code: str
    password: str = ""
    health: Optional[dict] = None
    agreed: bool = False


@app.get("/api/me")
def me_route(me=Depends(current), s: DB = Depends(db)):
    out = {"role": me["role"] if me else None}
    out["settings"] = {k: v for k, v in public_settings(s).items() if k in ("phone", "waiver")}
    return out


@app.post("/api/login")
def login(body: LoginIn, req: Request, resp: Response, s: DB = Depends(db)):
    key = "login:" + (req.client.host if req.client else "") + clean_phone(body.phone)
    if too_many(key):
        raise HTTPException(429, "Too many tries. Wait 15 minutes or text Nick.")
    c = s.query(Client).filter_by(phone=clean_phone(body.phone)).first()
    if not c or not check_pw(body.password, c.password_hash):
        failed(key)
        raise HTTPException(401, "That number and password don't match.")
    set_login(resp, req, {"role": "client", "id": c.id, "v": c.password_hash[-8:]})
    return {"role": "client"}


@app.post("/api/admin/login")
def admin_login(body: LoginIn, req: Request, resp: Response):
    pw = os.environ.get("ADMIN_PASSWORD", "")
    key = "admin:" + (req.client.host if req.client else "")
    if too_many(key):
        raise HTTPException(429, "Too many tries. Wait 15 minutes.")
    if not pw:
        raise HTTPException(503, "Set ADMIN_PASSWORD in Railway first.")
    if not hmac.compare_digest(body.password.encode(), pw.encode()):
        failed(key)
        raise HTTPException(401, "That password isn't right.")
    set_login(resp, req, {"role": "admin"})
    return {"role": "admin"}


@app.post("/api/logout")
def logout(resp: Response):
    resp.delete_cookie(COOKIE, path="/")
    return {"ok": True}


def match_code(s: DB, phone: str, code: str, req: Request) -> Client:
    bad = HTTPException(400, "That number and code don't match. Text Nick for help.")
    key = "join:" + (req.client.host if req.client else "")
    if too_many(key):
        raise HTTPException(429, "Too many tries. Wait 15 minutes or text Nick.")
    c = s.query(Client).filter_by(phone=clean_phone(phone)).first()
    if not c or not c.code:
        failed(key)
        raise bad
    if not hmac.compare_digest(c.code, re.sub(r"\D", "", code or "")):
        failed(key)
        c.code_tries = (c.code_tries or 0) + 1
        if c.code_tries >= 5:
            c.code, c.code_tries = None, 0
        s.commit()
        raise bad
    return c


@app.post("/api/join/check")
def join_check(body: JoinIn, req: Request, s: DB = Depends(db)):
    c = match_code(s, body.phone, body.code, req)
    return {"first_name": (c.name or "there").split(" ")[0], "needs_health": not (c.data or {}).get("health")}


@app.post("/api/join/complete")
def join_complete(body: JoinIn, req: Request, resp: Response, s: DB = Depends(db)):
    c = match_code(s, body.phone, body.code, req)
    if len(body.password) < 10:
        raise HTTPException(400, "Use at least 10 characters for your password.")
    d = dict(c.data or {})
    if not d.get("health"):
        apply_health(s, d, body.health, body.agreed)
    d.pop("temp_pw", None)
    c.data = d
    flag_modified(c, "data")
    c.password_hash, c.code, c.code_tries = hash_pw(body.password), None, 0
    s.commit()
    set_login(resp, req, {"role": "client", "id": c.id, "v": c.password_hash[-8:]})
    return {"role": "client"}


HEALTH_KEYS = ("doctor", "symptoms", "injury", "scan")


def apply_health(s: DB, d: dict, health, agreed):
    if not agreed or not health or any(health.get(k) not in ("yes", "no") for k in HEALTH_KEYS):
        raise HTTPException(400, "Answer each question and accept the agreement to continue.")
    d["health"] = {k: str(v)[:10] for k, v in health.items() if k in HEALTH_KEYS}
    d["agreed_at"] = now().isoformat()
    d["agreed_text"] = public_settings(s)["waiver"]


# ---------- client ----------
@app.get("/api/client/state")
def client_state(c: Client = Depends(need_client), s: DB = Depends(db)):
    raw = c.data or {}
    d = {k: v for k, v in raw.items() if k not in ("notes", "health", "temp_pw")}
    d["setup"] = {"password": bool(raw.get("temp_pw")), "health": not raw.get("health")}
    return {
        "client": {"id": c.id, "name": c.name, "phone": c.phone, **d},
        "sessions": [sess_json(x) for x in s.query(Sess).filter_by(client_id=c.id).order_by(Sess.date, Sess.minutes)],
        "checkins": [checkin_json(x) for x in s.query(CheckIn).filter_by(client_id=c.id).order_by(CheckIn.created.desc()).limit(26)],
        "files": [file_json(x) for x in s.query(FileRow).filter_by(client_id=c.id).order_by(FileRow.created.desc())],
        "settings": public_settings(s),
    }


class SetupIn(BaseModel):
    password: str = ""
    health: Optional[dict] = None
    agreed: bool = False


@app.post("/api/client/setup")
def client_setup(body: SetupIn, req: Request, resp: Response, c: Client = Depends(need_client), s: DB = Depends(db)):
    """First sign-in after Nick set a temporary login: pick a real password and confirm health + agreement."""
    d = dict(c.data or {})
    if d.get("temp_pw"):
        if len(body.password) < 10:
            raise HTTPException(400, "Use at least 10 characters for your new password.")
        if check_pw(body.password, c.password_hash):
            raise HTTPException(400, "Pick a new password, not the temporary one.")
    if not d.get("health"):
        apply_health(s, d, body.health, body.agreed)
    if d.get("temp_pw"):
        c.password_hash = hash_pw(body.password)
        d.pop("temp_pw", None)
    c.data = d
    flag_modified(c, "data")
    s.commit()
    set_login(resp, req, {"role": "client", "id": c.id, "v": c.password_hash[-8:]})
    return {"ok": True}


class PwIn(BaseModel):
    current: str = ""
    new: str = ""


@app.post("/api/client/password")
def client_password(body: PwIn, req: Request, resp: Response, c: Client = Depends(need_client), s: DB = Depends(db)):
    key = "pw:" + str(c.id)
    if too_many(key):
        raise HTTPException(429, "Too many tries. Wait 15 minutes or text Nick.")
    if not check_pw(body.current, c.password_hash):
        failed(key)
        raise HTTPException(400, "Your current password isn't right.")
    if len(body.new) < 10:
        raise HTTPException(400, "Use at least 10 characters for your new password.")
    c.password_hash = hash_pw(body.new)
    d = dict(c.data or {})
    d.pop("temp_pw", None)
    c.data = d
    flag_modified(c, "data")
    s.commit()
    set_login(resp, req, {"role": "client", "id": c.id, "v": c.password_hash[-8:]})
    return {"ok": True}


class LogIn(BaseModel):
    type: str
    key: str = ""
    value: object = None


def _txt(v, n):
    return str(v if v is not None else "").strip()[:n]


def clean_log_value(kind: str, v):
    """Keep only the fields each kind of entry uses, so a folder can't be stuffed with junk."""
    if v in (None, False, ""):
        return None
    if kind == "workout":
        if not isinstance(v, dict):
            return None
        out = {"w": _txt(v.get("w"), 12), "r": _txt(v.get("r"), 12), "x": _txt(v.get("x"), 80)}
        if v.get("done"):
            out["done"] = True
        out = {k: x for k, x in out.items() if x not in ("", None)}
        return out if (out.get("w") or out.get("r") or out.get("done")) else None
    if kind == "complete":
        if not isinstance(v, dict):
            return None
        def n(x):
            try:
                return max(0, min(int(x), 999))
            except (TypeError, ValueError):
                return 0
        return {"n": _txt(v.get("n"), 80), "s": n(v.get("s")), "t": n(v.get("t")), "note": _txt(v.get("note"), 600)}
    return True if v is True else (_txt(v, 40) or None)


LOG_FIELDS = {"meal": "meals", "extra": "extras", "workout": "workouts", "complete": "completed"}


def apply_log(c: Client, body: LogIn, by: str):
    d = dict(c.data or {})
    if body.type == "weight":
        try:
            w = float(body.value)
        except (TypeError, ValueError):
            raise HTTPException(400, "Enter your weight as a number.")
        if not 30 <= w <= 800:
            raise HTTPException(400, "Enter your weight in pounds.")
        d["weights"] = [x for x in d.get("weights", []) if x.get("date") != body.key[:10]] + [{"date": body.key[:10], "w": w}]
    elif body.type in LOG_FIELDS:
        field = LOG_FIELDS[body.type]
        if not body.key or len(body.key) > 80:
            raise HTTPException(400, "Bad entry.")
        store = dict(d.get(field, {}))
        v = clean_log_value(body.type, body.value)
        if v is None:
            store.pop(body.key, None)
        else:
            if body.type == "complete":
                old = store.get(body.key) or {}
                v["by"] = by
                v["at"] = old.get("at") if old.get("by") == by and old.get("at") else datetime.now(timezone.utc).isoformat(timespec="minutes")
            store[body.key] = v
        d[field] = store
    else:
        raise HTTPException(400, "Unknown entry.")
    if len(json.dumps(d)) > 1_500_000:
        raise HTTPException(400, "This folder is full. Text Nick.")
    c.data = d
    flag_modified(c, "data")


@app.post("/api/client/log")
def client_log(body: LogIn, c: Client = Depends(need_client), s: DB = Depends(db)):
    apply_log(c, body, "client")
    s.commit()
    return {"ok": True}


@app.post("/api/admin/clients/{cid}/log")
def admin_log(cid: int, body: LogIn, _=Depends(need_admin), s: DB = Depends(db)):
    c = s.get(Client, cid) or _404()
    if body.type == "meal":
        raise HTTPException(400, "Only the client logs meals.")
    apply_log(c, body, "nick")
    s.commit()
    return {"ok": True}


@app.post("/api/client/checkin")
def client_checkin(answers: dict, c: Client = Depends(need_client), s: DB = Depends(db)):
    clean = {str(k)[:20]: str(v)[:1000] for k, v in answers.items()}
    if not clean.get("weight"):
        raise HTTPException(400, "Add your weight.")
    s.add(CheckIn(client_id=c.id, answers=clean))
    s.commit()
    return {"ok": True}


@app.get("/api/files/{fid}")
def get_file(fid: int, me=Depends(current), s: DB = Depends(db)):
    f = s.get(FileRow, fid)
    if not me or not f or (me["role"] == "client" and me["client"].id != f.client_id):
        raise HTTPException(404, "File not found.")
    inline = f.mime == "application/pdf" or f.mime.startswith("image/")
    safe = re.sub(r"[^\w.\- ]", "_", f.name)
    return Response(f.blob, media_type=f.mime, headers={"Content-Disposition": f'{"inline" if inline else "attachment"}; filename="{safe}"', "Cache-Control": "private, no-store"})


# ---------- admin ----------
@app.get("/api/admin/state")
def admin_state(_=Depends(need_admin), s: DB = Depends(db)):
    clients = [{"id": c.id, "name": c.name, "phone": c.phone, "code": c.code, "has_account": bool(c.password_hash), **(c.data or {})} for c in s.query(Client).order_by(Client.name)]
    return {
        "clients": clients,
        "sessions": [sess_json(x, True) for x in s.query(Sess).order_by(Sess.date, Sess.minutes)],
        "checkins": [checkin_json(x, True) for x in s.query(CheckIn).order_by(CheckIn.created.desc()).limit(300)],
        "files": [file_json(x, True) for x in s.query(FileRow).order_by(FileRow.created.desc())],
        "settings": public_settings(s),
    }


ADMIN_KEYS = {"format", "goal", "why", "program", "start_w", "goal_w", "amount", "due", "due_label", "current_paid", "plan", "nutrition", "notes", "note", "scans", "weights"}


def apply_phone(s: DB, c: Client, raw: str):
    p = clean_phone(raw)
    if raw and len(p) != 10:
        raise HTTPException(400, "Enter the full 10-digit number.")
    p = p or None
    if p and s.query(Client).filter(Client.phone == p, Client.id != (c.id or 0)).first():
        raise HTTPException(409, "Another client already has that number.")
    if p != c.phone:
        c.phone = p
        if p and not c.password_hash:
            c.code, c.code_tries = new_code(), 0


@app.post("/api/admin/clients")
def add_client(body: dict, _=Depends(need_admin), s: DB = Depends(db)):
    name, raw = str(body.get("name", "")).strip()[:120], str(body.get("phone", "")).strip()
    if not name and not raw:
        raise HTTPException(400, "Add a name or a phone number.")
    c = Client(name=name, data={k: v for k, v in body.items() if k in ADMIN_KEYS})
    apply_phone(s, c, raw)
    s.add(c)
    s.commit()
    return {"id": c.id}


@app.put("/api/admin/clients/{cid}")
def edit_client(cid: int, body: dict, _=Depends(need_admin), s: DB = Depends(db)):
    c = s.get(Client, cid) or _404()
    if "name" in body:
        c.name = str(body["name"]).strip()[:120]
    if "phone" in body:
        apply_phone(s, c, str(body["phone"]).strip())
    d = dict(c.data or {})
    for k, v in body.items():
        if k in ADMIN_KEYS:
            d[k] = v
    c.data = d
    flag_modified(c, "data")
    s.commit()
    return {"ok": True}


def _404():
    raise HTTPException(404, "Not found.")


@app.post("/api/admin/clients/{cid}/login")
def admin_set_login(cid: int, body: dict, _=Depends(need_admin), s: DB = Depends(db)):
    """Nick sets a temporary password. The client picks their own (and confirms health + agreement) on first sign-in."""
    c = s.get(Client, cid) or _404()
    if not c.phone:
        raise HTTPException(400, "Add their phone number first. They sign in with it.")
    pw = str(body.get("password", "")).strip()
    if len(pw) < 8:
        raise HTTPException(400, "Use at least 8 characters for the temporary password.")
    c.password_hash, c.code, c.code_tries = hash_pw(pw), None, 0
    d = dict(c.data or {})
    d["temp_pw"] = True
    c.data = d
    flag_modified(c, "data")
    s.commit()
    return {"ok": True}


@app.delete("/api/admin/clients/{cid}")
def delete_client(cid: int, _=Depends(need_admin), s: DB = Depends(db)):
    c = s.get(Client, cid) or _404()
    for model in (Sess, CheckIn, FileRow):
        s.query(model).filter_by(client_id=cid).delete()
    s.delete(c)
    s.commit()
    return {"ok": True}


@app.post("/api/admin/clients/{cid}/code")
def renew_code(cid: int, _=Depends(need_admin), s: DB = Depends(db)):
    c = s.get(Client, cid) or _404()
    if not c.phone:
        raise HTTPException(400, "Add their phone number first.")
    c.code, c.code_tries = new_code(), 0
    s.commit()
    return {"code": c.code}


@app.post("/api/admin/clients/{cid}/paid")
def mark_paid(cid: int, _=Depends(need_admin), s: DB = Depends(db)):
    c = s.get(Client, cid) or _404()
    d = dict(c.data or {})
    if not d.get("current_paid"):
        d["current_paid"] = True
        d["payments"] = d.get("payments", []) + [{"label": d.get("due_label") or "Coaching", "amount": d.get("amount") or 0, "date": date.today().isoformat()}]
    c.data = d
    flag_modified(c, "data")
    s.commit()
    return {"ok": True}


@app.post("/api/admin/clients/{cid}/unpaid")
def undo_paid(cid: int, _=Depends(need_admin), s: DB = Depends(db)):
    c = s.get(Client, cid) or _404()
    d = dict(c.data or {})
    if d.get("current_paid"):
        d["current_paid"] = False
        d["payments"] = d.get("payments", [])[:-1]
    c.data = d
    flag_modified(c, "data")
    s.commit()
    return {"ok": True}


@app.post("/api/admin/sessions")
def add_session(body: dict, _=Depends(need_admin), s: DB = Depends(db)):
    c = s.get(Client, int(body.get("client_id", 0))) or _404()
    try:
        start = date.fromisoformat(str(body.get("date")))
        minutes = int(body.get("minutes"))
    except (TypeError, ValueError):
        raise HTTPException(400, "Pick a date and time.")
    if s.query(Sess).filter_by(date=start.isoformat(), minutes=minutes).first():
        raise HTTPException(409, "That time is already taken.")
    repeat = bool(body.get("repeat"))
    for w in range(12 if repeat else 1):
        d = (start + timedelta(weeks=w)).isoformat()
        if w and s.query(Sess).filter_by(date=d, minutes=minutes).first():
            continue
        s.add(Sess(client_id=c.id, date=d, minutes=minutes, length=int(body.get("length", 60)), title=str(body.get("title") or "Session")[:80], repeat=repeat))
    s.commit()
    return {"ok": True}


@app.patch("/api/admin/sessions/{sid}")
def edit_session(sid: int, body: dict, _=Depends(need_admin), s: DB = Depends(db)):
    x = s.get(Sess, sid) or _404()
    if "done" in body:
        x.done = bool(body["done"])
    s.commit()
    return {"ok": True}


@app.delete("/api/admin/sessions/{sid}")
def del_session(sid: int, _=Depends(need_admin), s: DB = Depends(db)):
    s.delete(s.get(Sess, sid) or _404())
    s.commit()
    return {"ok": True}


ALLOWED = {".pdf": "application/pdf", ".doc": "application/msword", ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document", ".xls": "application/vnd.ms-excel", ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png", ".heic": "image/heic", ".webp": "image/webp"}


@app.post("/api/admin/clients/{cid}/files")
async def upload(cid: int, file: UploadFile = File(...), _=Depends(need_admin), s: DB = Depends(db)):
    s.get(Client, cid) or _404()
    ext = Path(file.filename or "").suffix.lower()
    if ext not in ALLOWED:
        raise HTTPException(400, "Upload a PDF, Word file, spreadsheet, or photo.")
    blob = await file.read(15 * 1024 * 1024 + 1)
    if len(blob) > 15 * 1024 * 1024:
        raise HTTPException(400, "Keep files under 15 MB.")
    s.add(FileRow(client_id=cid, name=(file.filename or "file")[:200], mime=ALLOWED[ext], blob=blob))
    s.commit()
    return {"ok": True}


@app.post("/api/admin/clients/{cid}/import-plan")
async def import_plan(cid: int, file: UploadFile = File(...), _=Depends(need_admin), s: DB = Depends(db)):
    """Read a program .docx and hand back the plan for review. Nothing is saved until Nick taps Save."""
    s.get(Client, cid) or _404()
    if Path(file.filename or "").suffix.lower() != ".docx":
        raise HTTPException(400, "Pick the Word file (.docx) for this client's program.")
    blob = await file.read(15 * 1024 * 1024 + 1)
    if len(blob) > 15 * 1024 * 1024:
        raise HTTPException(400, "Keep files under 15 MB.")
    from plan_import import parse_docx
    try:
        r = parse_docx(blob)
    except Exception:
        raise HTTPException(400, "Couldn't read that file. Open it in Word, save it as .docx, and try again.")
    if not any(d["exercises"] for d in r["plan"]["days"]):
        raise HTTPException(400, "No workouts found in that file. It needs day lines like \"Monday — Upper Body\".")
    return r


@app.delete("/api/admin/files/{fid}")
def del_file(fid: int, _=Depends(need_admin), s: DB = Depends(db)):
    s.delete(s.get(FileRow, fid) or _404())
    s.commit()
    return {"ok": True}


@app.post("/api/admin/checkins/{cid}/reply")
def reply(cid: int, body: dict, _=Depends(need_admin), s: DB = Depends(db)):
    x = s.get(CheckIn, cid) or _404()
    text = str(body.get("reply", "")).strip()[:3000]
    if not text:
        raise HTTPException(400, "Write a reply first.")
    x.reply, x.replied_at = text, now()
    s.commit()
    return {"ok": True}


@app.put("/api/admin/settings")
def save_settings(body: dict, _=Depends(need_admin), s: DB = Depends(db)):
    cur = dict(public_settings(s))
    for k in ("venmo", "cashapp", "apple", "phone", "location", "waiver"):
        if k in body:
            cur[k] = str(body[k]).strip()[:20000 if k == "waiver" else 100].lstrip("@$")
    set_setting(s, "app", cur)
    return {"ok": True}
