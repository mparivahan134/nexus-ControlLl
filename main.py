import os, secrets, hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, Header, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, String, Boolean, DateTime, ForeignKey, Text, Integer, select, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./nexus.db")
JWT_SECRET = os.getenv("JWT_SECRET", "CHANGE_THIS_TO_A_LONG_RANDOM_SECRET_BEFORE_DEPLOYING")
JWT_ALG = "HS256"
TOKEN_MINUTES = int(os.getenv("TOKEN_MINUTES", "720"))
pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2 = OAuth2PasswordBearer(tokenUrl="/api/auth/token")

engine_args = {"connect_args": {"check_same_thread": False}} if DATABASE_URL.startswith("sqlite") else {"pool_pre_ping": True, "pool_size": 10, "max_overflow": 20}
engine = create_engine(DATABASE_URL, **engine_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

class Base(DeclarativeBase): pass

class Account(Base):
    __tablename__ = "accounts"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="customer")
    tenant_id: Mapped[Optional[int]] = mapped_column(ForeignKey("accounts.id"), nullable=True, index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

class Device(Base):
    __tablename__ = "devices"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("accounts.id"), index=True)
    device_name: Mapped[str] = mapped_column(String(120), default="Android device")
    device_model: Mapped[str] = mapped_column(String(120), default="Unknown")
    platform: Mapped[str] = mapped_column(String(40), default="Android")
    device_key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    status: Mapped[str] = mapped_column(String(20), default="offline")
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, index=True)
    actor: Mapped[str] = mapped_column(String(80))
    action: Mapped[str] = mapped_column(String(120))
    details: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

Base.metadata.create_all(engine)

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()

def audit(db: Session, tenant_id: Optional[int], actor: str, action: str, details: str = ""):
    db.add(AuditEvent(tenant_id=tenant_id, actor=actor, action=action, details=details[:1000]))
    db.commit()

def account_dict(a: Account):
    return {"id": a.id, "username": a.username, "role": a.role, "tenant_id": a.tenant_id, "active": a.active, "created_at": a.created_at.isoformat()}

def device_dict(d: Device):
    return {"id": d.id, "device_name": d.device_name, "device_model": d.device_model, "platform": d.platform, "status": d.status, "last_seen": d.last_seen.isoformat() if d.last_seen else None, "created_at": d.created_at.isoformat()}

class AccountCreate(BaseModel):
    username: str = Field(min_length=3, max_length=80, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: str = Field(min_length=12, max_length=128)
    active: bool = True

class DeviceCreate(BaseModel):
    device_name: str = Field(min_length=1, max_length=120)
    device_model: str = Field(default="Unknown", max_length=120)
    platform: str = Field(default="Android", max_length=40)

class Heartbeat(BaseModel):
    device_name: Optional[str] = Field(default=None, max_length=120)
    device_model: Optional[str] = Field(default=None, max_length=120)
    platform: Optional[str] = Field(default=None, max_length=40)

app = FastAPI(title="Nexus Control", version="1.0.0", description="Consent-based device management MVP")
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.on_event("startup")
def seed_admin():
    with SessionLocal() as db:
        admin_user = os.getenv("BOOTSTRAP_ADMIN_USER", "admin")
        admin_pass = os.getenv("BOOTSTRAP_ADMIN_PASSWORD", "")
        exists = db.scalar(select(Account).where(Account.username == admin_user))
        if not exists:
            if len(admin_pass) < 12:
                # Do not create a predictable default account.
                print("BOOTSTRAP_ADMIN_PASSWORD (12+ chars) not set; create first admin with scripts/create_admin.py")
            else:
                db.add(Account(username=admin_user, password_hash=pwd.hash(admin_pass), role="superadmin", tenant_id=None, active=True))
                db.commit()

@app.get("/")
def home(): return FileResponse("static/index.html")

def current_account(token: str = Depends(oauth2), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        uid = int(payload["sub"])
    except (JWTError, KeyError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    account = db.get(Account, uid)
    if not account or not account.active: raise HTTPException(status_code=401, detail="Account inactive")
    return account

def require_superadmin(a: Account = Depends(current_account)):
    if a.role != "superadmin": raise HTTPException(status_code=403, detail="Super-admin access required")
    return a

@app.post("/api/auth/token")
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    a = db.scalar(select(Account).where(Account.username == form.username))
    if not a or not pwd.verify(form.password, a.password_hash) or not a.active:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    token = jwt.encode({"sub": str(a.id), "exp": datetime.now(timezone.utc) + timedelta(minutes=TOKEN_MINUTES)}, JWT_SECRET, algorithm=JWT_ALG)
    audit(db, a.tenant_id, a.username, "login")
    return {"access_token": token, "token_type": "bearer", "account": account_dict(a)}

@app.get("/api/me")
def me(a: Account = Depends(current_account)): return account_dict(a)

@app.get("/api/summary")
def summary(a: Account = Depends(current_account), db: Session = Depends(get_db)):
    tenant = None if a.role == "superadmin" else a.id
    q = select(Device)
    if tenant is not None: q = q.where(Device.tenant_id == tenant)
    devices = list(db.scalars(q))
    customers = db.scalar(select(func.count()).select_from(Account).where(Account.role == "customer")) if a.role == "superadmin" else None
    return {"total_devices": len(devices), "online": sum(d.status == "online" for d in devices), "offline": sum(d.status != "online" for d in devices), "customers": customers, "role": a.role}

@app.get("/api/customers")
def customers(a: Account = Depends(require_superadmin), db: Session = Depends(get_db)):
    rows = db.scalars(select(Account).where(Account.role == "customer").order_by(Account.created_at.desc())).all()
    return [account_dict(x) for x in rows]

@app.post("/api/customers")
def create_customer(body: AccountCreate, a: Account = Depends(require_superadmin), db: Session = Depends(get_db)):
    if db.scalar(select(Account).where(Account.username == body.username)):
        raise HTTPException(status_code=409, detail="Username already exists")
    c = Account(username=body.username, password_hash=pwd.hash(body.password), role="customer", active=body.active)
    db.add(c); db.commit(); db.refresh(c)
    audit(db, c.id, a.username, "customer_created", c.username)
    return account_dict(c)

@app.patch("/api/customers/{customer_id}/status")
def customer_status(customer_id: int, active: bool, a: Account = Depends(require_superadmin), db: Session = Depends(get_db)):
    c = db.get(Account, customer_id)
    if not c or c.role != "customer": raise HTTPException(status_code=404, detail="Customer not found")
    c.active = active; db.commit()
    audit(db, c.id, a.username, "customer_status_changed", f"active={active}")
    return account_dict(c)

@app.get("/api/devices")
def list_devices(a: Account = Depends(current_account), db: Session = Depends(get_db)):
    q = select(Device).order_by(Device.created_at.desc())
    if a.role != "superadmin": q = q.where(Device.tenant_id == a.id)
    return [device_dict(d) for d in db.scalars(q).all()]

@app.post("/api/devices")
def create_device(body: DeviceCreate, a: Account = Depends(current_account), db: Session = Depends(get_db)):
    if a.role == "superadmin": raise HTTPException(status_code=400, detail="Create a customer first, then register a device under that customer account")
    raw_key = secrets.token_urlsafe(32)
    d = Device(tenant_id=a.id, device_name=body.device_name, device_model=body.device_model, platform=body.platform, device_key_hash=hash_key(raw_key), status="offline")
    db.add(d); db.commit(); db.refresh(d)
    audit(db, a.id, a.username, "device_registered", f"device_id={d.id}")
    return {**device_dict(d), "device_key": raw_key, "warning": "Copy this key now. It is shown only once."}

@app.delete("/api/devices/{device_id}")
def delete_device(device_id: int, a: Account = Depends(current_account), db: Session = Depends(get_db)):
    d = db.get(Device, device_id)
    if not d or (a.role != "superadmin" and d.tenant_id != a.id): raise HTTPException(status_code=404, detail="Device not found")
    db.delete(d); db.commit()
    audit(db, d.tenant_id, a.username, "device_deleted", f"device_id={device_id}")
    return {"ok": True}

@app.post("/api/device/heartbeat")
def heartbeat(body: Heartbeat, x_device_key: str = Header(default=""), db: Session = Depends(get_db)):
    if not x_device_key: raise HTTPException(status_code=401, detail="X-Device-Key required")
    d = db.scalar(select(Device).where(Device.device_key_hash == hash_key(x_device_key)))
    if not d: raise HTTPException(status_code=401, detail="Unknown device key")
    d.status = "online"; d.last_seen = datetime.now(timezone.utc)
    if body.device_name: d.device_name = body.device_name
    if body.device_model: d.device_model = body.device_model
    if body.platform: d.platform = body.platform
    db.commit()
    return {"ok": True, "server_time": d.last_seen.isoformat()}

@app.get("/api/audit")
def get_audit(a: Account = Depends(current_account), db: Session = Depends(get_db)):
    q = select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(200)
    if a.role != "superadmin": q = q.where(AuditEvent.tenant_id == a.id)
    return [{"id": e.id, "actor": e.actor, "action": e.action, "details": e.details, "created_at": e.created_at.isoformat()} for e in db.scalars(q).all()]

@app.get("/api/health")
def health(): return {"status": "ok", "service": "nexus-control"}

# Simple maintenance endpoint; production should run this periodically as a worker.
@app.post("/api/maintenance/mark-offline")
def mark_offline(a: Account = Depends(require_superadmin), db: Session = Depends(get_db)):
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=3)
    rows = db.scalars(select(Device).where(Device.status == "online")).all()
    changed = 0
    for d in rows:
        seen = d.last_seen
        if seen and seen.replace(tzinfo=timezone.utc) < cutoff:
            d.status = "offline"; changed += 1
    db.commit()
    return {"marked_offline": changed}
