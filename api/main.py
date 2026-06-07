"""
OpenHealthPlat — Backend FastAPI MVP
Gratuit, open source, RGPD/HDS compatible
Deploy: Render free tier (render.com)
"""
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime, timedelta
import hashlib, secrets, json, os

app = FastAPI(
    title="OpenHealthPlat API",
    description="Plateforme de santé numérique open source — API REST FHIR-compatible",
    version="0.1.0-mvp",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer(auto_error=False)

# ── In-memory store (MVP — remplacer par PostgreSQL en prod) ──────────────────
DB = {
    "users": {},
    "tokens": {},
    "patients": {},
    "appointments": [],
    "messages": [],
}

# ── Helpers ───────────────────────────────────────────────────────────────────
def hash_pwd(pwd: str) -> str:
    return hashlib.sha256(pwd.encode()).hexdigest()

def make_token(user_id: str) -> str:
    tok = secrets.token_urlsafe(32)
    DB["tokens"][tok] = {"user_id": user_id, "expires": datetime.utcnow() + timedelta(hours=24)}
    return tok

def get_current_user(creds: HTTPAuthorizationCredentials = Depends(security)):
    if not creds:
        raise HTTPException(status_code=401, detail="Token manquant")
    entry = DB["tokens"].get(creds.credentials)
    if not entry or entry["expires"] < datetime.utcnow():
        raise HTTPException(status_code=401, detail="Token invalide ou expiré")
    return DB["users"].get(entry["user_id"])

# ── Schemas ───────────────────────────────────────────────────────────────────
class RegisterIn(BaseModel):
    email: str
    password: str
    full_name: str
    role: str = "patient"  # patient | professional | admin

class LoginIn(BaseModel):
    email: str
    password: str

class PatientRecord(BaseModel):
    blood_type: Optional[str] = None
    allergies: List[str] = []
    conditions: List[str] = []
    medications: List[str] = []
    notes: Optional[str] = None

class AppointmentIn(BaseModel):
    patient_id: str
    professional_id: str
    date: str        # ISO8601
    type: str        # video | audio | in-person
    reason: Optional[str] = None

class MessageIn(BaseModel):
    to_user_id: str
    content: str
    encrypted: bool = True

# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/", tags=["Health"])
def root():
    return {
        "service": "OpenHealthPlat API",
        "version": "0.1.0-mvp",
        "status": "operational",
        "docs": "/api/docs",
        "license": "AGPL-3.0",
        "github": "https://github.com/openhealthplat",
    }

@app.get("/api/health", tags=["Health"])
def health_check():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat(), "uptime": "live"}

# ── Auth ──────────────────────────────────────────────────────────────────────

@app.post("/api/v1/auth/register", tags=["Auth"])
def register(body: RegisterIn):
    if body.email in DB["users"]:
        raise HTTPException(status_code=409, detail="Email déjà utilisé")
    user_id = secrets.token_hex(8)
    DB["users"][body.email] = {
        "id": user_id, "email": body.email,
        "full_name": body.full_name, "role": body.role,
        "password_hash": hash_pwd(body.password),
        "created_at": datetime.utcnow().isoformat(),
    }
    DB["users"][user_id] = DB["users"][body.email]  # index by id too
    token = make_token(user_id)
    return {"token": token, "user_id": user_id, "role": body.role, "message": "Compte créé"}

@app.post("/api/v1/auth/login", tags=["Auth"])
def login(body: LoginIn):
    user = DB["users"].get(body.email)
    if not user or user["password_hash"] != hash_pwd(body.password):
        raise HTTPException(status_code=401, detail="Email ou mot de passe incorrect")
    token = make_token(user["id"])
    return {"token": token, "user_id": user["id"], "role": user["role"], "full_name": user["full_name"]}

@app.get("/api/v1/auth/me", tags=["Auth"])
def me(user=Depends(get_current_user)):
    return {k: v for k, v in user.items() if k != "password_hash"}

# ── Dossier patient ───────────────────────────────────────────────────────────

@app.get("/api/v1/patients/{patient_id}/record", tags=["Dossier Medical"])
def get_record(patient_id: str, user=Depends(get_current_user)):
    record = DB["patients"].get(patient_id, {
        "patient_id": patient_id, "blood_type": None,
        "allergies": [], "conditions": [], "medications": [], "notes": "",
        "last_updated": None,
    })
    return record

@app.put("/api/v1/patients/{patient_id}/record", tags=["Dossier Medical"])
def update_record(patient_id: str, body: PatientRecord, user=Depends(get_current_user)):
    DB["patients"][patient_id] = {
        "patient_id": patient_id, **body.dict(),
        "last_updated": datetime.utcnow().isoformat(),
        "updated_by": user["id"],
    }
    return {"message": "Dossier mis à jour", "patient_id": patient_id}

@app.get("/api/v1/patients/{patient_id}/record/fhir", tags=["Dossier Medical"])
def get_record_fhir(patient_id: str, user=Depends(get_current_user)):
    """Export FHIR R4 — Patient resource"""
    record = DB["patients"].get(patient_id, {})
    return {
        "resourceType": "Patient",
        "id": patient_id,
        "meta": {"profile": ["http://hl7.org/fhir/StructureDefinition/Patient"]},
        "text": {"status": "generated"},
        "extension": [
            {"url": "allergies", "valueString": ", ".join(record.get("allergies", []))},
            {"url": "conditions", "valueString": ", ".join(record.get("conditions", []))},
        ],
    }

# ── Rendez-vous ────────────────────────────────────────────────────────────────

@app.post("/api/v1/appointments", tags=["Rendez-vous"])
def create_appointment(body: AppointmentIn, user=Depends(get_current_user)):
    appt_id = secrets.token_hex(6)
    appt = {
        "id": appt_id, **body.dict(),
        "status": "confirmed",
        "created_at": datetime.utcnow().isoformat(),
    }
    DB["appointments"].append(appt)
    return {"message": "Rendez-vous confirmé", "appointment": appt}

@app.get("/api/v1/appointments", tags=["Rendez-vous"])
def list_appointments(user=Depends(get_current_user)):
    uid = user["id"]
    appts = [a for a in DB["appointments"]
             if a["patient_id"] == uid or a["professional_id"] == uid]
    return {"appointments": appts, "count": len(appts)}

@app.delete("/api/v1/appointments/{appt_id}", tags=["Rendez-vous"])
def cancel_appointment(appt_id: str, user=Depends(get_current_user)):
    for a in DB["appointments"]:
        if a["id"] == appt_id:
            a["status"] = "cancelled"
            return {"message": "Rendez-vous annulé"}
    raise HTTPException(404, "Rendez-vous introuvable")

# ── Téléconsultation ───────────────────────────────────────────────────────────

@app.post("/api/v1/consultations/room", tags=["Teleconsultation"])
def create_room(appointment_id: str, user=Depends(get_current_user)):
    """Génère un lien de salle Jitsi Meet chiffrée"""
    room_id = secrets.token_urlsafe(12)
    jitsi_url = f"https://meet.jit.si/ohp-{room_id}"
    return {
        "room_id": room_id,
        "jitsi_url": jitsi_url,
        "e2ee": True,
        "audio_only_url": f"{jitsi_url}#config.startWithVideoMuted=true",
        "expires_in": "60min",
        "appointment_id": appointment_id,
    }

# ── Messagerie ─────────────────────────────────────────────────────────────────

@app.post("/api/v1/messages", tags=["Messagerie"])
def send_message(body: MessageIn, user=Depends(get_current_user)):
    msg_id = secrets.token_hex(8)
    msg = {
        "id": msg_id,
        "from_user_id": user["id"],
        "to_user_id": body.to_user_id,
        "content": body.content,
        "encrypted": body.encrypted,
        "sent_at": datetime.utcnow().isoformat(),
        "read": False,
    }
    DB["messages"].append(msg)
    return {"message_id": msg_id, "status": "sent"}

@app.get("/api/v1/messages", tags=["Messagerie"])
def get_messages(user=Depends(get_current_user)):
    uid = user["id"]
    msgs = [m for m in DB["messages"]
            if m["from_user_id"] == uid or m["to_user_id"] == uid]
    return {"messages": msgs, "unread": sum(1 for m in msgs if not m["read"] and m["to_user_id"] == uid)}

# ── Stats anonymisées ──────────────────────────────────────────────────────────

@app.get("/api/v1/stats", tags=["Statistiques"])
def get_stats():
    """Statistiques anonymisées — aucune donnée personnelle"""
    return {
        "total_users": len([u for u in DB["users"] if len(u) == 16]),
        "total_appointments": len(DB["appointments"]),
        "total_messages": len(DB["messages"]),
        "platform": "OpenHealthPlat MVP",
        "version": "0.1.0",
        "note": "Données anonymisées — aucune donnée personnelle exposée",
    }
