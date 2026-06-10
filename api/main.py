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
import hashlib, secrets, os
from supabase import create_client, Client

app = FastAPI(
    title="OpenHealthPlat API",
    description="Plateforme de santé numérique open source — API REST FHIR-compatible",
    version="0.2.0-mvp",
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

# ── Supabase client ────────────────────────────────────────────────────────────
SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY) if SUPABASE_URL and SUPABASE_KEY else None

# ── In-memory fallback (tokens + non-persistent data) ─────────────────────────
TOKENS = {}  # token -> user_id

# ── Helpers ───────────────────────────────────────────────────────────────────
def hash_pwd(pwd: str) -> str:
    return hashlib.sha256(pwd.encode()).hexdigest()

def make_token(user_id: str) -> str:
    tok = secrets.token_urlsafe(32)
    TOKENS[tok] = {"user_id": user_id, "expires": datetime.utcnow() + timedelta(hours=24)}
    return tok

def get_current_user(creds: HTTPAuthorizationCredentials = Depends(security)):
    if not creds:
        raise HTTPException(status_code=401, detail="Token manquant")
    tok = creds.credentials
    if tok not in TOKENS:
        raise HTTPException(status_code=401, detail="Token invalide ou expiré")
    data = TOKENS[tok]
    if datetime.utcnow() > data["expires"]:
        del TOKENS[tok]
        raise HTTPException(status_code=401, detail="Token expiré")
    return data["user_id"]

# ── Modèles ───────────────────────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    role: str = "patient"
    phone: Optional[str] = None

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class ProfileUpdate(BaseModel):
    full_name: Optional[str] = None
    phone: Optional[str] = None

# ── Routes ────────────────────────────────────────────────────────────────────
@app.get("/")
def root():
    return {
        "service": "OpenHealthPlat API",
        "version": "0.2.0-mvp",
        "status": "running",
        "docs": "/api/docs"
    }

@app.get("/health")
def health():
    db_ok = supabase is not None
    return {"status": "ok", "database": "supabase" if db_ok else "memory-only"}

@app.post("/auth/register", status_code=201)
def register(req: RegisterRequest):
    if not supabase:
        raise HTTPException(status_code=503, detail="Base de données non configurée")
    
    # Vérifie si l'email existe déjà
    existing = supabase.table("users").select("id").eq("email", req.email).execute()
    if existing.data:
        raise HTTPException(status_code=409, detail="Email déjà utilisé")
    
    # Crée l'utilisateur
    user_data = {
        "email": req.email,
        "password_hash": hash_pwd(req.password),
        "full_name": req.full_name,
        "role": req.role,
        "phone": req.phone,
    }
    result = supabase.table("users").insert(user_data).execute()
    
    if not result.data:
        raise HTTPException(status_code=500, detail="Erreur lors de la création du compte")
    
    user = result.data[0]
    token = make_token(user["id"])
    
    return {
        "message": "Compte créé avec succès",
        "token": token,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "full_name": user["full_name"],
            "role": user["role"],
        }
    }

@app.post("/auth/login")
def login(req: LoginRequest):
    if not supabase:
        raise HTTPException(status_code=503, detail="Base de données non configurée")
    
    result = supabase.table("users").select("*").eq("email", req.email).eq("password_hash", hash_pwd(req.password)).execute()
    
    if not result.data:
        raise HTTPException(status_code=401, detail="Email ou mot de passe incorrect")
    
    user = result.data[0]
    token = make_token(user["id"])
    
    return {
        "token": token,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "full_name": user["full_name"],
            "role": user["role"],
        }
    }

@app.get("/auth/me")
def me(user_id: str = Depends(get_current_user)):
    if not supabase:
        raise HTTPException(status_code=503, detail="Base de données non configurée")
    
    result = supabase.table("users").select("id, email, full_name, role, phone, created_at").eq("id", user_id).execute()
    
    if not result.data:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    
    return result.data[0]

@app.put("/auth/me")
def update_profile(update: ProfileUpdate, user_id: str = Depends(get_current_user)):
    if not supabase:
        raise HTTPException(status_code=503, detail="Base de données non configurée")
    
    data = {k: v for k, v in update.dict().items() if v is not None}
    result = supabase.table("users").update(data).eq("id", user_id).execute()
    return {"message": "Profil mis à jour", "user": result.data[0] if result.data else {}}

@app.get("/users/count")
def users_count():
    """Nombre total d'utilisateurs inscrits (public)"""
    if not supabase:
        return {"count": 0}
    result = supabase.table("users").select("id", count="exact").execute()
    return {"count": result.count or 0}

# ── Modèle Dossier Médical ────────────────────────────────────────────────────
class MedicalRecord(BaseModel):
    blood_type: Optional[str] = None
    allergies: Optional[str] = None
    chronic_conditions: Optional[str] = None
    current_treatments: Optional[str] = None
    family_history: Optional[str] = None
    emergency_contact_name: Optional[str] = None
    emergency_contact_phone: Optional[str] = None

# ── Routes Dossier Médical ────────────────────────────────────────────────────
@app.get("/medical/record")
def get_medical_record(user_id: str = Depends(get_current_user)):
    if not supabase:
        raise HTTPException(status_code=503, detail="Base de données non configurée")
    result = supabase.table("medical_records").select("*").eq("user_id", user_id).execute()
    if not result.data:
        return {}
    return result.data[0]

@app.put("/medical/record")
def save_medical_record(record: MedicalRecord, user_id: str = Depends(get_current_user)):
    if not supabase:
        raise HTTPException(status_code=503, detail="Base de données non configurée")
    
    data = {**record.dict(), "user_id": user_id, "updated_at": datetime.utcnow().isoformat()}
    
    existing = supabase.table("medical_records").select("id").eq("user_id", user_id).execute()
    if existing.data:
        result = supabase.table("medical_records").update(data).eq("user_id", user_id).execute()
    else:
        result = supabase.table("medical_records").insert(data).execute()
    
    return {"message": "Dossier médical enregistré", "data": result.data[0] if result.data else {}}

# ── Modèle Rendez-vous ────────────────────────────────────────────────────────
class AppointmentRequest(BaseModel):
    specialty: str
    doctor_name: Optional[str] = None
    appointment_date: str
    appointment_time: str
    reason: Optional[str] = None

# ── Routes Rendez-vous ────────────────────────────────────────────────────────
@app.post("/appointments", status_code=201)
def create_appointment(req: AppointmentRequest, user_id: str = Depends(get_current_user)):
    if not supabase:
        raise HTTPException(status_code=503, detail="Base de données non configurée")
    data = {
        "patient_id": user_id,
        "specialty": req.specialty,
        "doctor_name": req.doctor_name,
        "appointment_date": req.appointment_date,
        "appointment_time": req.appointment_time,
        "reason": req.reason,
        "status": "pending",
    }
    result = supabase.table("appointments").insert(data).execute()
    return {"message": "Rendez-vous créé", "data": result.data[0] if result.data else {}}

@app.get("/appointments")
def get_appointments(user_id: str = Depends(get_current_user)):
    if not supabase:
        raise HTTPException(status_code=503, detail="Base de données non configurée")
    result = supabase.table("appointments").select("*").eq("patient_id", user_id).order("appointment_date", desc=False).execute()
    return result.data or []

# ── Modèle Message ────────────────────────────────────────────────────────────
class MessageRequest(BaseModel):
    content: str
    conversation: Optional[str] = "support"

# ── Routes Messages ───────────────────────────────────────────────────────────
@app.post("/messages", status_code=201)
def send_message(req: MessageRequest, user_id: str = Depends(get_current_user)):
    if not supabase:
        raise HTTPException(status_code=503, detail="Base de données non configurée")
    data = {
        "user_id": user_id,
        "content": req.content,
        "is_from_patient": True,
        "conversation": req.conversation,
    }
    result = supabase.table("messages").insert(data).execute()
    return {"message": "Message envoyé", "data": result.data[0] if result.data else {}}

@app.get("/messages")
def get_messages(user_id: str = Depends(get_current_user)):
    if not supabase:
        raise HTTPException(status_code=503, detail="Base de données non configurée")
    result = supabase.table("messages").select("*").eq("user_id", user_id).order("created_at").execute()
    return result.data or []
