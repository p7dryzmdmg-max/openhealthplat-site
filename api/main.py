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
    version="0.3.0-mvp",
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

# ── Helpers ───────────────────────────────────────────────────────────────────
def hash_pwd(pwd: str) -> str:
    return hashlib.sha256(pwd.encode()).hexdigest()

def make_token(user_id: str) -> str:
    tok = secrets.token_urlsafe(32)
    expires = (datetime.utcnow() + timedelta(days=30)).isoformat()
    if supabase:
        try:
            # Nettoie les anciens tokens expirés de cet utilisateur
            supabase.table("sessions").delete().eq("user_id", user_id).lt("expires_at", datetime.utcnow().isoformat()).execute()
            supabase.table("sessions").insert({"token": tok, "user_id": user_id, "expires_at": expires}).execute()
        except Exception:
            pass
    return tok

def get_current_user(creds: HTTPAuthorizationCredentials = Depends(security)):
    if not creds:
        raise HTTPException(status_code=401, detail="Token manquant")
    tok = creds.credentials
    if not supabase:
        raise HTTPException(status_code=503, detail="Base de données non configurée")
    result = supabase.table("sessions").select("user_id, expires_at").eq("token", tok).execute()
    if not result.data:
        raise HTTPException(status_code=401, detail="Token invalide ou expiré — reconnectez-vous")
    session = result.data[0]
    if datetime.utcnow() > datetime.fromisoformat(session["expires_at"].replace("Z", "")):
        supabase.table("sessions").delete().eq("token", tok).execute()
        raise HTTPException(status_code=401, detail="Session expirée — reconnectez-vous")
    return session["user_id"]

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

@app.post("/auth/logout")
def logout(creds: HTTPAuthorizationCredentials = Depends(security), user_id: str = Depends(get_current_user)):
    if supabase and creds:
        supabase.table("sessions").delete().eq("token", creds.credentials).execute()
    return {"message": "Déconnecté avec succès"}

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

# ── Modèle Téléconsultation ───────────────────────────────────────────────────
class TeleconsultRequest(BaseModel):
    specialty: str
    doctor_name: Optional[str] = None
    scheduled_date: str
    scheduled_time: str
    reason: Optional[str] = None

# ── Routes Téléconsultation ───────────────────────────────────────────────────
@app.post("/teleconsultations", status_code=201)
def create_teleconsult(req: TeleconsultRequest, user_id: str = Depends(get_current_user)):
    if not supabase:
        raise HTTPException(status_code=503, detail="Base de données non configurée")
    data = {
        "patient_id": user_id,
        "specialty": req.specialty,
        "doctor_name": req.doctor_name,
        "scheduled_date": req.scheduled_date,
        "scheduled_time": req.scheduled_time,
        "reason": req.reason,
        "status": "pending",
    }
    result = supabase.table("teleconsultations").insert(data).execute()
    return {"message": "Téléconsultation planifiée", "data": result.data[0] if result.data else {}}

@app.get("/teleconsultations")
def get_teleconsults(user_id: str = Depends(get_current_user)):
    if not supabase:
        raise HTTPException(status_code=503, detail="Base de données non configurée")
    result = supabase.table("teleconsultations").select("*").eq("patient_id", user_id).order("scheduled_date", desc=False).execute()
    return result.data or []

# ── Modèle Métriques Santé ────────────────────────────────────────────────────
class HealthMetric(BaseModel):
    metric_type: str
    value: float
    value2: Optional[float] = None
    unit: Optional[str] = None
    measured_at: Optional[str] = None
    notes: Optional[str] = None

# ── Routes Métriques Santé ────────────────────────────────────────────────────
@app.post("/health-metrics", status_code=201)
def add_metric(req: HealthMetric, user_id: str = Depends(get_current_user)):
    if not supabase:
        raise HTTPException(status_code=503, detail="Base de données non configurée")
    data = {
        "user_id": user_id,
        "metric_type": req.metric_type,
        "value": req.value,
        "value2": req.value2,
        "unit": req.unit,
        "measured_at": req.measured_at or datetime.utcnow().isoformat(),
        "notes": req.notes,
    }
    result = supabase.table("health_metrics").insert(data).execute()
    return {"message": "Mesure enregistrée", "data": result.data[0] if result.data else {}}

@app.get("/health-metrics")
def get_metrics(metric_type: Optional[str] = None, user_id: str = Depends(get_current_user)):
    if not supabase:
        raise HTTPException(status_code=503, detail="Base de données non configurée")
    query = supabase.table("health_metrics").select("*").eq("user_id", user_id)
    if metric_type:
        query = query.eq("metric_type", metric_type)
    result = query.order("measured_at", desc=False).execute()
    return result.data or []

# ── Helpers Admin ─────────────────────────────────────────────────────────────
def require_admin(user_id: str):
    if not supabase:
        raise HTTPException(status_code=503, detail="Base de données non configurée")
    result = supabase.table("users").select("role").eq("id", user_id).execute()
    if not result.data or result.data[0].get("role") != "admin":
        raise HTTPException(status_code=403, detail="Accès réservé aux administrateurs")

# ── Routes Admin ──────────────────────────────────────────────────────────────
@app.get("/admin/stats")
def admin_stats(user_id: str = Depends(get_current_user)):
    require_admin(user_id)
    total_users = supabase.table("users").select("id", count="exact").execute().count or 0
    total_appointments = supabase.table("appointments").select("id", count="exact").execute().count or 0
    total_teleconsultations = supabase.table("teleconsultations").select("id", count="exact").execute().count or 0
    total_messages = supabase.table("messages").select("id", count="exact").execute().count or 0

    # Rôles
    users_data = supabase.table("users").select("role").execute().data or []
    roles = {}
    for u in users_data:
        r = u.get("role", "patient")
        roles[r] = roles.get(r, 0) + 1

    # Top spécialités
    appt_data = supabase.table("appointments").select("specialty").execute().data or []
    specs = {}
    for a in appt_data:
        s = a.get("specialty", "Autre")
        specs[s] = specs.get(s, 0) + 1
    top_specialties = sorted([{"specialty": k, "count": v} for k, v in specs.items()], key=lambda x: -x["count"])

    return {
        "total_users": total_users,
        "total_appointments": total_appointments,
        "total_teleconsultations": total_teleconsultations,
        "total_messages": total_messages,
        "roles": roles,
        "top_specialties": top_specialties,
    }

@app.get("/admin/users")
def admin_list_users(user_id: str = Depends(get_current_user)):
    require_admin(user_id)
    result = supabase.table("users").select("id, email, full_name, role, phone, created_at").order("created_at", desc=True).execute()
    return result.data or []

class RoleUpdate(BaseModel):
    role: str

@app.put("/admin/users/{target_id}/role")
def admin_update_role(target_id: str, req: RoleUpdate, user_id: str = Depends(get_current_user)):
    require_admin(user_id)
    if req.role not in ["patient", "medecin", "admin"]:
        raise HTTPException(status_code=400, detail="Rôle invalide")
    result = supabase.table("users").update({"role": req.role}).eq("id", target_id).execute()
    return {"message": "Rôle mis à jour", "data": result.data[0] if result.data else {}}
