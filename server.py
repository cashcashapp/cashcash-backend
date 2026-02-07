from fastapi import FastAPI, APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from supabase import create_client, Client
import os
from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import JWTError, jwt
import secrets

load_dotenv()

SUPABASE_URL = os.environ.get('SUPABASE_URL', 'https://hjtcrgwglkwjqoeihihr.supabase.co')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImhqdGNyZ3dnbGt3anFvZWloaWhyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzA0NjA5MzIsImV4cCI6MjA4NjAzNjkzMn0.qDhhs4I22akoFQ392vvie8kOshhlOmIwVJtJ2xGHz5I')
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

SECRET_KEY = os.environ.get('JWT_SECRET', secrets.token_hex(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

app = FastAPI(title="Cash-Cash API", version="2.0.0")

class UserCreate(BaseModel):
    email: EmailStr
    username: str
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class ParticipateRequest(BaseModel):
    city_id: str

class ScanQRRequest(BaseModel):
    city_id: str
    qr_code: str
    latitude: float = 0
    longitude: float = 0

class CityCreate(BaseModel):
    name: str
    slug: str
    image_url: Optional[str] = None

class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordResetConfirm(BaseModel):
    email: EmailStr
    code: str
    new_password: str

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        result = supabase.table('users').select('*').eq('id', user_id).execute()
        if not result.data:
            raise HTTPException(status_code=401, detail="User not found")
        return result.data[0]
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def do_register(user: UserCreate):
    result = supabase.table('users').select('*').eq('email', user.email).execute()
    if result.data:
        raise HTTPException(status_code=400, detail="Email déjà utilisé")
    hashed_password = get_password_hash(user.password)
    new_user = {"email": user.email, "username": user.username, "hashed_password": hashed_password, "wallet_balance": 0, "is_admin": False}
    result = supabase.table('users').insert(new_user).execute()
    if not result.data:
        raise HTTPException(status_code=500, detail="Erreur création compte")
    created_user = result.data[0]
    token = create_access_token({"sub": created_user["id"]})
    return {"access_token": token, "token_type": "bearer", "user": {"id": created_user["id"], "email": created_user["email"], "username": created_user["username"], "wallet_balance": created_user["wallet_balance"], "is_admin": created_user["is_admin"]}}

async def do_login(user: UserLogin):
    result = supabase.table('users').select('*').eq('email', user.email).execute()
    if not result.data:
        raise HTTPException(status_code=401, detail="Email ou mot de passe incorrect")
    db_user = result.data[0]
    if not verify_password(user.password, db_user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Email ou mot de passe incorrect")
    token = create_access_token({"sub": db_user["id"]})
    return {"access_token": token, "token_type": "bearer", "user": {"id": db_user["id"], "email": db_user["email"], "username": db_user["username"], "wallet_balance": db_user["wallet_balance"], "is_admin": db_user["is_admin"]}}

# AUTH ROUTES
@app.post("/auth/register")
async def auth_register(user: UserCreate):
    return await do_register(user)

@app.post("/auth/login")
async def auth_login(user: UserLogin):
    return await do_login(user)

@app.get("/auth/me")
async def auth_me(current_user: dict = Depends(get_current_user)):
    return {"id": current_user["id"], "email": current_user["email"], "username": current_user["username"], "wallet_balance": current_user["wallet_balance"], "is_admin": current_user["is_admin"]}

@app.post("/auth/forgot-password")
async def forgot_password(request: PasswordResetRequest):
    result = supabase.table('users').select('*').eq('email', request.email).execute()
    if not result.data:
        return {"message": "Si cet email existe, un code de réinitialisation a été envoyé"}
    code = secrets.token_urlsafe(6)[:6].upper()
    supabase.table('users').update({"reset_code": code}).eq('email', request.email).execute()
    # TODO: Envoyer l'email avec le code
    print(f"Reset code for {request.email}: {code}")
    return {"message": "Si cet email existe, un code de réinitialisation a été envoyé", "code": code}

@app.post("/auth/reset-password")
async def reset_password(request: PasswordResetConfirm):
    result = supabase.table('users').select('*').eq('email', request.email).execute()
    if not result.data:
        raise HTTPException(status_code=400, detail="Email non trouvé")
    user = result.data[0]
    if user.get("reset_code") != request.code:
        raise HTTPException(status_code=400, detail="Code invalide")
    hashed = get_password_hash(request.new_password)
    supabase.table('users').update({"hashed_password": hashed, "reset_code": None}).eq('email', request.email).execute()
    return {"message": "Mot de passe réinitialisé avec succès"}

# CITIES
@app.get("/cities")
async def get_cities(current_user: dict = Depends(get_current_user)):
    result = supabase.table('cities').select('*').eq('is_active', True).execute()
    cities = result.data or []
    participations = supabase.table('participations').select('city_id').eq('user_id', current_user["id"]).eq('status', 'active').execute()
    participated_city_ids = [p["city_id"] for p in (participations.data or [])]
    for city in cities:
        city["user_has_participated"] = city["id"] in participated_city_ids
        city["hint_available"] = city.get("hint_published", False) and city.get("hint_image") is not None
    return cities

@app.post("/init-cities")
async def init_cities():
    return {"message": "OK"}

# PARTICIPATE
@app.post("/participate")
async def participate(request: ParticipateRequest, current_user: dict = Depends(get_current_user)):
    result = supabase.table('cities').select('*').eq('id', request.city_id).execute()
    if not result.data:
        raise HTTPException(status_code=404, detail="Ville non trouvée")
    city = result.data[0]
    if current_user["wallet_balance"] < 1:
        raise HTTPException(status_code=400, detail="Solde insuffisant")
    week = datetime.utcnow().isocalendar()[1]
    year = datetime.utcnow().year
    existing = supabase.table('participations').select('*').eq('user_id', current_user["id"]).eq('city_id', request.city_id).eq('week_number', week).eq('year', year).execute()
    if existing.data:
        raise HTTPException(status_code=400, detail="Vous participez déjà")
    supabase.table('participations').insert({"user_id": current_user["id"], "city_id": request.city_id, "week_number": week, "year": year, "amount_paid": 1, "status": "active"}).execute()
    new_balance = float(current_user["wallet_balance"]) - 1
    supabase.table('users').update({"wallet_balance": new_balance}).eq('id', current_user["id"]).execute()
    new_pot = float(city.get("pot_amount", 0)) + 1
    new_count = int(city.get("participants_count", 0)) + 1
    supabase.table('cities').update({"pot_amount": new_pot, "participants_count": new_count}).eq('id', request.city_id).execute()
    return {"message": f"Inscription réussie pour {city['name']}", "new_balance": new_balance}

# SCAN QR
@app.post("/scan-qr")
async def scan_qr(request: ScanQRRequest, current_user: dict = Depends(get_current_user)):
    result = supabase.table('cities').select('*').eq('id', request.city_id).execute()
    if not result.data:
        raise HTTPException(status_code=404, detail="Ville non trouvée")
    city = result.data[0]
    week = datetime.utcnow().isocalendar()[1]
    year = datetime.utcnow().year
    participation = supabase.table('participations').select('*').eq('user_id', current_user["id"]).eq('city_id', request.city_id).eq('week_number', week).eq('year', year).eq('status', 'active').execute()
    if not participation.data:
        raise HTTPException(status_code=400, detail="Vous ne participez pas à cette ville")
    if request.qr_code != city.get("qr_code_secret"):
        raise HTTPException(status_code=400, detail="QR code invalide")
    pot_amount = float(city.get("pot_amount", 0))
    new_balance = float(current_user["wallet_balance"]) + pot_amount
    supabase.table('users').update({"wallet_balance": new_balance}).eq('id', current_user["id"]).execute()
    supabase.table('winners').insert({"user_id": current_user["id"], "city_id": request.city_id, "username": current_user["username"], "city_name": city["name"], "amount_won": pot_amount, "week_number": week, "year": year}).execute()
    supabase.table('participations').update({"status": "won"}).eq('id', participation.data[0]["id"]).execute()
    supabase.table('cities').update({"pot_amount": 0, "participants_count": 0, "hint_published": False, "hint_image": None, "qr_code_secret": secrets.token_urlsafe(16)}).eq('id', request.city_id).execute()
    return {"message": "Félicitations! Vous avez gagné!", "amount_won": pot_amount, "new_balance": new_balance}

# STATS
@app.get("/stats/global")
async def get_global_stats():
    cities = supabase.table('cities').select('pot_amount').execute()
    total_pot = sum(float(c.get("pot_amount", 0)) for c in (cities.data or []))
    winners = supabase.table('winners').select('amount_won').execute()
    total_winners = len(winners.data or [])
    total_distributed = sum(float(w.get("amount_won", 0)) for w in (winners.data or []))
    active_cities = supabase.table('cities').select('id').eq('is_active', True).execute()
    return {"total_pot": total_pot, "total_winners": total_winners, "total_distributed": total_distributed, "active_cities": len(active_cities.data or [])}

# WALLET
@app.get("/wallet/transactions")
async def get_transactions(current_user: dict = Depends(get_current_user)):
    result = supabase.table('transactions').select('*').eq('user_id', current_user["id"]).order('created_at', desc=True).limit(50).execute()
    return result.data or []

# ADMIN
@app.post("/admin/cities")
async def create_city(city: CityCreate, current_user: dict = Depends(get_current_user)):
    if not current_user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin only")
    new_city = {"name": city.name, "slug": city.slug, "image_url": city.image_url, "pot_amount": 0, "participants_count": 0, "is_active": True, "qr_code_secret": secrets.token_urlsafe(16)}
    result = supabase.table('cities').insert(new_city).execute()
    return result.data[0] if result.data else {"error": "Failed"}

@app.get("/admin/cities")
async def admin_get_cities(current_user: dict = Depends(get_current_user)):
    if not current_user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin only")
    result = supabase.table('cities').select('*').execute()
    return result.data or []

@app.put("/admin/cities/{city_id}")
async def update_city(city_id: str, city: CityCreate, current_user: dict = Depends(get_current_user)):
    if not current_user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin only")
    update_data = {"name": city.name, "slug": city.slug}
    if city.image_url:
        update_data["image_url"] = city.image_url
    supabase.table('cities').update(update_data).eq('id', city_id).execute()
    return {"message": "Ville mise à jour"}

@app.delete("/admin/cities/{city_id}")
async def delete_city(city_id: str, current_user: dict = Depends(get_current_user)):
    if not current_user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin only")
    supabase.table('cities').delete().eq('id', city_id).execute()
    return {"message": "Ville supprimée"}

@app.put("/admin/cities/{city_id}/hint")
async def publish_hint(city_id: str, hint_image: str = None, hint_published: bool = True, current_user: dict = Depends(get_current_user)):
    if not current_user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin only")
    update_data = {"hint_published": hint_published}
    if hint_image:
        update_data["hint_image"] = hint_image
    supabase.table('cities').update(update_data).eq('id', city_id).execute()
    return {"message": "Indice publié"}

# HEALTH
@app.get("/health")
async def health():
    return {"status": "healthy", "version": "2.0.0"}

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
