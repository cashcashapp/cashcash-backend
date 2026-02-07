from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from supabase import create_client, Client
import os
from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import JWTError, jwt
import secrets

SUPABASE_URL = 'https://hjtcrgwglkwjqoeihihr.supabase.co'
SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImhqdGNyZ3dnbGt3anFvZWloaWhyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzA0NjA5MzIsImV4cCI6MjA4NjAzNjkzMn0.qDhhs4I22akoFQ392vvie8kOshhlOmIwVJtJ2xGHz5I'
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

SECRET_KEY = os.environ.get('JWT_SECRET', secrets.token_hex(32))
ALGORITHM = "HS256"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

app = FastAPI(title="Cash-Cash API")

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

class CityUpdate(BaseModel):
    name: Optional[str] = None
    slug: Optional[str] = None
    image_url: Optional[str] = None
    hint_image: Optional[str] = None
    hint_published: Optional[bool] = None
    event_date: Optional[str] = None

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def create_access_token(data: dict):
    to_encode = data.copy()
    to_encode["exp"] = datetime.utcnow() + timedelta(days=7)
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        result = supabase.table('users').select('*').eq('id', payload.get("sub")).execute()
        if not result.data:
            raise HTTPException(status_code=401, detail="User not found")
        return result.data[0]
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# AUTH
@app.post("/auth/register")
async def register(user: UserCreate):
    if supabase.table('users').select('*').eq('email', user.email).execute().data:
        raise HTTPException(status_code=400, detail="Email déjà utilisé")
    hashed = get_password_hash(user.password)
    result = supabase.table('users').insert({"email": user.email, "username": user.username, "hashed_password": hashed, "wallet_balance": 0, "is_admin": False}).execute()
    u = result.data[0]
    token = create_access_token({"sub": u["id"]})
    return {"access_token": token, "token_type": "bearer", "user": {"id": u["id"], "email": u["email"], "username": u["username"], "wallet_balance": u["wallet_balance"], "is_admin": u["is_admin"]}}

@app.post("/auth/login")
async def login(user: UserLogin):
    result = supabase.table('users').select('*').eq('email', user.email).execute()
    if not result.data or not verify_password(user.password, result.data[0]["hashed_password"]):
        raise HTTPException(status_code=401, detail="Email ou mot de passe incorrect")
    u = result.data[0]
    token = create_access_token({"sub": u["id"]})
    return {"access_token": token, "token_type": "bearer", "user": {"id": u["id"], "email": u["email"], "username": u["username"], "wallet_balance": u["wallet_balance"], "is_admin": u["is_admin"]}}

@app.get("/auth/me")
async def me(current_user: dict = Depends(get_current_user)):
    return {"id": current_user["id"], "email": current_user["email"], "username": current_user["username"], "wallet_balance": current_user["wallet_balance"], "is_admin": current_user["is_admin"]}

# CITIES
@app.get("/cities")
async def get_cities(current_user: dict = Depends(get_current_user)):
    cities = supabase.table('cities').select('*').eq('is_active', True).execute().data or []
    participations = supabase.table('participations').select('city_id').eq('user_id', current_user["id"]).eq('status', 'active').execute().data or []
    participated = [p["city_id"] for p in participations]
    for c in cities:
        c["user_has_participated"] = c["id"] in participated
        c["hint_available"] = c.get("hint_published", False) and c.get("hint_image") is not None
    return cities

@app.post("/init-cities")
async def init_cities():
    return {"message": "OK"}

# PARTICIPATE
@app.post("/participate")
async def participate(req: ParticipateRequest, current_user: dict = Depends(get_current_user)):
    city = supabase.table('cities').select('*').eq('id', req.city_id).execute().data
    if not city:
        raise HTTPException(status_code=404, detail="Ville non trouvée")
    city = city[0]
    if current_user["wallet_balance"] < 1:
        raise HTTPException(status_code=400, detail="Solde insuffisant. Rechargez votre portefeuille.")
    week = datetime.utcnow().isocalendar()[1]
    year = datetime.utcnow().year
    existing = supabase.table('participations').select('*').eq('user_id', current_user["id"]).eq('city_id', req.city_id).eq('week_number', week).eq('year', year).execute().data
    if existing:
        raise HTTPException(status_code=400, detail="Vous participez déjà à cette ville cette semaine")
    supabase.table('participations').insert({"user_id": current_user["id"], "city_id": req.city_id, "week_number": week, "year": year, "amount_paid": 1, "status": "active"}).execute()
    new_balance = float(current_user["wallet_balance"]) - 1
    supabase.table('users').update({"wallet_balance": new_balance}).eq('id', current_user["id"]).execute()
    new_pot = float(city.get("pot_amount", 0)) + 1
    new_count = int(city.get("participants_count", 0)) + 1
    supabase.table('cities').update({"pot_amount": new_pot, "participants_count": new_count}).eq('id', req.city_id).execute()
    supabase.table('transactions').insert({"user_id": current_user["id"], "type": "participation", "amount": -1, "description": f"Participation {city['name']}", "status": "completed"}).execute()
    return {"message": f"Inscription réussie pour {city['name']}", "new_balance": new_balance}

# SCAN QR
@app.post("/scan-qr")
async def scan_qr(req: ScanQRRequest, current_user: dict = Depends(get_current_user)):
    city = supabase.table('cities').select('*').eq('id', req.city_id).execute().data
    if not city:
        raise HTTPException(status_code=404, detail="Ville non trouvée")
    city = city[0]
    week = datetime.utcnow().isocalendar()[1]
    year = datetime.utcnow().year
    participation = supabase.table('participations').select('*').eq('user_id', current_user["id"]).eq('city_id', req.city_id).eq('week_number', week).eq('year', year).eq('status', 'active').execute().data
    if not participation:
        raise HTTPException(status_code=400, detail="Vous ne participez pas à cette ville")
    if req.qr_code != city.get("qr_code_secret"):
        raise HTTPException(status_code=400, detail="QR code invalide")
    pot = float(city.get("pot_amount", 0))
    new_balance = float(current_user["wallet_balance"]) + pot
    supabase.table('users').update({"wallet_balance": new_balance}).eq('id', current_user["id"]).execute()
    supabase.table('winners').insert({"user_id": current_user["id"], "city_id": req.city_id, "username": current_user["username"], "city_name": city["name"], "amount_won": pot, "week_number": week, "year": year}).execute()
    supabase.table('participations').update({"status": "won"}).eq('id', participation[0]["id"]).execute()
    supabase.table('cities').update({"pot_amount": 0, "participants_count": 0, "hint_published": False, "hint_image": None, "qr_code_secret": secrets.token_urlsafe(16)}).eq('id', req.city_id).execute()
    return {"message": "Félicitations!", "amount_won": pot, "new_balance": new_balance}

# STATS
@app.get("/stats/global")
async def stats():
    cities = supabase.table('cities').select('pot_amount').execute().data or []
    winners = supabase.table('winners').select('amount_won').execute().data or []
    active = supabase.table('cities').select('id').eq('is_active', True).execute().data or []
    return {"total_pot": sum(float(c.get("pot_amount", 0)) for c in cities), "total_winners": len(winners), "total_distributed": sum(float(w.get("amount_won", 0)) for w in winners), "active_cities": len(active)}

# WALLET
@app.get("/wallet/transactions")
async def transactions(current_user: dict = Depends(get_current_user)):
    return supabase.table('transactions').select('*').eq('user_id', current_user["id"]).order('created_at', desc=True).limit(50).execute().data or []

# ADMIN
@app.get("/admin/cities")
async def admin_cities(current_user: dict = Depends(get_current_user)):
    if not current_user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin only")
    return supabase.table('cities').select('*').execute().data or []

@app.get("/admin/users")
async def admin_users(current_user: dict = Depends(get_current_user)):
    if not current_user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin only")
    return supabase.table('users').select('id,email,username,wallet_balance,is_admin,created_at').execute().data or []

@app.get("/admin/stats")
async def admin_stats(current_user: dict = Depends(get_current_user)):
    if not current_user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin only")
    users = supabase.table('users').select('id').execute().data or []
    cities = supabase.table('cities').select('id').execute().data or []
    participations = supabase.table('participations').select('id').execute().data or []
    winners = supabase.table('winners').select('id').execute().data or []
    return {"total_users": len(users), "total_cities": len(cities), "total_participations": len(participations), "total_winners": len(winners)}

@app.get("/admin/qr-codes")
async def admin_qr_codes(current_user: dict = Depends(get_current_user)):
    if not current_user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin only")
    cities = supabase.table('cities').select('id,name,qr_code_secret').execute().data or []
    return [{"city_id": c["id"], "city_name": c["name"], "qr_code": c["qr_code_secret"]} for c in cities]

@app.post("/admin/cities")
async def create_city(city: CityCreate, current_user: dict = Depends(get_current_user)):
    if not current_user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin only")
    result = supabase.table('cities').insert({"name": city.name, "slug": city.slug, "image_url": city.image_url, "pot_amount": 0, "participants_count": 0, "is_active": True, "qr_code_secret": secrets.token_urlsafe(16)}).execute()
    return result.data[0] if result.data else {"error": "Failed"}

@app.put("/admin/cities/{city_id}")
async def update_city(city_id: str, city: CityUpdate, current_user: dict = Depends(get_current_user)):
    if not current_user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin only")
    update = {k: v for k, v in city.dict().items() if v is not None}
    supabase.table('cities').update(update).eq('id', city_id).execute()
    return {"message": "Ville mise à jour"}

@app.delete("/admin/cities/{city_id}")
async def delete_city(city_id: str, current_user: dict = Depends(get_current_user)):
    if not current_user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin only")
    supabase.table('cities').delete().eq('id', city_id).execute()
    return {"message": "Supprimée"}

@app.get("/health")
async def health():
    return {"status": "healthy"}

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
