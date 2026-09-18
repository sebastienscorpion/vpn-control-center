from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.vpn import router as vpn_router
from app.api.auth import router as auth_router     # ← LIGNE À AJOUTER

app = FastAPI(
    title="VPN Control Center",
    description="API REST pour la gestion d'un VPN Site-to-Site avec strongSwan",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # à restreindre plus tard, ex: ["http://localhost:5173"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(vpn_router)
app.include_router(auth_router)                


@app.get("/")
def root():
    return {
        "application": "VPN Control Center",
        "status": "running"
    }


@app.get("/api/health")
def health():
    return {
        "status": "UP"
    }