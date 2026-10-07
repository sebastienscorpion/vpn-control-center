from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.config import router as config_router
from app.api.connection import router as connection_router
from app.api.ssh import router as ssh_router


tags_metadata = [
    {
        "name": "Configuration IPsec",
        "description": "Lecture et gestion CRUD des connexions configurées dans strongSwan.",
    },
    {
        "name": "Connexions VPN",
        "description": "État, démarrage, arrêt, redémarrage et tests des connexions strongSwan.",
    },
]


app = FastAPI(
    title="VPN Control Center",
    description="API REST pour la gestion d'un VPN Site-to-Site avec strongSwan",
    version="1.0.0",
    openapi_tags=tags_metadata,
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# ROUTERS
# ============================================================

app.include_router(config_router)
app.include_router(connection_router)
app.include_router(ssh_router)


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():
    return {
        "application": "VPN Control Center",
        "status": "running",
    }


@app.get("/api/health")
def health():
    return {
        "status": "UP",
    }