from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.services.vici_service import ViciService
from app.services.network_service import InvalidHostError, ping

router = APIRouter(
    prefix="/api/vpn",
    tags=["VPN"]
)

DEFAULT_CONNECTION_NAME = "site-to-site"


class PingRequest(BaseModel):
    host: str


@router.get("/version")
def vpn_version():
    vici = ViciService()
    return vici.get_version()


@router.get("/connections")
def vpn_connections():
    vici = ViciService()
    return vici.get_connections()


@router.get("/sas")
def vpn_security_associations():
    vici = ViciService()
    return vici.get_sas()


@router.get("/status")
@router.get("/status/{connection_name}")
def vpn_status(connection_name: str = DEFAULT_CONNECTION_NAME):
    vici = ViciService()
    try:
        return vici.get_status(connection_name)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"VICI inaccessible : {exc}")


@router.post("/start")
@router.post("/start/{connection_name}")
def vpn_start(connection_name: str = DEFAULT_CONNECTION_NAME):
    """Équivalent de `sudo ipsec up site-to-site`, via VICI."""
    vici = ViciService()
    try:
        if not vici.connection_exists(connection_name):
            raise HTTPException(
                status_code=404,
                detail=f"Connexion '{connection_name}' introuvable côté strongSwan.",
            )
        log = vici.initiate(connection_name)
        live_status = vici.get_status(connection_name)
        return {
            "success": live_status["ike_sa_state"] == "ESTABLISHED",
            "connection": connection_name,
            "status": live_status,
            "log": log,
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Échec du démarrage : {exc}")


@router.post("/stop")
@router.post("/stop/{connection_name}")
def vpn_stop(connection_name: str = DEFAULT_CONNECTION_NAME):
    """Équivalent de `sudo ipsec down site-to-site`, via VICI."""
    vici = ViciService()
    try:
        log = vici.terminate(connection_name)
        live_status = vici.get_status(connection_name)
        return {
            "success": live_status["ike_sa_state"] != "ESTABLISHED",
            "connection": connection_name,
            "status": live_status,
            "log": log,
        }
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Échec de l'arrêt : {exc}")


@router.post("/ping")
def vpn_ping(payload: PingRequest):
    try:
        return ping(payload.host)
    except InvalidHostError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

@router.get("/overview")
def vpn_overview():
    """
    Liste TOUTES les connexions configurées avec leur état réel (actif ou
    non). Pratique pour un tableau de bord qui doit gérer plusieurs
    connexions VPN, pas juste 'site-to-site'.
    """
    vici = ViciService()
    try:
        return vici.get_overview()
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"VICI inaccessible : {exc}")


class TestRequest(BaseModel):
    ping_host: str | None = None


@router.post("/test/{connection_name}")
def vpn_test(connection_name: str, payload: TestRequest = TestRequest()):
    """
    Teste une connexion précise : état du tunnel + ping optionnel à
    travers ce tunnel (si `ping_host` est fourni).
    """
    vici = ViciService()
    try:
        return vici.test_connection(connection_name, payload.ping_host)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Erreur lors du test : {exc}")