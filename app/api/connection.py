from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.services.network_service import InvalidHostError, ping
from app.services.vici_service import ViciService


router = APIRouter(prefix="/api/connections", tags=["Connexions VPN"])


class PingRequest(BaseModel):
    host: str


class TestRequest(BaseModel):
    ping_host: str | None = None


@router.get("/version", summary="Lire la version de strongSwan")
def vpn_version():
    return ViciService().get_version()


@router.get("", summary="Lister l’état de toutes les connexions")
def vpn_overview():
    try:
        return ViciService().get_overview()
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"VICI inaccessible : {exc}")


@router.get("/sas", summary="Lister les associations de sécurité actives")
def vpn_security_associations():
    try:
        return ViciService().get_sas()
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"VICI inaccessible : {exc}")


@router.get("/{connection_name}/status", summary="Lire l’état d’une connexion")
def vpn_status(connection_name: str):
    try:
        return ViciService().get_status(connection_name)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"VICI inaccessible : {exc}")


@router.post("/{connection_name}/start", summary="Démarrer une connexion")
def vpn_start(connection_name: str):
    vici = ViciService()
    try:
        if not vici.connection_exists(connection_name):
            raise HTTPException(status_code=404, detail=f"Connexion '{connection_name}' introuvable dans strongSwan.")
        log = vici.initiate(connection_name)
        status = vici.get_status(connection_name)
        return {
            "success": status["ike_sa_state"] == "ESTABLISHED",
            "connection": connection_name,
            "status": status,
            "log": log,
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Échec du démarrage : {exc}")


@router.post("/{connection_name}/down", summary="Arrêter une connexion")
def vpn_stop(connection_name: str):
    vici = ViciService()
    try:
        log = vici.terminate(connection_name)
        status = vici.get_status(connection_name)
        return {
            "success": status["ike_sa_state"] != "ESTABLISHED",
            "connection": connection_name,
            "status": status,
            "log": log,
        }
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Échec de l’arrêt : {exc}")


@router.post("/{connection_name}/restart", summary="Redémarrer une connexion")
def vpn_restart(connection_name: str):
    vici = ViciService()
    try:
        vici.terminate(connection_name)
        log = vici.initiate(connection_name)
        status = vici.get_status(connection_name)
        return {
            "success": status["ike_sa_state"] == "ESTABLISHED",
            "connection": connection_name,
            "status": status,
            "log": log,
        }
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Échec du redémarrage : {exc}")


@router.post("/ping", summary="Tester la connectivité IP d’un hôte")
def vpn_ping(payload: PingRequest):
    try:
        return ping(payload.host)
    except InvalidHostError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/{connection_name}/test", summary="Tester une connexion et, en option, son trafic")
def vpn_test(connection_name: str, payload: TestRequest | None = None):
    try:
        return ViciService().test_connection(
            connection_name,
            payload.ping_host if payload else None,
        )
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Erreur lors du test : {exc}")