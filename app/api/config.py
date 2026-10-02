from fastapi import APIRouter, HTTPException

from app.schemas.tunnel import IPsecTunnel
from app.services.config_service import (
    ConfigService,
    ConfigUnavailableError,
)
from app.services.config_writer_service import ConfigWriteError, ConfigWriterService
from app.services.vici_service import ViciService


router = APIRouter(
    prefix="/api/config",
    tags=["Configuration IPsec"],
)


config_service = ConfigService()


@router.get("/raw", summary="Lire le fichier ipsec.conf brut")
def get_raw_config():
    """
    Équivalent de `cat /etc/ipsec.conf`, mais via l'API.
    """
    try:
        return {
            "path": "/etc/ipsec.conf",
            "content": config_service.read_raw(),
        }

    except ConfigUnavailableError as exc:
        raise HTTPException(
            status_code=503,
            detail=str(exc),
        )


@router.get("/connections", summary="Lister les connexions configurées")
def get_parsed_config():
    """
    Retourne la configuration IPsec découpée connexion par connexion.
    """
    try:
        return config_service.parse_connections()

    except ConfigUnavailableError as exc:
        raise HTTPException(
            status_code=503,
            detail=str(exc),
        )


@router.get("/connections/{connection_name}", summary="Lire une connexion configurée")
def get_configured_connection(connection_name: str):
    try:
        connections = config_service.parse_connections()
    except ConfigUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    for connection in connections:
        if connection["name"] == connection_name:
            return connection
    raise HTTPException(status_code=404, detail=f"Connexion '{connection_name}' introuvable.")


@router.post("/connections", status_code=201, summary="Créer une connexion IPsec")
def create_connection(payload: IPsecTunnel):
    writer = ConfigWriterService()
    vici = ViciService()
    try:
        if any(item["name"] == payload.name for item in config_service.parse_connections()):
            raise HTTPException(status_code=409, detail=f"La connexion '{payload.name}' existe déjà.")
        result = writer.apply_tunnel(
            payload,
            verify=lambda: vici.connection_exists(payload.name),
        )
        return {"success": True, **result}
    except HTTPException:
        raise
    except NotImplementedError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except (ConfigWriteError, ConfigUnavailableError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Échec de la création : {exc}")


@router.put("/connections/{connection_name}", summary="Mettre à jour une connexion IPsec")
def update_connection(connection_name: str, payload: IPsecTunnel):
    if payload.name != connection_name:
        raise HTTPException(
            status_code=400,
            detail="Le nom de la connexion dans l’URL doit correspondre au nom du corps.",
        )

    writer = ConfigWriterService()
    vici = ViciService()
    try:
        connections = config_service.parse_connections()
        if not any(item["name"] == connection_name for item in connections):
            raise HTTPException(status_code=404, detail=f"Connexion '{connection_name}' introuvable.")
        result = writer.apply_tunnel(
            payload,
            verify=lambda: vici.connection_exists(connection_name),
        )
        return {"success": True, **result}
    except HTTPException:
        raise
    except NotImplementedError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except (ConfigWriteError, ConfigUnavailableError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Échec de la mise à jour : {exc}")


@router.delete("/connections/{connection_name}", summary="Supprimer une connexion IPsec")
def delete_connection(connection_name: str):
    writer = ConfigWriterService()
    try:
        result = writer.remove_connection(connection_name)
        if not result["removed"]:
            raise HTTPException(status_code=404, detail=f"Connexion '{connection_name}' introuvable.")
        return {"success": True, **result}
    except HTTPException:
        raise
    except ConfigWriteError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Échec de la suppression : {exc}")