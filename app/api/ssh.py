from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from app.services.ssh_service import (
    SSHAuthenticationError,
    SSHCommandError,
    SSHConnectionError,
    SSHFileOperationError,
    SSHService,
)

router = APIRouter(prefix="/api/ssh", tags=["SSH Paramiko"])
service = SSHService()


class SSHCredentials(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: str = Field(min_length=1)
    username: str = Field(min_length=1)
    password: SecretStr | None = None
    private_key: str | None = None
    private_key_passphrase: SecretStr | None = None
    port: int = Field(default=22, ge=1, le=65535)
    timeout: float = Field(default=30.0, gt=0)
    allow_unknown_hosts: bool = False


class CommandRequest(SSHCredentials):
    command: str = Field(min_length=1)
    command_timeout: float | None = Field(default=None, gt=0)


class RemotePathRequest(SSHCredentials):
    path: str = Field(min_length=1)


class FileUploadRequest(SSHCredentials):
    path: str = Field(min_length=1)
    content: str | None = None


class DirectoryRequest(SSHCredentials):
    path: str = Field(default="/", min_length=1)


class SFTPDownloadRequest(SSHCredentials):
    path: str = Field(min_length=1)
    local_path: str = Field(min_length=1)


def _ssh_error(exc: Exception, status_code: int = 502):
    raise HTTPException(status_code=status_code, detail=str(exc)) from exc


@router.get("/health", summary="Vérifier que Paramiko peut être chargé")
def ssh_health():
    return {
        "success": True,
        "implementation": "paramiko",
        "version": getattr(__import__("paramiko"), "__version__", None),
    }


@router.post("/command", summary="Exécuter une commande distante")
def execute_command(payload: CommandRequest):
    try:
        return service.execute_command(
            host=payload.host,
            username=payload.username,
            password=payload.password.get_secret_value() if payload.password else None,
            private_key=payload.private_key,
            private_key_passphrase=(
                payload.private_key_passphrase.get_secret_value()
                if payload.private_key_passphrase
                else None
            ),
            port=payload.port,
            timeout=payload.timeout,
            command=payload.command,
            allow_unknown_hosts=payload.allow_unknown_hosts,
            command_timeout=payload.command_timeout,
        )
    except (SSHAuthenticationError, SSHCommandError, SSHConnectionError) as exc:
        _ssh_error(exc, 503 if isinstance(exc, SSHAuthenticationError) else 502)


@router.post("/system", summary="Récupérer les informations système")
def system_info(payload: SSHCredentials):
    try:
        return service.get_remote_environment(
            host=payload.host,
            username=payload.username,
            password=payload.password.get_secret_value() if payload.password else None,
            private_key=payload.private_key,
            private_key_passphrase=(
                payload.private_key_passphrase.get_secret_value()
                if payload.private_key_passphrase
                else None
            ),
            port=payload.port,
            timeout=payload.timeout,
            allow_unknown_hosts=payload.allow_unknown_hosts,
        )
    except (SSHAuthenticationError, SSHConnectionError) as exc:
        _ssh_error(exc, 503 if isinstance(exc, SSHAuthenticationError) else 502)


@router.post("/uptime", summary="Afficher le temps de fonctionnement distant")
def system_uptime(payload: SSHCredentials):
    try:
        return service.get_system_uptime(
            host=payload.host,
            username=payload.username,
            password=payload.password.get_secret_value() if payload.password else None,
            private_key=payload.private_key,
            private_key_passphrase=(
                payload.private_key_passphrase.get_secret_value()
                if payload.private_key_passphrase
                else None
            ),
            port=payload.port,
            timeout=payload.timeout,
            allow_unknown_hosts=payload.allow_unknown_hosts,
        )
    except (SSHAuthenticationError, SSHConnectionError, SSHCommandError) as exc:
        _ssh_error(exc, 503 if isinstance(exc, SSHAuthenticationError) else 502)


@router.post("/facts", summary="Obtenir le nom d'hôte, l'utilisateur et le système")
def system_facts(payload: SSHCredentials):
    try:
        return service.get_system_facts(
            host=payload.host,
            username=payload.username,
            password=payload.password.get_secret_value() if payload.password else None,
            private_key=payload.private_key,
            private_key_passphrase=(
                payload.private_key_passphrase.get_secret_value()
                if payload.private_key_passphrase
                else None
            ),
            port=payload.port,
            timeout=payload.timeout,
            allow_unknown_hosts=payload.allow_unknown_hosts,
        )
    except (SSHAuthenticationError, SSHConnectionError, SSHCommandError) as exc:
        _ssh_error(exc, 503 if isinstance(exc, SSHAuthenticationError) else 502)


@router.post("/shell", summary="Ouvrir un shell interactif distant")
def open_shell(payload: SSHCredentials):
    try:
        channel = service.open_shell(
            host=payload.host,
            username=payload.username,
            password=payload.password.get_secret_value() if payload.password else None,
            private_key=payload.private_key,
            private_key_passphrase=(
                payload.private_key_passphrase.get_secret_value()
                if payload.private_key_passphrase
                else None
            ),
            port=payload.port,
            timeout=payload.timeout,
            allow_unknown_hosts=payload.allow_unknown_hosts,
        )
        return {
            "success": True,
            "host": payload.host,
            "shell_channel": "interactive",
            "note": "Le shell est disponible via une connexion SSH Paramiko; utilisez l'API command pour les commandes non interactives.",
        }
    except (SSHAuthenticationError, SSHConnectionError) as exc:
        _ssh_error(exc, 503 if isinstance(exc, SSHAuthenticationError) else 502)


@router.post("/files/list", summary="Lister un répertoire distant")
def list_directory(payload: DirectoryRequest):
    try:
        return service.list_directory(
            host=payload.host,
            username=payload.username,
            password=payload.password.get_secret_value() if payload.password else None,
            private_key=payload.private_key,
            private_key_passphrase=(
                payload.private_key_passphrase.get_secret_value()
                if payload.private_key_passphrase
                else None
            ),
            port=payload.port,
            timeout=payload.timeout,
            path=payload.path,
            allow_unknown_hosts=payload.allow_unknown_hosts,
        )
    except (SSHAuthenticationError, SSHConnectionError, SSHFileOperationError) as exc:
        _ssh_error(exc, 503 if isinstance(exc, SSHAuthenticationError) else 502)


@router.post("/files/info", summary="Récupérer les métadonnées d'un fichier distant")
def get_file_info(payload: RemotePathRequest):
    try:
        return service.get_file_info(
            host=payload.host,
            username=payload.username,
            password=payload.password.get_secret_value() if payload.password else None,
            private_key=payload.private_key,
            private_key_passphrase=(
                payload.private_key_passphrase.get_secret_value()
                if payload.private_key_passphrase
                else None
            ),
            port=payload.port,
            timeout=payload.timeout,
            path=payload.path,
            allow_unknown_hosts=payload.allow_unknown_hosts,
        )
    except (SSHAuthenticationError, SSHConnectionError, SSHFileOperationError) as exc:
        _ssh_error(exc, 503 if isinstance(exc, SSHAuthenticationError) else 502)


@router.post("/files/create-directory", summary="Créer un dossier distant")
def create_directory(payload: DirectoryRequest):
    try:
        return service.create_directory(
            host=payload.host,
            username=payload.username,
            password=payload.password.get_secret_value() if payload.password else None,
            private_key=payload.private_key,
            private_key_passphrase=(
                payload.private_key_passphrase.get_secret_value()
                if payload.private_key_passphrase
                else None
            ),
            port=payload.port,
            timeout=payload.timeout,
            path=payload.path,
            allow_unknown_hosts=payload.allow_unknown_hosts,
        )
    except (SSHAuthenticationError, SSHConnectionError, SSHFileOperationError) as exc:
        _ssh_error(exc, 503 if isinstance(exc, SSHAuthenticationError) else 502)


@router.post("/files/upload", summary="Envoyer un fichier vers la machine distante")
def upload_file(payload: FileUploadRequest):
    try:
        return service.upload_file(
            host=payload.host,
            username=payload.username,
            password=payload.password.get_secret_value() if payload.password else None,
            private_key=payload.private_key,
            private_key_passphrase=(
                payload.private_key_passphrase.get_secret_value()
                if payload.private_key_passphrase
                else None
            ),
            port=payload.port,
            timeout=payload.timeout,
            path=payload.path,
            remote_path=payload.path,
            allow_unknown_hosts=payload.allow_unknown_hosts,
            content=payload.content or "",
        )
    except (SSHAuthenticationError, SSHConnectionError, SSHFileOperationError, ValueError) as exc:
        _ssh_error(exc, 503 if isinstance(exc, SSHAuthenticationError) else 400)


@router.post("/files/upload-multipart", summary="Envoyer un fichier distant via UploadFile")
async def upload_file_multipart(
    file: UploadFile = File(...),
    host: str = None,
    username: str = None,
    password: str | None = None,
    private_key: str | None = None,
    private_key_passphrase: str | None = None,
    port: int = 22,
    timeout: float = 30.0,
    remote_path: str = "/tmp/",
    allow_unknown_hosts: bool = False,
):
    if not host or not username:
        raise HTTPException(status_code=400, detail="host et username sont requis.")
    try:
        content = await file.read()
        destination = os.path.join(remote_path, file.filename or "upload")
        return service.upload_file(
            host=host,
            username=username,
            password=password,
            private_key=private_key,
            private_key_passphrase=private_key_passphrase,
            port=port,
            timeout=timeout,
            path=destination,
            remote_path=destination,
            allow_unknown_hosts=allow_unknown_hosts,
            file_obj=__import__("io").BytesIO(content),
        )
    except (SSHAuthenticationError, SSHConnectionError, SSHFileOperationError, ValueError) as exc:
        _ssh_error(exc, 503 if isinstance(exc, SSHAuthenticationError) else 400)


@router.post("/files/download", summary="Télécharger un fichier distant")
def download_file(payload: SFTPDownloadRequest):
    if not payload.local_path:
        raise HTTPException(status_code=400, detail="local_path est requis.")
    try:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            temp_path = tmp.name
        try:
            result = service.download_file(
                host=payload.host,
                username=payload.username,
                password=payload.password.get_secret_value() if payload.password else None,
                private_key=payload.private_key,
                private_key_passphrase=(
                    payload.private_key_passphrase.get_secret_value()
                    if payload.private_key_passphrase
                    else None
                ),
                port=payload.port,
                timeout=payload.timeout,
                path=payload.path,
                local_path=temp_path,
                allow_unknown_hosts=payload.allow_unknown_hosts,
            )
            return FileResponse(
                temp_path,
                filename=Path(payload.path).name,
                media_type="application/octet-stream",
            )
        except Exception:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            raise
    except (SSHAuthenticationError, SSHConnectionError, SSHFileOperationError) as exc:
        _ssh_error(exc, 503 if isinstance(exc, SSHAuthenticationError) else 502)


@router.delete("/files", summary="Supprimer un fichier distant")
def remove_file(payload: RemotePathRequest):
    try:
        return service.remove_file(
            host=payload.host,
            username=payload.username,
            password=payload.password.get_secret_value() if payload.password else None,
            private_key=payload.private_key,
            private_key_passphrase=(
                payload.private_key_passphrase.get_secret_value()
                if payload.private_key_passphrase
                else None
            ),
            port=payload.port,
            timeout=payload.timeout,
            path=payload.path,
            allow_unknown_hosts=payload.allow_unknown_hosts,
        )
    except (SSHAuthenticationError, SSHConnectionError, SSHFileOperationError) as exc:
        _ssh_error(exc, 503 if isinstance(exc, SSHAuthenticationError) else 502)


@router.post("/reboot", summary="Redémarrer la machine distante")
def reboot(payload: SSHCredentials):
    try:
        return service.reboot(
            host=payload.host,
            username=payload.username,
            password=payload.password.get_secret_value() if payload.password else None,
            private_key=payload.private_key,
            private_key_passphrase=(
                payload.private_key_passphrase.get_secret_value()
                if payload.private_key_passphrase
                else None
            ),
            port=payload.port,
            timeout=payload.timeout,
            allow_unknown_hosts=payload.allow_unknown_hosts,
        )
    except (SSHAuthenticationError, SSHConnectionError, SSHCommandError) as exc:
        _ssh_error(exc, 503 if isinstance(exc, SSHAuthenticationError) else 502)


@router.post("/shutdown", summary="Arrêter la machine distante")
def shutdown(payload: SSHCredentials):
    try:
        return service.shutdown(
            host=payload.host,
            username=payload.username,
            password=payload.password.get_secret_value() if payload.password else None,
            private_key=payload.private_key,
            private_key_passphrase=(
                payload.private_key_passphrase.get_secret_value()
                if payload.private_key_passphrase
                else None
            ),
            port=payload.port,
            timeout=payload.timeout,
            allow_unknown_hosts=payload.allow_unknown_hosts,
        )
    except (SSHAuthenticationError, SSHConnectionError, SSHCommandError) as exc:
        _ssh_error(exc, 503 if isinstance(exc, SSHAuthenticationError) else 502)
