from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from app.services.ssh_service import (
    SSHAuthenticationError,
    SSHCommandError,
    SSHConnectionError,
    SSHService,
)

router = APIRouter(prefix="/api/ssh", tags=["SSH Paramiko"])
service = SSHService()


class SSHConnectRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: str = Field(min_length=1)
    username: str = Field(min_length=1)
    password: SecretStr | None = None
    private_key: str | None = None
    private_key_passphrase: SecretStr | None = None
    port: int = Field(default=22, ge=1, le=65535)
    timeout: float = Field(default=30.0, gt=0)
    command: str = Field(min_length=1)
    command_timeout: float | None = Field(default=None, gt=0)
    allow_unknown_hosts: bool = False


def _ssh_error(exc: Exception, status_code: int = 502):
    raise HTTPException(status_code=status_code, detail=str(exc)) from exc


@router.post("/connect", summary="Se connecter à une machine distante et exécuter une commande SSH")
def connect(payload: SSHConnectRequest):
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
