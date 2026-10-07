from __future__ import annotations

import io
import os
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Callable, Optional

import paramiko


class SSHConnectionError(Exception):
    pass


class SSHAuthenticationError(SSHConnectionError):
    pass


class SSHCommandError(SSHConnectionError):
    pass


class SSHFileOperationError(SSHConnectionError):
    pass


@dataclass(frozen=True)
class SSHConnectionConfig:
    host: str
    username: str
    password: Optional[str] = None
    port: int = 22
    private_key: Optional[str] = None
    private_key_passphrase: Optional[str] = None
    timeout: float = 30.0
    allow_unknown_hosts: bool = False
    banner_timeout: float = 30.0
    auth_timeout: float = 30.0
    keepalive_interval: int = 30
    command_timeout: Optional[float] = None

    def validate(self) -> None:
        if not self.host:
            raise ValueError("L'hôte SSH est requis.")
        if not self.username:
            raise ValueError("Le nom d'utilisateur SSH est requis.")
        if not (self.password or self.private_key):
            raise ValueError("Un mot de passe ou une clé privée SSH est requis.")
        if not 1 <= self.port <= 65535:
            raise ValueError("Le port SSH doit être compris entre 1 et 65535.")
        if self.private_key and not os.path.exists(self.private_key):
            raise ValueError(f"La clé privée SSH est introuvable : {self.private_key}")


class SSHClientFactory:
    """Créer et configurer les clients Paramiko avec le comportement SSH demandé."""

    def __init__(self, allow_unknown_hosts: bool = False):
        self.allow_unknown_hosts = allow_unknown_hosts

    def _create_client(self):
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        if self.allow_unknown_hosts:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        return client

    def create(self):
        return self._create_client()


class SSHService:
    def __init__(
        self,
        client_factory: Optional[Callable[..., Any]] = None,
    ):
        self.client_factory = client_factory or SSHClientFactory().create

    def _connect(self, config: SSHConnectionConfig):
        config.validate()
        client = self.client_factory()
        try:
            client.connect(
                hostname=config.host,
                username=config.username,
                password=config.password,
                pkey=self._load_private_key(config),
                port=config.port,
                timeout=config.timeout,
                banner_timeout=config.banner_timeout,
                auth_timeout=config.auth_timeout,
                allow_agent=False,
                look_for_keys=False,
            )
        except (paramiko.BadHostKeyException, paramiko.AuthenticationException,
                paramiko.SSHException, paramiko.PasswordRequiredException) as exc:
            raise SSHAuthenticationError(f"Échec de l'authentification SSH : {exc}") from exc
        except OSError as exc:
            raise SSHConnectionError(f"Connexion SSH impossible : {exc}") from exc
        client.keepalive_interval = config.keepalive_interval
        return client

    def _load_private_key(self, config: SSHConnectionConfig):
        if not config.private_key:
            return None
        try:
            key = paramiko.RSAKey.from_private_key_file(
                config.private_key,
                password=config.private_key_passphrase,
            )
        except (IOError, ValueError, paramiko.PasswordRequiredException) as exc:
            raise SSHAuthenticationError(
                f"Clé privée SSH invalide ou protégée par un mot de passe : {exc}"
            ) from exc
        return key

    def execute_command(
        self,
        host: str,
        username: str,
        password: Optional[str] = None,
        private_key: Optional[str] = None,
        private_key_passphrase: Optional[str] = None,
        port: int = 22,
        timeout: float = 30.0,
        command: str = "",
        allow_unknown_hosts: bool = False,
        command_timeout: Optional[float] = None,
    ) -> dict[str, Any]:
        if not command:
            raise ValueError("La commande à exécuter est requise.")

        config = SSHConnectionConfig(
            host=host,
            username=username,
            password=password,
            private_key=private_key,
            private_key_passphrase=private_key_passphrase,
            port=port,
            timeout=timeout,
            allow_unknown_hosts=allow_unknown_hosts,
            command_timeout=command_timeout,
        )
        client = self._connect(config)
        try:
            stdin, stdout, stderr = client.exec_command(
                command,
                timeout=config.command_timeout,
                get_pty=False,
            )
            stdout_data = stdout.read().decode(errors="replace")
            stderr_data = stderr.read().decode(errors="replace")
            exit_code = stdout.channel.recv_exit_status()
            return {
                "success": exit_code == 0,
                "host": host,
                "username": username,
                "command": command,
                "exit_code": exit_code,
                "stdout": stdout_data,
                "stderr": stderr_data,
                "duration_seconds": None,
            }
        except (SSHConnectionError, paramiko.SSHException) as exc:
            raise SSHCommandError(f"Échec de l'exécution de la commande : {exc}") from exc
        finally:
            client.close()

    def list_directory(
        self,
        host: str,
        username: str,
        password: Optional[str] = None,
        private_key: Optional[str] = None,
        private_key_passphrase: Optional[str] = None,
        port: int = 22,
        timeout: float = 30.0,
        path: str = "/",
        allow_unknown_hosts: bool = False,
    ) -> dict[str, Any]:
        config = SSHConnectionConfig(
            host=host,
            username=username,
            password=password,
            private_key=private_key,
            private_key_passphrase=private_key_passphrase,
            port=port,
            timeout=timeout,
            allow_unknown_hosts=allow_unknown_hosts,
        )
        client = self._connect(config)
        try:
            sftp = client.open_sftp()
            entries = sftp.listdir(path)
            files = []
            for entry in entries:
                full_path = f"{path.rstrip('/')}/{entry}" if path != "/" else f"/{entry}"
                try:
                    stat = sftp.stat(full_path)
                    files.append({
                        "name": entry,
                        "path": full_path,
                        "is_directory": stat.st_mode & 0o170000 == 0o040000,
                        "is_file": stat.st_mode & 0o170000 == 0o100000,
                        "mode": format(stat.st_mode, "06o"),
                        "size": stat.st_size,
                    })
                except (IOError, OSError):
                    files.append({"name": entry, "path": full_path, "exists": False})
            return {"path": path, "files": files}
        except (IOError, OSError, paramiko.SSHException) as exc:
            raise SSHFileOperationError(f"Impossible de lire le répertoire distant : {exc}") from exc
        finally:
            client.close()

    def get_file_info(
        self,
        host: str,
        username: str,
        password: Optional[str] = None,
        private_key: Optional[str] = None,
        private_key_passphrase: Optional[str] = None,
        port: int = 22,
        timeout: float = 30.0,
        path: str = "/",
        allow_unknown_hosts: bool = False,
    ) -> dict[str, Any]:
        cfg = SSHConnectionConfig(
            host=host,
            username=username,
            password=password,
            private_key=private_key,
            private_key_passphrase=private_key_passphrase,
            port=port,
            timeout=timeout,
            allow_unknown_hosts=allow_unknown_hosts,
        )
        client = self._connect(cfg)
        try:
            with client.open_sftp() as sftp:
                stat = sftp.stat(path)
                return {
                    "path": path,
                    "exists": True,
                    "is_directory": stat.st_mode & 0o170000 == 0o040000,
                    "is_file": stat.st_mode & 0o170000 == 0o100000,
                    "mode": format(stat.st_mode, "06o"),
                    "size": stat.st_size,
                }
        except (IOError, OSError, paramiko.SSHException) as exc:
            raise SSHFileOperationError(f"Impossible d'obtenir les informations du fichier : {exc}") from exc
        finally:
            client.close()

    def create_directory(
        self,
        host: str,
        username: str,
        password: Optional[str] = None,
        private_key: Optional[str] = None,
        private_key_passphrase: Optional[str] = None,
        port: int = 22,
        timeout: float = 30.0,
        path: str = "/",
        allow_unknown_hosts: bool = False,
    ) -> dict[str, Any]:
        cfg = SSHConnectionConfig(
            host=host,
            username=username,
            password=password,
            private_key=private_key,
            private_key_passphrase=private_key_passphrase,
            port=port,
            timeout=timeout,
            allow_unknown_hosts=allow_unknown_hosts,
        )
        client = self._connect(cfg)
        try:
            with client.open_sftp() as sftp:
                sftp.mkdir(path, mode=0o755)
            return {"success": True, "path": path, "created": True}
        except (IOError, OSError, paramiko.SSHException) as exc:
            raise SSHFileOperationError(f"Impossible de créer le dossier : {exc}") from exc
        finally:
            client.close()

    def remove_file(self, host: str, username: str, password: Optional[str] = None, private_key: Optional[str] = None, private_key_passphrase: Optional[str] = None, port: int = 22, timeout: float = 30.0, path: str = "/", allow_unknown_hosts: bool = False) -> dict[str, Any]:
        cfg = SSHConnectionConfig(
            host=host,
            username=username,
            password=password,
            private_key=private_key,
            private_key_passphrase=private_key_passphrase,
            port=port,
            timeout=timeout,
            allow_unknown_hosts=allow_unknown_hosts,
        )
        client = self._connect(cfg)
        try:
            with client.open_sftp() as sftp:
                sftp.remove(path)
            return {"success": True, "path": path, "removed": True}
        except (IOError, OSError, paramiko.SSHException) as exc:
            raise SSHFileOperationError(f"Impossible de supprimer le fichier : {exc}") from exc
        finally:
            client.close()

    def upload_file(
        self,
        host: str,
        username: str,
        password: Optional[str] = None,
        private_key: Optional[str] = None,
        private_key_passphrase: Optional[str] = None,
        port: int = 22,
        timeout: float = 30.0,
        path: str = "/",
        remote_path: str = "/",
        allow_unknown_hosts: bool = False,
        content: str = "",
        file_obj: Optional[io.BytesIO] = None,
    ) -> dict[str, Any]:
        if bool(content) == bool(file_obj):
            raise ValueError("Fournissez soit content, soit file_obj, mais pas les deux.")
        cfg = SSHConnectionConfig(
            host=host,
            username=username,
            password=password,
            private_key=private_key,
            private_key_passphrase=private_key_passphrase,
            port=port,
            timeout=timeout,
            allow_unknown_hosts=allow_unknown_hosts,
        )
        client = self._connect(cfg)
        try:
            with client.open_sftp() as sftp:
                payload = file_obj if file_obj is not None else io.BytesIO(content.encode())
                sftp.putfo(payload, remote_path)
            return {"success": True, "remote_path": remote_path, "uploaded": True}
        except (IOError, OSError, paramiko.SSHException) as exc:
            raise SSHFileOperationError(f"Impossible d'envoyer le fichier distant : {exc}") from exc
        finally:
            client.close()

    def download_file(
        self,
        host: str,
        username: str,
        password: Optional[str] = None,
        private_key: Optional[str] = None,
        private_key_passphrase: Optional[str] = None,
        port: int = 22,
        timeout: float = 30.0,
        path: str = "/",
        local_path: str = "/tmp",
        allow_unknown_hosts: bool = False,
    ) -> dict[str, Any]:
        cfg = SSHConnectionConfig(
            host=host,
            username=username,
            password=password,
            private_key=private_key,
            private_key_passphrase=private_key_passphrase,
            port=port,
            timeout=timeout,
            allow_unknown_hosts=allow_unknown_hosts,
        )
        client = self._connect(cfg)
        try:
            with client.open_sftp() as sftp:
                with open(local_path, "wb") as local_file:
                    sftp.getfo(path, local_file)
            return {"success": True, "remote_path": path, "local_path": local_path, "downloaded": True}
        except (IOError, OSError, paramiko.SSHException) as exc:
            raise SSHFileOperationError(f"Impossible de télécharger le fichier : {exc}") from exc
        finally:
            client.close()

    def get_remote_environment(self, host: str, username: str, password: Optional[str] = None, private_key: Optional[str] = None, private_key_passphrase: Optional[str] = None, port: int = 22, timeout: float = 30.0, allow_unknown_hosts: bool = False) -> dict[str, Any]:
        result = self.execute_command(
            host=host,
            username=username,
            password=password,
            private_key=private_key,
            private_key_passphrase=private_key_passphrase,
            port=port,
            timeout=timeout,
            command="uname -a && printf '\n---OS---\n' && cat /etc/os-release && printf '\n---HOME---\n' && printf '%s\n' \"$HOME\"",
            allow_unknown_hosts=allow_unknown_hosts,
        )
        return {
            "host": host,
            "username": username,
            "success": result["success"],
            "environment": result["stdout"],
            "stderr": result["stderr"],
            "exit_code": result["exit_code"],
        }

    def get_system_uptime(self, host: str, username: str, password: Optional[str] = None, private_key: Optional[str] = None, private_key_passphrase: Optional[str] = None, port: int = 22, timeout: float = 30.0, allow_unknown_hosts: bool = False) -> dict[str, Any]:
        return self.execute_command(
            host=host,
            username=username,
            password=password,
            private_key=private_key,
            private_key_passphrase=private_key_passphrase,
            port=port,
            timeout=timeout,
            command="uptime",
            allow_unknown_hosts=allow_unknown_hosts,
        )

    def get_system_facts(self, host: str, username: str, password: Optional[str] = None, private_key: Optional[str] = None, private_key_passphrase: Optional[str] = None, port: int = 22, timeout: float = 30.0, allow_unknown_hosts: bool = False) -> dict[str, Any]:
        return self.execute_command(
            host=host,
            username=username,
            password=password,
            private_key=private_key,
            private_key_passphrase=private_key_passphrase,
            port=port,
            timeout=timeout,
            command="hostnamectl 2>/dev/null || cat /etc/hostname; printf '\n'; id; printf '\n'; uname -srm",
            allow_unknown_hosts=allow_unknown_hosts,
        )

    def reboot(self, host: str, username: str, password: Optional[str] = None, private_key: Optional[str] = None, private_key_passphrase: Optional[str] = None, port: int = 22, timeout: float = 30.0, allow_unknown_hosts: bool = False) -> dict[str, Any]:
        result = self.execute_command(
            host=host,
            username=username,
            password=password,
            private_key=private_key,
            private_key_passphrase=private_key_passphrase,
            port=port,
            timeout=timeout,
            command="sudo -n /sbin/reboot",
            allow_unknown_hosts=allow_unknown_hosts,
        )
        return {"success": result["success"], "host": host, "action": "reboot", "result": result}

    def shutdown(self, host: str, username: str, password: Optional[str] = None, private_key: Optional[str] = None, private_key_passphrase: Optional[str] = None, port: int = 22, timeout: float = 30.0, allow_unknown_hosts: bool = False) -> dict[str, Any]:
        result = self.execute_command(
            host=host,
            username=username,
            password=password,
            private_key=private_key,
            private_key_passphrase=private_key_passphrase,
            port=port,
            timeout=timeout,
            command="sudo -n /sbin/shutdown -h now",
            allow_unknown_hosts=allow_unknown_hosts,
        )
        return {"success": result["success"], "host": host, "action": "shutdown", "result": result}

    def open_shell(self, host: str, username: str, password: Optional[str] = None, private_key: Optional[str] = None, private_key_passphrase: Optional[str] = None, port: int = 22, timeout: float = 30.0, allow_unknown_hosts: bool = False) -> paramiko.Channel:
        client = self._connect(
            SSHConnectionConfig(
                host=host,
                username=username,
                password=password,
                private_key=private_key,
                private_key_passphrase=private_key_passphrase,
                port=port,
                timeout=timeout,
                allow_unknown_hosts=allow_unknown_hosts,
            )
        )
        return client.invoke_shell(term="xterm")

    def close_shell(self, client: paramiko.Channel):
        client.close()
