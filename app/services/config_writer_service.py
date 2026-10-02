"""
Écriture de la configuration IPsec directement dans les fichiers système.

Contrairement à ViciService.create_tunnel() (qui envoie la config à charon
en mémoire, donc perdue au redémarrage et invisible dans les fichiers),
ce service écrit dans :

  - /etc/ipsec.conf     -> le bloc "conn <nom>"
  - /etc/ipsec.secrets  -> la ligne PSK

puis demande à strongSwan de relire ces fichiers (ipsec reload). La
connexion est donc visible au terminal (cat /etc/ipsec.conf) ET par
l'API, et elle survit à un redémarrage.

Sécurité :
  - le nom de connexion est validé (pas d'injection dans le fichier)
  - le PSK ne peut pas contenir de guillemet, d'antislash ni de retour
    à la ligne
  - une sauvegarde est faite avant chaque écriture
  - si strongSwan n'a pas chargé la connexion après le reload, l'ancien
    contenu des fichiers est restauré automatiquement
  - l'écriture passe par `sudo tee` sur des chemins FIXES (voir sudoers)
"""
import os
import re
import subprocess
from datetime import datetime
from pathlib import Path

NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
SECTION_RE = re.compile(r"^(conn|config|ca)\s")
BACKUP_DIR = Path(__file__).resolve().parent.parent / "data" / "backups"


class ConfigWriteError(Exception):
    pass


# ---------------------------------------------------------------------------
# Fonctions pures (faciles à tester, ne touchent à aucun fichier)
# ---------------------------------------------------------------------------
def render_connection(t) -> str:
    """Construit le bloc `conn ...` à partir d'un IPsecTunnel."""

    def join(items):
        return ",".join(str(i) for i in items)

    ike = ",".join(p.to_strongswan() for p in t.ike_proposals)
    esp = ",".join(p.to_strongswan() for p in t.esp_proposals)

    lines = [
        f"conn {t.name}",
        "    # Généré par VPN Control Center",
        f"    keyexchange={t.ike_version.value}",
        f"    left={t.local_gateway}",
        f"    leftsubnet={join(t.local_subnets)}",
        f"    right={t.remote_gateway}",
        f"    rightsubnet={join(t.remote_subnets)}",
        "    authby=secret",
        f"    ike={ike}!",
        f"    esp={esp}!",
        f"    ikelifetime={t.ike_lifetime}s",
        f"    lifetime={t.ipsec_lifetime}s",
        f"    rekey={'yes' if t.rekey else 'no'}",
        f"    type={t.mode.value}",
    ]
    if t.dpd_enabled:
        lines += [
            f"    dpdaction={t.dpd_action.value}",
            f"    dpddelay={t.dpd_interval}s",
            f"    dpdtimeout={t.dpd_timeout}s",
        ]
    else:
        lines.append("    dpdaction=none")
    lines.append("    auto=add")
    return "\n".join(lines) + "\n"


def _find_block(lines, name):
    """Renvoie (début, fin) du bloc `conn <name>`, ou None s'il n'existe pas."""
    start = None
    for i, line in enumerate(lines):
        if re.match(rf"^conn\s+{re.escape(name)}\s*$", line):
            start = i
            break
    if start is None:
        return None
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if SECTION_RE.match(lines[j]):
            end = j
            break
    while end - 1 > start and (lines[end - 1].strip() == "" or lines[end - 1].startswith("#")):
        end -= 1
    return start, end


def upsert_block(content: str, name: str, block: str) -> str:
    """Remplace le bloc `conn <name>` s'il existe, sinon l'ajoute à la fin."""
    lines = content.splitlines()
    block_lines = block.rstrip("\n").splitlines()
    found = _find_block(lines, name)

    if found is None:
        while lines and lines[-1].strip() == "":
            lines.pop()
        lines += [""] + block_lines
        return "\n".join(lines) + "\n"

    start, end = found
    before, after = lines[:start], lines[end:]
    result = before + block_lines
    if after and after[0].strip() != "":
        result.append("")
    result += after
    return "\n".join(result) + "\n"


def remove_block(content: str, name: str):
    """Supprime le bloc `conn <name>`. Renvoie (nouveau_contenu, supprimé?)."""
    lines = content.splitlines()
    found = _find_block(lines, name)
    if found is None:
        return content, False
    start, end = found
    result = lines[:start] + lines[end:]
    while result and result[-1].strip() == "":
        result.pop()
    return "\n".join(result) + "\n", True


def upsert_psk_line(content: str, owners, secret: str) -> str:
    """Remplace (ou ajoute) la ligne PSK associée à cette paire d'identités."""
    wanted = set(owners)
    new_line = f'{" ".join(owners)} : PSK "{secret}"'
    lines = content.splitlines()

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        ids_part, sep, rest = stripped.partition(":")
        if sep and rest.strip().upper().startswith("PSK") and set(ids_part.split()) == wanted:
            lines[i] = new_line
            return "\n".join(lines) + "\n"

    while lines and lines[-1].strip() == "":
        lines.pop()
    lines.append(new_line)
    return "\n".join(lines) + "\n"


def validate_name(name: str):
    if not NAME_RE.match(name):
        raise ConfigWriteError(
            "Nom de connexion invalide : uniquement lettres, chiffres, '-' et '_' "
            "(64 caractères maximum)."
        )


def validate_secret(secret: str):
    if not secret:
        raise ConfigWriteError("Le PSK ne peut pas être vide.")
    if any(c in secret for c in ('"', "\\", "\n", "\r")):
        raise ConfigWriteError(
            'Le PSK ne doit contenir ni guillemet ("), ni antislash (\\), ni retour à la ligne.'
        )


# ---------------------------------------------------------------------------
# Service (touche aux fichiers)
# ---------------------------------------------------------------------------
class ConfigWriterService:
    def __init__(self, conf_path=None, secrets_path=None, use_sudo=None):
        self.conf_path = Path(conf_path or os.environ.get("IPSEC_CONF_PATH", "/etc/ipsec.conf"))
        self.secrets_path = Path(
            secrets_path or os.environ.get("IPSEC_SECRETS_PATH", "/etc/ipsec.secrets")
        )
        if use_sudo is None:
            use_sudo = os.environ.get("IPSEC_USE_SUDO", "1") == "1"
        self.use_sudo = use_sudo

    def _run(self, cmd, input_text=None):
        full = (["sudo", "-n"] + cmd) if self.use_sudo else cmd
        try:
            proc = subprocess.run(
                full, input=input_text, capture_output=True, text=True, timeout=15
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            raise ConfigWriteError(f"Impossible d'exécuter {' '.join(cmd)} : {exc}") from exc
        if proc.returncode != 0:
            raise ConfigWriteError(
                f"La commande '{' '.join(cmd)}' a échoué : {proc.stderr.strip()} "
                "(vérifiez la règle sudoers /etc/sudoers.d/vpn-control-center)"
            )
        return proc.stdout

    def _read(self, path: Path, needs_root: bool = False) -> str:
        if needs_root and self.use_sudo:
            return self._run(["cat", str(path)])
        try:
            return path.read_text()
        except FileNotFoundError:
            raise ConfigWriteError(f"{path} introuvable sur cette machine.")
        except PermissionError as exc:
            raise ConfigWriteError(f"Permission refusée pour lire {path} : {exc}")

    def _write(self, path: Path, content: str):
        if self.use_sudo:
            self._run(["tee", str(path)], input_text=content)
        else:
            path.write_text(content)

    def _backup(self, path: Path, content: str):
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        target = BACKUP_DIR / f"{path.name}.{stamp}.bak"
        target.write_text(content)
        os.chmod(target, 0o600)

    def _reload(self):
        self._run(["ipsec", "reload"])
        self._run(["ipsec", "rereadsecrets"])

    def _rollback(self, conf_before, secrets_before):
        try:
            if conf_before is not None:
                self._write(self.conf_path, conf_before)
            if secrets_before is not None:
                self._write(self.secrets_path, secrets_before)
            self._reload()
        except Exception:
            pass

    def apply_tunnel(self, tunnel, verify=None):
        """
        Crée OU modifie la connexion dans ipsec.conf (et son PSK dans
        ipsec.secrets), puis recharge strongSwan.
        """
        validate_name(tunnel.name)
        if tunnel.authentication.value == "certificate":
            raise NotImplementedError(
                "L'authentification par certificat n'est pas encore implémentée : "
                "seul le PSK (pre-shared-key) est géré pour l'instant."
            )
        if tunnel.authentication.value == "pre-shared-key" and not tunnel.pre_shared_key:
            raise ConfigWriteError("Un PSK est requis pour l'authentification par clé pré-partagée.")
        if tunnel.pre_shared_key:
            validate_secret(tunnel.pre_shared_key)

        conf_before = self._read(self.conf_path)
        conf_after = upsert_block(conf_before, tunnel.name, render_connection(tunnel))
        existed = _find_block(conf_before.splitlines(), tunnel.name) is not None

        secrets_before = secrets_after = None
        if tunnel.pre_shared_key:
            secrets_before = self._read(self.secrets_path, needs_root=True)
            secrets_after = upsert_psk_line(
                secrets_before,
                [str(tunnel.local_gateway), str(tunnel.remote_gateway)],
                tunnel.pre_shared_key,
            )

        self._backup(self.conf_path, conf_before)
        if secrets_before is not None:
            self._backup(self.secrets_path, secrets_before)

        try:
            if secrets_after is not None:
                self._write(self.secrets_path, secrets_after)
            self._write(self.conf_path, conf_after)
            self._reload()
            if verify is not None and verify() is False:
                raise ConfigWriteError(
                    "strongSwan n'a pas chargé la connexion après le rechargement "
                    "(configuration probablement invalide). Les anciens fichiers ont "
                    "été restaurés."
                )
        except Exception:
            self._rollback(conf_before, secrets_before)
            raise

        return {
            "name": tunnel.name,
            "action": "updated" if existed else "created",
            "written_to": str(self.conf_path),
            "psk_written": secrets_after is not None,
        }

    def apply_psk(self, owner_local: str, owner_remote: str, secret: str):
        """Crée ou remplace un PSK dans ipsec.secrets (sans toucher aux connexions)."""
        validate_secret(secret)
        secrets_before = self._read(self.secrets_path, needs_root=True)
        secrets_after = upsert_psk_line(secrets_before, [owner_local, owner_remote], secret)
        self._backup(self.secrets_path, secrets_before)
        try:
            self._write(self.secrets_path, secrets_after)
            self._run(["ipsec", "rereadsecrets"])
        except Exception:
            self._rollback(None, secrets_before)
            raise
        return {"owner_local": owner_local, "owner_remote": owner_remote, "written_to": str(self.secrets_path)}

    def remove_connection(self, name: str):
        """Supprime le bloc `conn <name>` de ipsec.conf puis recharge strongSwan."""
        validate_name(name)
        conf_before = self._read(self.conf_path)
        conf_after, removed = remove_block(conf_before, name)
        if not removed:
            return {"name": name, "removed": False}
        self._backup(self.conf_path, conf_before)
        try:
            self._write(self.conf_path, conf_after)
            self._reload()
        except Exception:
            self._rollback(conf_before, None)
            raise
        return {"name": name, "removed": True}