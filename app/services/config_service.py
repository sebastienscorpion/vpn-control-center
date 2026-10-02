"""
Lecture de la configuration IPsec (/etc/ipsec.conf).

IMPORTANT : ce service ne lit JAMAIS /etc/ipsec.secrets (qui contient le
PSK). On expose uniquement ce qui est déjà "public" sur le système
(readable par tous), jamais un secret.
"""
import re
from pathlib import Path

IPSEC_CONF_PATH = Path("/etc/ipsec.conf")


class ConfigUnavailableError(Exception):
    pass


class ConfigService:
    def read_raw(self) -> str:
        """Équivalent de `cat /etc/ipsec.conf`."""
        if not IPSEC_CONF_PATH.exists():
            raise ConfigUnavailableError(f"{IPSEC_CONF_PATH} introuvable sur cette machine.")
        try:
            return IPSEC_CONF_PATH.read_text()
        except PermissionError as exc:
            raise ConfigUnavailableError(
                f"Permission refusée pour lire {IPSEC_CONF_PATH} : {exc}. "
                f"Essayez : sudo chmod o+r {IPSEC_CONF_PATH}"
            ) from exc

    def parse_connections(self) -> list:
        """
        Découpe le texte brut en blocs `conn <nom> { ... }` et renvoie
        une liste de dictionnaires {clé: valeur}, plus facile à afficher
        dans un tableau qu'un bloc de texte brut.
        """
        raw = self.read_raw()
        connections = []
        current_name = None
        current_params = {}

        for line in raw.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            conn_match = re.match(r"^conn\s+(\S+)", stripped)
            if conn_match:
                if current_name and current_name != "%default":
                    connections.append({"name": current_name, **current_params})
                current_name = conn_match.group(1)
                current_params = {}
                continue

            if current_name and "=" in stripped:
                key, _, value = stripped.partition("=")
                current_params[key.strip()] = value.strip()

        if current_name and current_name != "%default":
            connections.append({"name": current_name, **current_params})

        return connections