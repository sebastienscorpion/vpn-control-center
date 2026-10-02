import vici


class ViciService:
    def __init__(self):
        self.session = vici.Session()

    def get_version(self):
        return _decode(self.session.version())

    def get_connections(self):
        return [_decode(c) for c in self.session.list_conns()]

    def get_sas(self):
        return [_decode(s) for s in self.session.list_sas()]

    def get_status(self, connection_name: str):
        for entry in self.get_sas():
            data = entry.get(connection_name)
            if data is None:
                continue
            child_sas = data.get("child-sas", {})
            child_state = "DOWN"
            if child_sas:
                child_state = next(iter(child_sas.values()), {}).get("state", "UNKNOWN")
            return {
                "connection": connection_name,
                "ike_sa_state": data.get("state", "UNKNOWN"),
                "child_sa_state": child_state,
                "local_host": data.get("local-host"),
                "remote_host": data.get("remote-host"),
                "established_seconds": data.get("established"),
            }
        return {
            "connection": connection_name, "ike_sa_state": "DOWN", "child_sa_state": "DOWN",
            "local_host": None, "remote_host": None, "established_seconds": None,
        }

    def get_overview(self):
        """
        Combine list_conns() (les connexions CONFIGURÉES) et list_sas()
        (les tunnels ACTIFS) pour donner, en un seul appel, l'état réel de
        CHAQUE connexion connue de strongSwan.
        """
        overview = []
        for entry in self.get_connections():
            name = list(entry.keys())[0]
            live = self.get_status(name)
            overview.append({
                "name": name,
                "ike_sa_state": live["ike_sa_state"],
                "child_sa_state": live["child_sa_state"],
                "active": live["ike_sa_state"] == "ESTABLISHED",
                "local_host": live["local_host"],
                "remote_host": live["remote_host"],
            })
        return overview

    def test_connection(self, connection_name: str, ping_host: str = None):
        """
        "Teste" une connexion : renvoie son état réel + un ping optionnel
        vers `ping_host` (utile pour vérifier que le trafic passe VRAIMENT
        à travers le tunnel, pas juste que le tunnel est monté).
        """
        from app.services.network_service import ping as do_ping

        status = self.get_status(connection_name)
        result = {"connection": connection_name, "status": status, "ping": None}

        if ping_host:
            try:
                result["ping"] = do_ping(ping_host)
            except Exception as exc:
                result["ping"] = {"success": False, "error": str(exc)}

        return result

    def connection_exists(self, connection_name: str) -> bool:
        for entry in self.get_connections():
            if connection_name in entry:
                return True
        return False

    def _active_ike_ids(self, connection_name: str):
        ids = []
        for entry in self.get_sas():
            data = entry.get(connection_name)
            if data is not None and data.get("uniqueid"):
                ids.append(data["uniqueid"])
        return ids

    def initiate(self, child_name: str):
        events = list(self.session.initiate({"child": child_name.encode()}))
        return [_decode(e) for e in events]

    def terminate(self, connection_name: str):
        ike_ids = self._active_ike_ids(connection_name)
        if not ike_ids:
            return []
        all_events = []
        for ike_id in ike_ids:
            events = list(self.session.terminate({"ike-id": str(ike_id).encode()}))
            all_events.extend(_decode(e) for e in events)
        return all_events

    def create_tunnel(self, tunnel):
        """
        Crée une connexion IPsec Site-to-Site complète, via VICI, à partir
        d'un objet IPsecTunnel (app/schemas/tunnel.py) : plusieurs
        propositions IKE/ESP, plusieurs sous-réseaux, DPD configurable,
        rekey et mode tunnel/transport.

        C'est la méthode officielle et unique de création de connexion
        dans ce projet.
        """
        if tunnel.authentication.value == "certificate":
            raise NotImplementedError(
                "L'authentification par certificat n'est pas encore implémentée "
                "dans ce backend — seul le PSK (pre-shared-key) est géré pour "
                "l'instant."
            )

        ike_version_number = "1" if tunnel.ike_version.value == "ikev1" else "2"
        ike_proposals = [p.to_strongswan() for p in tunnel.ike_proposals]
        esp_proposals = [p.to_strongswan() for p in tunnel.esp_proposals]
        local_ts = [str(net) for net in tunnel.local_subnets]
        remote_ts = [str(net) for net in tunnel.remote_subnets]

        child_config = {
            "local_ts": local_ts,
            "remote_ts": remote_ts,
            "esp_proposals": esp_proposals,
            "mode": tunnel.mode.value,
            # rekey=False -> on désactive le renouvellement automatique des
            # clés (rekey_time="0"), comme on l'a observé sur les
            # connexions configurées à la main dans ipsec.conf.
            "rekey_time": str(tunnel.ipsec_lifetime) if tunnel.rekey else "0",
        }

        conn_config = {
            "version": ike_version_number,
            "local_addrs": [str(tunnel.local_gateway)],
            "remote_addrs": [str(tunnel.remote_gateway)],
            "local": {"auth": "psk", "id": str(tunnel.local_gateway)},
            "remote": {"auth": "psk", "id": str(tunnel.remote_gateway)},
            "proposals": ike_proposals,
            "reauth_time": str(tunnel.ike_lifetime) if tunnel.rekey else "0",
            "children": {
                tunnel.name: child_config,
            },
        }

        if tunnel.dpd_enabled:
            conn_config["dpd_delay"] = str(tunnel.dpd_interval)
            conn_config["dpd_timeout"] = str(tunnel.dpd_timeout)
            child_config["dpd_action"] = tunnel.dpd_action.value

        self.session.load_conn({tunnel.name: conn_config})

        if tunnel.authentication.value == "pre-shared-key" and tunnel.pre_shared_key:
            self.session.load_shared({
                "type": "IKE",
                "data": tunnel.pre_shared_key,
                "owners": [str(tunnel.local_gateway), str(tunnel.remote_gateway)],
            })

        return {"name": tunnel.name, "created": True}
    def define_psk(self, owner_local: str, owner_remote: str, secret: str):
        """
        Déclare une clé pré-partagée (PSK) dans charon, indépendamment de
        toute connexion précise. Équivalent VICI de load_shared(), mais
        utilisable seul, sans passer par create_tunnel().
        """
        self.session.load_shared({
            "type": "IKE",
            "data": secret,
            "owners": [owner_local, owner_remote],
        })
        return {"owner_local": owner_local, "owner_remote": owner_remote, "defined": True}

    def list_psks(self):
        """
        Liste les clés partagées actuellement chargées dans charon.

        ATTENTION (comportement connu de VICI) : get_shared() renvoie
        souvent une liste vide même juste après un load_shared() réussi
        — ce n'est PAS un signe d'échec, juste une limitation de charon.
        Ne vous fiez pas à cette liste pour vérifier qu'un PSK a bien été
        pris en compte ; utilisez plutôt un test réel (start + status).
        """
        return [_decode(k) for k in self.session.get_shared()]

    def clear_all_credentials(self):
        """
        Efface TOUS les identifiants chargés dans charon (PSK, certificats,
        clés privées) — équivalent de la commande VICI clear-creds.
        Affecte TOUTES les connexions, pas seulement une en particulier.
        """
        self.session.clear_creds()

def _decode(value):
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    if isinstance(value, dict):
        return {_decode(k): _decode(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_decode(v) for v in value]
    return value