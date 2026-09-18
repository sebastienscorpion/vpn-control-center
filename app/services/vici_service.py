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


def _decode(value):
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    if isinstance(value, dict):
        return {_decode(k): _decode(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_decode(v) for v in value]
    return value