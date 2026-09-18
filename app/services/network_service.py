import ipaddress
import re
import subprocess


class InvalidHostError(Exception):
    pass


def _validate_host(host: str):
    try:
        ipaddress.ip_address(host)
    except ValueError as exc:
        raise InvalidHostError(f"Adresse IP invalide : {host}") from exc


def ping(host: str, count: int = 4, timeout_s: int = 1):
    _validate_host(host)
    cmd = ["ping", "-c", str(count), "-W", str(timeout_s), host]

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=count * timeout_s + 5
        )
        output = proc.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {
            "success": False, "host": host, "packets_sent": count,
            "packets_received": 0, "packet_loss": 100, "avg_rtt_ms": None,
            "error": "Hôte inaccessible ou commande ping indisponible.",
        }

    sent, received, loss, avg_rtt = count, 0, 100, None
    m = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", output)
    if m:
        sent, received = int(m.group(1)), int(m.group(2))
        loss = 0 if sent == 0 else round(100 * (sent - received) / sent, 1)
    m2 = re.search(r"= [\d.]+/([\d.]+)/", output)
    if m2:
        avg_rtt = float(m2.group(1))

    return {
        "success": received > 0, "host": host, "packets_sent": sent,
        "packets_received": received, "packet_loss": loss, "avg_rtt_ms": avg_rtt,
        "error": None if received > 0 else "Hôte inaccessible.",
    }