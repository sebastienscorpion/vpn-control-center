"""
Service d'authentification minimaliste, volontairement sans dépendance
externe (pas de bcrypt/JWT à installer) : hachage PBKDF2 (bibliothèque
standard Python) + jetons de session stockés dans un petit fichier JSON.
"""
import hashlib
import hmac
import json
import secrets
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DATA_DIR.mkdir(exist_ok=True)
USERS_FILE = DATA_DIR / "users.json"
SESSIONS_FILE = DATA_DIR / "sessions.json"


def _load(path):
    if not path.exists():
        return {}
    with open(path, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}


def _save(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def _hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000).hex()


class AuthService:
    def register(self, username: str, password: str, full_name: str = ""):
        users = _load(USERS_FILE)
        key = username.strip().lower()
        if not key or not password:
            raise ValueError("Nom d'utilisateur et mot de passe requis.")
        if len(password) < 4:
            raise ValueError("Le mot de passe doit faire au moins 4 caractères.")
        if key in users:
            raise ValueError("Ce nom d'utilisateur existe déjà.")

        salt = secrets.token_hex(16)
        users[key] = {
            "username": username.strip(),
            "full_name": full_name.strip(),
            "salt": salt,
            "password_hash": _hash_password(password, salt),
        }
        _save(USERS_FILE, users)
        return {"username": users[key]["username"], "full_name": users[key]["full_name"]}

    def authenticate(self, username: str, password: str):
        users = _load(USERS_FILE)
        user = users.get(username.strip().lower())
        if not user:
            raise ValueError("Identifiants invalides.")
        expected = _hash_password(password, user["salt"])
        if not hmac.compare_digest(expected, user["password_hash"]):
            raise ValueError("Identifiants invalides.")
        return user

    def create_session(self, username: str) -> str:
        sessions = _load(SESSIONS_FILE)
        token = secrets.token_hex(32)
        sessions[token] = username
        _save(SESSIONS_FILE, sessions)
        return token

    def get_user_by_token(self, token: str):
        return _load(SESSIONS_FILE).get(token)

    def revoke(self, token: str):
        sessions = _load(SESSIONS_FILE)
        sessions.pop(token, None)
        _save(SESSIONS_FILE, sessions)