import json
import os
import hashlib
import secrets
from functools import wraps
from flask import session, redirect, url_for, request

CREDS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'users.json')


def _hash(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 260000).hex()


def init_creds():
    """Create default admin/admin credentials file if it doesn't exist."""
    if not os.path.exists(CREDS_FILE):
        salt = secrets.token_hex(16)
        data = {
            'username': 'admin',
            'salt': salt,
            'hash': _hash('admin', salt)
        }
        with open(CREDS_FILE, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"[auth] Created default credentials file at {CREDS_FILE}")
        print("[auth] Default login: admin / admin  — CHANGE THIS IMMEDIATELY")


def check_creds(username: str, password: str) -> bool:
    if not os.path.exists(CREDS_FILE):
        return False
    with open(CREDS_FILE) as f:
        data = json.load(f)
    return (
        username == data.get('username') and
        _hash(password, data.get('salt', '')) == data.get('hash', '')
    )


def change_password(username: str, new_password: str):
    salt = secrets.token_hex(16)
    data = {
        'username': username,
        'salt': salt,
        'hash': _hash(new_password, salt)
    }
    with open(CREDS_FILE, 'w') as f:
        json.dump(data, f, indent=2)


def change_username(new_username: str, password: str) -> bool:
    """Change username — requires current password to confirm."""
    if not os.path.exists(CREDS_FILE):
        return False
    with open(CREDS_FILE) as f:
        data = json.load(f)
    # Verify current password first
    if _hash(password, data.get('salt', '')) != data.get('hash', ''):
        return False
    data['username'] = new_username
    with open(CREDS_FILE, 'w') as f:
        json.dump(data, f, indent=2)
    return True


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            # Use a plain path redirect — Flask url_for can produce http:// even
            # when the server is running HTTPS, causing the Secure cookie to be
            # lost.  A path-only redirect lets the browser keep the current scheme.
            next_path = request.path
            return redirect(f'/login?next={next_path}')
        return f(*args, **kwargs)
    return decorated