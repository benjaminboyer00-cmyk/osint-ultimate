"""Authentification 2FA TOTP (Google Authenticator, etc.)."""
from __future__ import annotations

import io
import base64

from extensions import db


def generate_secret() -> str:
    import pyotp
    return pyotp.random_base32()


def provisioning_uri(user, secret: str) -> str:
    import pyotp
    return pyotp.TOTP(secret).provisioning_uri(
        name=user.email or user.username,
        issuer_name='OSINT Ultimate',
    )


def verify_code(secret: str, code: str) -> bool:
    if not secret or not code:
        return False
    import pyotp
    totp = pyotp.TOTP(secret)
    return totp.verify(str(code).strip().replace(' ', ''), valid_window=1)


def qr_code_base64(uri: str) -> str | None:
    try:
        import qrcode
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        return base64.b64encode(buf.getvalue()).decode('ascii')
    except Exception:
        return None


def enable_totp(user, secret: str, code: str, fernet) -> bool:
    """Active 2FA après vérification du premier code."""
    if not verify_code(secret, code):
        return False
    user.totp_secret_enc = fernet.encrypt(secret.encode()).decode()
    user.totp_enabled = True
    db.session.commit()
    return True


def disable_totp(user) -> None:
    user.totp_secret_enc = None
    user.totp_enabled = False
    db.session.commit()


def get_decrypted_secret(user, fernet) -> str | None:
    if not user.totp_secret_enc:
        return None
    try:
        return fernet.decrypt(user.totp_secret_enc.encode()).decode()
    except Exception:
        return None
