"""Résolution des clés API : secret HF global → clés utilisateur chiffrées."""
import os


def get_key(user, key_name: str, env_name: str, fernet) -> str:
    if user and getattr(user, 'api_keys_enc', None):
        keys = user.get_api_keys(fernet)
        val = keys.get(key_name) or keys.get(key_name.replace('_', ''))
        if val:
            return val
    return os.environ.get(env_name, '')
