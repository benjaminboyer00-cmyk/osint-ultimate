"""Exceptions métier OSINT — éviter les échecs silencieux."""


class OSINTError(Exception):
    """Erreur applicative de base."""


class ConnectorError(OSINTError):
    """Échec d'un connecteur externe (réseau, parsing, quota)."""

    def __init__(self, message: str, *, provider: str = '', status_code: int | None = None):
        super().__init__(message)
        self.provider = provider
        self.status_code = status_code


class APIQuotaExceeded(ConnectorError):
    """Quota API atteint (429 / message explicite)."""

    def __init__(self, message: str = 'Quota API atteint', *, provider: str = ''):
        super().__init__(message, provider=provider, status_code=429)


class AccessDeniedError(OSINTError):
    """Accès dossier / entité refusé (IDOR)."""


class ValidationError(OSINTError):
    """Entrée utilisateur invalide."""
