"""WHOIS domaine — point d'entrée unifié (RDAP HTTP uniquement, pas de socket 43)."""
from connectors.whois_domain import lookup

__all__ = ['lookup']
