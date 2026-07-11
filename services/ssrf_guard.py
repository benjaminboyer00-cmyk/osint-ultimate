"""Garde anti-SSRF : empêche les scans de viser des ressources internes.

Les modules OSINT requêtent la cible fournie par l'utilisateur. Sans garde,
un utilisateur pourrait faire scanner par le serveur des IP privées / de
métadonnées cloud (169.254.169.254), du loopback, etc. — reconnaissance
interne / SSRF. On bloque :
  - les IP littérales privées/loopback/link-local/réservées/multicast ;
  - les domaines qui RÉSOLVENT vers une de ces IP.

Échappatoire dev : ALLOW_PRIVATE_SCAN_TARGETS=1 (jamais en prod).
"""
import ipaddress
import os
import socket


def _allow_private() -> bool:
    return os.environ.get('ALLOW_PRIVATE_SCAN_TARGETS') == '1'


def _ip_public_state(value: str):
    """True=IP publique, False=IP interne à bloquer, None=pas une IP."""
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    blocked = (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    )
    return not blocked


def ip_is_internal(value: str) -> bool:
    """True si `value` est une IP interne/privée (à bloquer)."""
    if _allow_private():
        return False
    return _ip_public_state(value) is False


def host_is_public(host: str) -> bool:
    """True si `host` (IP ou domaine) est sûr à requêter (aucune IP interne).

    Résout le domaine et bloque si UNE des IP est interne (anti-SSRF). En cas
    d'échec de résolution : autorisé (la requête échouera d'elle-même, pas
    d'accès interne possible).
    """
    if _allow_private():
        return True
    h = (host or '').strip().lower().rstrip('.')
    if not h:
        return False
    state = _ip_public_state(h)
    if state is not None:
        return state
    try:
        infos = socket.getaddrinfo(h, None)
    except Exception:
        return True
    for info in infos:
        ip = info[4][0]
        if _ip_public_state(ip) is False:
            return False
    return True
