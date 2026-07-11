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
import logging
import os
import socket
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)


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


_REDIRECT_CODES = {301, 302, 303, 307, 308}


def guarded_get(getter, url: str, *, max_redirects: int = 5, **kwargs):
    """GET qui suit les redirections en REVALIDANT chaque hôte (anti-SSRF).

    ``requests`` suit les 3xx sans revalider : un hôte public peut rediriger
    vers 169.254.169.254 / une IP interne. Ici on désactive le suivi auto et on
    contrôle chaque « Location ». Retourne None si une redirection vise une
    ressource interne. ``getter(url, allow_redirects=False, **kwargs) -> Response``.
    """
    kwargs.pop('allow_redirects', None)
    current = url
    resp = None
    for _ in range(max_redirects + 1):
        resp = getter(current, allow_redirects=False, **kwargs)
        if resp is None:
            return None
        if resp.status_code not in _REDIRECT_CODES:
            return resp
        loc = resp.headers.get('Location') or resp.headers.get('location')
        if not loc:
            return resp
        nxt = urljoin(current, loc)
        parsed = urlparse(nxt)
        if parsed.scheme and parsed.scheme not in ('http', 'https'):
            logger.warning('Redirection vers schéma non-HTTP bloquée: %s', parsed.scheme)
            return None
        host = parsed.hostname or ''
        if host and not host_is_public(host):
            logger.warning('Redirection SSRF bloquée vers hôte interne: %s', host)
            return None
        current = nxt
    return resp  # trop de redirections -> on rend la dernière réponse 3xx
