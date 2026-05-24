"""Circuit breaker simple en mémoire — évite d'appeler une API en panne."""
import logging
import threading
import time

logger = logging.getLogger(__name__)

_state: dict[str, dict] = {}
_lock = threading.Lock()
DEFAULT_COOLDOWN_SEC = 300
DEFAULT_FAILURE_THRESHOLD = 3


def is_open(provider: str) -> bool:
    with _lock:
        st = _state.get(provider)
        if not st or not st.get('open_until'):
            return False
        if time.time() < st['open_until']:
            return True
        st['open_until'] = 0
        st['failures'] = 0
        return False


def record_success(provider: str) -> None:
    with _lock:
        _state[provider] = {'failures': 0, 'open_until': 0}


def record_failure(provider: str, *, threshold: int = DEFAULT_FAILURE_THRESHOLD,
                   cooldown_sec: int = DEFAULT_COOLDOWN_SEC) -> None:
    with _lock:
        st = _state.setdefault(provider, {'failures': 0, 'open_until': 0})
        st['failures'] = st.get('failures', 0) + 1
        if st['failures'] >= threshold:
            st['open_until'] = time.time() + cooldown_sec
            logger.warning(
                'Circuit breaker OUVERT %s (%ss) après %s échecs',
                provider, cooldown_sec, st['failures'],
            )


def breaker_open_response(provider: str) -> dict:
    return {
        'Erreur': f'Service {provider} temporairement indisponible (circuit ouvert)',
        '_circuit_open': True,
    }
