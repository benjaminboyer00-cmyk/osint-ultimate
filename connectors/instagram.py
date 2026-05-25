"""
Instagram — profil, bio, posts et stories via instaloader (proxy + compte chaussette optionnels).
"""
from __future__ import annotations

import logging
import os
import random
from typing import Any

logger = logging.getLogger(__name__)

MAX_POSTS = 12
MAX_STORIES = 30
MAX_HIGHLIGHTS = 15
MAX_ITEMS_PER_HIGHLIGHT = 8

try:
    import instaloader
    from instaloader import Instaloader, Profile
    from instaloader.exceptions import (
        ConnectionException,
        LoginRequiredException,
        ProfileNotExistsException,
    )

    INSTALOADER_AVAILABLE = True
except ImportError:
    INSTALOADER_AVAILABLE = False
    instaloader = None  # type: ignore
    Instaloader = Profile = None  # type: ignore
    ConnectionException = LoginRequiredException = ProfileNotExistsException = Exception  # type: ignore


def is_available() -> bool:
    return INSTALOADER_AVAILABLE


def _mask_proxy(proxy_url: str) -> str:
    """Masque identifiants pour les logs (host:port visible)."""
    if not proxy_url:
        return ''
    if '@' in proxy_url:
        return proxy_url.split('@', 1)[-1][:80]
    return proxy_url[:80]


def _proxy_array(options: dict | None) -> list[str]:
    """Liste des proxys — PROXY_LIST (.env) mutualisé avec le reste de l'app."""
    opts = options or {}
    raw = opts.get('_proxy_list') or os.environ.get('PROXY_LIST', '')
    proxies = [p.strip() for p in str(raw).split(',') if p.strip()]
    extra = (os.environ.get('IG_PROXY_URL') or '').strip()
    if extra and extra not in proxies:
        proxies.append(extra)
    return proxies


def inject_rotating_proxy(options: dict | None) -> str | None:
    """
    Rotation dynamique : random.choice(PROXY_LIST) au début de chaque extraction
    (tâche Celery / thread scan_runner).
    """
    opts = options if options is not None else {}
    proxies = _proxy_array(opts)
    if not proxies:
        logger.debug('Instagram: PROXY_LIST vide — connexion directe')
        return None
    chosen = random.choice(proxies)
    opts['_proxy_for_run'] = chosen
    logger.info(
        'Instagram extraction — proxy %s (%d dans PROXY_LIST)',
        _mask_proxy(chosen),
        len(proxies),
    )
    return chosen


def _is_rate_limited(exc: BaseException) -> bool:
    msg = str(exc).lower()
    return '429' in msg or 'too many requests' in msg or 'please wait' in msg


def _handle_ig_rate_limit(context: str, exc: BaseException, proxy: str | None) -> None:
    if not _is_rate_limited(exc):
        return
    logger.warning(
        'Instagram HTTP 429 Too Many Requests [%s] — proxy=%s — rotation au prochain scan',
        context,
        _mask_proxy(proxy or ''),
    )
    if proxy:
        try:
            from services.http_session import mark_proxy_dead
            mark_proxy_dead(proxy)
        except Exception:
            pass


def _format_posts(posts: list[dict]) -> list[dict]:
    out = []
    for p in posts:
        cap = (p.get('caption') or '').strip()
        if len(cap) > 200:
            cap = cap[:200] + '…'
        out.append({
            'URL': p.get('url', ''),
            'Légende': cap or '—',
            'Date': p.get('date', ''),
        })
    return out


def _story_item_to_dict(item) -> dict:
    media_url = item.video_url if item.is_video else item.url
    return {
        'url': str(media_url) if media_url else '',
        'date': item.date_utc.isoformat() if getattr(item, 'date_utc', None) else '',
        'is_video': bool(item.is_video),
    }


def _format_stories(stories: list[dict]) -> list[dict]:
    return [
        {
            'URL': s.get('url', ''),
            'Date': s.get('date', ''),
            'Vidéo': 'Oui' if s.get('is_video') else 'Non',
        }
        for s in stories
    ]


def _format_highlights(highlights: list[dict]) -> list[dict]:
    """Stories à la une — un bloc par highlight avec ses médias."""
    out = []
    for h in highlights:
        medias = [
            {
                'URL': m.get('url', ''),
                'Date': m.get('date', ''),
                'Vidéo': 'Oui' if m.get('is_video') else 'Non',
            }
            for m in (h.get('items') or [])
        ]
        cover = h.get('cover_url', '')
        block: dict[str, Any] = {
            'Titre': h.get('title') or '—',
            'Nombre de médias': len(medias),
            'Médias': medias,
        }
        if cover:
            block['Couverture'] = cover
        out.append(block)
    return out


def _to_scan_result(raw: dict) -> dict:
    """Convertit la sortie interne vers le format affiché dans l'UI OSINT."""
    if not raw.get('success'):
        err = raw.get('error', 'Échec scan Instagram')
        username = raw.get('username', '')
        out: dict[str, Any] = {'Erreur': err}
        if username:
            out['Profil'] = f'https://www.instagram.com/{username}/'
        return out

    username = raw.get('username', '')
    result: dict[str, Any] = {
        'Nom complet': raw.get('full_name') or '—',
        'Bio': raw.get('biography') or '—',
        'Followers': raw.get('followers', 'N/A'),
        'Following': raw.get('following', 'N/A'),
        'Publications (total)': raw.get('posts_count', 'N/A'),
        'Vérifié': '✓ Oui' if raw.get('is_verified') else 'Non',
        'Privé': 'Oui' if raw.get('is_private') else 'Non',
        'Avatar URL': raw.get('profile_pic_url', ''),
        'Profil': f'https://www.instagram.com/{username}/',
        '_source': 'instaloader',
    }
    posts = _format_posts(raw.get('recent_posts') or [])
    stories = _format_stories(raw.get('recent_stories') or [])
    highlights = _format_highlights(raw.get('recent_highlights') or [])
    if posts:
        result['Posts récents'] = posts
    if stories:
        result['Stories actives'] = stories
    if highlights:
        result['Stories à la une'] = highlights
    if raw.get('note'):
        result['Note'] = raw['note']
    if raw.get('is_private') and not posts and not stories and not highlights:
        result['Note'] = (
            raw.get('note')
            or 'Profil privé — posts/stories visibles seulement si le compte IG_DUMMY suit la cible.'
        )
    return result


class InstagramConnector:
    """Scan profil Instagram (instaloader + proxy + login optionnel)."""

    def __init__(self, options: dict | None = None):
        self.options = options or {}
        self._loader = None
        if not INSTALOADER_AVAILABLE:
            return

        self.L = Instaloader(
            download_pictures=False,
            download_videos=False,
            download_video_thumbnails=False,
            compress_json=False,
            save_metadata=False,
            post_metadata_txt_pattern='',
            max_connection_attempts=2,
            request_timeout=25.0,
        )

        self._proxy_used = self._apply_proxy_to_session()

        self._login()

    def _apply_proxy_to_session(self) -> str | None:
        proxy_url = (self.options.get('_proxy_for_run') or '').strip()
        if not proxy_url:
            proxy_url = inject_rotating_proxy(self.options)
        if proxy_url and INSTALOADER_AVAILABLE:
            self.L.context._session.proxies = {'http': proxy_url, 'https': proxy_url}
        return proxy_url or None

    def _login(self) -> None:
        if not INSTALOADER_AVAILABLE:
            return
        session_file = (os.environ.get('IG_SESSION_FILE') or '').strip()
        if session_file and not os.path.isfile(session_file):
            logger.warning(
                'IG_SESSION_FILE introuvable (%s) — login mot de passe (risque blocage IG en Docker)',
                session_file,
            )
        if session_file and os.path.isfile(session_file):
            try:
                self.L.load_session_from_file(
                    os.environ.get('IG_DUMMY_USER', '').strip(),
                    session_file,
                )
                logger.info('Session Instagram chargée depuis %s', session_file)
                return
            except Exception as e:
                logger.warning('Session Instagram invalide (%s): %s', session_file, e)

        ig_user = (os.environ.get('IG_DUMMY_USER') or '').strip()
        ig_pass = (os.environ.get('IG_DUMMY_PASS') or '').strip()
        if ig_user and ig_pass:
            try:
                self.L.login(ig_user, ig_pass)
                logger.info('Connecté Instagram (%s) — stories activées', ig_user)
            except Exception as e:
                logger.error('Auth Instagram échouée: %s', e)

    def get_profile_data(self, target_username: str) -> dict:
        if not INSTALOADER_AVAILABLE:
            return {'success': False, 'error': 'instaloader non installé', 'username': target_username}

        username = target_username.strip().lstrip('@')
        try:
            profile = Profile.from_username(self.L.context, username)
        except ProfileNotExistsException:
            return {'success': False, 'error': 'Profil introuvable', 'username': username}
        except ConnectionException as e:
            return {'success': False, 'error': f'Connexion Instagram: {e}', 'username': username}
        except Exception as e:
            logger.error('Instagram %s: %s', username, e)
            return {'success': False, 'error': str(e)[:200], 'username': username}

        result = {
            'success': True,
            'username': profile.username,
            'full_name': profile.full_name or '',
            'biography': profile.biography or '',
            'profile_pic_url': str(profile.profile_pic_url),
            'followers': profile.followers,
            'following': profile.followees,
            'posts_count': profile.mediacount,
            'is_private': profile.is_private,
            'is_verified': getattr(profile, 'is_verified', False),
            'recent_posts': [],
            'recent_stories': [],
            'recent_highlights': [],
            'note': '',
        }

        can_view_media = (not profile.is_private) or profile.followed_by_viewer

        if can_view_media:
            result['recent_posts'] = self._fetch_posts(profile)
            if self.L.context.is_logged_in:
                result['recent_stories'] = self._fetch_stories(profile)
                result['recent_highlights'] = self._fetch_highlights(profile)
            elif not profile.is_private:
                result['note'] = (
                    'Stories / à la une non lues — session IG requise (IG_SESSION_FILE + IG_DUMMY_USER).'
                )
        else:
            result['note'] = (
                'Profil privé — le compte configuré (IG_DUMMY_*) doit suivre la cible '
                'pour posts, stories et à la une.'
            )

        return result

    def _fetch_posts(self, profile: Profile) -> list[dict]:
        posts: list[dict] = []
        try:
            for i, post in enumerate(profile.get_posts()):
                if i >= MAX_POSTS:
                    break
                caption = post.caption or ''
                posts.append({
                    'url': f'https://www.instagram.com/p/{post.shortcode}/',
                    'caption': caption,
                    'date': post.date_utc.isoformat() if post.date_utc else '',
                })
        except LoginRequiredException:
            logger.warning('Posts %s: login requis', profile.username)
        except Exception as e:
            _handle_ig_rate_limit('posts', e, getattr(self, '_proxy_used', None))
            logger.warning('Posts %s: %s', profile.username, e)
        return posts

    def _fetch_stories(self, profile: Profile) -> list[dict]:
        stories: list[dict] = []
        try:
            for story in self.L.get_stories(userids=[profile.userid]):
                for item in story.get_items():
                    if len(stories) >= MAX_STORIES:
                        return stories
                    stories.append(_story_item_to_dict(item))
        except Exception as e:
            _handle_ig_rate_limit('stories', e, getattr(self, '_proxy_used', None))
            logger.warning('Stories %s: %s', profile.username, e)
        return stories

    def _fetch_highlights(self, profile: Profile) -> list[dict]:
        """Stories à la une (highlights) — nécessite une session connectée."""
        if not self.L.context.is_logged_in:
            return []
        if not getattr(profile, 'has_highlight_reels', False):
            return []

        highlights: list[dict] = []
        try:
            for hi_idx, highlight in enumerate(self.L.get_highlights(profile)):
                if hi_idx >= MAX_HIGHLIGHTS:
                    break
                items: list[dict] = []
                for item_idx, item in enumerate(highlight.get_items()):
                    if item_idx >= MAX_ITEMS_PER_HIGHLIGHT:
                        break
                    items.append(_story_item_to_dict(item))
                highlights.append({
                    'title': highlight.title or 'Sans titre',
                    'cover_url': str(highlight.cover_url) if highlight.cover_url else '',
                    'items': items,
                })
        except LoginRequiredException:
            logger.warning('Highlights %s: login requis', profile.username)
        except Exception as e:
            _handle_ig_rate_limit('highlights', e, getattr(self, '_proxy_used', None))
            logger.warning('Highlights %s: %s', profile.username, e)
        return highlights


def scan(username: str, options: dict | None = None) -> dict | None:
    """
    Point d'entrée scan OSINT. Retourne None si instaloader indisponible (fallback HTTP app.py).
    """
    try:
        from services.runtime_env import instagram_instaloader_enabled, is_hf_space
        if not instagram_instaloader_enabled():
            if is_hf_space():
                logger.info(
                    'Instagram HF : mode léger (HTTP). Définir OSINT_IG_MODE=full sur VPS/HF Pro.',
                )
            return None
    except ImportError:
        pass
    if not INSTALOADER_AVAILABLE:
        return None
    opts = dict(options or {})
    if not opts.get('_proxy_for_run'):
        inject_rotating_proxy(opts)
    connector = InstagramConnector(options=opts)
    raw = connector.get_profile_data(username)
    if not raw.get('success') and raw.get('error', '').startswith('Connexion'):
        return {**_to_scan_result(raw), '_retry_http': True}
    return _to_scan_result(raw)
