#!/usr/bin/env python3
"""
OSINT ULTIMATE V5.0 – Auth, Supabase PostgreSQL, Scans async, IA Groq, PWA
"""
import os
import re
import json
from datetime import datetime
from io import BytesIO

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import requests
from PIL import Image
from PIL.ExifTags import TAGS
import docx
from pypdf import PdfReader
from sqlalchemy import text as sa_text
from flask import (Flask, render_template, request, jsonify,
                   redirect, url_for, flash, send_file, abort)
from flask_socketio import SocketIO
from flask_login import login_user, logout_user, login_required, current_user
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix

from config import build_config
from extensions import db, login_manager, migrate, limiter, init_csrf, csrf
from models import User, Scan

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1, x_for=1)
app.config.update(build_config())
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Garde-fou Pillow : refuse les images au-delà de ~64 Mpx (anti-OOM / decompression bomb)
Image.MAX_IMAGE_PIXELS = int(os.environ.get('MAX_IMAGE_PIXELS', str(64_000_000)))

db.init_app(app)
migrate.init_app(app, db)
login_manager.init_app(app)
login_manager.login_view = 'auth.login'
# 'strong' invalide la session si IP/UA semblent changer entre requêtes —
# trop agressif derrière le proxy HF (IP/UA forwardés de façon incohérente),
# ça déconnectait les utilisateurs sur les routes @login_required.
login_manager.session_protection = 'basic'
limiter.init_app(app)
init_csrf(app)

from flask_compress import Compress
Compress(app)

# ---------- Perf : cache long + versionnement des assets statiques ----------
_ASSET_VER_CACHE: dict[str, str] = {}


def _asset_version(filename: str) -> str:
    """Version d'un asset = mtime (bust le cache après chaque déploiement)."""
    v = _ASSET_VER_CACHE.get(filename)
    if v is not None:
        return v
    try:
        path = os.path.join(app.static_folder, filename)
        v = str(int(os.path.getmtime(path)))
    except OSError:
        v = app.config.get('APP_VERSION', '1')
    _ASSET_VER_CACHE[filename] = v
    return v


@app.url_defaults
def _static_cache_buster(endpoint, values):
    if endpoint == 'static' and values.get('filename') and 'v' not in values:
        values['v'] = _asset_version(values['filename'])


@app.after_request
def _immutable_static(resp):
    """Les URLs statiques sont versionnées -> cache immutable sûr et rapide."""
    try:
        if request.path.startswith('/static/') and resp.status_code == 200:
            resp.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
    except Exception:
        pass
    return resp

# Sentry (optionnel — SENTRY_DSN dans les secrets)
_sentry_dsn = os.environ.get('SENTRY_DSN', '').strip()
if _sentry_dsn:
    try:
        import sentry_sdk
        from sentry_sdk.integrations.flask import FlaskIntegration
        sentry_sdk.init(
            dsn=_sentry_dsn,
            integrations=[FlaskIntegration()],
            traces_sample_rate=float(os.environ.get('SENTRY_TRACES_SAMPLE_RATE', '0.1')),
            environment=os.environ.get('SENTRY_ENVIRONMENT', 'production'),
        )
    except Exception as _sentry_err:
        app.logger.warning('Sentry non chargé: %s', _sentry_err)

# Headers sécurité (CSP permissive pour templates inline + CDN existants)
try:
    from flask_talisman import Talisman
    _csp = {
        'default-src': "'self'",
        'script-src': [
            "'self'", "'unsafe-inline'",
            'https://unpkg.com', 'https://cdn.socket.io', 'https://cdn.jsdelivr.net',
        ],
        'style-src': [
            "'self'", "'unsafe-inline'",
            'https://fonts.googleapis.com', 'https://unpkg.com',
        ],
        'font-src': ["'self'", 'https://fonts.gstatic.com', 'data:'],
        'img-src': ["'self'", 'data:', 'https:', 'blob:'],
        'connect-src': ["'self'", 'https:', 'wss:'],
        'frame-ancestors': "'none'",
    }
    Talisman(
        app,
        force_https=app.config.get('FORCE_HTTPS', False),
        strict_transport_security=app.config.get('SESSION_COOKIE_SECURE', False),
        content_security_policy=_csp,
        referrer_policy='no-referrer',
        frame_options='DENY',
    )
except ImportError:
    pass

from services.flask_cache_ext import init_cache
init_cache(app)

_cors_origins = os.environ.get('CORS_ORIGINS', '*').strip()
_socketio_cors = (
    [o.strip() for o in _cors_origins.split(',') if o.strip()]
    if _cors_origins and _cors_origins != '*'
    else '*'
)
_on_hf = bool(os.environ.get('SPACE_ID') or os.environ.get('SYSTEM'))
# gthread → 'threading' (long-polling). gevent worker → 'gevent'. Piloté par env.
_socketio_async = os.environ.get('SOCKETIO_ASYNC_MODE', 'threading')
socketio = SocketIO(
    app,
    cors_allowed_origins=_socketio_cors,
    async_mode=_socketio_async,
    ping_timeout=int(os.environ.get('SOCKETIO_PING_TIMEOUT', '60')),
    ping_interval=int(os.environ.get('SOCKETIO_PING_INTERVAL', '25')),
    logger=False,
    engineio_logger=False,
)

from services.request_log import init_request_logging
init_request_logging(app)

from services.error_handlers import register_error_handlers
register_error_handlers(app)


@app.teardown_appcontext
def _shutdown_db_session(exception=None):
    """Rollback + libération de la session à chaque fin de contexte (anti-cascade)."""
    if exception is not None:
        try:
            db.session.rollback()
        except Exception:
            pass
    db.session.remove()

from services.http_cache import init_http_cache
init_http_cache(app)

# ---------- ENCRYPTION (singleton — préférer services.crypto_service.get_fernet) ----------
from services.crypto_service import get_fernet
fernet = get_fernet()

# ---------- HTTP HELPERS (scans/connecteurs) ----------
from services.http_helpers import safe_get, make_http_session, USER_AGENTS, PROXIES  # noqa: F401

# ---------- GROQ IA ----------
GROQ_API_BASE = 'https://api.groq.com/openai/v1'
GROQ_DEFAULT_MODEL = 'llama-3.3-70b-versatile'


def summarize_osint_with_groq(text, api_key=None, system: str | None = None):
    """Résume des résultats OSINT via l'API Groq (format OpenAI)."""
    default_msg = 'Résumé IA indisponible. Vérifiez GROQ_API_KEY dans les secrets du Space.'
    key = api_key or os.environ.get('GROQ_API_KEY')
    if not key:
        return default_msg

    if isinstance(text, dict):
        json_data = json.dumps(text, ensure_ascii=False)
    else:
        json_data = str(text)
    json_data = json_data[:4000]

    messages = []
    if system:
        messages.append({'role': 'system', 'content': system})
    messages.append({
        'role': 'user',
        'content': (
            'Analyse et résume ces résultats OSINT en français. '
            'Sois concis, structuré, et mets en évidence les points importants '
            f'et risques potentiels:\n\n{json_data}'
        ),
    })

    model = os.environ.get('GROQ_MODEL', GROQ_DEFAULT_MODEL).strip() or GROQ_DEFAULT_MODEL

    try:
        r = requests.post(
            f'{GROQ_API_BASE}/chat/completions',
            headers={
                'Authorization': f'Bearer {key}',
                'Content-Type': 'application/json',
            },
            json={
                'model': model,
                'messages': messages,
            },
            timeout=45,
        )
        if r.status_code == 200:
            data = r.json()
            content = (data.get('choices') or [{}])[0].get('message', {}).get('content', '')
            if content:
                return content.strip()
        return f'{default_msg} (erreur API Groq {r.status_code}).'
    except Exception as exc:
        return f'{default_msg} (connexion : {exc}).'

def init_database():
    """Applique les migrations Alembic (appelé aussi par entrypoint.sh)."""
    from flask_migrate import upgrade
    with app.app_context():
        try:
            upgrade()
        except Exception as exc:
            app.logger.warning('Migration Alembic: %s — fallback create_all', exc)
            db.create_all()


# ---------- AUTH ----------
@login_manager.user_loader
def load_user(uid):
    return db.session.get(User, int(uid))

# ============================================================
#  SCAN FUNCTIONS (scans/core_scans.py + scan_modules.py)
# ============================================================
from scans.registry import SCAN_FUNCTIONS  # noqa: E402

# ============================================================
#  ASYNC SCANS (thread dédié — fiable avec Gunicorn gevent)
# ============================================================
def run_scan_async(module, target, options=None, user_id=None, mode='expert', scheduled_scan_id=None):
    from services.scan_runner import dispatch_scan

    if isinstance(options, list):
        options = {'email_checks': options}
    options = options or {}
    from services.scan_poll import ensure_poll_token
    ensure_poll_token(options)

    if not SCAN_FUNCTIONS.get(module):
        return None

    root_ent = options.get('_root_entity_id')
    scan = Scan(
        module=module, target=target, user_id=user_id, status='pending',
        mode=mode, scheduled_scan_id=scheduled_scan_id,
        root_entity_id=int(root_ent) if root_ent else None,
    )
    from services.db_session import safe_commit
    db.session.add(scan)
    safe_commit(db.session)
    scan_id = scan.id

    if root_ent and user_id:
        try:
            from services.dossier_notify import notify_dossier_scan_started
            notify_dossier_scan_started(
                socketio, int(root_ent), user_id, scan_id, module, target,
            )
        except Exception as e:
            app.logger.warning('notify scan_started #%s: %s', scan_id, e)

    # Stocker options + jeton polling pour le worker
    if options:
        from services.scan_poll import pending_payload
        scan.result_json = json.dumps(pending_payload(options), ensure_ascii=False)
        safe_commit(db.session)

    dispatch_scan(scan_id, app, socketio, fernet)
    return scan_id


# ============================================================
#  ROUTES
# ============================================================
@app.route('/health')
def health():
    import importlib
    db_ok = False
    try:
        db.session.execute(sa_text('SELECT 1'))
        db_ok = True
    except Exception:
        pass
    redis_ok = False
    try:
        from services.cache_manager import redis_available
        redis_ok = redis_available()
    except Exception:
        pass
    celery_configured = False
    celery_connected = False
    try:
        from services.task_queue import use_celery
        celery_configured = use_celery()
        if celery_configured and redis_ok:
            try:
                from celery_app import celery_app
                ping = celery_app.control.ping(timeout=1.5)
                celery_connected = bool(ping)
            except Exception:
                celery_connected = False
    except Exception:
        pass
    critical_modules = (
        'services.report_consolidate',
        'services.report_data',
        'services.narrative_api',
        'services.dossier_access',
        'services.collaboration',
        'services.social_fetch',
        'services.cache_manager',
        'services.async_tasks',
    )
    module_checks = {}
    imports_ok = True
    for name in critical_modules:
        try:
            importlib.import_module(name)
            module_checks[name] = 'ok'
        except Exception as exc:
            module_checks[name] = str(exc)[:200]
            imports_ok = False
    groq_ok = bool(os.environ.get('GROQ_API_KEY'))
    overall = db_ok and imports_ok
    from flask import make_response
    from services.runtime_env import is_hf_space
    payload = {
        'status': 'ok' if overall else 'degraded',
        'version': app.config.get('APP_VERSION', '5.2'),
        'hf_space': is_hf_space(),
        'database': 'connected' if db_ok else 'error',
        'celery': (
            'connected' if celery_connected
            else ('configured' if celery_configured else 'thread')
        ),
        'redis_cache': 'connected' if redis_ok else 'off',
        'groq_configured': groq_ok,
        'modules': module_checks,
    }
    resp = make_response(jsonify(payload), 200 if overall else 503)
    resp.headers['Cache-Control'] = 'public, max-age=15'
    return resp


@app.route('/api/runtime')
def api_runtime():
    """Métadonnées publiques (HF, modes) — pas de secrets."""
    from services.runtime_public import public_runtime_info
    from flask import make_response
    payload = public_runtime_info()
    resp = make_response(jsonify(payload), 200)
    resp.headers['Cache-Control'] = 'public, max-age=60'
    return resp


@app.route('/scan', methods=['POST'])
@limiter.limit('20/minute', key_func=get_remote_address)
def scan_start():
    from services.target_detector import target_category
    data = request.json or {}
    module = data.get('module', '')
    target = data.get('target', '').strip()
    raw_opts = data.get('options', [])
    if isinstance(raw_opts, dict):
        options = raw_opts
    else:
        options = {'email_checks': raw_opts} if raw_opts else {}
    if data.get('stealth'):
        options['_stealth_mode'] = True
    if data.get('deep_dorking'):
        options['_deep_dorking'] = True
    mode = data.get('mode', 'expert')
    if data.get('multi') or module == 'multi':
        module = 'multi'
        options['_scan_mode'] = mode
        options['_category'] = data.get('category') or target_category(target)
        if data.get('modules'):
            options['_modules'] = data.get('modules')
    if data.get('root_entity_id'):
        options['_root_entity_id'] = int(data['root_entity_id'])
    user_id = current_user.is_authenticated and current_user.id or None
    # Rattachement au graphe actif de la session (si aucune racine explicite)
    if user_id and not options.get('_root_entity_id'):
        try:
            from services.active_graph import get_active
            ag = get_active(user_id)
            if ag:
                options['_root_entity_id'] = ag['root_id']
        except Exception:
            pass
    try:
        options['_app'] = current_app._get_current_object()
    except Exception:
        pass
    if options.get('_root_entity_id'):
        if not user_id:
            return jsonify({'error': 'Connexion requise pour scanner ce dossier partagé'}), 401
        from services.dossier_access import get_dossier_context
        if not get_dossier_context(int(options['_root_entity_id']), user_id, min_role='editor'):
            return jsonify({'error': 'Droits insuffisants pour scanner ce dossier partagé'}), 403
    if not target:
        return jsonify({'error': 'Cible manquante'}), 400
    if module not in SCAN_FUNCTIONS:
        return jsonify({'error': f'Module inconnu: {module}'}), 403
    from services.scan_poll import ensure_poll_token

    poll_token = ensure_poll_token(options)
    scan_id = run_scan_async(module, target, options, user_id, mode=mode)
    if scan_id:
        return jsonify({
            'scan_id': scan_id,
            'poll_token': poll_token,
            'status': 'started',
            'module': module,
        })
    return jsonify({'error': 'Échec du lancement'}), 500


@app.route('/scan/<int:scan_id>/retry-timeouts', methods=['POST'])
@login_required
@limiter.limit('10/minute')
def scan_retry_timeouts(scan_id):
    """Relance uniquement les modules en timeout d'un scan multi."""
    from services.scanner import retry_timeout_modules
    scan = db.session.get(Scan, scan_id)
    if not scan or scan.user_id != current_user.id:
        return jsonify({'error': 'Scan non trouvé'}), 404
    opts = {}
    if scan.user_id:
        from services.user_keys import get_key
        u = db.session.get(User, scan.user_id)
        if u:
            for opt_k, ukey, env in [
                ('_hunter_key', 'hunter', 'HUNTER_API_KEY'),
                ('_dehashed_key', 'dehashed', 'DEHASHED_API_KEY'),
                ('_dehashed_email', 'dehashed_email', 'DEHASHED_EMAIL'),
                ('_epieos_key', 'epieos', 'EPIEOS_API_KEY'),
                ('_otx_key', 'otx', 'OTX_API_KEY'),
            ]:
                opts[opt_k] = get_key(u, ukey, env, fernet) or os.environ.get(env, '')
    opts['_retry'] = True
    merged = retry_timeout_modules(scan, opts)
    scan.result_json = json.dumps(merged, ensure_ascii=False, default=str)
    scan.completed_at = datetime.utcnow()
    db.session.commit()
    try:
        from services.correlation import process_multi_correlations
        process_multi_correlations(scan_id, scan.target, merged, scan.user_id)
    except Exception:
        pass
    socketio.emit('scan_done', {'scan_id': scan_id, 'result': merged})
    return jsonify({'status': 'ok', 'result': merged})


@app.route('/scan/<int:scan_id>')
def scan_result(scan_id):
    from services.scan_poll import poll_token_valid

    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({'error': 'Scan non trouvé'}), 404

    poll_tok = (request.args.get('poll_token') or '').strip()
    if poll_token_valid(scan, poll_tok):
        pass  # polling autorisé (HF cross-origin, pas de cookie session)
    elif scan.user_id:
        if not current_user.is_authenticated:
            return jsonify({'error': 'Connexion requise pour ce scan'}), 401
        if scan.user_id != current_user.id:
            allowed = False
            if scan.root_entity_id:
                from services.dossier_access import get_dossier_context
                allowed = bool(get_dossier_context(
                    int(scan.root_entity_id), current_user.id, min_role='reader',
                ))
            if not allowed:
                return jsonify({'error': 'Accès refusé'}), 403
    elif scan.mode != 'express' and not current_user.is_authenticated:
        return jsonify({'error': 'Connexion requise'}), 401
    if scan.status == 'completed':
        try:
            out = json.loads(scan.result_json or '{}')
        except json.JSONDecodeError:
            out = {'error': 'Résultat scan illisible'}
        if scan.ai_summary:
            out['_ai_summary'] = scan.ai_summary
        meta = out.get('_meta') if isinstance(out.get('_meta'), dict) else {}
        meta.update({
            'scan_id': scan.id,
            'status': scan.status,
            'module': scan.module,
            'target': scan.target,
        })
        out['_meta'] = meta
        return jsonify(out)
    return jsonify({
        'status': scan.status,
        'scan_id': scan.id,
        'module': scan.module,
        'target': scan.target,
    })


@app.route('/history')
@login_required
def history():
    module_f = request.args.get('module', '')
    q = Scan.query.filter_by(user_id=current_user.id)
    if module_f:
        q = q.filter_by(module=module_f)
    scans = q.order_by(Scan.timestamp.desc()).limit(200).all()
    return render_template('history.html', scans=scans, module_filter=module_f)


@app.route('/export/<int:scan_id>/csv')
@login_required
@limiter.limit('25/minute')
def export_csv(scan_id):
    import csv
    scan = db.session.get(Scan, scan_id)
    if not scan or scan.user_id != current_user.id:
        abort(404)
    data = json.loads(scan.result_json or '{}')
    buf = BytesIO()
    w = csv.writer(buf)
    w.writerow(['section', 'key', 'value'])
    for section, content in data.items():
        if section.startswith('_'):
            continue
        if isinstance(content, dict):
            for k, v in content.items():
                w.writerow([section, k, str(v)[:500]])
        elif isinstance(content, list):
            for i, item in enumerate(content):
                w.writerow([section, str(i), str(item)[:500]])
        else:
            w.writerow([section, '', str(content)[:500]])
    buf.seek(0)
    return send_file(buf, mimetype='text/csv', as_attachment=True,
                     download_name=f'osint_{scan.module}_{scan_id}.csv')


@app.route('/export/<int:scan_id>')
@login_required
@limiter.limit('25/minute')
def export(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan: abort(404)
    if scan.user_id != current_user.id: abort(403)
    data = json.loads(scan.result_json)
    content = json.dumps(data, ensure_ascii=False, indent=2).encode('utf-8')
    return send_file(BytesIO(content), mimetype='application/json',
                     as_attachment=True,
                     download_name=f'osint_{scan.module}_{scan_id}.json')


@app.route('/report/<int:scan_id>', methods=['GET', 'POST'])
@login_required
@limiter.limit('15/minute')
def report_pdf(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan: abort(404)
    if scan.user_id != current_user.id: abort(403)
    graph_image = request.args.get('graph', '')
    if request.method == 'POST' and request.json:
        graph_image = request.json.get('graph_png', graph_image)
    raw_data = json.loads(scan.result_json or '{}')
    from services.report_export import generate_pdf_response
    _, response, err = generate_pdf_response(
        scan, raw_data,
        investigator=current_user.username,
        classification=request.args.get('classification', 'CONFIDENTIEL'),
        graph_image=graph_image or None,
    )
    if err:
        return err
    return response


@app.route('/report/<int:scan_id>/verify')
@login_required
def report_verify(scan_id):
    """Vérification d'intégrité : compare hash fourni aux empreintes du scan."""
    from services.report_signing import build_report_hashes
    scan = db.session.get(Scan, scan_id)
    if not scan or scan.user_id != current_user.id:
        return jsonify({'error': 'Scan non trouvé'}), 404
    raw_data = json.loads(scan.result_json or '{}')
    generated_at = request.args.get('generated_at', datetime.utcnow().strftime('%d/%m/%Y %H:%M UTC'))
    hashes = build_report_hashes(scan, raw_data, generated_at)
    provided = request.args.get('hash', '')
    match_content = provided == hashes['content_hash']
    match_sig = provided == hashes['signature_hash']
    match_pdf = provided == (scan.report_pdf_hash or '')
    return jsonify({
        'scan_id': scan_id,
        'valid': match_content or match_sig or match_pdf,
        'match_content': match_content,
        'match_signature': match_sig,
        'match_pdf': match_pdf,
        'content_hash': hashes['content_hash'],
        'signature_hash': hashes['signature_hash'],
        'report_pdf_hash': scan.report_pdf_hash,
        'verify_url': f'/verify/{scan_id}',
    })


@app.route('/upload', methods=['POST'])
@login_required
@limiter.limit('12/minute')
def upload():
    if 'file' not in request.files:
        return jsonify({'error': 'Aucun fichier'}), 400
    file = request.files['file']
    if not file.filename:
        return jsonify({'error': 'Nom de fichier vide'}), 400
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    metadata = {}
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    try:
        if ext in ('jpg', 'jpeg', 'png', 'tiff', 'bmp', 'webp'):
            img = Image.open(filepath)
            metadata['Format']     = img.format or ext.upper()
            metadata['Mode']       = img.mode
            metadata['Dimensions'] = f'{img.width}×{img.height} px'
            exif_data = img._getexif()
            if exif_data:
                for tag_id, value in exif_data.items():
                    tag_name = TAGS.get(tag_id, str(tag_id))
                    try:
                        metadata[tag_name] = str(value) if not isinstance(value, bytes) else value.hex()
                    except Exception:
                        pass
            else:
                metadata['EXIF'] = 'Aucune métadonnée EXIF trouvée'
        elif ext == 'pdf':
            reader = PdfReader(filepath)
            meta = reader.metadata or {}
            for k, v in meta.items():
                metadata[k.lstrip('/')] = str(v)
            metadata['Pages'] = len(reader.pages)
        elif ext == 'docx':
            doc_file = docx.Document(filepath)
            p = doc_file.core_properties
            for k, v in [('Auteur', p.author), ('Titre', p.title), ('Sujet', p.subject),
                          ('Mots-clés', p.keywords), ('Créé le', p.created),
                          ('Modifié le', p.modified), ('Dernière modif. par', p.last_modified_by),
                          ('Révision', p.revision)]:
                if v: metadata[k] = str(v)
        else:
            metadata['Note'] = f'Format .{ext} non supporté'
    except Exception as e:
        metadata['Erreur'] = str(e)
    finally:
        try: os.remove(filepath)
        except Exception: pass
    return jsonify({'metadata': metadata})


@app.route('/ai-summary', methods=['POST'])
@limiter.limit('15/minute')
def ai_summary():
    data = request.json or {}
    text = data.get('result', '')
    scan_id = data.get('scan_id')
    if not text:
        return jsonify({'error': 'Aucun résultat de scan à résumer'}), 400

    scan = None
    if scan_id:
        scan = db.session.get(Scan, int(scan_id))
        if scan and scan.ai_summary:
            return jsonify({'summary': scan.ai_summary, 'cached': True})

    # Confidentialité : pseudonymise avant envoi à l'IA, ré-hydrate ensuite.
    from services.pseudonymize import Pseudonymizer
    from services.target_detector import target_category
    pseudo = Pseudonymizer()
    if scan is not None:
        _t = 'username' if scan.module in ('sherlock', 'pseudo', 'github') \
            else target_category(scan.target)
        pseudo.token_for(scan.target, _t)
    tok_text = pseudo.pseudonymize_obj(text) if isinstance(text, dict) \
        else pseudo.pseudonymize_text(text)

    summary = summarize_osint_with_groq(tok_text)
    if summary.startswith('Résumé IA indisponible'):
        return jsonify({'error': summary}), 500
    summary = pseudo.rehydrate(summary)
    if scan:
        if scan.user_id and current_user.is_authenticated and scan.user_id != current_user.id:
            return jsonify({'error': 'Accès refusé'}), 403
        scan.ai_summary = summary
        db.session.commit()
    return jsonify({'summary': summary})


@app.route('/scan/<int:scan_id>/view')
@login_required
def scan_view(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan or scan.user_id != current_user.id:
        abort(404)
    if scan.status != 'completed':
        return redirect(url_for('views.expert'))
    return redirect(url_for('views.expert', scan_id=scan_id))


# ---------- SOCKETIO ----------
@socketio.on('connect')
def on_connect():
    pass


@socketio.on('join_investigation')
def on_join_investigation(data=None):
    """Salle Socket.IO par utilisateur pour l'enquête guidée."""
    from flask_socketio import join_room
    if current_user.is_authenticated:
        join_room(str(current_user.id))


@socketio.on('join_graph')
def on_join_graph(data=None):
    """Salle Socket.IO pour mises à jour graphe (pivot)."""
    from flask_socketio import join_room
    if current_user.is_authenticated:
        join_room(str(current_user.id))


@socketio.on('join_map')
def on_join_map(data=None):
    """Même salle utilisateur — mises à jour carte en temps réel."""
    from flask_socketio import join_room
    if current_user.is_authenticated:
        join_room(str(current_user.id))


@socketio.on('join_timeline')
def on_join_timeline(data=None):
    """Mises à jour frise chronologique (même salle utilisateur)."""
    from flask_socketio import join_room
    if current_user.is_authenticated:
        join_room(str(current_user.id))


@socketio.on('join_dossier')
def on_join_dossier(data=None):
    """Room temps réel par dossier partagé (Phase 8)."""
    from flask_socketio import join_room
    if not current_user.is_authenticated:
        return
    payload = data or {}
    root_id = payload.get('root_entity_id') or payload.get('entity_id')
    if not root_id:
        return
    from services.dossier_access import get_dossier_context, dossier_room_name
    if get_dossier_context(int(root_id), current_user.id, min_role='reader'):
        join_room(dossier_room_name(int(root_id)))
        join_room(str(current_user.id))


@socketio.on('disconnect')
def on_disconnect():
    pass

# ---------- PWA ----------
@app.route('/sw.js')
def service_worker():
    return app.send_static_file('sw.js')

@app.route('/manifest.json')
def manifest():
    return app.send_static_file('manifest.json')


@login_manager.unauthorized_handler
def _login_unauthorized():
    """JSON pour les routes expert/API (évite page HTML opaque côté XHR)."""
    path = request.path or ''
    if path.startswith('/expert/') or path.startswith('/api/'):
        return jsonify({'error': 'Connexion requise'}), 401
    from flask import redirect, url_for
    return redirect(url_for('auth.login'))


_API_JSON_FALLBACK_MD = (
    '## Rapport narratif\n\n'
    '*Le serveur a rencontré une erreur. Réessayez dans quelques instants '
    'ou consultez /health pour le diagnostic.*\n'
)
_API_JSON_FALLBACK_HTML = (
    '<h2>Rapport narratif</h2>'
    '<p><em>Le serveur a rencontré une erreur. Réessayez plus tard.</em></p>'
)


@app.errorhandler(500)
def handle_500(err):
    """JSON de secours sans import de modules métier (évite échec en cascade)."""
    path = request.path or ''
    if (
        '/narrative' in path
        or path.startswith('/api/v1')
        or path.startswith('/dossier/')
        or path.startswith('/expert/')
    ):
        app.logger.exception('HTTP 500 sur %s', path)
        return jsonify({
            'error': 'Erreur serveur interne',
            'detail': str(getattr(err, 'description', err)),
            'markdown': _API_JSON_FALLBACK_MD,
            'html': _API_JSON_FALLBACK_HTML,
            'partial': True,
        }), 200
    return err


from routes.views import views_bp
from routes.auth import auth_bp
from routes.api_v1 import api_bp
from routes.collaboration import collab_bp

app.register_blueprint(auth_bp)
app.register_blueprint(views_bp)
app.register_blueprint(collab_bp)
app.register_blueprint(api_bp, url_prefix='/api/v1')

# CSRF : formulaires HTML protégés ; JSON/API exemptés
if csrf:
    csrf.exempt(api_bp)
    csrf.exempt(collab_bp)
    for _ep in (
        'scan_start', 'health', 'api_runtime', 'service_worker', 'manifest',
        'views.verify_upload', 'auth.api_password_strength',
    ):
        _vf = app.view_functions.get(_ep)
        if _vf:
            csrf.exempt(_vf)
    _JSON_VIEW_ENDPOINTS = (
        'views.express_detect', 'views.express_card', 'views.express_assist',
        'views.dossier_launch_scan', 'views.dossier_narrative',
        'views.dossier_narrative_status', 'views.graph_data', 'views.graph_pivot',
        'views.graph_scan_node', 'views.graph_suggestions', 'views.timeline_data',
        'views.map_data', 'views.investigate_start', 'views.investigate_status',
        'views.dossier_suggestions',
    )
    for _ep in _JSON_VIEW_ENDPOINTS:
        _vf = app.view_functions.get(_ep)
        if _vf:
            csrf.exempt(_vf)

def _log_production_guards():
    if not app.config.get('OSINT_PRODUCTION'):
        return
    missing = []
    if not (os.environ.get('SECRET_KEY') or '').strip():
        missing.append('SECRET_KEY')
    if not (os.environ.get('FERNET_KEY') or '').strip():
        missing.append('FERNET_KEY')
    if not (os.environ.get('DATABASE_URL') or '').strip():
        missing.append('DATABASE_URL')
    if missing:
        app.logger.warning(
            'Production (OSINT_PRODUCTION / PostgreSQL) : secrets manquants → %s',
            ', '.join(missing),
        )
    if not app.config.get('SESSION_COOKIE_SECURE'):
        app.logger.warning('SESSION_COOKIE_SECURE=false en production')
    if not app.config.get('WTF_CSRF_ENABLED'):
        app.logger.warning('WTF_CSRF_ENABLED=false en production')


with app.app_context():
    _log_production_guards()
    try:
        from services.scheduler import start_scheduler
        start_scheduler(app)
    except Exception as sched_err:
        app.logger.warning('Scheduler: %s', sched_err)


if __name__ == '__main__':
    init_database()
    socketio.run(app, debug=False, host='0.0.0.0',
                 port=int(os.environ.get('PORT', 5000)))
