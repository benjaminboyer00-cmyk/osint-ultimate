"""Agent d'enquête OSINT — planificateur Groq + exécution séquentielle."""
import json
import logging
import os
import re
import threading
from datetime import datetime

from extensions import db
from models import Investigation, Scan, User
from services.groq import chat_completion
from services.target_detector import detect_target_type, target_category

logger = logging.getLogger(__name__)

MAX_STEPS = int(os.environ.get('INVESTIGATION_MAX_STEPS', '6'))
MODULE_TIMEOUT = int(os.environ.get('INVESTIGATION_MODULE_TIMEOUT', '25'))


def _run_module_with_timeout(func, target, opts, app, timeout=MODULE_TIMEOUT):
    """Exécute un module dans un thread daemon borné : un scan lent ne bloque
    plus la boucle d'enquête à l'infini (cause du « chargement infini »)."""
    box = {}

    def _w():
        try:
            if app is not None:
                with app.app_context():
                    box['r'] = func(target, opts)
            else:
                box['r'] = func(target, opts)
        except Exception as e:  # noqa: BLE001
            box['e'] = e

    t = threading.Thread(target=_w, daemon=True, name='inv-module')
    t.start()
    t.join(timeout)
    if t.is_alive():
        return {'_timeout': True, 'Erreur': f'Module interrompu (>{timeout}s)'}
    if 'e' in box:
        return {'Erreur': str(box['e'])}
    return box.get('r') or {}

MODULES_SPEC = [
    {'name': 'sherlock', 'description': 'Recherche un pseudo sur 300+ réseaux sociaux', 'inputs': ['pseudo', 'username']},
    {'name': 'dehashed', 'description': 'Fuites de données (email, pseudo, téléphone)', 'inputs': ['email', 'pseudo', 'phone']},
    {'name': 'hunter', 'description': 'Emails professionnels par domaine', 'inputs': ['domain']},
    {'name': 'epieos', 'description': 'Enrichissement email / Google / Microsoft', 'inputs': ['email']},
    {'name': 'email', 'description': 'Analyse technique email (MX, SPF, fuites HIBP)', 'inputs': ['email']},
    {'name': 'phone', 'description': 'Validation et géolocalisation téléphone', 'inputs': ['phone']},
    {'name': 'whois', 'description': 'WHOIS domaine', 'inputs': ['domain']},
    {'name': 'wayback', 'description': 'Archives web Wayback Machine', 'inputs': ['domain', 'url']},
    {'name': 'site', 'description': 'Analyse site web (DNS, HTTP, sécurité)', 'inputs': ['domain', 'url']},
    {'name': 'ip', 'description': 'Géolocalisation et Shodan IP', 'inputs': ['ip']},
    {'name': 'github', 'description': 'Profil GitHub public', 'inputs': ['pseudo']},
    {'name': 'pseudo', 'description': 'Recherche pseudo réseaux classiques', 'inputs': ['pseudo']},
    {'name': 'subdomains', 'description': 'Sous-domaines exposés (Certificate Transparency / crt.sh)', 'inputs': ['domain']},
    {'name': 'reverse_ip', 'description': 'Domaines hébergés sur la même IP (mutualisé)', 'inputs': ['ip', 'domain']},
    {'name': 'typosquat', 'description': 'Domaines sosies qui résolvent (anti-phishing)', 'inputs': ['domain']},
]


def _parse_action_json(text: str) -> dict | None:
    if not text:
        return None
    text = text.strip()
    m = re.search(r'```(?:json)?\s*([\s\S]*?)```', text)
    if m:
        text = m.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r'\{[\s\S]*\}', text)
        if m:
            try:
                return json.loads(m.group(0))
            except json.JSONDecodeError:
                pass
    return None


def _extract_target_from_params(params: dict, fallback: str) -> str:
    if not params:
        return fallback
    for key in ('target', 'email', 'pseudo', 'username', 'phone', 'domain', 'ip', 'url'):
        if params.get(key):
            return str(params[key]).strip()
    return fallback


def _summarize_result(module: str, result: dict) -> str:
    if not result:
        return 'Aucune donnée'
    if result.get('_timeout'):
        return 'Timeout — service lent'
    if result.get('Erreur') or result.get('error'):
        return str(result.get('Erreur') or result.get('error'))[:120]
    if module in ('sherlock', 'pseudo'):
        found = [k for k, v in result.items() if 'Existe' in str(v) or '✓' in str(v)]
        return f'{len(found)} profil(s) trouvé(s)' if found else 'Aucun profil'
    if module == 'dehashed':
        n = result.get('Entrées') or result.get('Total') or 0
        if isinstance(n, list):
            n = len(n)
        return f'{n} entrée(s) fuite(s)'
    if module == 'hunter':
        return f"{result.get('Emails trouvés', 0)} email(s) pro"
    if module == 'email':
        return f"MX: {result.get('MX', '—')}, fuites: {result.get('Fuites (HIBP)', '—')}"
    keys = list(result.keys())[:3]
    return ', '.join(f'{k}: {str(result[k])[:40]}' for k in keys if not str(k).startswith('_'))


def plan_next_action(objective: str, previous_steps: list, step_num: int) -> dict:
    """Demande à Groq la prochaine action ou TERMINE."""
    prev_compact = []
    for s in previous_steps[-6:]:
        prev_compact.append({
            'step': s.get('step'),
            'action': s.get('action'),
            'target': s.get('target'),
            'summary': s.get('summary'),
        })

    system = (
        'Tu es un enquêteur OSINT autonome. Réponds UNIQUEMENT en JSON valide, sans markdown. '
        'Format: {"action":"nom_module","params":{"target":"valeur"},"reason":"courte explication"} '
        'ou {"action":"TERMINE","summary":"synthèse finale en français"} si objectif atteint ou plus rien à faire. '
        'Modules autorisés: sherlock, dehashed, hunter, epieos, email, phone, whois, wayback, site, ip, github, pseudo, subdomains, reverse_ip, typosquat.'
    )

    # Confidentialité : le LLM ne voit que des jetons (USERNAME_1, EMAIL_2…) ;
    # l'action est ré-hydratée pour cibler la vraie valeur.
    from services.pseudonymize import Pseudonymizer
    pseudo = Pseudonymizer()
    tok_objective = pseudo.pseudonymize_text(objective)
    tok_prev = pseudo.pseudonymize_obj(prev_compact)

    prompt = (
        f'Objectif utilisateur: {tok_objective}\n'
        f'Étape {step_num}/{MAX_STEPS}\n'
        f'Outils: {json.dumps(MODULES_SPEC, ensure_ascii=False)}\n'
        f'Résultats précédents: {json.dumps(tok_prev, ensure_ascii=False)}\n'
        'Propose UNE seule prochaine action logique. Ne répète pas un scan identique déjà fait.'
    )

    try:
        # Modèle rapide + sortie courte : la planification enchaîne jusqu'à
        # MAX_STEPS appels -> latence divisée.
        raw = chat_completion(prompt, system=system, fast=True,
                              max_tokens=int(os.environ.get('INVESTIGATION_PLAN_MAX_TOKENS', '400')))
        parsed = _parse_action_json(raw)
        if parsed and parsed.get('action'):
            return pseudo.rehydrate(parsed)
    except Exception:
        pass

    return _fallback_plan(objective, previous_steps)


def _fallback_plan(objective: str, previous_steps: list) -> dict:
    """Plan local si Groq indisponible."""
    done = {s.get('action') for s in previous_steps}
    t = objective.strip()
    for word in re.findall(r'[\w.\-@+]+', t):
        if len(word) < 3:
            continue
        cat = target_category(word)
        if cat == 'email' and 'email' not in done and '@' in word:
            return {'action': 'email', 'params': {'email': word}, 'reason': 'Analyse email'}
        if cat == 'pseudo' and 'sherlock' not in done:
            return {'action': 'sherlock', 'params': {'pseudo': word}, 'reason': 'Recherche pseudo'}
        if cat == 'domain':
            # Enchaînement d'enrichissement d'infrastructure sur un domaine
            for mod, reason in (
                ('whois', 'WHOIS domaine'),
                ('subdomains', 'Sous-domaines exposés'),
                ('site', 'DNS / HTTP / sécurité'),
                ('hunter', 'Emails professionnels'),
                ('typosquat', 'Domaines sosies (phishing)'),
                ('wayback', 'Historique web'),
            ):
                if mod not in done:
                    return {'action': mod, 'params': {'domain': word}, 'reason': reason}
    if len(previous_steps) >= 3:
        return {'action': 'TERMINE', 'summary': 'Enquête terminée. Dossier et corrélations disponibles dans le graphe.'}
    return {'action': 'sherlock', 'params': {'pseudo': t[:40]}, 'reason': 'Recherche initiale'}


def _final_dossier(user_id: int, root_entity_id, base_summary: str) -> str:
    """Synthèse finale enrichie par l'analyse IA du graphe (vrai dossier)."""
    if not root_entity_id:
        return base_summary
    try:
        from services.graph_analysis import analyze_graph
        a = analyze_graph(user_id, int(root_entity_id))
        if not isinstance(a, dict) or a.get('error'):
            return base_summary
        parts = []
        if a.get('synthese'):
            parts.append(a['synthese'])
        inc = a.get('incoherences') or []
        if inc:
            parts.append('⚠️ Incohérences : ' + ' ; '.join(
                str(i.get('observation', '')) for i in inc[:3] if i.get('observation')))
        pistes = sorted(a.get('pistes') or [], key=lambda p: p.get('priorite', 9))[:3]
        if pistes:
            parts.append('🎯 Pistes : ' + ' ; '.join(
                str(p.get('action', '')) for p in pistes if p.get('action')))
        return '\n\n'.join(p for p in parts if p) or base_summary
    except Exception as e:  # noqa: BLE001
        logger.debug('dossier final: %s', e)
        return base_summary


def _build_user_options(user_id: int, fernet) -> dict:
    opts = {}
    if not user_id:
        return opts
    from services.user_keys import get_key
    import os
    u = db.session.get(User, user_id)
    if not u:
        return opts
    for opt_k, ukey, env in [
        ('_hunter_key', 'hunter', 'HUNTER_API_KEY'),
        ('_dehashed_key', 'dehashed', 'DEHASHED_API_KEY'),
        ('_dehashed_email', 'dehashed_email', 'DEHASHED_EMAIL'),
        ('_epieos_key', 'epieos', 'EPIEOS_API_KEY'),
        ('_hibp_key', 'hibp', 'HIBP_API_KEY'),
        ('_shodan_key', 'shodan', 'SHODAN_API_KEY'),
    ]:
        opts[opt_k] = get_key(u, ukey, env, fernet) or os.environ.get(env, '')
    if u.proxy_list:
        opts['_proxy_list'] = u.proxy_list
    if u.stealth_mode:
        opts['_stealth_mode'] = True
    return opts


def execute_module(module: str, target: str, user_id: int, options: dict, investigation_id: int):
    """Exécute un module synchrone et enregistre le scan."""
    from app import SCAN_FUNCTIONS, fernet
    from services.correlation import process_scan_correlations

    func = SCAN_FUNCTIONS.get(module)
    if not func:
        return {'Erreur': f'Module {module} inconnu'}, None

    opts = dict(options or {})
    opts['_root_entity_id'] = opts.get('_root_entity_id')

    result = _run_module_with_timeout(func, target, opts, opts.get('_app'))

    scan = Scan(
        user_id=user_id,
        module=module,
        target=target,
        result_json=json.dumps(result, ensure_ascii=False, default=str),
        status='completed',
        mode='investigation',
        completed_at=datetime.utcnow(),
    )
    db.session.add(scan)
    db.session.flush()

    if user_id and result and not result.get('error'):
        try:
            process_scan_correlations(
                scan.id, module, target, result, user_id,
                root_entity_id=opts.get('_root_entity_id'),
            )
        except Exception:
            pass

    db.session.commit()
    return result, scan.id


def _emit(socketio, event: str, payload: dict, user_id: int | None = None):
    if socketio:
        payload = dict(payload)
        if 'status' not in payload and payload.get('phase'):
            payload['status'] = payload['phase']
        room = str(user_id) if user_id else None
        if room:
            socketio.emit(event, payload, room=room)
        else:
            socketio.emit(event, payload)


def _run_investigation_loop_inner(investigation_id: int, user_id: int, app, socketio, fernet):
    """Corps de la boucle d'enquête (enveloppé par run_investigation_loop)."""
    with app.app_context():
        inv = db.session.get(Investigation, investigation_id)
        if not inv:
            return
        inv.status = 'running'
        db.session.commit()

        objective = inv.objective or inv.title
        steps = []
        options = _build_user_options(user_id, fernet)
        options['_root_entity_id'] = inv.root_entity_id
        options['_app'] = app

        _emit(socketio, 'investigation_started', {
            'investigation_id': investigation_id,
            'objective': objective,
            'message': '🧠 L\'IA analyse votre objectif et prépare le plan d\'enquête…',
        }, user_id)

        _emit(socketio, 'investigation_step', {
            'investigation_id': investigation_id,
            'step': 0,
            'phase': 'planning',
            'status': 'planning',
            'message': '🧠 Planification de l\'enquête en cours…',
        }, user_id)

        for step_num in range(1, MAX_STEPS + 1):
            _emit(socketio, 'investigation_step', {
                'investigation_id': investigation_id,
                'step': step_num,
                'phase': 'planning',
                'status': 'planning',
                'message': f'🧠 Étape {step_num}/{MAX_STEPS} — l\'IA choisit le prochain module…',
            }, user_id)

            plan = plan_next_action(objective, steps, step_num)
            action = (plan.get('action') or '').upper()

            if action == 'TERMINE':
                base = plan.get('summary') or 'Enquête terminée.'
                summary = _final_dossier(user_id, inv.root_entity_id, base)
                inv.result_summary = summary
                inv.status = 'completed'
                inv.completed_at = datetime.utcnow()
                inv.steps_json = json.dumps(steps, ensure_ascii=False)
                db.session.commit()
                _emit(socketio, 'investigation_done', {
                    'investigation_id': investigation_id,
                    'summary': summary,
                    'steps': steps,
                }, user_id)
                return

            module = action.lower()
            params = plan.get('params') or {}
            target = _extract_target_from_params(params, objective[:200])
            reason = plan.get('reason', f'Lancement {module}')

            _emit(socketio, 'investigation_step', {
                'investigation_id': investigation_id,
                'step': step_num,
                'phase': 'running',
                'status': 'running',
                'action': module,
                'target': target,
                'message': f'🔍 Recherche en cours : {module} sur « {target[:60]} »…',
            }, user_id)

            result, scan_id = execute_module(
                module, target, user_id, options, investigation_id,
            )
            summary = _summarize_result(module, result)

            step_record = {
                'step': step_num,
                'action': module,
                'target': target,
                'reason': reason,
                'status': 'timeout' if result.get('_timeout') else 'done',
                'scan_id': scan_id,
                'summary': summary,
            }
            steps.append(step_record)
            inv.steps_json = json.dumps(steps, ensure_ascii=False)
            db.session.commit()

            _emit(socketio, 'investigation_step', {
                'investigation_id': investigation_id,
                'step': step_num,
                'phase': 'done',
                'status': 'done',
                'action': module,
                'target': target,
                'message': f'✅ {module} : {summary}',
                'scan_id': scan_id,
            }, user_id)

            if not inv.root_entity_id and user_id:
                from services.entity_resolve import find_entity_for_target
                ent = find_entity_for_target(user_id, target, module)
                if ent:
                    inv.root_entity_id = ent.id
                    options['_root_entity_id'] = ent.id
                    db.session.commit()

        inv.status = 'completed'
        inv.result_summary = _final_dossier(
            user_id, inv.root_entity_id,
            f'Enquête terminée après {len(steps)} étapes. '
            'Ouvrez le graphe pour explorer les corrélations.',
        )
        inv.completed_at = datetime.utcnow()
        inv.steps_json = json.dumps(steps, ensure_ascii=False)
        db.session.commit()
        _emit(socketio, 'investigation_done', {
            'investigation_id': investigation_id,
            'summary': inv.result_summary,
            'steps': steps,
        }, user_id)


def run_investigation_loop(investigation_id: int, user_id: int, app, socketio, fernet):
    """Enveloppe bulletproof : toute exception finalise l'enquête + émet
    ``investigation_done`` (évite le statut bloqué à « running » = spinner infini)."""
    try:
        _run_investigation_loop_inner(investigation_id, user_id, app, socketio, fernet)
    except Exception as e:  # noqa: BLE001
        logger.exception('Enquête #%s interrompue', investigation_id)
        try:
            with app.app_context():
                inv = db.session.get(Investigation, investigation_id)
                if inv and inv.status != 'completed':
                    inv.status = 'completed'
                    inv.result_summary = f'Enquête interrompue par une erreur : {e}'
                    inv.completed_at = datetime.utcnow()
                    db.session.commit()
        except Exception:
            logger.exception('Échec finalisation enquête #%s', investigation_id)
        _emit(socketio, 'investigation_done', {
            'investigation_id': investigation_id,
            'summary': f'Enquête interrompue : {e}',
            'steps': [],
        }, user_id)


def start_investigation(user_id: int, query: str, app, socketio, fernet) -> int:
    """Crée une enquête et lance le thread agent."""
    with app.app_context():
        title = (query or 'Enquête')[:180]
        inv = Investigation(
            user_id=user_id,
            title=title,
            objective=query,
            status='pending',
            steps_json='[]',
        )
        db.session.add(inv)
        db.session.commit()
        inv_id = inv.id

    t = threading.Thread(
        target=run_investigation_loop,
        args=(inv_id, user_id, app, socketio, fernet),
        daemon=True,
        name=f'investigation-{inv_id}',
    )
    t.start()
    return inv_id
