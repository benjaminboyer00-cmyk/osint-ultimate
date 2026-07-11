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


_PLACEHOLDER_RE = re.compile(
    r'obtenu|r[ée]sultat|gr[âa]ce|[àa]_?partir|du_email|domaine_du|pseudo_de|'
    r'pseudo_obtenu|nom_de|placeholder|exemple|inconnu|d[ée]terminer|valeur_de',
    re.I,
)


def _is_concrete_target(target: str) -> bool:
    """Rejette les cibles descriptives inventées par le LLM (placeholders).

    Le planificateur invente parfois des cibles du type
    « domaine_du_email_1_obtenu_grace_au_resultat_de_epieos » quand il n'a pas
    de valeur réelle. Les scanner créait des entités bidons dans le graphe.
    """
    t = (target or '').strip()
    if not t or len(t) > 80:
        return False
    if ' ' in t:                       # un identifiant concret n'a pas d'espace
        return False
    if _PLACEHOLDER_RE.search(t):
        return False
    # snake_case descriptif : ≥3 mots de 3+ lettres reliés par « _ »
    if re.search(r'[a-zà-ÿ]{3,}_[a-zà-ÿ]{3,}_[a-zà-ÿ]{3,}', t.lower()):
        return False
    return True


def _grounded_values(objective: str, root_entity_id, user_id) -> set:
    """Ensemble des valeurs réellement connues : identifiants de l'objectif +
    domaines de ses emails + entités déjà découvertes dans le graphe."""
    known: set[str] = set()
    ids = _extract_identifiers(objective or '')
    for lst in ids.values():
        for v in lst:
            known.add(v.lower())
    for e in ids['email']:
        if '@' in e:
            known.add(e.split('@', 1)[1].lower())     # domaine de l'email
    try:
        from services.correlation import build_graph_json
        if root_entity_id:
            g = build_graph_json(int(root_entity_id), int(user_id))
            for n in g.get('nodes', []):
                v = (n.get('value') or '').strip().lower()
                if v:
                    known.add(v)
    except Exception:  # noqa: BLE001
        pass
    return known


def _is_grounded_target(target: str, objective: str, known: set) -> bool:
    """La cible doit exister dans l'objectif ou dans les données déjà découvertes.

    Empêche le LLM d'inventer des valeurs plausibles (ex: « pourdehashed.fr »
    fabriqué à partir de « pour dehashed », ou « dehashed.com » depuis le nom du
    module) qui pollueraient le graphe avec des entités fantômes.
    """
    t = (target or '').strip().lower()
    if not t:
        return False
    if t in _STOPWORDS:                    # mot vide pris pour une cible
        return False
    if t in known:
        return True
    if t in (objective or '').lower():     # apparaît littéralement dans l'objectif
        return True
    # cible = sous-partie d'une valeur connue (ex: « victoria » dans un email connu).
    # UNIQUEMENT ce sens : jamais « connu ⊂ cible » (sinon « dehashed » validerait
    # « pourdehashed.fr » inventé par le LLM).
    for k in known:
        if len(t) >= 4 and t in k:
            return True
    return False


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


def plan_next_action(objective: str, previous_steps: list, step_num: int, deep: bool = False) -> dict:
    """Demande à Groq la prochaine action ou TERMINE."""
    prev_compact = []
    for s in previous_steps[-6:]:
        prev_compact.append({
            'step': s.get('step'),
            'action': s.get('action'),
            'target': s.get('target'),
            'summary': s.get('summary'),
        })

    mods = ('sherlock, hunter, epieos, email, phone, whois, wayback, site, ip, '
            'github, pseudo, subdomains, reverse_ip, typosquat')
    if deep:
        mods += ', dehashed'
    system = (
        'Tu es un enquêteur OSINT autonome. Réponds UNIQUEMENT en JSON valide, sans markdown. '
        'Format: {"action":"nom_module","params":{"target":"valeur_CONCRETE"},"reason":"courte explication"} '
        'ou {"action":"TERMINE","summary":"synthèse finale en français"} si objectif atteint ou plus rien à faire. '
        'RÈGLE STRICTE : "target" doit être une valeur RÉELLE et concrète (un email, un domaine, '
        'un pseudo, un numéro, une IP effectivement présents dans les données) — JAMAIS une description '
        'du type "le domaine obtenu via epieos". Si tu n\'as pas de valeur concrète, réponds TERMINE. '
        f'Modules autorisés: {mods}.'
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

    return _fallback_plan(objective, previous_steps, deep)


# Mots vides FR/EN : ne doivent jamais être pris pour un pseudo à scanner.
_STOPWORDS = {
    'enquête', 'enquete', 'sur', 'analyse', 'analyser', 'trouve', 'trouver',
    'qui', 'est', 'les', 'des', 'recherche', 'rechercher', 'tout', 'toute',
    'toutes', 'tous', 'info', 'infos', 'informations', 'personne', 'compte',
    'profil', 'identité', 'identite', 'email', 'mail', 'pseudo', 'numéro',
    'numero', 'téléphone', 'telephone', 'domaine', 'site', 'adresse', 'son',
    'ses', 'avec', 'pour', 'dans', 'une', 'des', 'the', 'and', 'find', 'about',
    'complète', 'complete', 'faire', 'sait', 'derrière', 'derriere', 'cache',
    'se', 'ce', 'cette', 'que', 'quoi', 'comment', 'où', 'quand', 'nom',
    'prénom', 'prenom', 'this', 'that', 'with', 'from', 'who', 'what', 'his',
    'her', 'get', 'sais', 'connais', 'donne', 'moi', 'plus', 'possible',
    'peux', 'peut', 'veux', 'veut', 'autre', 'autres', 'donc', 'juste',
    'dis', 'refaire', 'besoin', 'coup', 'fais', 'fait', 'voir', 'sur',
    'aussi', 'encore', 'déjà', 'deja', 'bien', 'vraiment', 'via', 'grace',
    'grâce', 'obtenu', 'resultat', 'résultat', 'concernant', 'à', 'au', 'aux',
    # Noms d'outils/modules OSINT : ne doivent jamais être scannés comme pseudos.
    'dehashed', 'hunter', 'sherlock', 'epieos', 'wayback', 'whois', 'shodan',
    'otx', 'typosquat', 'subdomains', 'holehe', 'maigret', 'pipl', 'hibp',
    'dorking', 'reverse', 'github', 'gitlab',
}


def _extract_identifiers(text: str) -> dict:
    """Identifiants réels d'un objectif en langage naturel, par type + priorité."""
    text = text or ''
    def uniq(seq):
        seen, out = set(), []
        for x in seq:
            k = x.lower()
            if k not in seen:
                seen.add(k); out.append(x)
        return out

    emails = re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', text)
    rest = re.sub(r'[\w.+-]+@[\w-]+\.[\w.-]+', ' ', text)  # retire les emails
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', rest)
    phones = re.findall(r'(?<!\w)(?:\+\d[\d ().-]{7,}\d|0[1-9](?:[ .-]?\d{2}){4})', rest)
    domains = [d for d in re.findall(r'\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b', rest, re.I)
               if not re.match(r'^\d+$', d.split('.')[0])]
    dom_low = {d.lower() for d in domains}
    # Capture les mots ENTIERS (accents inclus) pour que le filtre de mots
    # vides fonctionne (« derrière » ne doit pas devenir le pseudo « derri »).
    usernames = [
        w for w in re.findall(r'[A-Za-zÀ-ÿ0-9_](?:[A-Za-zÀ-ÿ0-9_.\-]{2,29})', rest)
        if w.lower() not in _STOPWORDS and '.' not in w and not w.isdigit()
        and w.lower() not in dom_low and re.search(r'[A-Za-z0-9]', w)
        # rejette les mots 100% alphabétiques accentués (mots français courants)
        and not re.search(r'[À-ÿ]', w)
    ]
    return {'email': uniq(emails), 'ip': uniq(ips), 'phone': uniq(phones),
            'domain': uniq(domains), 'username': uniq(usernames)}


def _fallback_plan(objective: str, previous_steps: list, deep: bool = False) -> dict:
    """Plan local si Groq indisponible — cible le VRAI identifiant, pas les mots vides.

    ``deep`` : mode approfondi -> inclut dehashed (fuites de données, plus lent).
    """
    done = {s.get('action') for s in previous_steps}
    ids = _extract_identifiers(objective)

    for e in ids['email']:
        if 'email' not in done:
            return {'action': 'email', 'params': {'email': e}, 'reason': 'Analyse email'}
        if 'epieos' not in done:
            return {'action': 'epieos', 'params': {'email': e}, 'reason': 'Enrichissement email'}
        if deep and 'dehashed' not in done:
            return {'action': 'dehashed', 'params': {'email': e}, 'reason': 'Fuites de données (approfondi)'}
    for ip in ids['ip']:
        if 'ip' not in done:
            return {'action': 'ip', 'params': {'ip': ip}, 'reason': 'Géoloc & Shodan'}
        if 'reverse_ip' not in done:
            return {'action': 'reverse_ip', 'params': {'ip': ip}, 'reason': 'Domaines même IP'}
    for ph in ids['phone']:
        if 'phone' not in done:
            return {'action': 'phone', 'params': {'phone': ph}, 'reason': 'Analyse téléphone'}
    for d in ids['domain']:
        for mod, reason in (('whois', 'WHOIS domaine'), ('subdomains', 'Sous-domaines exposés'),
                            ('site', 'DNS / HTTP / sécurité'), ('hunter', 'Emails professionnels'),
                            ('typosquat', 'Domaines sosies'), ('wayback', 'Historique web')):
            if mod not in done:
                return {'action': mod, 'params': {'domain': d}, 'reason': reason}
    for u in ids['username']:
        if 'sherlock' not in done:
            return {'action': 'sherlock', 'params': {'pseudo': u}, 'reason': 'Recherche pseudo'}
        if deep and 'dehashed' not in done:
            return {'action': 'dehashed', 'params': {'pseudo': u}, 'reason': 'Fuites pseudo (approfondi)'}

    return {'action': 'TERMINE',
            'summary': 'Enquête terminée. Ouvrez le graphe pour explorer les corrélations.'}


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


def execute_module(module: str, target: str, user_id: int, options: dict,
                   investigation_id: int, timeout: int = MODULE_TIMEOUT):
    """Exécute un module synchrone et enregistre le scan."""
    from app import SCAN_FUNCTIONS, fernet
    from services.correlation import process_scan_correlations

    func = SCAN_FUNCTIONS.get(module)
    if not func:
        return {'Erreur': f'Module {module} inconnu'}, None

    opts = dict(options or {})
    opts['_root_entity_id'] = opts.get('_root_entity_id')

    result = _run_module_with_timeout(func, target, opts, opts.get('_app'), timeout=timeout)

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


def _run_investigation_loop_inner(investigation_id: int, user_id: int, app, socketio, fernet, deep: bool = False):
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

            plan = plan_next_action(objective, steps, step_num, deep)
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

            if not _is_concrete_target(target):
                # Cible descriptive inventée par le LLM -> on n'exécute pas
                # (sinon on crée une entité bidon dans le graphe).
                steps.append({
                    'step': step_num, 'action': module, 'target': target,
                    'reason': reason, 'status': 'skipped', 'scan_id': None,
                    'summary': 'Cible non concrète — étape ignorée',
                })
                inv.steps_json = json.dumps(steps, ensure_ascii=False)
                db.session.commit()
                _emit(socketio, 'investigation_step', {
                    'investigation_id': investigation_id, 'step': step_num,
                    'phase': 'done', 'status': 'done', 'action': module, 'target': target,
                    'message': f'⏭️ {module} ignoré (cible non concrète)',
                }, user_id)
                continue

            # Anti-hallucination : la cible doit être FONDÉE sur des données réelles
            # (objectif ou entités déjà trouvées). Bloque les valeurs inventées par
            # le LLM (« pourdehashed.fr », « dehashed.com »…) et les mots courants.
            if not _is_grounded_target(target, objective,
                                       _grounded_values(objective, inv.root_entity_id, user_id)):
                steps.append({
                    'step': step_num, 'action': module, 'target': target,
                    'reason': reason, 'status': 'skipped', 'scan_id': None,
                    'summary': 'Cible non fondée (absente des données réelles) — étape ignorée',
                })
                inv.steps_json = json.dumps(steps, ensure_ascii=False)
                db.session.commit()
                _emit(socketio, 'investigation_step', {
                    'investigation_id': investigation_id, 'step': step_num,
                    'phase': 'done', 'status': 'done', 'action': module, 'target': target,
                    'message': f'⏭️ {module} ignoré (cible non fondée)',
                }, user_id)
                continue

            # dehashed : lent -> seulement en mode approfondi (avec timeout long).
            if module == 'dehashed' and not deep:
                steps.append({
                    'step': step_num, 'action': module, 'target': target,
                    'reason': reason, 'status': 'skipped', 'scan_id': None,
                    'summary': 'Ignoré (mode rapide — cocher « approfondie » pour les fuites)',
                })
                inv.steps_json = json.dumps(steps, ensure_ascii=False)
                db.session.commit()
                _emit(socketio, 'investigation_step', {
                    'investigation_id': investigation_id, 'step': step_num,
                    'phase': 'done', 'status': 'done', 'action': module, 'target': target,
                    'message': '⏭️ dehashed ignoré (mode rapide)',
                }, user_id)
                continue

            step_timeout = (int(os.environ.get('DEHASHED_DEEP_TIMEOUT', '90'))
                            if module == 'dehashed' else MODULE_TIMEOUT)

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
                module, target, user_id, options, investigation_id, timeout=step_timeout,
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


def run_investigation_loop(investigation_id: int, user_id: int, app, socketio, fernet, deep: bool = False):
    """Enveloppe bulletproof : toute exception finalise l'enquête + émet
    ``investigation_done`` (évite le statut bloqué à « running » = spinner infini)."""
    try:
        _run_investigation_loop_inner(investigation_id, user_id, app, socketio, fernet, deep)
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


def start_investigation(user_id: int, query: str, app, socketio, fernet, deep: bool = False) -> int:
    """Crée une enquête et lance le thread agent. ``deep`` = mode approfondi."""
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
        args=(inv_id, user_id, app, socketio, fernet, deep),
        daemon=True,
        name=f'investigation-{inv_id}',
    )
    t.start()
    return inv_id
