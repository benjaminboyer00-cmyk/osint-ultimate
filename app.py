#!/usr/bin/env python3
"""
OSINT ULTIMATE V5.0 – Auth, Supabase PostgreSQL, Scans async, IA Groq, PWA
"""
import os, re, json, socket, hashlib, threading, random
from datetime import datetime
from urllib.parse import urlparse
from io import BytesIO

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import requests
import whois
import dns.resolver
from bs4 import BeautifulSoup
import phonenumbers
from phonenumbers import carrier, geocoder
from phonenumbers import timezone as ph_timezone
from PIL import Image
from PIL.ExifTags import TAGS
import docx
from pypdf import PdfReader
from cryptography.fernet import Fernet
from sqlalchemy import text as sa_text
from flask import (Flask, render_template, request, jsonify,
                   redirect, url_for, flash, send_file, abort)
from flask_socketio import SocketIO
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix

from config import build_config
from extensions import db, login_manager, migrate
from models import User, Scan

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.config.update(build_config())
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db.init_app(app)
migrate.init_app(app, db)
login_manager.init_app(app)
login_manager.login_view = 'login'

socketio = SocketIO(app, cors_allowed_origins='*')

# ---------- ENCRYPTION ----------
_fenv = os.environ.get('FERNET_KEY')
if _fenv:
    _fkey = _fenv.encode() if isinstance(_fenv, str) else _fenv
else:
    _fkey = Fernet.generate_key()
fernet = Fernet(_fkey)

# ---------- HTTP HELPERS ----------
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
]
_proxy_env = os.environ.get('PROXY_LIST', '')
PROXIES = [p.strip() for p in _proxy_env.split(',') if p.strip()]

def make_http_session():
    s = requests.Session()
    s.headers.update({'User-Agent': random.choice(USER_AGENTS)})
    if PROXIES:
        proxy = random.choice(PROXIES)
        s.proxies = {'http': proxy, 'https': proxy}
    return s

def safe_get(url, timeout=15, **kwargs):
    try:
        s = make_http_session()
        return s.get(url, timeout=timeout, verify=False, **kwargs)
    except Exception:
        return None

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

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email    = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        if not all([username, email, password]):
            flash('Tous les champs sont requis.', 'error')
            return redirect(url_for('register'))
        if User.query.filter_by(username=username).first():
            flash("Nom d'utilisateur déjà pris.", 'error')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Email déjà enregistré.', 'error')
            return redirect(url_for('register'))
        user = User(username=username, email=email)
        user.set_password(password)
        user.ensure_api_token()
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for('views.expert'))
    return render_template('auth.html', mode='register')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            user.last_login = datetime.utcnow()
            db.session.commit()
            login_user(user, remember=True)
            return redirect(url_for('views.expert'))
        flash('Identifiants invalides. Sur Hugging Face, recréez un compte après chaque redéploiement si la base n\'est pas persistante.', 'error')
    return render_template('auth.html', mode='login')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('views.expert'))

# ============================================================
#  SCAN FUNCTIONS
# ============================================================

def scan_site(target, options=None):
    domain = target.strip()
    if domain.startswith('http'):
        domain = urlparse(domain).netloc
    domain = re.sub(r'^www\.', '', domain).split('/')[0]
    results = {}
    http_resp = None

    # ── WHOIS (RDAP + repli, timeouts courts) ──
    try:
        from connectors.whois_domain import lookup as whois_lookup
        results['WHOIS'] = whois_lookup(domain, options)
    except Exception as e:
        results['WHOIS'] = {'Erreur': str(e)}

    # ── DNS ──
    dns_rec = {}
    for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']:
        try:
            dns_rec[rtype] = [str(r) for r in dns.resolver.resolve(domain, rtype)]
        except Exception:
            dns_rec[rtype] = []
    results['DNS'] = dns_rec

    # ── HTTP + IP + Geo ──
    try:
        http_resp = safe_get(f'https://{domain}', options=options) or safe_get(f'http://{domain}', options=options)
        if not http_resp or (http_resp.status_code in (403, 503, 520, 521, 522, 523)):
            from connectors.scraper_fallback import fetch_url_protected
            cf = fetch_url_protected(f'https://{domain}', options)
            if cf and cf.text:
                http_resp = cf
                results['_http_via'] = 'cloudscraper'
        if http_resp:
            results['HTTP'] = {
                'Statut':   http_resp.status_code,
                'URL finale': http_resp.url,
            }
            results['Headers HTTP'] = dict(http_resp.headers)
        ip = socket.gethostbyname(domain)
        results['IP'] = ip
        geo = safe_get(f'http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,proxy,hosting')
        if geo and geo.status_code == 200:
            g = geo.json()
            if g.get('status') == 'success':
                results['Géolocalisation'] = {
                    'Pays': g.get('country'), 'Région': g.get('regionName'),
                    'Ville': g.get('city'),   'FAI': g.get('isp'),
                    'Organisation': g.get('org'), 'AS': g.get('as'),
                    'Lat': g.get('lat'),      'Lon': g.get('lon'),
                    'Fuseau': g.get('timezone'),
                    'Proxy/VPN': 'Oui ⚠️' if g.get('proxy') else 'Non',
                    'Hébergement': 'Oui' if g.get('hosting') else 'Non',
                }
    except Exception as e:
        results['Réseau'] = str(e)

    # ── SSL ──
    try:
        import ssl as _ssl
        ctx = _ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as ss:
            ss.settimeout(5); ss.connect((domain, 443))
            cert = ss.getpeercert()
            results['SSL/TLS'] = {
                'Valide jusqu\'au': cert.get('notAfter', 'N/A'),
                'Émetteur': dict(x[0] for x in cert.get('issuer', [])).get('organizationName', 'N/A'),
                'Sujet':    dict(x[0] for x in cert.get('subject', [])).get('commonName', 'N/A'),
            }
    except Exception as e:
        results['SSL/TLS'] = {'Erreur': str(e)}

    # ── Ports (socket fallback, nmap si dispo) ──
    common = {21:'FTP',22:'SSH',25:'SMTP',80:'HTTP',110:'POP3',
              143:'IMAP',443:'HTTPS',3306:'MySQL',3389:'RDP',
              5432:'PostgreSQL',8080:'HTTP-Alt',8443:'HTTPS-Alt'}
    try:
        import nmap
        nm = nmap.PortScanner()
        nm.scan(domain, ','.join(str(p) for p in common.keys()), arguments='-T4 --open')
        open_ports = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port, info in nm[host][proto].items():
                    if info.get('state') == 'open':
                        svc = info.get('name', common.get(port, ''))
                        open_ports.append(f'{port}/{proto} ({svc})')
        results['Ports ouverts'] = open_ports or ['Aucun port ouvert détecté']
    except Exception:
        open_ports = []
        for port, svc in list(common.items())[:8]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                if s.connect_ex((domain, port)) == 0:
                    open_ports.append(f'{port} ({svc})')
                s.close()
            except Exception:
                pass
        results['Ports ouverts'] = open_ports or ['Aucun détecté']

    # ── Technologies ──
    techs = {}
    if http_resp:
        try:
            soup = BeautifulSoup(http_resp.text, 'html.parser')
            for h in ('Server', 'X-Powered-By', 'X-Generator'):
                v = http_resp.headers.get(h)
                if v: techs[h] = v
            gen = soup.find('meta', attrs={'name': 'generator'})
            if gen and gen.get('content'): techs['CMS (meta)'] = gen['content']
            ct = http_resp.text
            if 'wp-content' in ct or 'wp-includes' in ct: techs['CMS'] = 'WordPress'
            elif 'Joomla' in ct:  techs['CMS'] = 'Joomla'
            elif 'Drupal' in ct:  techs['CMS'] = 'Drupal'
            elif 'shopify' in ct.lower(): techs['E-commerce'] = 'Shopify'
            if 'react' in ct.lower():   techs['Frontend'] = 'React'
            elif 'vue.js' in ct.lower(): techs['Frontend'] = 'Vue.js'
            elif 'angular' in ct.lower(): techs['Frontend'] = 'Angular'
            for path, label in [('/robots.txt','robots.txt'),('/sitemap.xml','sitemap.xml')]:
                r = safe_get(f'https://{domain}{path}')
                techs[label] = 'Accessible ✓' if r and r.status_code == 200 else 'Absent'
        except Exception as e:
            techs['Erreur analyse'] = str(e)
    results['Technologies'] = techs

    # ── Security headers ──
    if http_resp:
        hdrs = ['Strict-Transport-Security','Content-Security-Policy',
                'X-Frame-Options','X-Content-Type-Options',
                'Referrer-Policy','Permissions-Policy']
        results['En-têtes sécurité'] = {
            h: (http_resp.headers.get(h) or '❌ Absent') for h in hdrs
        }

    # ── Wayback Machine ──
    try:
        wb = safe_get(f'https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit=5&fl=timestamp,original&collapse=urlkey')
        if wb and wb.status_code == 200:
            data = wb.json()
            if len(data) > 1:
                results['Wayback Machine'] = [
                    {'Date': r[0][:8], 'URL': r[1]} for r in data[1:]
                ]
    except Exception:
        pass

    return results


def scan_email(email, options=None):
    email = email.strip().lower()
    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        return {'Erreur': 'Format invalide'}

    domain = email.split('@')[1]
    results = {'Format': 'Valide ✓', 'Domaine': domain}

    # MX
    try:
        mx = dns.resolver.resolve(domain, 'MX')
        results['MX'] = sorted([str(r.exchange).rstrip('.') for r in mx])
    except Exception as e:
        results['MX'] = f'Absent ({e})'

    # SPF
    try:
        txt = dns.resolver.resolve(domain, 'TXT')
        spf = [str(r).strip('"') for r in txt if 'v=spf1' in str(r)]
        results['SPF'] = spf if spf else 'Absent'
    except Exception:
        results['SPF'] = 'Absent'

    # DMARC
    try:
        dm = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        results['DMARC'] = [str(r).strip('"') for r in dm]
    except Exception:
        results['DMARC'] = 'Absent'

    # DKIM selectors communs
    dkim_found = []
    for sel in ['default','google','mail','dkim','k1','s1','s2','smtp','selector1','selector2']:
        try:
            dns.resolver.resolve(f'{sel}._domainkey.{domain}', 'TXT')
            dkim_found.append(sel)
        except Exception:
            pass
    results['DKIM (sélecteurs trouvés)'] = dkim_found or 'Aucun sélecteur courant détecté'

    try:
        from connectors.whois_domain import lookup as whois_lookup
        results['Domaine WHOIS'] = whois_lookup(domain, options)
    except Exception:
        pass

    # SMTP check
    try:
        import smtplib
        mx_host = results['MX'][0] if isinstance(results['MX'], list) and results['MX'] else None
        if mx_host:
            with smtplib.SMTP(timeout=8) as smtp:
                smtp.connect(mx_host, 25)
                smtp.helo('verify.osint.local')
                smtp.mail('probe@osint.local')
                code, _ = smtp.rcpt(email)
                results['SMTP'] = '✓ Boîte existe (250)' if code == 250 else f'Code SMTP: {code}'
        else:
            results['SMTP'] = 'MX absent – vérification impossible'
    except Exception as e:
        results['SMTP'] = f'Non vérifié: {e}'

    # Gravatar
    em_hash = hashlib.md5(email.encode()).hexdigest()
    grav = safe_get(f'https://www.gravatar.com/{em_hash}.json')
    if grav and grav.status_code == 200:
        results['Gravatar'] = 'Existe ✓'
        try:
            e = grav.json().get('entry', [{}])[0]
            results['Gravatar Info'] = {
                'Nom': e.get('displayName',''),
                'Avatar': f'https://www.gravatar.com/avatar/{em_hash}?s=200',
            }
        except Exception:
            pass
    else:
        results['Gravatar'] = 'Non trouvé'

    # HIBP (optionnel)
    hibp_key = (options or {}).get('_hibp_key') or os.environ.get('HIBP_API_KEY', '')
    if hibp_key:
        r = safe_get(f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}',
                     headers={'hibp-api-key': hibp_key, 'User-Agent': 'OSINT-Ultimate'})
        if r and r.status_code == 200:
            results['Fuites (HIBP)'] = [b['Name'] for b in r.json()]
        elif r and r.status_code == 404:
            results['Fuites (HIBP)'] = 'Aucune fuite connue ✓'
    else:
        results['Fuites (HIBP)'] = 'Clé HIBP_API_KEY non configurée'

    return results


def scan_phone(phone_str, options=None):
    results = {}
    phone = None
    for region in [None, 'FR', 'US', 'GB']:
        try:
            phone = phonenumbers.parse(phone_str, region)
            break
        except Exception:
            continue
    if phone is None:
        return {'Erreur': 'Numéro impossible à analyser'}

    try:
        valid    = phonenumbers.is_valid_number(phone)
        possible = phonenumbers.is_possible_number(phone)
        results['Valide']              = '✓ Oui' if valid else 'Non'
        results['Possible']            = 'Oui' if possible else 'Non'
        results['Pays']                = geocoder.description_for_number(phone, 'fr') or 'Inconnu'
        results['Opérateur']           = carrier.name_for_number(phone, 'fr') or 'Inconnu'
        results['Fuseaux horaires']    = list(ph_timezone.time_zones_for_number(phone))
        results['Format international'] = phonenumbers.format_number(phone, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        results['Format national']     = phonenumbers.format_number(phone, phonenumbers.PhoneNumberFormat.NATIONAL)
        results['Format E.164']        = phonenumbers.format_number(phone, phonenumbers.PhoneNumberFormat.E164)
        results['Indicatif pays']      = f'+{phone.country_code}'
        type_map = {
            phonenumbers.PhoneNumberType.MOBILE:             'Mobile 📱',
            phonenumbers.PhoneNumberType.FIXED_LINE:         'Fixe ☎️',
            phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: 'Fixe ou Mobile',
            phonenumbers.PhoneNumberType.TOLL_FREE:          'Numéro gratuit',
            phonenumbers.PhoneNumberType.PREMIUM_RATE:       'Surtaxé ⚠️',
            phonenumbers.PhoneNumberType.VOIP:               'VoIP 💻',
        }
        results['Type'] = type_map.get(phonenumbers.number_type(phone), 'Inconnu')
    except Exception as e:
        results['Erreur analyse'] = str(e)

    # Numverify si clé dispo
    nv_key = os.environ.get('NUMVERIFY_KEY')
    if nv_key and results.get('Format E.164'):
        nv = safe_get(f'http://apilayer.net/api/validate?access_key={nv_key}&number={results["Format E.164"]}')
        if nv and nv.status_code == 200:
            d = nv.json()
            results['Numverify'] = {
                'Valide': d.get('valid'),
                'Ligne': d.get('line_type'),
                'Opérateur': d.get('carrier'),
            }
    return results


def scan_ip(ip, options=None):
    ip = ip.strip()
    results = {}

    # Geolocalisation
    try:
        r = safe_get(f'http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting,query')
        if r and r.status_code == 200:
            g = r.json()
            if g.get('status') == 'success':
                results['Géolocalisation'] = {
                    'IP': g.get('query'), 'Pays': g.get('country'),
                    'Région': g.get('regionName'), 'Ville': g.get('city'),
                    'CP': g.get('zip'), 'FAI': g.get('isp'),
                    'Organisation': g.get('org'), 'AS': g.get('as'),
                    'Fuseau': g.get('timezone'),
                    'Lat': g.get('lat'), 'Lon': g.get('lon'),
                    'Mobile': 'Oui' if g.get('mobile') else 'Non',
                    'Proxy/VPN': '⚠️ Oui' if g.get('proxy') else 'Non',
                    'Hébergement': 'Oui' if g.get('hosting') else 'Non',
                }
    except Exception as e:
        results['Géolocalisation'] = {'Erreur': str(e)}

    # Reverse DNS
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        results['Reverse DNS'] = hostname
    except Exception:
        results['Reverse DNS'] = 'Aucun enregistrement PTR'

    # Scan ports
    common = {21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',
              80:'HTTP',110:'POP3',143:'IMAP',443:'HTTPS',
              3306:'MySQL',3389:'RDP',5432:'PostgreSQL',
              6379:'Redis',8080:'HTTP-Alt',8443:'HTTPS-Alt',27017:'MongoDB'}
    try:
        import nmap
        nm = nmap.PortScanner()
        nm.scan(ip, ','.join(str(p) for p in common.keys()), arguments='-T3 --open')
        open_ports = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port, info in nm[host][proto].items():
                    if info.get('state') == 'open':
                        open_ports.append(f"{port}/{proto} ({info.get('name', common.get(port,''))})")
        results['Ports ouverts (nmap)'] = open_ports or ['Aucun']
    except Exception:
        open_ports = []
        for port, svc in list(common.items())[:12]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.8)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(f'{port} ({svc})')
                s.close()
            except Exception:
                pass
        results['Ports ouverts'] = open_ports or ['Aucun détecté']

    # Shodan (clé globale ou utilisateur via options) + cache
    shodan_key = (options or {}).get('_shodan_key') or os.environ.get('SHODAN_API_KEY')
    if shodan_key:
        from services.cache import get_cached, set_cached, get_ttl_hours
        cached_sh = get_cached('shodan', ip)
        if cached_sh:
            results['Shodan'] = cached_sh
            results['Shodan']['_cached'] = True
        sh = None if cached_sh else safe_get(
            f'https://api.shodan.io/shodan/host/{ip}?key={shodan_key}', options=options
        )
        if sh and sh.status_code == 200:
            d = sh.json()
            results['Shodan'] = {
                'Hostnames': d.get('hostnames', []),
                'Domaines': d.get('domains', []),
                'OS': d.get('os', 'N/A'),
                'Ports': d.get('ports', []),
                'Tags': d.get('tags', []),
                'Organisation': d.get('org', 'N/A'),
                'ISP': d.get('isp', 'N/A'),
                'CVE (top 10)': list(d.get('vulns', {}).keys())[:10],
            }
            banners = []
            for item in (d.get('data') or [])[:8]:
                banners.append({
                    'Port': item.get('port'),
                    'Service': item.get('product') or item.get('_shodan', {}).get('module', ''),
                    'Bannière': (item.get('data') or '')[:200],
                })
            if banners:
                results['Shodan']['Bannières'] = banners
            if d.get('vulns'):
                results['Shodan']['Vulnérabilités'] = [
                    {'CVE': k, 'CVSS': v.get('cvss', 'N/A')}
                    for k, v in list(d.get('vulns', {}).items())[:10]
                    if isinstance(v, dict)
                ]
            set_cached('shodan', ip, results['Shodan'], ttl_hours=get_ttl_hours('shodan'))
        elif sh and sh.status_code == 401:
            results['Shodan'] = {'Erreur': 'Clé Shodan invalide'}
        elif sh and sh.status_code == 429:
            results['Shodan'] = {'Erreur': 'Quota Shodan dépassé'}

    return results


def scan_sherlock(username, options=None):
    """Recherche multi-plateformes (Sherlock CLI ou repli scan_pseudo)."""
    from connectors.sherlock_scan import search
    return search(username, fallback_fn=scan_pseudo)


def scan_pseudo(username, options=None):
    username = username.strip()
    platforms = {
        'GitHub':     ('https://github.com/{u}',            ['Not Found','404','Page not found']),
        'Instagram':  ('https://www.instagram.com/{u}/',    ['Page Not Found','Sorry, this page']),
        'Twitter/X':  ('https://twitter.com/{u}',           ["This account doesn","doesn't exist",'Page Not Found']),
        'TikTok':     ('https://www.tiktok.com/@{u}',       ["Couldn't find this account",'Page Not Found']),
        'Reddit':     ('https://www.reddit.com/user/{u}',   ['page not found','Sorry, nobody on Reddit']),
        'YouTube':    ('https://www.youtube.com/@{u}',      ['404','This page is not available']),
        'Twitch':     ('https://www.twitch.tv/{u}',         ["Sorry. Unless you've been", '404']),
        'Pinterest':  ('https://www.pinterest.com/{u}/',    ["didn't find",'Page Not Found']),
        'Tumblr':     ('https://{u}.tumblr.com',            ["There's nothing here",'404']),
        'Medium':     ('https://medium.com/@{u}',           ['404','Page Not Found']),
        'GitLab':     ('https://gitlab.com/{u}',            ['404','The page you']),
        'Mastodon':   ('https://mastodon.social/@{u}',      ['The page you','404']),
        'Keybase':    ('https://keybase.io/{u}',            ['404','Not found']),
        'Dev.to':     ('https://dev.to/{u}',                ['404','Page not found']),
        'HackerNews': ('https://news.ycombinator.com/user?id={u}', ['No such user','Unknown']),
        'Steam':      ('https://steamcommunity.com/id/{u}', ['The specified profile could not be found']),
        'Patreon':    ('https://www.patreon.com/{u}',       ['404','Page not found']),
        'Vimeo':      ('https://vimeo.com/{u}',             ["Sorry, we couldn",'404']),
        'SoundCloud': ('https://soundcloud.com/{u}',        ['404',"We can't find"]),
        'Flickr':     ('https://www.flickr.com/people/{u}/',['Page Not Found','404']),
    }
    results = {}

    def check(name, url_tpl, not_found):
        url = url_tpl.replace('{u}', username)
        try:
            r = safe_get(url, timeout=10, allow_redirects=True)
            if not r:
                results[name] = 'Timeout'
                return
            if r.status_code == 200:
                pl = r.text.lower()
                found = not any(m.lower() in pl for m in not_found)
                results[name] = '✓ Existe' if found else 'Non trouvé'
            elif r.status_code == 404:
                results[name] = 'Non trouvé'
            else:
                results[name] = f'Inconnu ({r.status_code})'
        except Exception:
            results[name] = 'Erreur'

    threads = [threading.Thread(target=check, args=(n, u, nf))
               for n, (u, nf) in platforms.items()]
    for t in threads: t.start()
    for t in threads: t.join(timeout=12)
    return results


def scan_instagram(username, options=None):
    username = username.strip().lstrip('@')
    results = {}
    headers = {
        'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/20A362 Instagram/301.0.0.34.109',
        'Accept': '*/*', 'Accept-Language': 'fr-FR,fr;q=0.9',
        'X-IG-App-ID': '936619743392459',
    }
    try:
        r = safe_get(f'https://www.instagram.com/api/v1/users/web_profile_info/?username={username}', headers=headers)
        if r and r.status_code == 200:
            user = r.json().get('data', {}).get('user', {})
            if user:
                results['Nom complet']  = user.get('full_name', '')
                results['Bio']          = user.get('biography', '')
                results['Followers']    = user.get('edge_followed_by', {}).get('count', 'N/A')
                results['Following']    = user.get('edge_follow', {}).get('count', 'N/A')
                results['Publications'] = user.get('edge_owner_to_timeline_media', {}).get('count', 'N/A')
                results['Vérifié']      = '✓ Oui' if user.get('is_verified') else 'Non'
                results['Privé']        = 'Oui' if user.get('is_private') else 'Non'
                results['Entreprise']   = 'Oui' if user.get('is_business_account') else 'Non'
                results['Site web']     = user.get('external_url', '')
                results['Catégorie']    = user.get('category_name', '')
                results['Avatar URL']   = user.get('profile_pic_url_hd', '')
                return results
    except Exception:
        pass

    # Fallback HTML
    try:
        r2 = safe_get(f'https://www.instagram.com/{username}/')
        if r2:
            if r2.status_code == 404:
                return {'Résultat': 'Compte non trouvé'}
            for pattern, key in [(r'"edge_followed_by":\{"count":(\d+)\}', 'Followers'),
                                  (r'"edge_follow":\{"count":(\d+)\}', 'Following'),
                                  (r'"edge_owner_to_timeline_media":\{"count":(\d+)\}', 'Publications')]:
                m = re.search(pattern, r2.text)
                if m: results[key] = int(m.group(1))
            results['Profil'] = f'https://www.instagram.com/{username}/'
            results['Note']   = 'Données partielles – Instagram limite le scraping non-authentifié'
    except Exception as e:
        results['Erreur'] = str(e)
    return results


def scan_twitter(username, options=None):
    username = username.strip().lstrip('@')
    results = {'Profil URL': f'https://twitter.com/{username}'}
    nitter_instances = [
        'https://nitter.privacydev.net', 'https://nitter.net', 'https://nitter.it',
    ]
    for instance in nitter_instances:
        try:
            r = safe_get(f'{instance}/{username}', timeout=8)
            if r and r.status_code == 200 and 'timeline' in r.text.lower():
                soup = BeautifulSoup(r.text, 'html.parser')
                for sel, key in [('.profile-card-fullname','Nom'), ('.profile-bio','Bio'),
                                  ('.profile-location','Localisation')]:
                    el = soup.select_one(sel)
                    if el: results[key] = el.text.strip()
                web_el = soup.select_one('.profile-website a')
                if web_el: results['Site web'] = web_el.get('href','')
                for stat, label in zip(soup.select('.profile-stat-num'),
                                       soup.select('.profile-stat-header')):
                    results[label.text.strip()] = stat.text.strip()
                verified = soup.select_one('.icon-ok')
                results['Vérifié'] = '✓ Oui' if verified else 'Non'
                results['Source'] = instance
                return results
        except Exception:
            continue
    results['Note'] = 'Twitter/X bloque le scraping. Vérifiez manuellement.'
    return results


def scan_tiktok(username, options=None):
    username = username.strip().lstrip('@')
    results = {}
    try:
        r = safe_get(f'https://www.tiktok.com/@{username}')
        if r and r.status_code == 200:
            m = re.search(r'<script id="SIGI_STATE"[^>]*>(.*?)</script>', r.text, re.DOTALL)
            if m:
                try:
                    data = json.loads(m.group(1))
                    ui = data.get('UserModule', {}).get('users', {}).get(username, {})
                    st = data.get('UserModule', {}).get('stats', {}).get(username, {})
                    if ui:
                        results['Nom']        = ui.get('nickname', '')
                        results['Bio']        = ui.get('signature', '')
                        results['Vérifié']    = '✓ Oui' if ui.get('verified') else 'Non'
                        results['Privé']      = 'Oui' if ui.get('privateAccount') else 'Non'
                        results['Région']     = ui.get('region', '')
                        results['Langue']     = ui.get('language', '')
                    if st:
                        results['Followers']  = st.get('followerCount', 'N/A')
                        results['Following']  = st.get('followingCount', 'N/A')
                        results['Likes']      = st.get('heartCount', 'N/A')
                        results['Vidéos']     = st.get('videoCount', 'N/A')
                    if ui: return results
                except Exception:
                    pass
            # JSON-LD fallback
            soup = BeautifulSoup(r.text, 'html.parser')
            ld = soup.find('script', type='application/ld+json')
            if ld:
                try:
                    d = json.loads(ld.string)
                    results['Nom']  = d.get('author', {}).get('name', 'N/A')
                    results['Desc'] = d.get('description', '')
                except Exception:
                    pass
            results['Profil']  = f'https://www.tiktok.com/@{username}'
            results['Statut HTTP'] = r.status_code
        elif r and r.status_code == 404:
            results['Résultat'] = 'Compte non trouvé'
    except Exception as e:
        results['Erreur'] = str(e)
    return results


def scan_github(username, options=None):
    username = username.strip()
    results = {}
    headers = {}
    gh_token = (options or {}).get('_github_key') or os.environ.get('GITHUB_TOKEN')
    if gh_token:
        headers['Authorization'] = f'token {gh_token}'
    try:
        r = safe_get(f'https://api.github.com/users/{username}', headers=headers)
        if r and r.status_code == 200:
            d = r.json()
            for k, v in [('Nom', 'name'), ('Bio', 'bio'), ('Localisation', 'location'),
                          ('Email', 'email'), ('Entreprise', 'company'), ('Blog', 'blog'),
                          ('Twitter', 'twitter_username'), ('Repos publics', 'public_repos'),
                          ('Gists publics', 'public_gists'), ('Followers', 'followers'),
                          ('Following', 'following'), ('Créé le', 'created_at'),
                          ('Dernière activité', 'updated_at'), ('Avatar', 'avatar_url'),
                          ('Profil', 'html_url')]:
                val = d.get(v, '')
                if val or val == 0: results[k] = val
            results['À recruter'] = 'Oui' if d.get('hireable') else 'Non précisé'
            # Repos récents
            rr = safe_get(f'https://api.github.com/users/{username}/repos?sort=updated&per_page=5', headers=headers)
            if rr and rr.status_code == 200:
                results['Repos récents'] = [{
                    'Nom': r2['name'], 'Stars': r2.get('stargazers_count', 0),
                    'Langue': r2.get('language', ''), 'URL': r2.get('html_url', ''),
                    'Description': (r2.get('description') or '')[:80],
                } for r2 in rr.json()[:5]]
        elif r and r.status_code == 404:
            results['Résultat'] = 'Utilisateur non trouvé'
        else:
            results['Erreur'] = f'API GitHub: HTTP {r.status_code if r else "N/A"}'
    except Exception as e:
        results['Erreur'] = str(e)
    return results


def scan_facebook(username, options=None):
    username = username.strip()
    results = {'Profil': f'https://www.facebook.com/{username}'}
    try:
        r = safe_get(f'https://www.facebook.com/{username}')
        if r and r.status_code == 200:
            soup = BeautifulSoup(r.text, 'html.parser')
            for prop, key in [('og:title','Nom'), ('og:description','Description'), ('og:image','Image')]:
                el = soup.find('meta', property=prop)
                if el: results[key] = el.get('content', '')
            title = soup.find('title')
            if title: results['Titre'] = title.text
        elif r and r.status_code == 404:
            results['Résultat'] = 'Page non trouvée'
        results['Note'] = 'Facebook restreint fortement le scraping non-authentifié'
    except Exception as e:
        results['Erreur'] = str(e)
    return results


def scan_linkedin(username, options=None):
    username = username.strip()
    results = {'Profil': f'https://www.linkedin.com/in/{username}/'}
    try:
        r = safe_get(f'https://www.linkedin.com/in/{username}/')
        if r:
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, 'html.parser')
                for prop, key in [('og:title','Nom'), ('og:description','Description'), ('og:image','Photo')]:
                    el = soup.find('meta', property=prop)
                    if el: results[key] = el.get('content', '')
            elif r.status_code == 404:
                results['Résultat'] = 'Profil non trouvé'
            elif r.status_code == 999:
                results['Note'] = 'LinkedIn bloque les requêtes automatisées (HTTP 999)'
            else:
                results['Status HTTP'] = r.status_code
    except Exception as e:
        results['Erreur'] = str(e)
    return results


def scan_snapchat(username, options=None):
    username = username.strip().lstrip('@')
    results = {}
    try:
        r = safe_get(f'https://www.snapchat.com/add/{username}')
        if r and r.status_code == 200 and username.lower() in r.text.lower():
            soup = BeautifulSoup(r.text, 'html.parser')
            for prop, key in [('og:title','Nom'), ('og:description','Description'), ('og:image','Photo')]:
                el = soup.find('meta', property=prop)
                if el: results[key] = el.get('content', '')
            results['Résultat'] = '✓ Compte existe'
            results['Lien Snapchat'] = f'snapchat://add/{username}'
            results['Profil'] = f'https://www.snapchat.com/add/{username}'
        else:
            results['Résultat'] = 'Compte non trouvé ou privé'
    except Exception as e:
        results['Erreur'] = str(e)
    return results


# ──────────────────────────────────────────
SCAN_FUNCTIONS = {
    'site': scan_site, 'email': scan_email, 'phone': scan_phone,
    'ip': scan_ip, 'pseudo': scan_pseudo, 'sherlock': scan_sherlock,
    'instagram': scan_instagram,
    'twitter': scan_twitter, 'tiktok': scan_tiktok, 'github': scan_github,
    'facebook': scan_facebook, 'linkedin': scan_linkedin, 'snapchat': scan_snapchat,
}
from scan_modules import EXTRA_SCAN_FUNCTIONS
SCAN_FUNCTIONS.update(EXTRA_SCAN_FUNCTIONS)

# ============================================================
#  ASYNC SCANS (thread dédié — fiable avec Gunicorn gevent)
# ============================================================
def run_scan_async(module, target, options=None, user_id=None, mode='expert', scheduled_scan_id=None):
    from services.scan_runner import dispatch_scan

    if isinstance(options, list):
        options = {'email_checks': options}
    options = options or {}

    if not SCAN_FUNCTIONS.get(module):
        return None

    scan = Scan(
        module=module, target=target, user_id=user_id, status='pending',
        mode=mode, scheduled_scan_id=scheduled_scan_id,
    )
    db.session.add(scan)
    db.session.commit()
    scan_id = scan.id

    # Stocker options pour le worker (root_entity_id, stealth, etc.)
    if options:
        scan.result_json = json.dumps({'_pending_options': options}, ensure_ascii=False)
        db.session.commit()

    dispatch_scan(scan_id, app, socketio, fernet)
    return scan_id


# ============================================================
#  ROUTES
# ============================================================
@app.route('/health')
def health():
    db_ok = False
    try:
        db.session.execute(sa_text('SELECT 1'))
        db_ok = True
    except Exception:
        pass
    celery_on = False
    try:
        from services.task_queue import use_celery
        celery_on = use_celery()
    except Exception:
        pass
    return jsonify({
        'status': 'ok' if db_ok else 'degraded',
        'version': app.config.get('APP_VERSION', '5.2'),
        'database': 'connected' if db_ok else 'error',
        'celery': 'enabled' if celery_on else 'thread',
    }), 200 if db_ok else 503


@app.route('/scan', methods=['POST'])
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
    if not target:
        return jsonify({'error': 'Cible manquante'}), 400
    if module not in SCAN_FUNCTIONS:
        return jsonify({'error': f'Module inconnu: {module}'}), 400
    user_id = current_user.is_authenticated and current_user.id or None
    scan_id = run_scan_async(module, target, options, user_id, mode=mode)
    if scan_id:
        return jsonify({'scan_id': scan_id, 'status': 'started', 'module': module})
    return jsonify({'error': 'Échec du lancement'}), 500


@app.route('/scan/<int:scan_id>/retry-timeouts', methods=['POST'])
@login_required
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
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({'error': 'Scan non trouvé'}), 404
    if scan.user_id:
        if not current_user.is_authenticated:
            return jsonify({'error': 'Connexion requise pour ce scan'}), 401
        if scan.user_id != current_user.id:
            return jsonify({'error': 'Accès refusé'}), 403
    elif scan.mode != 'express' and not current_user.is_authenticated:
        return jsonify({'error': 'Connexion requise'}), 401
    if scan.status == 'completed':
        out = json.loads(scan.result_json)
        if scan.ai_summary:
            out['_ai_summary'] = scan.ai_summary
        return jsonify(out)
    return jsonify({'status': scan.status})


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

    summary = summarize_osint_with_groq(text)
    if summary.startswith('Résumé IA indisponible'):
        return jsonify({'error': summary}), 500
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


from routes.views import views_bp
from routes.api_v1 import api_bp
app.register_blueprint(views_bp)
app.register_blueprint(api_bp, url_prefix='/api/v1')

with app.app_context():
    try:
        from services.scheduler import start_scheduler
        start_scheduler(app)
    except Exception as sched_err:
        app.logger.warning('Scheduler: %s', sched_err)


if __name__ == '__main__':
    init_database()
    socketio.run(app, debug=False, host='0.0.0.0',
                 port=int(os.environ.get('PORT', 5000)))
