#!/usr/bin/env python3
"""
OSINT ULTIMATE V3.0 – Full Async, Auth, DB, Reports, PWA
"""
import os, re, json, socket, hashlib, threading, queue, random
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
import PyPDF2
from cryptography.fernet import Fernet
from flask import (Flask, render_template, request, jsonify,
                   redirect, url_for, flash, send_file, abort)
from flask_socketio import SocketIO
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                         login_required, current_user)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-me-' + os.urandom(16).hex())
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///osint.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

socketio = SocketIO(app, cors_allowed_origins='*')
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

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

# ---------- MODELS ----------
class User(UserMixin, db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80), unique=True, nullable=False)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    api_keys_enc  = db.Column(db.Text)

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)

    def get_api_keys(self):
        if self.api_keys_enc:
            try:
                return json.loads(fernet.decrypt(self.api_keys_enc.encode()).decode())
            except Exception:
                return {}
        return {}

    def set_api_keys(self, d):
        self.api_keys_enc = fernet.encrypt(json.dumps(d).encode()).decode()


class Scan(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    module      = db.Column(db.String(50))
    target      = db.Column(db.String(500))
    result_json = db.Column(db.Text)
    timestamp   = db.Column(db.DateTime, default=datetime.utcnow)
    status      = db.Column(db.String(20), default='pending')


with app.app_context():
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
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for('index'))
    return render_template('auth.html', mode='register')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username', '')).first()
        if user and user.check_password(request.form.get('password', '')):
            login_user(user)
            return redirect(url_for('index'))
        flash('Identifiants invalides.', 'error')
    return render_template('auth.html', mode='login')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

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

    # ── WHOIS ──
    try:
        w = whois.whois(domain)
        cd = w.creation_date;  cd = cd[0] if isinstance(cd, list) else cd
        ed = w.expiration_date; ed = ed[0] if isinstance(ed, list) else ed
        results['WHOIS'] = {
            'Registrar':   str(w.registrar  or 'N/A'),
            'Création':    str(cd  or 'N/A'),
            'Expiration':  str(ed  or 'N/A'),
            'Pays':        str(w.country    or 'N/A'),
            'Statut':      str(w.status     or 'N/A'),
        }
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
        http_resp = safe_get(f'https://{domain}') or safe_get(f'http://{domain}')
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

    # WHOIS domaine
    try:
        w = whois.whois(domain)
        cd = w.creation_date; cd = cd[0] if isinstance(cd, list) else cd
        results['Domaine WHOIS'] = {
            'Registrar': str(w.registrar or 'N/A'),
            'Création': str(cd or 'N/A'),
        }
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
    hibp_key = os.environ.get('HIBP_API_KEY', '')
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

    # Shodan (si clé)
    shodan_key = os.environ.get('SHODAN_API_KEY')
    if shodan_key:
        sh = safe_get(f'https://api.shodan.io/shodan/host/{ip}?key={shodan_key}')
        if sh and sh.status_code == 200:
            d = sh.json()
            results['Shodan'] = {
                'Hostnames': d.get('hostnames', []),
                'Domaines': d.get('domains', []),
                'OS': d.get('os', 'N/A'),
                'Ports': d.get('ports', []),
                'Tags': d.get('tags', []),
                'CVE (top 10)': list(d.get('vulns', {}).keys())[:10],
            }

    return results


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
    gh_token = os.environ.get('GITHUB_TOKEN')
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
    'ip': scan_ip, 'pseudo': scan_pseudo, 'instagram': scan_instagram,
    'twitter': scan_twitter, 'tiktok': scan_tiktok, 'github': scan_github,
    'facebook': scan_facebook, 'linkedin': scan_linkedin, 'snapchat': scan_snapchat,
}

# ============================================================
#  ASYNC WORKER
# ============================================================
scan_queue = queue.Queue()

def worker():
    while True:
        task = scan_queue.get()
        if task is None:
            break
        scan_id, func, args, kwargs = task
        with app.app_context():
            scan = db.session.get(Scan, scan_id)
            scan.status = 'running'
            db.session.commit()
            try:
                result = func(*args, **kwargs)
                scan.result_json = json.dumps(result, ensure_ascii=False, default=str)
                scan.status = 'completed'
                db.session.commit()
                socketio.emit('scan_done', {'scan_id': scan_id, 'result': result})
            except Exception as e:
                scan.result_json = json.dumps({'error': str(e)}, ensure_ascii=False)
                scan.status = 'completed'
                db.session.commit()
                socketio.emit('scan_error', {'scan_id': scan_id, 'error': str(e)})
        scan_queue.task_done()

threading.Thread(target=worker, daemon=True).start()


def run_scan_async(module, target, options=None, user_id=None):
    scan = Scan(module=module, target=target, user_id=user_id, status='pending')
    db.session.add(scan)
    db.session.commit()
    scan_id = scan.id
    func = SCAN_FUNCTIONS.get(module)
    if not func:
        return None
    scan_queue.put((scan_id, func, (target,), {'options': options}))
    return scan_id


# ============================================================
#  ROUTES
# ============================================================
@app.route('/')
def index():
    return render_template('index.html',
        authenticated=current_user.is_authenticated,
        username=current_user.username if current_user.is_authenticated else None)


@app.route('/scan', methods=['POST'])
def scan_start():
    data = request.json or {}
    module = data.get('module', '')
    target = data.get('target', '').strip()
    options = data.get('options', [])
    if not target:
        return jsonify({'error': 'Cible manquante'}), 400
    if module not in SCAN_FUNCTIONS:
        return jsonify({'error': f'Module inconnu: {module}'}), 400
    user_id = current_user.id if current_user.is_authenticated else None
    scan_id = run_scan_async(module, target, options, user_id)
    if scan_id:
        return jsonify({'scan_id': scan_id, 'status': 'started'})
    return jsonify({'error': 'Échec du lancement'}), 500


@app.route('/scan/<int:scan_id>')
def scan_result(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({'error': 'Scan non trouvé'}), 404
    if scan.status == 'completed':
        return jsonify(json.loads(scan.result_json))
    return jsonify({'status': scan.status})


@app.route('/history')
@login_required
def history():
    scans = Scan.query.filter_by(user_id=current_user.id)\
                      .order_by(Scan.timestamp.desc()).all()
    return render_template('history.html', scans=scans)


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


@app.route('/report/<int:scan_id>')
@login_required
def report_pdf(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan: abort(404)
    if scan.user_id != current_user.id: abort(403)
    try:
        from weasyprint import HTML as WeasyHTML
        data = json.loads(scan.result_json)
        html_str = render_template('report.html', scan=scan, data=data)
        pdf_bytes = WeasyHTML(string=html_str).write_pdf()
        return send_file(BytesIO(pdf_bytes), mimetype='application/pdf',
                         as_attachment=True,
                         download_name=f'osint_report_{scan_id}.pdf')
    except ImportError:
        return jsonify({'error': 'WeasyPrint non disponible sur ce serveur'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


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
            reader = PyPDF2.PdfReader(filepath)
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
    if isinstance(text, dict):
        text = json.dumps(text, ensure_ascii=False)
    text = str(text)[:4000]
    key = os.environ.get('OPENROUTER_KEY') or os.environ.get('ANTHROPIC_API_KEY')
    if not key:
        return jsonify({'error': 'Configurez OPENROUTER_KEY dans les variables d\'environnement Render'}), 500
    try:
        r = requests.post(
            'https://openrouter.ai/api/v1/chat/completions',
            headers={'Authorization': f'Bearer {key}', 'Content-Type': 'application/json'},
            json={'model': 'mistralai/mistral-7b-instruct:free',
                  'messages': [{'role': 'user',
                                'content': f'Analyse et résume ces résultats OSINT en français. Sois concis, structuré, et mets en évidence les points importants et risques potentiels:\n\n{text}'}]},
            timeout=30
        )
        if r.status_code == 200:
            return jsonify({'summary': r.json()['choices'][0]['message']['content']})
        return jsonify({'error': f'Erreur API OpenRouter: {r.status_code}'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ---------- SOCKETIO ----------
@socketio.on('connect')
def on_connect():
    pass

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


if __name__ == '__main__':
    socketio.run(app, debug=False, host='0.0.0.0',
                 port=int(os.environ.get('PORT', 5000)))
