#!/usr/bin/env python3
"""
OSINT ULTIMATE V2.1 – Web Interface
Modules: Site Web (deep), Instagram, Email (sub-options), Phone (WhatsApp/Telegram),
IP (Shodan/SecurityTrails), Pseudo Search, Twitter, TikTok, GitHub, Facebook, Snapchat, LinkedIn.
Robust: retry, user-agent rotation, proxy support (optional).
"""

import os, re, json, socket, ssl, random, time, smtplib, concurrent.futures
from urllib.parse import urlparse
from datetime import datetime
from functools import wraps

import requests
import whois
import dns.resolver
from bs4 import BeautifulSoup
import phonenumbers
from phonenumbers import carrier, geocoder, timezone as ph_timezone, PhoneNumberType
from flask import Flask, render_template, request, jsonify, session

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-change-me')

# ---------- CONFIG ----------
TIMEOUT = 25
RETRIES = 2
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0"
]
PROXIES = []  # list of "http://host:port" strings, fill from environment or settings

# API keys (set via environment or settings form)
NUMVERIFY_KEY = os.environ.get('NUMVERIFY_KEY', '')
HIBP_KEY = os.environ.get('HIBP_KEY', '')
EMAILREP_KEY = os.environ.get('EMAILREP_KEY', '')
SHODAN_KEY = os.environ.get('SHODAN_KEY', '')
SECURITYTRAILS_KEY = os.environ.get('SECURITYTRAILS_KEY', '')

# ---------- UTILS ----------
def get_session():
    """Create a requests session with retries, random UA, and optional proxy."""
    s = requests.Session()
    adapter = requests.adapters.HTTPAdapter(max_retries=RETRIES)
    s.mount('http://', adapter)
    s.mount('https://', adapter)
    s.headers.update({'User-Agent': random.choice(USER_AGENTS)})
    if PROXIES:
        proxy = random.choice(PROXIES)
        s.proxies = {'http': proxy, 'https': proxy}
    return s

def safe_get(url, **kwargs):
    try:
        s = get_session()
        resp = s.get(url, timeout=TIMEOUT, **kwargs)
        return resp
    except Exception as e:
        return None

def check_private_ip(ip):
    parts = ip.split('.')
    if len(parts) == 4:
        first, second = int(parts[0]), int(parts[1])
        return first == 10 or (first == 172 and 16 <= second <= 31) or (first == 192 and second == 168)
    return False

def check_vulnerabilities(software, version):
    if not version:
        return []
    try:
        resp = safe_get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={software}%20{version}&resultsPerPage=3")
        if resp and resp.status_code == 200:
            cves = []
            for vuln in resp.json().get('vulnerabilities', []):
                cve_id = vuln['cve']['id']
                desc = vuln['cve']['descriptions'][0]['value'][:200]
                cves.append(f"{cve_id}: {desc}...")
            return cves
    except:
        pass
    return []

# ---------- MODULE SITE WEB (enhanced) ----------
def scan_site(target):
    domain = target if '.' in target else target + '.com'
    if not target.startswith('http'):
        url = 'http://' + domain
    else:
        url = target
        domain = urlparse(url).netloc.split(':')[0]

    results = {}

    # WHOIS
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        expiration = w.expiration_date
        if isinstance(creation, list): creation = creation[0]
        if isinstance(expiration, list): expiration = expiration[0]
        results['WHOIS'] = {
            'Registrar': w.registrar,
            'Création': str(creation),
            'Expiration': str(expiration),
            'Serveurs DNS': w.name_servers if isinstance(w.name_servers, list) else [w.name_servers]
        }
    except Exception as e:
        results['WHOIS'] = {'Erreur': str(e)}

    # DNS
    dns_records = {}
    for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            dns_records[rtype] = [str(r) for r in answers]
        except:
            dns_records[rtype] = []
    results['DNS'] = dns_records

    # Sous-domaines (crt.sh)
    try:
        resp = safe_get(f'https://crt.sh/?q=%25.{domain}&output=json')
        if resp and resp.status_code == 200:
            data = resp.json()
            subs = set()
            for entry in data:
                name = entry.get('name_value', '')
                for n in name.split('\n'):
                    n = n.strip().lower().lstrip('*.')
                    if n.endswith(domain) and n != domain:
                        subs.add(n)
            results['Sous-domaines'] = sorted(subs)
        else:
            results['Sous-domaines'] = []
    except:
        results['Sous-domaines'] = []

    # Port scan (common ports)
    ports = [21,22,25,53,80,110,143,443,465,587,993,995,3306,3389,5432,8080,8443]
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((socket.gethostbyname(domain), port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    results['Ports ouverts'] = open_ports

    # Sensitive files check
    sensitive_paths = [
        '/.git/HEAD', '/.env', '/.env.backup', '/.env.example',
        '/wp-config.php.bak', '/wp-config.php~', '/wp-config.php.old',
        '/backup.zip', '/backup.tar.gz', '/admin/', '/phpinfo.php',
        '/robots.txt', '/sitemap.xml'
    ]
    found_sensitive = []
    for path in sensitive_paths:
        try:
            resp = safe_get(url.rstrip('/') + path)
            if resp and resp.status_code == 200:
                found_sensitive.append(path)
        except:
            pass
    results['Fichiers sensibles trouvés'] = found_sensitive if found_sensitive else 'Aucun'

    # WAF detection (basic)
    try:
        resp = safe_get(url)
        if resp:
            headers = resp.headers
            waf = None
            if 'cf-ray' in headers: waf = 'Cloudflare'
            elif 'x-sucuri-id' in headers: waf = 'Sucuri'
            elif 'x-waf' in headers or 'x-fw' in headers: waf = 'Generic WAF'
            elif 'Server' in headers and 'akamai' in headers['Server'].lower(): waf = 'Akamai'
            results['WAF'] = waf if waf else 'Aucun détecté'
        else:
            results['WAF'] = 'Erreur'
    except:
        results['WAF'] = 'Erreur'

    # Headers & IP
    try:
        resp = safe_get(url, allow_redirects=True)
        if resp:
            headers = dict(resp.headers)
            results['Headers HTTP'] = headers
            results['Statut HTTP'] = resp.status_code
            ip = socket.gethostbyname(domain)
            results['IP'] = ip
            if not check_private_ip(ip):
                geo_resp = safe_get(f'http://ip-api.com/json/{ip}')
                if geo_resp and geo_resp.status_code == 200:
                    geo = geo_resp.json()
                    if geo.get('status') == 'success':
                        results['Géolocalisation IP'] = {
                            'Pays': geo.get('country'),
                            'Région': geo.get('regionName'),
                            'Ville': geo.get('city'),
                            'FAI': geo.get('isp'),
                            'Organisation': geo.get('org'),
                            'Proxy/VPN': geo.get('proxy'),
                            'Hébergement': geo.get('hosting'),
                            'Lat': geo.get('lat'),
                            'Lon': geo.get('lon')
                        }
            else:
                results['Géolocalisation IP'] = 'IP privée'
    except Exception as e:
        results['Headers HTTP'] = {'Erreur': str(e)}

    # Technologies & vulns
    techs = {}
    try:
        resp = safe_get(url)
        if resp:
            soup = BeautifulSoup(resp.text, 'html.parser')
            page = resp.text.lower()
            server = resp.headers.get('Server', '')
            powered = resp.headers.get('X-Powered-By', '')
            if server:
                techs['Serveur'] = server
                if '/' in server:
                    soft, ver = server.split('/', 1)
                    techs['Serveur version'] = ver
                    vulns = check_vulnerabilities(soft, ver)
                    if vulns: techs['Vulnérabilités serveur'] = vulns
            if powered:
                techs['X-Powered-By'] = powered

            gen = soup.find('meta', attrs={'name': 'generator'})
            if gen and gen.get('content'):
                techs['Générateur'] = gen['content']
                if 'WordPress' in gen['content']:
                    techs['CMS'] = 'WordPress'
                    ver = gen['content'].replace('WordPress ', '')
                    techs['WordPress version'] = ver
                    vulns = check_vulnerabilities('WordPress', ver)
                    if vulns: techs['Vulnérabilités WordPress'] = vulns

            if '/wp-content/' in page: techs.setdefault('CMS', 'WordPress')
            if '/sites/default/' in page: techs.setdefault('CMS', 'Drupal')
            if '/media/system/js/' in page: techs.setdefault('CMS', 'Joomla')

            if 'next/dist/' in page or '__NEXT_DATA__' in page: techs['Framework'] = 'Next.js'
            if 'nuxt.config.js' in page or '__NUXT__' in page: techs['Framework'] = 'Nuxt.js'
            if 'react' in page: techs['Bibliothèque'] = 'React'

            for script in soup.find_all('script', src=True):
                src = script['src'].lower()
                if 'jquery' in src:
                    match = re.search(r'jquery[.-]?(\d+\.\d+\.\d+)', src)
                    if match:
                        ver = match.group(1)
                        techs['jQuery version'] = ver
                        vulns = check_vulnerabilities('jQuery', ver)
                        if vulns: techs['Vulnérabilités jQuery'] = vulns
                if 'bootstrap' in src:
                    match = re.search(r'bootstrap[.-]?(\d+\.\d+\.\d+)', src)
                    if match:
                        ver = match.group(1)
                        techs['Bootstrap version'] = ver
                        vulns = check_vulnerabilities('Bootstrap', ver)
                        if vulns: techs['Vulnérabilités Bootstrap'] = vulns

            title = soup.find('title')
            if title and title.string:
                techs['Titre'] = title.string.strip()
    except Exception as e:
        techs['Erreur'] = str(e)
    results['Technologies & Vulnérabilités'] = techs

    # Wayback
    try:
        resp = safe_get(f'https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit=5&fl=timestamp,original')
        if resp and resp.status_code == 200:
            data = resp.json()
            if len(data) > 1:
                results['Wayback (5 derniers)'] = [{'timestamp': row[0], 'url': row[1]} for row in data[1:]]
    except:
        pass
    return results

# ---------- MODULE INSTAGRAM ----------
def scan_instagram(username):
    # Try JSON endpoint
    try:
        headers = {'User-Agent': random.choice(USER_AGENTS), 'X-Requested-With': 'XMLHttpRequest'}
        resp = safe_get(f'https://www.instagram.com/{username}/?__a=1', headers=headers)
        if resp and resp.status_code == 200:
            data = resp.json()
            user = data.get('graphql', {}).get('user')
            if user and not user.get('is_private'):
                result = {
                    'Nom complet': user.get('full_name'),
                    'Bio': user.get('biography'),
                    'URL externe': user.get('external_url'),
                    'Abonnés': user.get('edge_followed_by', {}).get('count'),
                    'Abonnements': user.get('edge_follow', {}).get('count'),
                    'Publications': user.get('edge_owner_to_timeline_media', {}).get('count'),
                    'Vérifié': user.get('is_verified'),
                    'Catégorie': user.get('business_category_name'),
                    'Photo de profil': user.get('profile_pic_url_hd')
                }
                # Last 3 posts
                posts = []
                timeline = user.get('edge_owner_to_timeline_media', {})
                for edge in timeline.get('edges', [])[:3]:
                    node = edge.get('node', {})
                    posts.append({
                        'Date': datetime.fromtimestamp(node.get('taken_at_timestamp', 0)).strftime('%Y-%m-%d %H:%M'),
                        'Likes': node.get('edge_liked_by', {}).get('count'),
                        'Commentaires': node.get('edge_media_to_comment', {}).get('count'),
                        'URL': f"https://www.instagram.com/p/{node.get('shortcode')}/",
                        'Légende': node.get('edge_media_to_caption', {}).get('edges', [{}])[0].get('node', {}).get('text', '')[:200]
                    })
                result['Dernières publications'] = posts
                return result
    except:
        pass

    # Fallback HTML parse
    try:
        resp = safe_get(f'https://www.instagram.com/{username}/')
        if resp and resp.status_code == 200:
            soup = BeautifulSoup(resp.text, 'html.parser')
            scripts = soup.find_all('script', type='text/javascript')
            for script in scripts:
                if 'window.__INITIAL_STATE__' in script.text:
                    json_str = script.text.split(' = ', 1)[1].rstrip(';')
                    data = json.loads(json_str)
                    user = data.get('ProfilePage', [{}])[0].get('user')
                    if user:
                        if user.get('is_private'):
                            return {'Erreur': 'Compte privé'}
                        return {
                            'Nom complet': user.get('full_name'),
                            'Bio': user.get('biography'),
                            'URL externe': user.get('external_url'),
                            'Abonnés': user.get('edge_followed_by', {}).get('count'),
                            'Abonnements': user.get('edge_follow', {}).get('count'),
                            'Publications': user.get('edge_owner_to_timeline_media', {}).get('count'),
                            'Vérifié': user.get('is_verified'),
                            'Photo de profil': user.get('profile_pic_url_hd')
                        }
            return {'Erreur': 'Impossible de parser (compte inexistant ou blocage).'}
    except Exception as e:
        return {'Erreur': str(e)}

# ---------- MODULE EMAIL (avec sous-options) ----------
def scan_email(email, options=None):
    if options is None:
        options = ['all']
    if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
        return {'Valide': False, 'Raison': 'Format invalide'}
    result = {'Valide': True}
    domain = email.split('@')[1]

    def run_if(opt):
        return 'all' in options or opt in options

    if run_if('mx'):
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            result['Serveurs MX'] = [str(r.exchange) for r in answers]
            result['Domaine OK'] = True
        except Exception as e:
            result['Serveurs MX'] = []
            result['Domaine OK'] = False
            result['Erreur MX'] = str(e)

    if run_if('spf') or run_if('dmarc'):
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for r in answers:
                if 'v=spf1' in str(r):
                    result['SPF'] = str(r)
                    break
        except: pass
        try:
            answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            for r in answers:
                if 'v=DMARC1' in str(r):
                    result['DMARC'] = str(r)
                    break
        except: pass

    if run_if('smtp'):
        # Basic SMTP check
        if result.get('Serveurs MX'):
            mx_host = str(result['Serveurs MX'][0]).rstrip('.')
            try:
                server = smtplib.SMTP(mx_host, timeout=10)
                server.ehlo()
                if server.has_extn('STARTTLS'):
                    server.starttls()
                server.ehlo()
                server.mail('test@example.com')
                code, message = server.rcpt(email)
                server.quit()
                result['SMTP vérification'] = 'Existe' if code == 250 else 'Inexistant ou refusé'
            except Exception as e:
                result['SMTP vérification'] = f'Erreur: {str(e)}'
        else:
            result['SMTP vérification'] = 'Pas de serveur MX trouvé'

    if run_if('catchall'):
        # Test avec une adresse aléatoire
        random_email = f"random_{int(time.time())}@{domain}"
        try:
            if result.get('Serveurs MX'):
                mx_host = str(result['Serveurs MX'][0]).rstrip('.')
                server = smtplib.SMTP(mx_host, timeout=10)
                server.ehlo()
                if server.has_extn('STARTTLS'):
                    server.starttls()
                server.ehlo()
                server.mail('test@example.com')
                code, _ = server.rcpt(random_email)
                server.quit()
                result['Catch-all'] = 'Oui' if code == 250 else 'Non'
            else:
                result['Catch-all'] = 'Inconnu (pas de MX)'
        except Exception as e:
            result['Catch-all'] = f'Erreur: {str(e)}'

    if run_if('breaches') and HIBP_KEY:
        try:
            headers = {'hibp-api-key': HIBP_KEY, 'User-Agent': random.choice(USER_AGENTS)}
            resp = safe_get(f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}', headers=headers)
            if resp and resp.status_code == 200:
                result['Fuites'] = [b['Name'] for b in resp.json()]
            elif resp and resp.status_code == 404:
                result['Fuites'] = 'Aucune fuite connue'
        except: pass

    if run_if('reputation') and EMAILREP_KEY:
        try:
            headers = {'key': EMAILREP_KEY, 'User-Agent': random.choice(USER_AGENTS)}
            resp = safe_get(f'https://emailrep.io/{email}', headers=headers)
            if resp and resp.status_code == 200:
                data = resp.json()
                result['Réputation'] = data.get('reputation')
                result['Suspect'] = data.get('suspicious')
                social = data.get('details', {}).get('profiles', [])
                result['Profils sociaux liés'] = social if social else 'Aucun'
        except: pass

    if run_if('social'):
        # Check Gravatar, GitHub, etc. (simple)
        social = []
        # Gravatar
        try:
            hash = hashlib.md5(email.lower().strip().encode()).hexdigest()
            resp = safe_get(f'https://www.gravatar.com/{hash}.json')
            if resp and resp.status_code == 200:
                data = resp.json()
                if data.get('entry'):
                    for e in data['entry']:
                        social.append({
                            'Plateforme': 'Gravatar',
                            'Nom': e.get('displayName'),
                            'URL': e.get('profileUrl')
                        })
        except: pass
        # GitHub (search users)
        try:
            resp = safe_get(f'https://api.github.com/search/users?q={email}')
            if resp and resp.status_code == 200:
                data = resp.json()
                if data.get('total_count', 0) > 0:
                    for item in data['items'][:3]:
                        social.append({'Plateforme': 'GitHub', 'Login': item['login'], 'URL': item['html_url']})
        except: pass
        result['Profils sociaux'] = social if social else 'Aucun trouvé'

    # Jetable
    disposable = ['mailinator.com', '10minutemail.com', 'guerrillamail.com', 'temp-mail.org']
    result['Jetable'] = domain in disposable
    return result

# ---------- MODULE TÉLÉPHONE ----------
def scan_phone(phone_str):
    try:
        parsed = phonenumbers.parse(phone_str, None)
    except phonenumbers.NumberParseException as e:
        return {'Erreur': f'Numéro invalide : {e}'}
    result = {
        'Possible': phonenumbers.is_possible_number(parsed),
        'Valide': phonenumbers.is_valid_number(parsed),
        'Type': 'Inconnu',
        'Format international': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        'Format national': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
        'E.164': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
        'Code pays': parsed.country_code,
        'Pays': geocoder.description_for_number(parsed, 'fr') or phonenumbers.region_code_for_number(parsed),
        'Opérateur (attribution)': carrier.name_for_number(parsed, 'fr') or 'Inconnu',
        'Fuseaux horaires': ph_timezone.time_zones_for_number(parsed)
    }
    type_map = {
        PhoneNumberType.FIXED_LINE: 'Fixe',
        PhoneNumberType.MOBILE: 'Mobile',
        PhoneNumberType.FIXED_LINE_OR_MOBILE: 'Fixe ou mobile',
        PhoneNumberType.VOIP: 'VoIP',
        PhoneNumberType.TOLL_FREE: 'Numéro vert',
        PhoneNumberType.PREMIUM_RATE: 'Surtaxé',
        PhoneNumberType.UNKNOWN: 'Inconnu'
    }
    result['Type'] = type_map.get(phonenumbers.number_type(parsed), 'Inconnu')

    if NUMVERIFY_KEY:
        try:
            params = {'access_key': NUMVERIFY_KEY, 'number': result['E.164'], 'format': 1}
            resp = safe_get('http://apilayer.net/api/validate', params=params)
            if resp and resp.status_code == 200:
                data = resp.json()
                if data.get('valid'):
                    result['HLR Opérateur actuel'] = data.get('carrier')
                    result['HLR Type de ligne'] = data.get('line_type')
                    result['HLR Localisation'] = data.get('location')
        except: pass

    # WhatsApp check
    try:
        resp = safe_get(f"https://api.whatsapp.com/send?phone={result['E.164']}")
        if resp and 'api.whatsapp.com' in resp.url and 'phone=' in resp.url:
            result['WhatsApp'] = 'Numéro associé'
        else:
            result['WhatsApp'] = 'Non associé ou impossible à vérifier'
    except:
        result['WhatsApp'] = 'Erreur'

    # Telegram check (via t.me)
    try:
        resp = safe_get(f"https://t.me/+{result['E.164']}")
        if resp and resp.status_code == 200 and 'tgme_page_title' in resp.text:
            result['Telegram'] = 'Probablement associé'
        else:
            result['Telegram'] = 'Non trouvé'
    except:
        result['Telegram'] = 'Erreur'

    return result

# ---------- MODULE IP ----------
def scan_ip(ip):
    if check_private_ip(ip):
        return {'Erreur': 'IP privée, aucune information géographique.'}
    result = {}
    # Geolocation
    try:
        resp = safe_get(f'http://ip-api.com/json/{ip}')
        if resp and resp.status_code == 200:
            data = resp.json()
            if data.get('status') == 'success':
                result['Géolocalisation'] = {
                    'Pays': data.get('country'),
                    'Région': data.get('regionName'),
                    'Ville': data.get('city'),
                    'FAI': data.get('isp'),
                    'Organisation': data.get('org'),
                    'Proxy/VPN': data.get('proxy'),
                    'Hébergement': data.get('hosting'),
                    'Lat': data.get('lat'),
                    'Lon': data.get('lon')
                }
    except: pass

    # Shodan (optional)
    if SHODAN_KEY:
        try:
            resp = safe_get(f'https://api.shodan.io/shodan/host/{ip}?key={SHODAN_KEY}')
            if resp and resp.status_code == 200:
                shodan_data = resp.json()
                result['Shodan'] = {
                    'Ports ouverts': shodan_data.get('ports'),
                    'Organisation': shodan_data.get('org'),
                    'Services': [{'port': d['port'], 'transport': d['transport']} for d in shodan_data.get('data', [])]
                }
        except: pass

    # SecurityTrails (optional)
    if SECURITYTRAILS_KEY:
        try:
            headers = {'APIKEY': SECURITYTRAILS_KEY}
            resp = safe_get(f'https://api.securitytrails.com/v1/ips/nearby/{ip}', headers=headers)
            if resp and resp.status_code == 200:
                result['SecurityTrails - IP voisines'] = resp.json().get('blocks', [])
        except: pass

    return result

# ---------- PSEUDO SEARCH (basic) ----------
PSEUDO_SITES = [
    {"name": "Twitter", "url": "https://twitter.com/{}", "check": "status"},
    {"name": "Instagram", "url": "https://www.instagram.com/{}/", "check": "status"},
    {"name": "GitHub", "url": "https://github.com/{}", "check": "status"},
    {"name": "Reddit", "url": "https://www.reddit.com/user/{}", "check": "status"},
    {"name": "YouTube", "url": "https://www.youtube.com/@{}", "check": "status"},
    {"name": "Twitch", "url": "https://www.twitch.tv/{}", "check": "status"},
    {"name": "TikTok", "url": "https://www.tiktok.com/@{}", "check": "status"},
    {"name": "Pinterest", "url": "https://www.pinterest.com/{}/", "check": "status"},
    {"name": "Steam", "url": "https://steamcommunity.com/id/{}", "check": "status"},
    {"name": "Snapchat", "url": "https://www.snapchat.com/add/{}", "check": "redirect"},
    {"name": "LinkedIn", "url": "https://www.linkedin.com/in/{}", "check": "status"},
    {"name": "Facebook", "url": "https://www.facebook.com/{}", "check": "status"},
    {"name": "VK", "url": "https://vk.com/{}", "check": "status"},
    {"name": "Telegram", "url": "https://t.me/{}", "check": "status"},
    {"name": "Medium", "url": "https://medium.com/@{}", "check": "status"},
    {"name": "Dev.to", "url": "https://dev.to/{}", "check": "status"},
    {"name": "Patreon", "url": "https://www.patreon.com/{}", "check": "status"},
    {"name": "Spotify", "url": "https://open.spotify.com/user/{}", "check": "status"},
]

def scan_pseudo(username):
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for site in PSEUDO_SITES:
            future = executor.submit(check_single_site, site, username)
            futures.append((site['name'], future))
        for name, future in futures:
            results[name] = future.result()
    return results

def check_single_site(site, username):
    url = site['url'].format(username)
    try:
        resp = safe_get(url, allow_redirects=False)
        if not resp: return 'Erreur'
        if site['check'] == 'status':
            return 'Existe' if resp.status_code == 200 else 'Non'
        elif site['check'] == 'redirect':
            if 300 <= resp.status_code < 400:
                return 'Existe' if 'location' in resp.headers else 'Non'
            return 'Existe' if resp.status_code == 200 else 'Non'
    except:
        return 'Erreur'

# ---------- NEW SOCIAL MODULES ----------
def scan_twitter(username):
    try:
        resp = safe_get(f"https://twitter.com/{username}")
        if resp and resp.status_code == 200:
            soup = BeautifulSoup(resp.text, 'html.parser')
            # Parse public meta
            desc = soup.find('meta', attrs={'name': 'description'})
            bio = ''
            if desc:
                content = desc.get('content', '')
                if 'The latest tweets from' in content:
                    parts = content.split('The latest tweets from ')
                    if len(parts) > 1:
                        bio = parts[1].strip()
            title = soup.find('title')
            return {
                'Existe': True,
                'Bio': bio,
                'Titre': title.text.strip() if title else ''
            }
        elif resp and resp.status_code == 404:
            return {'Existe': False}
    except Exception as e:
        return {'Erreur': str(e)}

def scan_tiktok(username):
    try:
        resp = safe_get(f"https://www.tiktok.com/@{username}")
        if resp and resp.status_code == 200:
            # Try to extract JSON data
            soup = BeautifulSoup(resp.text, 'html.parser')
            script = soup.find('script', id='__UNIVERSAL_DATA_FOR_REHYDRATION__')
            if script:
                data = json.loads(script.string)
                user_info = data.get('__DEFAULT_SCOPE__', {}).get('webapp.user-detail', {}).get('userInfo', {})
                if user_info:
                    return {
                        'Nom': user_info.get('nickname'),
                        'Bio': user_info.get('signature'),
                        'Abonnés': user_info.get('followerCount'),
                        'Abonnements': user_info.get('followingCount'),
                        'Vérifié': user_info.get('verified'),
                        'Photo': user_info.get('avatarLarger')
                    }
            return {'Existe': True, 'Détails': 'Parsing impossible'}
        elif resp and resp.status_code == 404:
            return {'Existe': False}
    except Exception as e:
        return {'Erreur': str(e)}

def scan_github(username):
    try:
        resp = safe_get(f"https://api.github.com/users/{username}")
        if resp and resp.status_code == 200:
            data = resp.json()
            return {
                'Login': data.get('login'),
                'Nom': data.get('name'),
                'Bio': data.get('bio'),
                'Compagnie': data.get('company'),
                'Blog': data.get('blog'),
                'Localisation': data.get('location'),
                'Email public': data.get('email'),
                'Followers': data.get('followers'),
                'Following': data.get('following'),
                'Repos publics': data.get('public_repos'),
                'URL': data.get('html_url')
            }
        elif resp and resp.status_code == 404:
            return {'Existe': False}
    except Exception as e:
        return {'Erreur': str(e)}

def scan_facebook(username):
    # Very limited: just check profile URL
    try:
        resp = safe_get(f"https://www.facebook.com/{username}")
        if resp and resp.status_code == 200:
            return {'Existe': True}
        else:
            return {'Existe': False}
    except:
        return {'Erreur'}

def scan_linkedin(username):
    try:
        headers = {
            'User-Agent': random.choice(USER_AGENTS),
            'Accept-Language': 'fr,fr-FR;q=0.9,en;q=0.8',
            'Referer': 'https://www.google.com/'
        }
        resp = safe_get(f"https://www.linkedin.com/in/{username}", headers=headers)
        if resp:
            if resp.status_code == 999:
                return {'Erreur': 'Blocage LinkedIn (statut 999).'}
            if resp.status_code == 404:
                return {'Erreur': 'Profil introuvable.'}
            soup = BeautifulSoup(resp.text, 'html.parser')
            script = soup.find('script', type='application/ld+json')
            if script:
                data = json.loads(script.string)
                return {
                    'Nom': data.get('name'),
                    'Titre': data.get('jobTitle'),
                    'Description': data.get('description'),
                    'URL': data.get('url')
                }
            title = soup.find('title')
            if title and 'LinkedIn' in title.text:
                return {'Profil existant': True, 'Titre': title.text.strip()}
            return {'Profil existant': True}
    except Exception as e:
        return {'Erreur': str(e)}

def scan_snapchat(username):
    try:
        resp = safe_get(f"https://www.snapchat.com/add/{username}")
        if resp and resp.status_code == 200:
            soup = BeautifulSoup(resp.text, 'html.parser')
            scripts = soup.find_all('script', type='application/json')
            for script in scripts:
                try:
                    data = json.loads(script.string)
                    if 'props' in data and 'pageProps' in data['props']:
                        page_props = data['props']['pageProps']
                        if 'userProfile' in page_props:
                            user = page_props['userProfile']
                            return {
                                'Existe': True,
                                'Nom d\'affichage': user.get('displayName'),
                                'Bitmoji': user.get('bitmoji3d', {}).get('avatarImage', {}).get('url'),
                                'URL publique': user.get('shareableSnapcodeUrl')
                            }
                except:
                    pass
            return {'Existe': True, 'URL': resp.url}
        elif resp and resp.status_code == 404:
            return {'Existe': False}
    except Exception as e:
        return {'Erreur': str(e)}

# ---------- ROUTES ----------
@app.route('/')
def index():
    return render_template('index.html',
        numverify=NUMVERIFY_KEY,
        hibp=HIBP_KEY,
        emailrep=EMAILREP_KEY,
        shodan=SHODAN_KEY,
        securitytrails=SECURITYTRAILS_KEY)

@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    module = data.get('module')
    target = data.get('target', '').strip()
    options = data.get('options', [])
    if not target:
        return jsonify({'error': 'Cible vide'}), 400

    try:
        if module == 'site':
            result = scan_site(target)
        elif module == 'instagram':
            result = scan_instagram(target)
        elif module == 'email':
            result = scan_email(target, options)
        elif module == 'phone':
            result = scan_phone(target)
        elif module == 'ip':
            result = scan_ip(target)
        elif module == 'pseudo':
            result = scan_pseudo(target)
        elif module == 'twitter':
            result = scan_twitter(target)
        elif module == 'tiktok':
            result = scan_tiktok(target)
        elif module == 'github':
            result = scan_github(target)
        elif module == 'facebook':
            result = scan_facebook(target)
        elif module == 'linkedin':
            result = scan_linkedin(target)
        elif module == 'snapchat':
            result = scan_snapchat(target)
        else:
            return jsonify({'error': 'Module inconnu'}), 400

        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ---------- MAIN ----------
if __name__ == '__main__':
    app.run(debug=True)
