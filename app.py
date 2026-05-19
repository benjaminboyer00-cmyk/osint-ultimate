#!/usr/bin/env python3
"""
OSINT ULTIMATE V2.0 – Web Interface
Flask-based, ready for Vercel deployment.
"""

import re, json, socket, ssl
from urllib.parse import urlparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

import requests
import whois
import dns.resolver
from bs4 import BeautifulSoup
import phonenumbers
from phonenumbers import carrier, geocoder, timezone, PhoneNumberType

from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# ---------- CONFIG ----------
TIMEOUT = 25
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# Clés API gratuites (laisser vide si non utilisé)
NUMVERIFY_KEY = "b5ce770ab16b6ab31a8ddcb37d7b5b55"
HIBP_KEY = ""          # https://haveibeenpwned.com/API/Key
EMAILREP_KEY = ""      # https://emailrep.io/key

# ---------- HELPERS ----------
def safe_get(url, **kwargs):
    headers = kwargs.pop('headers', {})
    headers.setdefault('User-Agent', UA)
    return requests.get(url, timeout=TIMEOUT, headers=headers, **kwargs)

def clean_domain(raw):
    raw = raw.strip()
    if not raw.startswith(('http://', 'https://')):
        raw = 'http://' + raw
    return urlparse(raw).netloc.split(':')[0]

def check_private_ip(ip):
    parts = ip.split('.')
    if len(parts) == 4:
        first = int(parts[0])
        second = int(parts[1])
        if first == 10: return True
        if first == 172 and 16 <= second <= 31: return True
        if first == 192 and second == 168: return True
    return False

def check_vulnerabilities(software, version):
    if not version:
        return []
    try:
        base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {"keywordSearch": f"{software} {version}", "resultsPerPage": 3}
        resp = requests.get(base, params=params, timeout=15)
        if resp.status_code == 200:
            cves = []
            for vuln in resp.json().get("vulnerabilities", []):
                cve_id = vuln["cve"]["id"]
                desc = vuln["cve"]["descriptions"][0]["value"][:200]
                cves.append(f"{cve_id}: {desc}...")
            return cves
    except:
        pass
    return []

# ---------- MODULES ----------

def module_site(target):
    domain = clean_domain(target)
    url = f"http://{domain}" if not target.startswith('http') else target
    results = {}

    # WHOIS
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        expiration = w.expiration_date
        if isinstance(creation, list): creation = creation[0]
        if isinstance(expiration, list): expiration = expiration[0]
        results["WHOIS"] = {
            "Registrar": w.registrar,
            "Création": str(creation),
            "Expiration": str(expiration),
            "Serveurs DNS": w.name_servers if isinstance(w.name_servers, list) else [w.name_servers]
        }
    except Exception as e:
        results["WHOIS"] = {"Erreur": str(e)}

    # DNS
    dns_records = {}
    for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            dns_records[rtype] = [str(r) for r in answers]
        except:
            dns_records[rtype] = []
    results["DNS"] = dns_records

    # Sous-domaines (crt.sh)
    try:
        resp = safe_get(f"https://crt.sh/?q=%25.{domain}&output=json")
        if resp.status_code == 200:
            data = resp.json()
            subs = set()
            for entry in data:
                name = entry.get('name_value', '')
                for n in name.split('\n'):
                    n = n.strip().lower().lstrip('*.')
                    if n.endswith(domain) and n != domain:
                        subs.add(n)
            results["Sous-domaines"] = sorted(subs)
        else:
            results["Sous-domaines"] = [f"Statut HTTP {resp.status_code}"]
    except Exception as e:
        results["Sous-domaines"] = [f"Erreur: {e}"]

    # Headers & IP
    try:
        r = safe_get(url, allow_redirects=True)
        headers = dict(r.headers)
        status = r.status_code
        ip = socket.gethostbyname(urlparse(url).hostname)
        results["Headers HTTP"] = headers
        results["Statut HTTP"] = status
        results["IP"] = ip
        # Géolocalisation IP
        if not check_private_ip(ip):
            geo_resp = safe_get(f"http://ip-api.com/json/{ip}")
            if geo_resp.status_code == 200:
                geo = geo_resp.json()
                if geo.get("status") == "success":
                    results["Géolocalisation IP"] = {
                        "Pays": geo.get("country"),
                        "Région": geo.get("regionName"),
                        "Ville": geo.get("city"),
                        "FAI": geo.get("isp"),
                        "Organisation": geo.get("org"),
                        "Proxy/VPN": geo.get("proxy"),
                        "Hébergement": geo.get("hosting")
                    }
        else:
            results["Géolocalisation IP"] = "Adresse IP privée (non routable)"
    except Exception as e:
        results["Headers HTTP"] = {"Erreur": str(e)}

    # Technologies & vulns
    techs = {}
    try:
        r = safe_get(url)
        soup = BeautifulSoup(r.text, 'html.parser')
        page = r.text.lower()

        server = r.headers.get('Server', '')
        powered = r.headers.get('X-Powered-By', '')
        if server:
            techs["Serveur"] = server
            if '/' in server:
                soft, ver = server.split('/', 1)
                techs["Serveur version"] = ver
                vulns = check_vulnerabilities(soft, ver)
                if vulns: techs["Vulnérabilités serveur"] = vulns
        if powered:
            techs["X-Powered-By"] = powered

        gen = soup.find("meta", attrs={"name": "generator"})
        if gen and gen.get("content"):
            techs["Générateur"] = gen["content"]
            if "WordPress" in gen["content"]:
                techs["CMS"] = "WordPress"
                ver = gen["content"].replace("WordPress ", "")
                techs["WordPress version"] = ver
                vulns = check_vulnerabilities("WordPress", ver)
                if vulns: techs["Vulnérabilités WordPress"] = vulns

        if '/wp-content/' in page:
            techs.setdefault("CMS", "WordPress")
        if '/sites/default/' in page:
            techs.setdefault("CMS", "Drupal")
        if '/media/system/js/' in page:
            techs.setdefault("CMS", "Joomla")

        if 'next/dist/' in page or '__NEXT_DATA__' in page:
            techs["Framework"] = "Next.js"
        if 'nuxt.config.js' in page or '__NUXT__' in page:
            techs["Framework"] = "Nuxt.js"
        if 'react' in page:
            techs["Bibliothèque"] = "React"

        for script in soup.find_all('script', src=True):
            src = script['src'].lower()
            if 'jquery' in src:
                match = re.search(r'jquery[.-]?(\d+\.\d+\.\d+)', src)
                if match:
                    ver = match.group(1)
                    techs["jQuery version"] = ver
                    vulns = check_vulnerabilities("jQuery", ver)
                    if vulns: techs["Vulnérabilités jQuery"] = vulns
            if 'bootstrap' in src:
                match = re.search(r'bootstrap[.-]?(\d+\.\d+\.\d+)', src)
                if match:
                    ver = match.group(1)
                    techs["Bootstrap version"] = ver
                    vulns = check_vulnerabilities("Bootstrap", ver)
                    if vulns: techs["Vulnérabilités Bootstrap"] = vulns

        try:
            rob = safe_get(url.rstrip('/') + '/robots.txt')
            if rob.status_code == 200:
                techs["robots.txt"] = "Accessible"
        except: pass

        title = soup.find('title')
        if title and title.string:
            techs["Titre"] = title.string.strip()
    except Exception as e:
        techs["Erreur"] = str(e)
    results["Technologies & Vulnérabilités"] = techs

    # Wayback
    try:
        resp = safe_get(f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit=5&fl=timestamp,original")
        if resp.status_code == 200:
            data = resp.json()
            if len(data) > 1:
                wayback = [{"timestamp": row[0], "url": row[1]} for row in data[1:]]
                results["Wayback (5 derniers)"] = wayback
    except:
        pass
    return results

def module_instagram(username):
    result = {}
    # Essaye d'abord l'endpoint JSON
    try:
        headers = {"User-Agent": UA, "X-Requested-With": "XMLHttpRequest"}
        resp = requests.get(f"https://www.instagram.com/{username}/?__a=1", headers=headers, timeout=TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            user = data.get("graphql", {}).get("user")
            if user and not user.get("is_private"):
                result = {
                    "Nom complet": user.get("full_name"),
                    "Bio": user.get("biography"),
                    "URL externe": user.get("external_url"),
                    "Abonnés": user.get("edge_followed_by", {}).get("count"),
                    "Abonnements": user.get("edge_follow", {}).get("count"),
                    "Publications": user.get("edge_owner_to_timeline_media", {}).get("count"),
                    "Vérifié": user.get("is_verified"),
                    "Catégorie": user.get("business_category_name"),
                    "Photo de profil": user.get("profile_pic_url_hd")
                }
                posts = []
                timeline = user.get("edge_owner_to_timeline_media", {})
                for edge in timeline.get("edges", [])[:3]:
                    node = edge.get("node", {})
                    posts.append({
                        "Date": datetime.fromtimestamp(node.get("taken_at_timestamp", 0)).strftime('%Y-%m-%d %H:%M'),
                        "Likes": node.get("edge_liked_by", {}).get("count"),
                        "Commentaires": node.get("edge_media_to_comment", {}).get("count"),
                        "URL": f"https://www.instagram.com/p/{node.get('shortcode')}/",
                        "Légende": node.get("edge_media_to_caption", {}).get("edges", [{}])[0].get("node", {}).get("text", "")[:200]
                    })
                result["Dernières publications"] = posts
                return result
    except:
        pass

    # Fallback : parse HTML
    try:
        resp = safe_get(f"https://www.instagram.com/{username}/")
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.text, 'html.parser')
            scripts = soup.find_all('script', type="text/javascript")
            for script in scripts:
                if 'window.__INITIAL_STATE__' in script.text:
                    json_str = script.text.split(' = ', 1)[1].rstrip(';')
                    data = json.loads(json_str)
                    user = data.get("ProfilePage", [{}])[0].get("user")
                    if user:
                        if user.get("is_private"):
                            return {"Erreur": "Compte privé"}
                        result["Nom complet"] = user.get("full_name")
                        result["Bio"] = user.get("biography")
                        result["URL externe"] = user.get("external_url")
                        result["Abonnés"] = user.get("edge_followed_by", {}).get("count")
                        result["Abonnements"] = user.get("edge_follow", {}).get("count")
                        result["Publications"] = user.get("edge_owner_to_timeline_media", {}).get("count")
                        result["Vérifié"] = user.get("is_verified")
                        result["Photo de profil"] = user.get("profile_pic_url_hd")
                        return result
            return {"Erreur": "Impossible de parser les données (compte inexistant ou blocage)."}
    except Exception as e:
        return {"Erreur": str(e)}
    return {"Erreur": "Échec de la récupération"}

def module_email(email):
    result = {}
    if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
        result["Valide"] = False
        result["Raison"] = "Format invalide"
        return result
    result["Valide"] = True
    domain = email.split('@')[1]

    # MX
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        result["Serveurs MX"] = [str(r.exchange) for r in answers]
        result["Domaine OK"] = True
    except Exception as e:
        result["Serveurs MX"] = []
        result["Domaine OK"] = False
        result["Erreur MX"] = str(e)

    # SPF, DMARC
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for r in answers:
            if "v=spf1" in str(r):
                result["SPF"] = str(r)
                break
    except: pass
    try:
        answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        for r in answers:
            if "v=DMARC1" in str(r):
                result["DMARC"] = str(r)
                break
    except: pass

    # HIBP
    if HIBP_KEY:
        try:
            headers = {"hibp-api-key": HIBP_KEY, "user-agent": UA}
            resp = requests.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}", headers=headers, timeout=10)
            if resp.status_code == 200:
                result["Fuites"] = [b['Name'] for b in resp.json()]
            elif resp.status_code == 404:
                result["Fuites"] = "Aucune fuite connue"
            else:
                result["Fuites"] = f"Erreur API {resp.status_code}"
        except: pass
    else:
        result["Fuites"] = "Non configuré (gratuit : https://haveibeenpwned.com/API/Key)"

    # EmailRep
    if EMAILREP_KEY:
        try:
            headers = {"key": EMAILREP_KEY, "user-agent": UA}
            resp = requests.get(f"https://emailrep.io/{email}", headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                result["Réputation"] = data.get("reputation")
                result["Suspect"] = data.get("suspicious")
                social = data.get("details", {}).get("profiles", [])
                result["Profils sociaux liés"] = social if social else "Aucun"
        except: pass
    else:
        result["EmailRep"] = "Non configuré (gratuit : https://emailrep.io/key)"

    # Jetable
    disposable = ["mailinator.com", "10minutemail.com", "guerrillamail.com", "temp-mail.org"]
    result["Jetable"] = domain in disposable
    return result

def module_phone(phone_str):
    try:
        parsed = phonenumbers.parse(phone_str, None)
    except phonenumbers.NumberParseException as e:
        return {"Erreur": f"Numéro invalide : {e}"}
    result = {
        "Possible": phonenumbers.is_possible_number(parsed),
        "Valide": phonenumbers.is_valid_number(parsed),
        "Type": "Inconnu",
        "Format international": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        "Format national": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
        "E.164": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
        "Code pays": parsed.country_code,
        "Pays": geocoder.description_for_number(parsed, "fr") or phonenumbers.region_code_for_number(parsed),
        "Opérateur (attribution)": carrier.name_for_number(parsed, "fr") or "Inconnu",
        "Fuseaux horaires": timezone.time_zones_for_number(parsed)
    }
    type_map = {
        PhoneNumberType.FIXED_LINE: "Fixe",
        PhoneNumberType.MOBILE: "Mobile",
        PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixe ou mobile",
        PhoneNumberType.VOIP: "VoIP",
        PhoneNumberType.TOLL_FREE: "Numéro vert",
        PhoneNumberType.PREMIUM_RATE: "Surtaxé",
        PhoneNumberType.UNKNOWN: "Inconnu"
    }
    result["Type"] = type_map.get(phonenumbers.number_type(parsed), "Inconnu")

    if NUMVERIFY_KEY:
        try:
            params = {"access_key": NUMVERIFY_KEY, "number": result["E.164"], "format": 1}
            resp = requests.get("http://apilayer.net/api/validate", params=params, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("valid"):
                    result["HLR Opérateur actuel"] = data.get("carrier")
                    result["HLR Type de ligne"] = data.get("line_type")
                    result["HLR Localisation"] = data.get("location")
        except: pass
    return result

def module_ip(ip):
    if check_private_ip(ip):
        return {"Erreur": "IP privée : aucune information géographique possible."}
    try:
        resp = safe_get(f"http://ip-api.com/json/{ip}")
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "Pays": data.get("country"),
                    "Région": data.get("regionName"),
                    "Ville": data.get("city"),
                    "FAI": data.get("isp"),
                    "Organisation": data.get("org"),
                    "Proxy/VPN": data.get("proxy"),
                    "Hébergement": data.get("hosting")
                }
        return {"Erreur": "API injoignable ou limite atteinte"}
    except Exception as e:
        return {"Erreur": str(e)}

def module_linkedin(username):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept-Language": "fr,fr-FR;q=0.9,en;q=0.8",
            "Referer": "https://www.google.com/"
        }
        resp = safe_get(f"https://www.linkedin.com/in/{username}", headers=headers)
        if resp.status_code == 999:
            return {"Erreur": "LinkedIn bloque la requête (statut 999)."}
        if resp.status_code == 404:
            return {"Erreur": "Profil introuvable."}
        soup = BeautifulSoup(resp.text, 'html.parser')
        script = soup.find('script', type='application/ld+json')
        if script:
            data = json.loads(script.string)
            return {
                "Nom": data.get('name'),
                "Titre": data.get('jobTitle'),
                "Description": data.get('description'),
                "URL": data.get('url')
            }
        title = soup.find('title')
        if title and 'LinkedIn' in title.text:
            return {"Profil existant": True, "Titre": title.text.strip()}
        return {"Profil existant": False}
    except Exception as e:
        return {"Erreur": str(e)}

def module_snapchat(username):
    try:
        resp = safe_get(f"https://www.snapchat.com/add/{username}")
        if resp.status_code == 200 and username.lower() in resp.url.lower():
            # Tenter d'extraire les infos de la page
            soup = BeautifulSoup(resp.text, 'html.parser')
            # Le site charge des données dans une balise script type="application/json"
            scripts = soup.find_all('script', type='application/json')
            for script in scripts:
                try:
                    data = json.loads(script.string)
                    if 'props' in data and 'pageProps' in data['props']:
                        page_props = data['props']['pageProps']
                        if 'userProfile' in page_props:
                            user = page_props['userProfile']
                            return {
                                "Existe": True,
                                "Nom d'affichage": user.get('displayName'),
                                "Bitmoji": user.get('bitmoji3d', {}).get('avatarImage', {}).get('url'),
                                "URL publique": user.get('shareableSnapcodeUrl')
                            }
                except:
                    pass
            return {"Existe": True, "URL": resp.url}
        elif resp.status_code == 200:
            return {"Existe": False, "Redirigé vers": resp.url}
        else:
            return {"Existe": False, "Statut HTTP": resp.status_code}
    except Exception as e:
        return {"Erreur": str(e)}

# ---------- ROUTES ----------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    module = request.json.get('module')
    target = request.json.get('target', '').strip()
    if not target:
        return jsonify({"error": "Cible vide"}), 400

    try:
        if module == 'site':
            data = module_site(target)
        elif module == 'instagram':
            data = module_instagram(target)
        elif module == 'email':
            data = module_email(target)
        elif module == 'phone':
            data = module_phone(target)
        elif module == 'ip':
            data = module_ip(target)
        elif module == 'linkedin':
            data = module_linkedin(target)
        elif module == 'snapchat':
            data = module_snapchat(target)
        else:
            return jsonify({"error": "Module inconnu"}), 400

        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
