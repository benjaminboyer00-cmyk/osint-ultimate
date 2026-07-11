"""Scans cœur : site, email, téléphone, IP, réseaux sociaux."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import dns.resolver
import phonenumbers
from bs4 import BeautifulSoup
from phonenumbers import carrier, geocoder
from phonenumbers import timezone as ph_timezone

from services.http_helpers import safe_get

logger = logging.getLogger(__name__)

def scan_site(target, options=None):
    domain = target.strip()
    if domain.startswith('http'):
        domain = urlparse(domain).netloc
    domain = re.sub(r'^www\.', '', domain).split('/')[0]
    results = {}

    # ── WHOIS (RDAP + repli, timeouts courts) ──
    def _task_whois():
        try:
            from connectors.whois_domain import lookup as whois_lookup
            return whois_lookup(domain, options)
        except Exception as e:
            return {'Erreur': str(e)}

    # ── DNS (cache court pour limiter la latence sur scans répétés) ──
    def _task_dns():
        try:
            from services.cache import get_cached, set_cached
            cached = get_cached('dns', domain)
            if cached is not None:
                return cached
        except Exception:
            get_cached = set_cached = None
        dns_rec = {}
        for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']:
            try:
                dns_rec[rtype] = [str(r) for r in dns.resolver.resolve(domain, rtype)]
            except Exception:
                dns_rec[rtype] = []
        try:
            if set_cached:
                set_cached('dns', domain, dns_rec)
        except Exception:
            pass
        return dns_rec

    # ── HTTP + IP + Geo ──
    def _task_http_geo():
        out = {}
        try:
            http_resp = safe_get(f'https://{domain}', options=options) or safe_get(f'http://{domain}', options=options)
            if not http_resp or (http_resp.status_code in (403, 503, 520, 521, 522, 523)):
                from connectors.scraper_fallback import fetch_url_protected
                cf = fetch_url_protected(f'https://{domain}', options)
                if cf and cf.text:
                    http_resp = cf
                    out['_http_via'] = 'cloudscraper'
            if http_resp:
                out['HTTP'] = {
                    'Statut':   http_resp.status_code,
                    'URL finale': http_resp.url,
                }
                out['Headers HTTP'] = dict(http_resp.headers)
            ip = socket.gethostbyname(domain)
            out['IP'] = ip
            geo = safe_get(f'http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,proxy,hosting')
            if geo and geo.status_code == 200:
                g = geo.json()
                if g.get('status') == 'success':
                    out['Géolocalisation'] = {
                        'Pays': g.get('country'), 'Région': g.get('regionName'),
                        'Ville': g.get('city'),   'FAI': g.get('isp'),
                        'Organisation': g.get('org'), 'AS': g.get('as'),
                        'Lat': g.get('lat'),      'Lon': g.get('lon'),
                        'Fuseau': g.get('timezone'),
                        'Proxy/VPN': 'Oui ⚠️' if g.get('proxy') else 'Non',
                        'Hébergement': 'Oui' if g.get('hosting') else 'Non',
                    }
            out['_http_resp'] = http_resp
        except Exception as e:
            out['Réseau'] = str(e)
        return out

    # ── SSL ──
    def _task_ssl():
        try:
            import ssl as _ssl
            ctx = _ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as ss:
                ss.settimeout(5); ss.connect((domain, 443))
                cert = ss.getpeercert()
                return {
                    'Valide jusqu\'au': cert.get('notAfter', 'N/A'),
                    'Émetteur': dict(x[0] for x in cert.get('issuer', [])).get('organizationName', 'N/A'),
                    'Sujet':    dict(x[0] for x in cert.get('subject', [])).get('commonName', 'N/A'),
                }
        except Exception as e:
            return {'Erreur': str(e)}

    # ── Ports (socket fallback, nmap si dispo) ──
    common = {21:'FTP',22:'SSH',25:'SMTP',80:'HTTP',110:'POP3',
              143:'IMAP',443:'HTTPS',3306:'MySQL',3389:'RDP',
              5432:'PostgreSQL',8080:'HTTP-Alt',8443:'HTTPS-Alt'}

    def _task_ports():
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
            return open_ports or ['Aucun port ouvert détecté']
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
            return open_ports or ['Aucun détecté']

    # ── Wayback Machine ──
    def _task_wayback():
        try:
            wb = safe_get(f'https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit=5&fl=timestamp,original&collapse=urlkey')
            if wb and wb.status_code == 200:
                data = wb.json()
                if len(data) > 1:
                    return [{'Date': r[0][:8], 'URL': r[1]} for r in data[1:]]
        except Exception:
            pass
        return None

    # ── Exécution parallèle des opérations indépendantes ──
    with ThreadPoolExecutor(max_workers=6, thread_name_prefix='site-scan') as pool:
        fut_whois = pool.submit(_task_whois)
        fut_dns = pool.submit(_task_dns)
        fut_http = pool.submit(_task_http_geo)
        fut_ssl = pool.submit(_task_ssl)
        fut_ports = pool.submit(_task_ports)
        fut_wayback = pool.submit(_task_wayback)

        results['WHOIS'] = fut_whois.result()
        results['DNS'] = fut_dns.result()

        http_out = fut_http.result()
        http_resp = http_out.pop('_http_resp', None)
        results.update(http_out)

        results['SSL/TLS'] = fut_ssl.result()
        results['Ports ouverts'] = fut_ports.result()

        wb_result = fut_wayback.result()
        if wb_result:
            results['Wayback Machine'] = wb_result

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
            with ThreadPoolExecutor(max_workers=2, thread_name_prefix='site-scan-rb') as pool:
                paths = [('/robots.txt','robots.txt'),('/sitemap.xml','sitemap.xml')]
                futs = {label: pool.submit(safe_get, f'https://{domain}{path}') for path, label in paths}
                for label, fut in futs.items():
                    r = fut.result()
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
        try:
            from services.country_geo import coords_for_country
            region = phonenumbers.region_code_for_number(phone)
            if region:
                loc = coords_for_country(region)
                if loc:
                    results['Géolocalisation'] = {
                        'Pays': results.get('Pays') or loc.get('country', region),
                        'Code pays': region,
                        'Lat': loc['lat'],
                        'Lon': loc['lon'],
                        'Précision': 'Pays (indicatif téléphonique)',
                    }
        except Exception:
            pass
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
    from services.url_sanitize import safe_path_segment

    username = safe_path_segment(username.strip())
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

    import os
    per_site = int(os.environ.get('PSEUDO_SITE_TIMEOUT', '8'))

    def check(name, url_tpl, not_found):
        from services.social_fetch import social_http_get
        url = url_tpl.replace('{u}', username)
        try:
            r = social_http_get(url, options, timeout=per_site)
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

    # Toutes les plateformes en parallèle ; threads daemon (pas de fuite si
    # un site est lent) + fenêtre globale bornée -> ~per_site secondes au total.
    threads = [threading.Thread(target=check, args=(n, u, nf), daemon=True)
               for n, (u, nf) in platforms.items()]
    for t in threads:
        t.start()
    deadline = time.monotonic() + per_site + 2
    for t in threads:
        t.join(timeout=max(0.1, deadline - time.monotonic()))
    return results


def scan_instagram(username, options=None):
    from services.social_fetch import (
        social_http_get,
        parse_instagram_api_json,
        parse_instagram_profile_html,
        profile_exists_in_html,
    )
    from services.url_sanitize import sanitize_username

    username = sanitize_username(username)
    if not username:
        return {'Erreur': 'Pseudo Instagram manquant'}
    opts = options or {}

    try:
        from connectors import instagram as ig_connector
        from services.runtime_env import is_hf_space

        if ig_connector.is_available():
            ig_result = ig_connector.scan(username, opts)
            if ig_result and not ig_result.get('Erreur'):
                return ig_result
        elif is_hf_space():
            opts = dict(opts or {})
            opts.setdefault(
                '_hf_ig_note',
                'Mode Hugging Face léger (HTTP). Stories/highlights : VPS ou OSINT_IG_MODE=full.',
            )
    except Exception as e:
        logger.debug('Instagram instaloader %s: %s', username, e)
    headers = {
        'User-Agent': (
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) '
            'AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Instagram/312.0.0.0.0'
        ),
        'Accept': '*/*',
        'Accept-Language': 'fr-FR,fr;q=0.9,en;q=0.8',
        'X-IG-App-ID': '936619743392459',
        'X-Requested-With': 'XMLHttpRequest',
        'Referer': f'https://www.instagram.com/{username}/',
    }
    api_url = (
        f'https://www.instagram.com/api/v1/users/web_profile_info/?username={username}'
    )
    api_404 = False
    try:
        r = social_http_get(api_url, opts, headers=headers, timeout=18)
        if r and r.status_code == 200:
            try:
                parsed = parse_instagram_api_json(r.json())
                if parsed:
                    return _merge_hf_note(parsed)
            except (json.JSONDecodeError, ValueError):
                pass
        api_404 = bool(r and r.status_code == 404)
    except Exception as e:
        logger.debug('Instagram API %s: %s', username, e)

    hf_note = (opts or {}).pop('_hf_ig_note', None)

    def _merge_hf_note(results: dict) -> dict:
        if hf_note and isinstance(results, dict):
            prev = results.get('Note', '')
            results['Note'] = f'{prev} {hf_note}'.strip() if prev else hf_note
        return results

    profile_url = f'https://www.instagram.com/{username}/'
    html_404 = False
    try:
        r2 = social_http_get(profile_url, opts, headers=headers, timeout=18)
        if r2:
            if r2.status_code == 404:
                html_404 = True
            elif r2.status_code == 200:
                results = parse_instagram_profile_html(r2.text, username)
                if (
                    results.get('Followers')
                    or results.get('Nom complet')
                    or results.get('Publications')
                    or results.get('Description')
                ):
                    if 'Note' not in results:
                        results['Note'] = (
                            'Métadonnées publiques (Open Graph). '
                            'Pas de téléchargement des photos sur ce déploiement.'
                        )
                    return _merge_hf_note(results)
                if profile_exists_in_html(r2.text, username):
                    return _merge_hf_note({
                        'Profil': profile_url,
                        'Résultat': (
                            'Profil détecté — bio/stats masquées '
                            '(connexion Instagram ou VPS + session requise)'
                        ),
                        'Note': hf_note or (
                            'Le lien profil est valide. Pour bio, posts et stories : '
                            'déployer sur VPS avec session-ig (voir docs/VPS_DEPLOY.md).'
                        ),
                    })
                if 'login' in r2.url.lower() or 'connexion' in (r2.text or '')[:3000].lower():
                    return _merge_hf_note({
                        'Profil': profile_url,
                        'Résultat': 'Profil existant (page login — données masquées)',
                        'Note': (
                            'Instagram exige une session pour les détails. '
                            'VPS + session-ig ou ouvrir le lien manuellement.'
                        ),
                    })
    except Exception as e:
        return _merge_hf_note({'Erreur': str(e), 'Profil': profile_url})

    if html_404 and api_404:
        return _merge_hf_note({
            'Profil': profile_url,
            'Résultat': 'Compte non trouvé',
        })

    return _merge_hf_note({
        'Profil': profile_url,
        'Résultat': 'Données limitées — ouvrez le lien profil ou utilisez le VPS (instaloader)',
        'Note': hf_note or 'Instagram bloque souvent les requêtes depuis Hugging Face.',
    })


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
    from services.social_fetch import social_http_get

    username = username.strip().lstrip('@')
    results = {}
    try:
        r = social_http_get(f'https://www.tiktok.com/@{username}', options)
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
    from services.social_fetch import social_http_get

    username = username.strip()
    results = {'Profil': f'https://www.facebook.com/{username}'}
    try:
        r = social_http_get(f'https://www.facebook.com/{username}', options)
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
    from services.social_fetch import social_http_get

    username = username.strip()
    results = {'Profil': f'https://www.linkedin.com/in/{username}/'}
    try:
        r = social_http_get(f'https://www.linkedin.com/in/{username}/', options)
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
    from services.social_fetch import social_http_get

    username = username.strip().lstrip('@')
    results = {}
    try:
        r = social_http_get(f'https://www.snapchat.com/add/{username}', options)
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
