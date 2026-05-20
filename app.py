#!/usr/bin/env python3
"""
OSINT ULTIMATE V3.0 – Vercel Edition
Sans WebSocket, sans nmap, sans weasyprint.
"""
import os, json, re, socket, hashlib, threading, queue, time, random
from datetime import datetime
from urllib.parse import urlparse

import requests
import whois
import dns.resolver
from bs4 import BeautifulSoup
import phonenumbers
from phonenumbers import carrier, geocoder, timezone as ph_timezone, PhoneNumberType

from flask import (Flask, render_template, request, jsonify, session,
                   redirect, url_for, flash, send_file, abort)
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                         login_required, current_user)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# ---------- CONFIG ----------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-me')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///osint.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = '/tmp/uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ---------- MODELS ----------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    module = db.Column(db.String(50))
    target = db.Column(db.String(500))
    result_json = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')  # pending/running/completed

with app.app_context():
    db.create_all()

# ---------- AUTH ----------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username déjà utilisé.')
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
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            login_user(user)
            return redirect(url_for('index'))
        flash('Identifiants invalides.')
    return render_template('auth.html', mode='login')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# ---------- SCAN WORKER (sans socketio) ----------
scan_queue = queue.Queue()

def worker():
    while True:
        task = scan_queue.get()
        if task is None:
            break
        scan_id, func, args, kwargs = task
        with app.app_context():
            scan = Scan.query.get(scan_id)
            scan.status = 'running'
            db.session.commit()
            try:
                result = func(*args, **kwargs)
                scan.result_json = json.dumps(result)
                scan.status = 'completed'
            except Exception as e:
                scan.result_json = json.dumps({'error': str(e)})
                scan.status = 'completed'
            db.session.commit()
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

# ---------- SCAN MODULES (versions légères) ----------
def scan_site(target):
    domain = target if not target.startswith('http') else urlparse(target).netloc
    results = {}
    # WHOIS
    try:
        w = whois.whois(domain)
        results['WHOIS'] = {
            'Registrar': w.registrar,
            'Création': str(w.creation_date),
            'Expiration': str(w.expiration_date)
        }
    except Exception as e:
        results['WHOIS'] = {'Erreur': str(e)}
    # DNS
    dns_rec = {}
    for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            dns_rec[rtype] = [str(r) for r in answers]
        except:
            dns_rec[rtype] = []
    results['DNS'] = dns_rec
    # Headers & IP
    try:
        resp = requests.get(f'http://{domain}', timeout=10)
        results['Headers HTTP'] = dict(resp.headers)
        results['Statut HTTP'] = resp.status_code
        ip = socket.gethostbyname(domain)
        results['IP'] = ip
        if not (ip.startswith('10.') or ip.startswith('192.168.')):
            geo = requests.get(f'http://ip-api.com/json/{ip}', timeout=5).json()
            if geo.get('status') == 'success':
                results['Géolocalisation'] = {
                    'Pays': geo.get('country'),
                    'Ville': geo.get('city'),
                    'Lat': geo.get('lat'),
                    'Lon': geo.get('lon')
                }
    except Exception as e:
        results['Headers'] = str(e)
    # Technologies
    techs = {}
    try:
        resp = requests.get(f'http://{domain}', timeout=10)
        soup = BeautifulSoup(resp.text, 'html.parser')
        server = resp.headers.get('Server', '')
        if server: techs['Serveur'] = server
        gen = soup.find('meta', attrs={'name': 'generator'})
        if gen and gen.get('content'): techs['Générateur'] = gen['content']
        techs['robots.txt'] = 'Accessible' if requests.get(f'http://{domain}/robots.txt').status_code == 200 else 'Non'
    except Exception as e:
        techs['Erreur'] = str(e)
    results['Technologies'] = techs
    return results

def scan_email(email, options=None):
    # version simplifiée
    if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
        return {'Valide': False}
    domain = email.split('@')[1]
    result = {'Valide': True}
    try:
        mx = dns.resolver.resolve(domain, 'MX')
        result['MX'] = [str(r.exchange) for r in mx]
    except: pass
    return result

def scan_phone(phone_str):
    try:
        p = phonenumbers.parse(phone_str, None)
        return {
            'Possible': phonenumbers.is_possible_number(p),
            'Valide': phonenumbers.is_valid_number(p),
            'Type': 'Mobile' if phonenumbers.number_type(p) == PhoneNumberType.MOBILE else 'Autre',
            'Pays': geocoder.description_for_number(p, 'fr'),
            'Opérateur': carrier.name_for_number(p, 'fr')
        }
    except: return {'error': 'invalide'}

def scan_ip(ip):
    if ip.startswith('10.') or ip.startswith('192.168.'):
        return {'Erreur': 'IP privée'}
    try:
        geo = requests.get(f'http://ip-api.com/json/{ip}').json()
        if geo.get('status') == 'success':
            return {
                'Pays': geo['country'],
                'Ville': geo['city'],
                'FAI': geo['isp'],
                'Lat': geo['lat'],
                'Lon': geo['lon']
            }
    except: pass
    return {'error': 'non trouvé'}

def scan_pseudo(username):
    # version limitée à quelques sites
    sites = {
        'GitHub': f'https://github.com/{username}',
        'Twitter': f'https://twitter.com/{username}',
        'Instagram': f'https://www.instagram.com/{username}/',
        'Reddit': f'https://www.reddit.com/user/{username}',
        'Snapchat': f'https://www.snapchat.com/add/{username}'
    }
    results = {}
    for name, url in sites.items():
        try:
            r = requests.get(url, timeout=5)
            if name == 'Snapchat':
                results[name] = 'Existe' if username.lower() in r.url.lower() else 'Non'
            else:
                results[name] = 'Existe' if r.status_code == 200 else 'Non'
        except:
            results[name] = 'Erreur'
    return results

# ... ajoute les autres modules (instagram, twitter, etc.) de manière similaire

SCAN_FUNCTIONS = {
    'site': scan_site,
    'email': scan_email,
    'phone': scan_phone,
    'ip': scan_ip,
    'pseudo': scan_pseudo,
    # etc.
}

# ---------- ROUTES ----------
@app.route('/')
def index():
    return render_template('index.html',
        authenticated=current_user.is_authenticated,
        username=current_user.username if current_user.is_authenticated else None)

@app.route('/scan', methods=['POST'])
def scan_start():
    data = request.json
    module = data.get('module')
    target = data.get('target', '').strip()
    options = data.get('options', [])
    user_id = current_user.id if current_user.is_authenticated else None
    scan_id = run_scan_async(module, target, options, user_id)
    if scan_id:
        return jsonify({'scan_id': scan_id})
    return jsonify({'error': 'Module inconnu'}), 400

@app.route('/scan/<int:scan_id>')
def scan_result(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    if scan.status == 'completed':
        return jsonify(json.loads(scan.result_json))
    return jsonify({'status': scan.status})

@app.route('/history')
@login_required
def history():
    scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.timestamp.desc()).all()
    return render_template('history.html', scans=scans)

# upload de fichier simple (sans analyse EXIF lourde)
@app.route('/upload', methods=['POST'])
@login_required
def upload():
    file = request.files['file']
    filename = file.filename
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    return jsonify({'filename': filename, 'size': os.path.getsize(filepath)})

# IA summary (optionnel)
@app.route('/ai-summary', methods=['POST'])
def ai_summary():
    data = request.json
    text = json.dumps(data.get('result', {}))
    key = os.environ.get('OPENROUTER_KEY')
    if not key:
        return jsonify({'error': 'Clé manquante'}), 500
    resp = requests.post(
        'https://openrouter.ai/api/v1/chat/completions',
        headers={'Authorization': f'Bearer {key}'},
        json={'model': 'mistralai/mistral-7b-instruct:free', 'messages': [{'role': 'user', 'content': f'Résume en français : {text}'}]}
    )
    if resp.status_code == 200:
        return jsonify({'summary': resp.json()['choices'][0]['message']['content']})
    return jsonify({'error': 'Échec IA'}), 500

# ---------- PWA ----------
@app.route('/sw.js')
def sw():
    return app.send_static_file('sw.js')
@app.route('/manifest.json')
def manifest():
    return app.send_static_file('manifest.json')

if __name__ == '__main__':
    app.run()
