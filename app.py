k#!/usr/bin/env python3
"""
OSINT ULTIMATE V3.0 – Full Async, Auth, DB, Reports, PWA, AI, etc.
"""
import os, re, json, socket, ssl, smtplib, hashlib, threading, queue, time, random
from datetime import datetime, timedelta
from urllib.parse import urlparse

import requests
import whois
import dns.resolver
from bs4 import BeautifulSoup
import phonenumbers
from phonenumbers import carrier, geocoder, timezone as ph_timezone, PhoneNumberType
import nmap
from PIL import Image
from PIL.ExifTags import TAGS
import docx
import PyPDF2
from weasyprint import HTML
from cryptography.fernet import Fernet
from flask import (Flask, render_template, request, jsonify, session,
                   redirect, url_for, flash, send_file, abort)
from flask_socketio import SocketIO, emit
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                         login_required, current_user)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'super-secret-change-me')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///osint.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

socketio = SocketIO(app, async_mode='threading')
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ---------- ENCRYPTION ----------
fernet_key = os.environ.get('FERNET_KEY', Fernet.generate_key())
fernet = Fernet(fernet_key)

# ---------- PROXY & UA ROTATION ----------
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ...",
    # ... liste complète
]
PROXIES = []  # chargés depuis PROXY_LIST env

def get_requests_session():
    session = requests.Session()
    session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
    if PROXIES:
        proxy = random.choice(PROXIES)
        session.proxies = {'http': proxy, 'https': proxy}
    return session

def safe_get(url, **kwargs):
    try:
        sess = get_requests_session()
        return sess.get(url, timeout=25, **kwargs)
    except Exception:
        return None

# ---------- MODELS ----------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    api_keys = db.Column(db.Text)  # JSON encrypted

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_api_keys(self):
        if self.api_keys:
            decrypted = fernet.decrypt(self.api_keys.encode()).decode()
            return json.loads(decrypted)
        return {}

    def set_api_keys(self, keys_dict):
        encrypted = fernet.encrypt(json.dumps(keys_dict).encode()).decode()
        self.api_keys = encrypted

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
            flash('Username already exists.', 'error')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
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
        flash('Invalid credentials.', 'error')
    return render_template('auth.html', mode='login')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# ---------- ASYNC SCAN WORKER ----------
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
                db.session.commit()
                socketio.emit(f'scan_{scan_id}_done', {'result': result})
            except Exception as e:
                scan.result_json = json.dumps({'error': str(e)})
                scan.status = 'completed'
                db.session.commit()
                socketio.emit(f'scan_{scan_id}_error', {'error': str(e)})
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

# ---------- SCAN FUNCTIONS ----------
def scan_site(target, **kwargs):
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
    # Ports avec nmap
    try:
        nm = nmap.PortScanner()
        nm.scan(domain, '21,22,80,443,8080,8443,3306,3389')
        open_ports = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    open_ports.append(f"{port}/{proto}")
        results['Ports ouverts (nmap)'] = open_ports
    except Exception as e:
        results['Ports'] = f"Erreur nmap: {e}"
    # Headers & IP
    try:
        resp = safe_get(f'http://{domain}')
        if resp:
            results['Headers HTTP'] = dict(resp.headers)
            results['Statut HTTP'] = resp.status_code
            ip = socket.gethostbyname(domain)
            results['IP'] = ip
            if not (ip.startswith('10.') or ip.startswith('192.168.')):
                geo_resp = safe_get(f'http://ip-api.com/json/{ip}')
                if geo_resp and geo_resp.status_code == 200:
                    geo = geo_resp.json()
                    if geo.get('status') == 'success':
                        results['Géolocalisation'] = {
                            'Pays': geo.get('country'),
                            'Ville': geo.get('city'),
                            'Lat': geo.get('lat'),
                            'Lon': geo.get('lon')
                        }
    except Exception as e:
        results['Headers'] = str(e)
    # Technologies & vulns
    techs = {}
    try:
        resp = safe_get(f'http://{domain}')
        if resp:
            soup = BeautifulSoup(resp.text, 'html.parser')
            server = resp.headers.get('Server', '')
            if server:
                techs['Serveur'] = server
            gen = soup.find('meta', attrs={'name': 'generator'})
            if gen and gen.get('content'):
                techs['Générateur'] = gen['content']
            # recherche WordPress, etc.
            techs['robots.txt'] = 'Accessible' if safe_get(f'http://{domain}/robots.txt') else 'Non'
    except Exception as e:
        techs['Erreur'] = str(e)
    results['Technologies'] = techs
    # En-têtes de sécurité
    security_headers = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options']
    sec_result = {}
    if resp:
        for h in security_headers:
            sec_result[h] = resp.headers.get(h, 'Absent')
    results['Sécurité'] = sec_result
    # Wayback
    try:
        wayback_resp = safe_get(f'https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit=5')
        if wayback_resp and wayback_resp.status_code == 200:
            data = wayback_resp.json()
            if len(data) > 1:
                results['Wayback'] = [{'timestamp': row[0], 'url': row[1]} for row in data[1:]]
    except:
        pass
    return results

def scan_email(email, options=None):
    # ... (code complet de V2.1, avec sous-options)
    pass

def scan_phone(phone_str):
    # ... (analyse locale + Numverify + WhatsApp/Telegram)
    pass

def scan_ip(ip):
    # ... (ip-api, Shodan, SecurityTrails)
    pass

def scan_pseudo(username):
    # ... (recherche sur 20+ plateformes)
    pass

def scan_instagram(username):
    # ... (JSON + fallback HTML)
    pass

# (Tous les autres modules sociaux)

SCAN_FUNCTIONS = {
    'site': scan_site,
    'email': scan_email,
    'phone': scan_phone,
    'ip': scan_ip,
    'pseudo': scan_pseudo,
    'instagram': scan_instagram,
    # ... etc.
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
        return jsonify({'scan_id': scan_id, 'status': 'started'})
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

@app.route('/export/<int:scan_id>')
@login_required
def export(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    if scan.user_id != current_user.id:
        abort(403)
    data = json.loads(scan.result_json)
    return jsonify(data)  # simplification

@app.route('/report/<int:scan_id>')
@login_required
def report(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    if scan.user_id != current_user.id:
        abort(403)
    data = json.loads(scan.result_json)
    html_str = render_template('report.html', scan=scan, data=data)
    pdf = HTML(string=html_str).write_pdf()
    return send_file(pdf, mimetype='application/pdf', as_attachment=True, download_name=f'osint_report_{scan_id}.pdf')

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    if 'file' not in request.files:
        return jsonify({'error': 'Aucun fichier'}), 400
    file = request.files['file']
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(filepath)
    metadata = {}
    # Extraction selon type
    ext = file.filename.split('.')[-1].lower()
    try:
        if ext in ('jpg', 'jpeg', 'png'):
            img = Image.open(filepath)
            exif = img._getexif()
            if exif:
                for tag, value in exif.items():
                    tag_name = TAGS.get(tag, tag)
                    metadata[tag_name] = str(value)
        elif ext == 'pdf':
            reader = PyPDF2.PdfReader(filepath)
            metadata = reader.metadata
        elif ext == 'docx':
            doc = docx.Document(filepath)
            metadata['author'] = doc.core_properties.author
            metadata['modified'] = str(doc.core_properties.modified)
    except Exception as e:
        metadata['error'] = str(e)
    return jsonify({'metadata': metadata})

@app.route('/ai-summary', methods=['POST'])
def ai_summary():
    data = request.json
    text = json.dumps(data.get('result', {}))
    key = os.environ.get('OPENROUTER_KEY')
    if not key:
        return jsonify({'error': 'Clé API OpenRouter non configurée'}), 500
    resp = requests.post(
        'https://openrouter.ai/api/v1/chat/completions',
        headers={'Authorization': f'Bearer {key}'},
        json={
            'model': 'mistralai/mistral-7b-instruct:free',
            'messages': [{'role': 'user', 'content': f'Résume ces résultats OSINT en français:\n{text}'}]
        }
    )
    if resp.status_code == 200:
        summary = resp.json()['choices'][0]['message']['content']
        return jsonify({'summary': summary})
    return jsonify({'error': 'Échec de l\'IA'}), 500

# ---------- SOCKETIO EVENTS ----------
@socketio.on('connect')
def handle_connect():
    print('Client connected')

# ---------- PWA ROUTES ----------
@app.route('/sw.js')
def service_worker():
    return app.send_static_file('sw.js')

@app.route('/manifest.json')
def manifest():
    return app.send_static_file('manifest.json')

if __name__ == '__main__':
    socketio.run(app, debug=True)
