"""Modèles SQLAlchemy V4 – Supabase / PostgreSQL."""
from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from extensions import db


class User(UserMixin, db.Model):
    __tablename__ = 'user'

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email         = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256))
    api_keys_enc  = db.Column(db.Text)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login    = db.Column(db.DateTime)

    scans = db.relationship('Scan', backref='owner', lazy='dynamic')

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)

    def get_api_keys(self, fernet):
        if self.api_keys_enc:
            try:
                import json
                return json.loads(fernet.decrypt(self.api_keys_enc.encode()).decode())
            except Exception:
                return {}
        return {}

    def set_api_keys(self, d, fernet):
        import json
        self.api_keys_enc = fernet.encrypt(json.dumps(d).encode()).decode()


class Scan(db.Model):
    __tablename__ = 'scan'

    id           = db.Column(db.Integer, primary_key=True)
    user_id      = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True, index=True)
    module       = db.Column(db.String(50), nullable=False)
    target       = db.Column(db.String(500), nullable=False)
    result_json  = db.Column(db.Text)
    ai_summary   = db.Column(db.Text)
    timestamp    = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    completed_at = db.Column(db.DateTime)
    status       = db.Column(db.String(20), default='pending', nullable=False, index=True)
