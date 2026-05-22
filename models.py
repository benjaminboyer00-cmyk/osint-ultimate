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
    api_token     = db.Column(db.String(64), unique=True, index=True)

    scans = db.relationship('Scan', backref='owner', lazy='dynamic')
    entities = db.relationship('Entity', backref='owner', lazy='dynamic')
    scheduled_scans = db.relationship('ScheduledScan', backref='owner', lazy='dynamic')

    def ensure_api_token(self):
        import secrets
        if not self.api_token:
            self.api_token = secrets.token_hex(32)
        return self.api_token

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
    mode         = db.Column(db.String(20), default='expert')
    scheduled_scan_id = db.Column(db.Integer, db.ForeignKey('scheduled_scan.id'), nullable=True)


class Entity(db.Model):
    __tablename__ = 'entity'

    id             = db.Column(db.Integer, primary_key=True)
    user_id        = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    entity_type    = db.Column(db.String(30), nullable=False, index=True)
    value          = db.Column(db.String(500), nullable=False, index=True)
    source_scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=True)
    created_at     = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        db.UniqueConstraint('user_id', 'entity_type', 'value', name='uq_entity_user_type_value'),
    )


class EntityLink(db.Model):
    __tablename__ = 'entity_link'

    id           = db.Column(db.Integer, primary_key=True)
    user_id      = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    source_id    = db.Column(db.Integer, db.ForeignKey('entity.id'), nullable=False)
    target_id    = db.Column(db.Integer, db.ForeignKey('entity.id'), nullable=False)
    link_type    = db.Column(db.String(50), nullable=False)
    source_proof = db.Column(db.String(500))
    scan_id      = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=True)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class ScheduledScan(db.Model):
    """Surveillance programmée d'une cible."""
    __tablename__ = 'scheduled_scan'

    id            = db.Column(db.Integer, primary_key=True)
    user_id       = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    module        = db.Column(db.String(50), nullable=False)
    target        = db.Column(db.String(500), nullable=False)
    interval_hours = db.Column(db.Integer, default=24, nullable=False)
    enabled       = db.Column(db.Boolean, default=True, nullable=False)
    last_run_at   = db.Column(db.DateTime)
    next_run_at   = db.Column(db.DateTime, index=True)
    last_scan_id  = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=True)
    notify_on_change = db.Column(db.Boolean, default=False)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
