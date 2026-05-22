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
    proxy_list    = db.Column(db.Text)
    stealth_mode  = db.Column(db.Boolean, default=False)
    scrape_fallback_enabled = db.Column(db.Boolean, default=True, nullable=False)
    locale        = db.Column(db.String(5), default='fr')

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
    report_pdf_hash = db.Column(db.String(64), nullable=True, index=True)
    report_sealed_at = db.Column(db.DateTime, nullable=True)


class Entity(db.Model):
    __tablename__ = 'entity'

    id             = db.Column(db.Integer, primary_key=True)
    user_id        = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    entity_type    = db.Column(db.String(30), nullable=False, index=True)
    value          = db.Column(db.String(500), nullable=False, index=True)
    source_scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=True)
    created_at     = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    latitude       = db.Column(db.Float, nullable=True)
    longitude      = db.Column(db.Float, nullable=True)
    geo_label      = db.Column(db.String(255), nullable=True)
    geo_source     = db.Column(db.String(50), nullable=True)

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
    confidence   = db.Column(db.Float, default=0.5)
    sources_json = db.Column(db.Text)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at   = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


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
    webhook_url   = db.Column(db.String(500))
    alert_rules_json = db.Column(db.Text)
    last_snapshot_json = db.Column(db.Text)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    alerts = db.relationship('MonitoringAlert', backref='job', lazy='dynamic', foreign_keys='MonitoringAlert.job_id')


class MonitoringAlert(db.Model):
    """Historique des alertes surveillance (centre de notifications)."""
    __tablename__ = 'monitoring_alert'

    id           = db.Column(db.Integer, primary_key=True)
    user_id      = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    job_id       = db.Column(db.Integer, db.ForeignKey('scheduled_scan.id'), nullable=True, index=True)
    scan_id      = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=True)
    level        = db.Column(db.String(20), default='info', nullable=False)
    alert_type   = db.Column(db.String(50), nullable=False)
    message      = db.Column(db.Text, nullable=False)
    details_json = db.Column(db.Text)
    read         = db.Column(db.Boolean, default=False, nullable=False, index=True)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    owner = db.relationship('User', backref=db.backref('monitoring_alerts', lazy='dynamic'))


class ApiCache(db.Model):
    __tablename__ = 'api_cache'

    id         = db.Column(db.Integer, primary_key=True)
    provider   = db.Column(db.String(40), nullable=False, index=True)
    cache_key  = db.Column(db.String(64), unique=True, nullable=False, index=True)
    query      = db.Column('query', db.String(500))  # nom de colonne SQL ; ne pas utiliser ApiCache.query (conflit ORM)
    payload    = db.Column(db.Text, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class Webhook(db.Model):
    __tablename__ = 'webhook'

    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    url        = db.Column(db.String(500), nullable=False)
    enabled    = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class Investigation(db.Model):
    """Dossier d'investigation / enquête guidée par l'agent IA."""
    __tablename__ = 'investigation'

    id             = db.Column(db.Integer, primary_key=True)
    user_id        = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    title          = db.Column(db.String(200), nullable=False)
    objective      = db.Column(db.Text)
    status         = db.Column(db.String(20), default='pending', index=True)
    steps_json     = db.Column(db.Text)
    result_summary = db.Column(db.Text)
    root_entity_id = db.Column(db.Integer, db.ForeignKey('entity.id'), nullable=True)
    notes          = db.Column(db.Text)
    created_at     = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at     = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    completed_at   = db.Column(db.DateTime)


class InvestigationMessage(db.Model):
    __tablename__ = 'investigation_message'

    id                = db.Column(db.Integer, primary_key=True)
    user_id           = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    role              = db.Column(db.String(20), nullable=False)
    content           = db.Column(db.Text, nullable=False)
    suggested_actions = db.Column(db.Text)
    created_at        = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class Recipe(db.Model):
    """Recette d'investigation partageable (séquence de modules)."""
    __tablename__ = 'recipe'

    id             = db.Column(db.Integer, primary_key=True)
    user_id        = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    name           = db.Column(db.String(120), nullable=False)
    description    = db.Column(db.Text)
    target_types   = db.Column(db.Text)   # JSON: ["email","domain"]
    modules_json   = db.Column(db.Text, nullable=False)  # JSON: ["email","dehashed",...]
    is_public      = db.Column(db.Boolean, default=False, nullable=False, index=True)
    forked_from_id = db.Column(db.Integer, db.ForeignKey('recipe.id'), nullable=True)
    usage_count    = db.Column(db.Integer, default=0, nullable=False)
    created_at     = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at     = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    owner = db.relationship('User', backref=db.backref('recipes', lazy='dynamic'))
