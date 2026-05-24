"""Blueprint principal des vues HTML."""
from flask import Blueprint

views_bp = Blueprint('views', __name__)


def entities_paginated(user_id: int, page: int = 1, per_page: int = 25) -> dict:
    from services.pagination import paginate_query
    from models import Entity
    from extensions import db
    q = db.session.query(Entity).filter_by(user_id=user_id).order_by(Entity.created_at.desc())
    return paginate_query(q, page=page, per_page=per_page, max_per_page=50)
