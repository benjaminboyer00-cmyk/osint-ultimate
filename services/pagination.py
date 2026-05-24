"""Pagination utilitaire pour listes SQLAlchemy / séquences."""
from math import ceil


def paginate_query(query, page: int = 1, per_page: int = 25, *, max_per_page: int = 50):
    page = max(1, int(page or 1))
    per_page = min(max_per_page, max(1, int(per_page or 25)))
    total = query.count()
    pages = max(1, ceil(total / per_page)) if total else 1
    page = min(page, pages)
    items = (
        query.offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )
    return {
        'items': items,
        'page': page,
        'per_page': per_page,
        'total': total,
        'pages': pages,
        'has_prev': page > 1,
        'has_next': page < pages,
    }
