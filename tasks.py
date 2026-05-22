"""Tâches Celery — migration progressive depuis le worker thread."""
import os

try:
    from celery_app import celery_app, enabled
except ImportError:
    enabled = False
    celery_app = None


if enabled and celery_app:

    @celery_app.task(bind=True, name='osint.run_scan')
    def run_scan_task(self, scan_id: int):
        """Exécute un scan en file Celery (à brancher sur le worker existant)."""
        from app import app, db, SCAN_FUNCTIONS, fernet
        from models import Scan
        from services.user_keys import get_key

        with app.app_context():
            scan = db.session.get(Scan, scan_id)
            if not scan:
                return {'error': 'scan not found'}
            func = SCAN_FUNCTIONS.get(scan.module)
            if not func:
                return {'error': 'unknown module'}
            opts = {}
            if scan.user_id:
                u = db.session.get(__import__('models', fromlist=['User']).User, scan.user_id)
                if u:
                    for opt_k, ukey, env in [
                        ('_shodan_key', 'shodan', 'SHODAN_API_KEY'),
                        ('_hunter_key', 'hunter', 'HUNTER_API_KEY'),
                    ]:
                        opts[opt_k] = get_key(u, ukey, env, fernet) or os.environ.get(env, '')
                    if u.proxy_list:
                        opts['_proxy_list'] = u.proxy_list
                    if u.stealth_mode:
                        opts['_stealth_mode'] = True
            self.update_state(state='PROGRESS', meta={'scan_id': scan_id})
            result = func(scan.target, opts)
            scan.result_json = __import__('json').dumps(result, ensure_ascii=False, default=str)
            scan.status = 'completed'
            from datetime import datetime
            scan.completed_at = datetime.utcnow()
            db.session.commit()
            return {'scan_id': scan_id, 'status': 'completed'}

else:

    def run_scan_task(*args, **kwargs):
        raise RuntimeError('Celery désactivé — définir REDIS_URL')
