"""Monitoring, notifications, planification."""
from flask import render_template, request, jsonify, redirect, url_for, flash
from flask_login import login_required, current_user

from routes.views_bp import views_bp
from extensions import db
from models import ScheduledScan

def _jobs_for_user(user_id: int):
    from services.monitoring import frequency_label
    from services.entity_resolve import find_entity_for_target
    jobs = ScheduledScan.query.filter_by(user_id=user_id)\
        .order_by(ScheduledScan.next_run_at.asc()).all()
    for j in jobs:
        j.frequency_label = frequency_label(j.interval_hours or 24)
        ent = find_entity_for_target(user_id, j.target, j.module)
        j.entity_id = ent.id if ent else None
    return jobs


@views_bp.route('/monitoring', methods=['GET', 'POST'])
@login_required
def monitoring_page():
    from services.monitoring import create_monitoring_job
    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        module = request.form.get('module') or None
        frequency = request.form.get('frequency', 'daily')
        notify = request.form.get('notify_on_change') == 'on'
        from services.monitor_rules import rules_from_form
        alert_rules = rules_from_form(request.form)
        try:
            if target:
                create_monitoring_job(
                    current_user.id, target, module=module, frequency=frequency,
                    notify_on_change=notify,
                    alert_rules=alert_rules if notify else None,
                )
                flash('Surveillance activée.', 'success')
        except ValueError as e:
            flash(str(e), 'error')
        return redirect(url_for('views.monitoring_page'))

    from services.monitor_rules import RULE_LABELS, DEFAULT_RULES
    from services.notifications import list_alerts
    return render_template(
        'monitoring.html',
        jobs=_jobs_for_user(current_user.id),
        username=current_user.username,
        rule_labels=RULE_LABELS,
        default_rules=DEFAULT_RULES,
        recent_alerts=list_alerts(current_user.id, limit=30),
    )


@views_bp.route('/monitoring/quick', methods=['POST'])
@login_required
def monitoring_quick():
    """Création rapide depuis le mode Expert (après un scan)."""
    from services.monitoring import create_monitoring_job
    data = request.json or {}
    target = (data.get('target') or '').strip()
    module = data.get('module') or ''
    frequency = data.get('frequency', 'daily')
    if not target:
        return jsonify({'error': 'Cible manquante'}), 400
    try:
        from services.monitor_rules import parse_alert_rules
        job = create_monitoring_job(
            current_user.id, target, module=module or None, frequency=frequency,
            notify_on_change=bool(data.get('notify_on_change')),
            alert_rules=parse_alert_rules(data.get('alert_rules')),
        )
        return jsonify({
            'ok': True,
            'job_id': job.id,
            'message': f'Surveillance {job.target} programmée',
            'monitoring_url': url_for('views.monitoring_page'),
        })
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@views_bp.route('/monitoring/<int:job_id>/toggle', methods=['POST'])
@login_required
def monitoring_toggle(job_id):
    job = db.session.get(ScheduledScan, job_id)
    if job and job.user_id == current_user.id:
        job.enabled = not job.enabled
        db.session.commit()
    return redirect(url_for('views.monitoring_page'))


@views_bp.route('/notifications')
@login_required
def notifications_list():
    from services.notifications import list_alerts, unread_count
    return jsonify({
        'unread': unread_count(current_user.id),
        'alerts': list_alerts(current_user.id, limit=80),
    })


@views_bp.route('/notifications/count')
@login_required
def notifications_count():
    from services.notifications import unread_count
    return jsonify({'unread': unread_count(current_user.id)})


@views_bp.route('/notifications/<int:alert_id>/read', methods=['POST'])
@login_required
def notifications_mark_read(alert_id):
    from services.notifications import mark_read, unread_count
    if not mark_read(current_user.id, alert_id):
        return jsonify({'error': 'Alerte non trouvée'}), 404
    return jsonify({'ok': True, 'unread': unread_count(current_user.id)})


@views_bp.route('/notifications/read-all', methods=['POST'])
@login_required
def notifications_mark_all_read():
    from services.notifications import mark_all_read
    n = mark_all_read(current_user.id)
    return jsonify({'ok': True, 'marked': n, 'unread': 0})


@views_bp.route('/monitoring/<int:job_id>/delete', methods=['POST'])
@login_required
def monitoring_delete(job_id):
    job = db.session.get(ScheduledScan, job_id)
    if job and job.user_id == current_user.id:
        db.session.delete(job)
        db.session.commit()
    return redirect(url_for('views.monitoring_page'))


@views_bp.route('/scheduled', methods=['GET', 'POST'])
@views_bp.route('/scheduled/', methods=['GET', 'POST'])
@login_required
def scheduled_page():
    """Ancienne URL — délègue à /monitoring."""
    return monitoring_page()


@views_bp.route('/scheduled/<int:job_id>/toggle', methods=['POST'])
@login_required
def scheduled_toggle(job_id):
    return monitoring_toggle(job_id)


@views_bp.route('/scheduled/<int:job_id>/delete', methods=['POST'])
@login_required
def scheduled_delete(job_id):
    return monitoring_delete(job_id)
