# routes/admin_routes.py
from flask import Blueprint, render_template
from app.models import AICategorizationLog, User
from sqlalchemy import func
from app import db
from sqlalchemy import func, case

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/admin/ai-metrics')
def ai_metrics():
    total_logs = AICategorizationLog.query.count()
    accepted_logs = AICategorizationLog.query.filter_by(accepted=True).count()
    overridden_logs = AICategorizationLog.query.filter_by(accepted=False).count()
    tag_logs_total = AICategorizationLog.query.filter(AICategorizationLog.ai_tags_guess.isnot(None)).count()
    tag_logs_accepted = AICategorizationLog.query.filter_by(tags_accepted=True).count()
    tag_logs_overridden = AICategorizationLog.query.filter_by(tags_accepted=False).count()
    tag_acceptance_rate = (tag_logs_accepted / tag_logs_total * 100) if tag_logs_total else 0

    acceptance_rate = (accepted_logs / total_logs * 100) if total_logs else 0

    # Top 5 most common mismatches
    top_mismatches = db.session.query(
        AICategorizationLog.ai_guess,
        AICategorizationLog.user_division,
        func.count().label("count")
    ).filter(AICategorizationLog.accepted == False)\
     .group_by(AICategorizationLog.ai_guess, AICategorizationLog.user_division)\
     .order_by(func.count().desc())\
     .limit(5).all()

    # Most overridden transactions by name (optional)
    # Most overridden by user
    per_user_stats = db.session.query(
        AICategorizationLog.user_id,
        func.count().label("total"),
        func.sum(case((AICategorizationLog.accepted == True, 1), else_=0)).label("accepted"),
        func.sum(case((AICategorizationLog.accepted == False, 1), else_=0)).label("overridden"),
    ).group_by(AICategorizationLog.user_id).all()

    # Convert user IDs to usernames if needed
    user_map = {u.id: u.username for u in User.query.all()}  # assumes User model has username

    return render_template('admin/ai_metrics.html',
                           total=total_logs,
                           accepted=accepted_logs,
                           overridden=overridden_logs,
                           acceptance_rate=round(acceptance_rate, 2),
                           top_mismatches=top_mismatches,
                           per_user_stats=per_user_stats,
                           user_map=user_map)
