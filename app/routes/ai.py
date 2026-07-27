from flask import Blueprint, jsonify, request
from flask_login import login_required
from app.models import db, Log
from app.services.ai_analyzer import AIThreatAnalyzer

ai_bp = Blueprint('ai', __name__)

@ai_bp.route('/api/ai-analyze/<int:log_id>', methods=['POST'])
@login_required
def analyze_log(log_id):
    log = Log.query.get_or_404(log_id)
    
    force_refresh = request.args.get('refresh', 'false').lower() == 'true'
    
    if not log.ai_analysis or force_refresh:
        analysis_res = AIThreatAnalyzer.analyze_log(log)
        log.ai_analysis = analysis_res
        db.session.commit()
    else:
        analysis_res = log.ai_analysis

    return jsonify({
        'status': 'success',
        'log_id': log.id,
        'analysis': analysis_res
    })
