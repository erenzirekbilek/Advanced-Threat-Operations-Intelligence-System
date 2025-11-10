# src/app.py
from flask import Flask, jsonify, request
from flask_cors import CORS
from datetime import datetime, timedelta
import json
import threading
import os


# local modules
from models import db, SystemLog, ThreatDetection, ComplianceCheck
from detectors import ThreatDetector, analyze_threats_background
from compliance import ComplianceChecker
from utils import setup_logger, SimpleRateLimiter, retry_on_exception, model_to_dict, mask_ip

# ---------- APP & LOGGER ----------
app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///esip.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
logger = setup_logger("esip", logfile="esip.log")

# Simple in-memory rate limiter per source_ip (dev only)
rate_limiter = SimpleRateLimiter(max_calls=60, window_seconds=60)  # 60 calls per minute

# small helper to safely commit with retries
@retry_on_exception(max_attempts=3, wait_seconds=0.5)
def db_commit():
    db.session.commit()

# ----------------- ENDPOINTS -----------------
@app.route('/api/ingest/log', methods=['POST'])
def ingest_log():
    data = request.json or {}
    src = data.get('source_ip') or "unknown"
    # rate limit by source IP
    if not rate_limiter.allow(src):
        logger.warning("Rate limit exceeded for %s", mask_ip(src))
        return jsonify({'status':'error','message':'rate limit exceeded'}), 429

    try:
        log = SystemLog(
            source_ip=src,
            destination_ip=data.get('destination_ip'),
            port=data.get('port'),
            protocol=data.get('protocol'),
            action=data.get('action'),
            user_id=data.get('user_id'),
            status_code=data.get('status_code'),
            message=data.get('message',''),
            raw_log=json.dumps(data)
        )
        db.session.add(log)
        db_commit()

        # realtime checks
        detector = ThreatDetector()
        threats = []
        threats.extend(detector.detect_malicious_payload(log))
        threats.extend(detector.detect_blacklisted_ip(log))

        created = 0
        for threat in threats:
            existing = ThreatDetection.query.filter_by(
                source_ip=threat['source_ip'],
                threat_type=threat['type'],
                status='active'
            ).first()
            if not existing:
                new_threat = ThreatDetection(
                    threat_type=threat['type'],
                    severity=threat['severity'],
                    source_ip=threat['source_ip'],
                    description=threat['description'],
                    detection_method=threat['method'],
                    confidence_score=threat['confidence']
                )
                db.session.add(new_threat)
                created += 1
        if created:
            db_commit()

        logger.info("Ingested log from %s action=%s threats=%d", mask_ip(src), data.get('action'), len(threats))
        return jsonify({'status':'success','log_id':log.id,'threats_detected': len(threats)}), 201

    except Exception as e:
        logger.exception("Failed ingesting log: %s", e)
        return jsonify({'status':'error','message':str(e)}), 500


@app.route('/api/threats', methods=['GET'])
def get_threats():
    status = request.args.get('status','active')
    severity = request.args.get('severity')
    query = ThreatDetection.query
    if status:
        query = query.filter_by(status=status)
    if severity:
        query = query.filter_by(severity=severity)
    threats = query.order_by(ThreatDetection.timestamp.desc()).limit(50).all()
    return jsonify([model_to_dict(t) for t in threats])


@app.route('/api/metrics', methods=['GET'])
def get_metrics():
    total_threats = ThreatDetection.query.count()
    active_incidents = ThreatDetection.query.filter_by(status='active').count()
    compliance_checks = ComplianceCheck.query.order_by(ComplianceCheck.timestamp.desc()).limit(4).all()
    avg_compliance = sum(c.score for c in compliance_checks)/len(compliance_checks) if compliance_checks else 94
    return jsonify({
        'totalThreats': total_threats,
        'activeIncidents': active_incidents,
        'systemUptime': 99.8,
        'complianceScore': round(avg_compliance,1)
    })


@app.route('/api/analytics/timeline', methods=['GET'])
def get_threat_timeline():
    hours = int(request.args.get('hours',24))
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    threats = ThreatDetection.query.filter(ThreatDetection.timestamp >= cutoff).all()
    timeline = {}
    for threat in threats:
        hour_key = threat.timestamp.strftime('%H:00')
        if hour_key not in timeline:
            timeline[hour_key] = {'critical':0,'high':0,'medium':0,'low':0}
        timeline[hour_key][threat.severity] += 1
    return jsonify([{'time':k, **v} for k,v in sorted(timeline.items())])


@app.route('/api/compliance/status', methods=['GET'])
def get_compliance_status():
    checker = ComplianceChecker()
    gdpr = checker.check_gdpr_compliance()
    pci = checker.check_pci_dss_compliance()
    return jsonify([gdpr, pci, {'standard':'ISO_27001','score':94,'status':'compliant'}, {'standard':'SOC_2','score':91,'status':'compliant'}])


@app.route('/api/simulate/attack', methods=['POST'])
def simulate_attack():
    attack_type = request.json.get('type','brute_force')
    if attack_type=='brute_force':
        for i in range(10):
            log = SystemLog(
                source_ip='192.168.1.100',
                destination_ip='10.0.0.1',
                port=22,
                protocol='SSH',
                action='login',
                user_id='admin',
                status_code=401,
                message='Authentication failed',
                raw_log=json.dumps({'attempt': i+1})
            )
            db.session.add(log)
    elif attack_type=='sql_injection':
        log = SystemLog(
            source_ip='203.0.113.45',
            destination_ip='10.0.0.5',
            port=80,
            protocol='HTTP',
            action='web_request',
            status_code=200,
            message="SELECT * FROM users WHERE id=1 OR 1=1--",
            raw_log=json.dumps({'payload':'malicious'})
        )
        db.session.add(log)
    db_commit()
    return jsonify({'status':'simulated','type':attack_type})


# ---------------- START SERVER ----------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        logger.info("Database initialized")

        # Sadece reloader'ın child sürecinde veya production modunda başlat
        if (not app.debug) or (os.environ.get("WERKZEUG_RUN_MAIN") == "true"):
            thread = threading.Thread(target=analyze_threats_background, args=(app,), daemon=True)
            thread.start()
            logger.info("Background threat analysis thread started")

    logger.info("ESIP Backend started on port 5000")
    app.run(debug=True, port=5000)