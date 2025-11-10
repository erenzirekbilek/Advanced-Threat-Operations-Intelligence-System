from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import json
import threading
import time
import re
from collections import Counter

# ------------------ APP & DB ------------------
app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///esip.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ------------------ MODELLER ------------------
class SystemLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    source_ip = db.Column(db.String(50))
    destination_ip = db.Column(db.String(50))
    port = db.Column(db.Integer)
    protocol = db.Column(db.String(20))
    action = db.Column(db.String(50))
    user_id = db.Column(db.String(100))
    status_code = db.Column(db.Integer)
    message = db.Column(db.Text)
    raw_log = db.Column(db.Text)

class ThreatDetection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    threat_type = db.Column(db.String(100))
    severity = db.Column(db.String(20))
    source_ip = db.Column(db.String(50))
    destination_ip = db.Column(db.String(50))
    description = db.Column(db.Text)
    status = db.Column(db.String(50), default='active')
    detection_method = db.Column(db.String(100))
    confidence_score = db.Column(db.Float)
    related_logs = db.Column(db.Text)

class ComplianceCheck(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    standard = db.Column(db.String(50))
    check_name = db.Column(db.String(200))
    status = db.Column(db.String(20))
    score = db.Column(db.Float)
    details = db.Column(db.Text)

# ------------------ THREAT DETECTOR ------------------
class ThreatDetector:
    BLACKLISTED_IPS = ['203.0.113.', '198.51.100.', '192.0.2.', '185.220.101.']
    MALICIOUS_PATTERNS = {
        'sql_injection': r"('|(--)|;|\bOR\b|\bAND\b|\bUNION\b|\bSELECT\b|\bDROP\b)",
        'xss': r'(<script|javascript:|onerror=|onclick=)',
        'path_traversal': r'(\.\./|\.\.\\)',
        'command_injection': r'(;|\||&|`|\$\()'
    }
    PORT_SCAN_THRESHOLD = 10

    @staticmethod
    def detect_brute_force(logs, time_window=5):
        failed_logins = {}
        threats = []
        cutoff_time = datetime.utcnow() - timedelta(minutes=time_window)
        for log in logs:
            if log.action == 'login' and log.status_code in [401,403]:
                if log.timestamp >= cutoff_time:
                    failed_logins.setdefault(log.source_ip, []).append(log)
        for ip, attempts in failed_logins.items():
            if len(attempts) >= 5:
                threats.append({
                    'type':'Brute Force Attack',
                    'severity':'high',
                    'source_ip':ip,
                    'description':f'{len(attempts)} failed login attempts detected',
                    'confidence':0.85,
                    'method':'pattern_analysis'
                })
        return threats

    @staticmethod
    def detect_blacklisted_ip(log):
        threats = []
        for blacklisted in ThreatDetector.BLACKLISTED_IPS:
            if log.source_ip.startswith(blacklisted):
                threats.append({
                    'type':'Blacklisted IP',
                    'severity':'critical',
                    'source_ip':log.source_ip,
                    'description':'Known malicious IP detected',
                    'confidence':0.99,
                    'method':'threat_intelligence'
                })
        return threats

# ------------------ BACKGROUND ------------------
def analyze_threats_background():
    with app.app_context():
        while True:
            try:
                recent_logs = SystemLog.query.filter(
                    SystemLog.timestamp >= datetime.utcnow() - timedelta(minutes=10)
                ).all()
                detector = ThreatDetector()
                all_threats = []

                # Brute force ve blacklisted IP kontrolü
                all_threats.extend(detector.detect_brute_force(recent_logs))
                for log in recent_logs:
                    all_threats.extend(detector.detect_blacklisted_ip(log))

                # Veritabanına ekle
                for threat in all_threats:
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
                db.session.commit()
            except Exception as e:
                print(f"Background analysis error: {e}")
            time.sleep(30)

# ------------------ API ENDPOINTS ------------------
@app.route('/api/ingest/log', methods=['POST'])
def ingest_log():
    data = request.json
    try:
        log = SystemLog(
            source_ip=data.get('source_ip'),
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
        db.session.commit()
        return jsonify({'status':'success','log_id':log.id}),201
    except Exception as e:
        return jsonify({'status':'error','message':str(e)}),500

@app.route('/api/threats', methods=['GET'])
def get_threats():
    threats = ThreatDetection.query.order_by(ThreatDetection.timestamp.desc()).limit(50).all()
    return jsonify([{
        'id':t.id,
        'type':t.threat_type,
        'severity':t.severity,
        'source':t.source_ip,
        'time':t.timestamp.isoformat(),
        'status':t.status,
        'description':t.description,
        'confidence':t.confidence_score,
        'method':t.detection_method
    } for t in threats])

# ------------------ START SERVER ------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("✓ Database created")

        # Background threat analysis thread
        thread = threading.Thread(target=analyze_threats_background, daemon=True)
        thread.start()
        print("✓ Background threat analysis started")

    print("\n=== ESIP Backend Started ===\n")
    app.run(debug=True, port=5000)
