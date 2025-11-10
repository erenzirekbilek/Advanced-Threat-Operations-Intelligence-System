from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

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
    description = db.Column(db.Text)
    status = db.Column(db.String(50), default='active')
    detection_method = db.Column(db.String(100))
    confidence_score = db.Column(db.Float)

class ComplianceCheck(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    standard = db.Column(db.String(50))
    check_name = db.Column(db.String(200))
    status = db.Column(db.String(20))
    score = db.Column(db.Float)
    details = db.Column(db.Text)