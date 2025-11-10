# src/detectors.py
import re
import time
from datetime import datetime, timedelta
from utils import setup_logger, mask_ip, retry_on_exception

logger = setup_logger("detectors")

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
        failed_logins, threats = {}, []
        cutoff = datetime.utcnow() - timedelta(minutes=time_window)
        for log in logs:
            if not getattr(log, 'timestamp', None):
                continue
            if log.action == 'login' and log.status_code in [401,403] and log.timestamp >= cutoff:
                failed_logins.setdefault(log.source_ip, []).append(log)
        for ip, attempts in failed_logins.items():
            if len(attempts) >= 5:
                logger.info("Brute force detected from %s (%d attempts)", mask_ip(ip), len(attempts))
                threats.append({
                    'type': 'Brute Force',
                    'severity': 'high',
                    'source_ip': ip,
                    'description': f'{len(attempts)} failed login attempts',
                    'confidence': 0.85,
                    'method': 'pattern_analysis'
                })
        return threats

    @staticmethod
    def detect_port_scanning(logs, time_window=1):
        cutoff = datetime.utcnow() - timedelta(minutes=time_window)
        ip_ports, threats = {}, []
        for log in logs:
            if not getattr(log, 'timestamp', None):
                continue
            if log.action == 'network_request' and log.timestamp >= cutoff:
                ip_ports.setdefault(log.source_ip, set()).add(getattr(log,'port', None))
        for ip, ports in ip_ports.items():
            if len(ports) >= ThreatDetector.PORT_SCAN_THRESHOLD:
                logger.info("Port scan suspected from %s (%d ports)", mask_ip(ip), len(ports))
                threats.append({
                    'type': 'Port Scan',
                    'severity': 'medium',
                    'source_ip': ip,
                    'description': f'{len(ports)} port attempts',
                    'confidence': 0.9,
                    'method': 'behavioral_analysis'
                })
        return threats

    @staticmethod
    def detect_malicious_payload(log):
        threats = []
        msg = getattr(log, 'message', None)
        if not msg:
            return threats
        for attack_type, pattern in ThreatDetector.MALICIOUS_PATTERNS.items():
            if re.search(pattern, msg, re.IGNORECASE):
                sev = 'critical' if attack_type in ['sql_injection','command_injection'] else 'high'
                logger.debug("Payload match (%s) from %s", attack_type, mask_ip(getattr(log,'source_ip', None)))
                threats.append({
                    'type': f'{attack_type.replace("_"," ").title()} Attempt',
                    'severity': sev,
                    'source_ip': getattr(log,'source_ip', None),
                    'description': f'Malicious payload detected: {attack_type}',
                    'confidence': 0.95,
                    'method': 'signature_based'
                })
        return threats

    @staticmethod
    def detect_blacklisted_ip(log):
        threats = []
        src = getattr(log, 'source_ip', None)
        if not src:
            return threats
        for ip_prefix in ThreatDetector.BLACKLISTED_IPS:
            if src.startswith(ip_prefix):
                logger.warning("Blacklisted IP seen: %s", mask_ip(src))
                threats.append({
                    'type': 'Blacklisted IP',
                    'severity': 'critical',
                    'source_ip': src,
                    'description': 'Known malicious IP detected',
                    'confidence': 0.99,
                    'method': 'threat_intelligence'
                })
        return threats

# Background thread loop
@retry_on_exception(max_attempts=3, wait_seconds=1.0)
def analyze_threats_background(app):
    """
    Background analyzer running in Flask app context.
    Start with: threading.Thread(target=analyze_threats_background, args=(app,), daemon=True)
    """
    from models import SystemLog, ThreatDetection, db  # late import to avoid circulars
    logger.info("Background analyzer starting (thread)")

    with app.app_context():
        logger.info("Background analyzer app context entered")
        while True:
            try:
                recent_logs = SystemLog.query.filter(
                    SystemLog.timestamp >= datetime.utcnow() - timedelta(minutes=10)
                ).all()

                detector = ThreatDetector()
                all_threats = []
                all_threats.extend(detector.detect_brute_force(recent_logs))
                all_threats.extend(detector.detect_port_scanning(recent_logs))
                for log in recent_logs[-200:]:
                    all_threats.extend(detector.detect_malicious_payload(log))
                    all_threats.extend(detector.detect_blacklisted_ip(log))

                created = 0
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
                        created += 1

                if created:
                    db.session.commit()
                    logger.info("Background created %d new threats", created)
            except Exception as e:
                logger.exception("Background analyzer error: %s", e)

            time.sleep(30)  # Thread sleep outside try
