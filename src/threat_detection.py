import re
from datetime import datetime, timedelta
from collections import Counter

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
            if not hasattr(log, 'timestamp') or not log.timestamp:
                continue  # timestamp yoksa atla
            if log.action=='login' and log.status_code in [401,403] and log.timestamp >= cutoff:
                failed_logins.setdefault(log.source_ip, []).append(log)
        for ip, attempts in failed_logins.items():
            if len(attempts) >= 5:
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
            if not hasattr(log, 'timestamp') or not log.timestamp:
                continue
            if log.action=='network_request' and log.timestamp>=cutoff:
                ip_ports.setdefault(log.source_ip,set()).add(log.port)
        for ip, ports in ip_ports.items():
            if len(ports)>=ThreatDetector.PORT_SCAN_THRESHOLD:
                threats.append({
                    'type':'Port Scan',
                    'severity':'medium',
                    'source_ip':ip,
                    'description':f'{len(ports)} port attempts',
                    'confidence':0.9,
                    'method':'behavioral_analysis'
                })
        return threats

    @staticmethod
    def detect_malicious_payload(log):
        threats=[]
        if not hasattr(log,'message') or not log.message:
            return threats
        for attack_type, pattern in ThreatDetector.MALICIOUS_PATTERNS.items():
            if re.search(pattern, log.message, re.IGNORECASE):
                severity='critical' if attack_type in ['sql_injection','command_injection'] else 'high'
                threats.append({
                    'type':f'{attack_type.replace("_"," ").title()} Attempt',
                    'severity':severity,
                    'source_ip':log.source_ip,
                    'description':f'Malicious payload detected: {attack_type}',
                    'confidence':0.95,
                    'method':'signature_based'
                })
        return threats

    @staticmethod
    def detect_blacklisted_ip(log):
        threats=[]
        if not hasattr(log,'source_ip') or not log.source_ip:
            return threats
        for ip_prefix in ThreatDetector.BLACKLISTED_IPS:
            if log.source_ip.startswith(ip_prefix):
                threats.append({
