#!/usr/bin/env python3
"""
Wazuh Integration Module for PCAP Analyzer
Handles log forwarding, alert generation, and dashboard data export
"""

import json
import socket
import time
from datetime import datetime
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class WazuhIntegration:
    """Integration with Wazuh SIEM for log forwarding and alerting"""
    
    def __init__(self, wazuh_manager_ip='127.0.0.1', wazuh_port=1514):
        self.wazuh_manager_ip = wazuh_manager_ip
        self.wazuh_port = wazuh_port
        self.socket = None
        self.log_dir = Path('/var/log/pcap_analyzer')
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
    def connect(self):
        """Establish connection to Wazuh Manager"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            logger.info(f"Connected to Wazuh Manager at {self.wazuh_manager_ip}:{self.wazuh_port}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to Wazuh Manager: {e}")
            return False
    
    def send_alert(self, alert_data):
        """Send alert to Wazuh Manager via syslog"""
        try:
            # Format as JSON syslog message
            timestamp = datetime.utcnow().strftime('%b %d %H:%M:%S')
            hostname = socket.gethostname()
            
            # Wazuh expects JSON in the message
            message = f"<14>{timestamp} {hostname} pcap_analyzer: {json.dumps(alert_data)}"
            
            if self.socket:
                self.socket.sendto(message.encode('utf-8'), 
                                 (self.wazuh_manager_ip, self.wazuh_port))
            
            # Also write to local log file
            log_file = self.log_dir / 'alerts.json'
            with open(log_file, 'a') as f:
                f.write(json.dumps(alert_data) + '\n')
            
            return True
        except Exception as e:
            logger.error(f"Failed to send alert: {e}")
            return False
    
    def format_port_scan_alert(self, risk_data):
        """Format port scan detection for Wazuh"""
        return {
            'timestamp': risk_data['timestamp'].isoformat(),
            'detection_type': 'Port Scan',
            'severity': risk_data['severity'],
            'src_ip': risk_data.get('src_ip', 'Unknown'),
            'dst_ip': risk_data.get('dst_ip', 'Unknown'),
            'port_count': risk_data.get('details', '').split()[0] if 'scanned' in risk_data.get('details', '') else 'Unknown',
            'description': risk_data['description'],
            'evidence': risk_data.get('evidence', ''),
            'mitre_attack': {
                'technique_id': 'T1046',
                'technique_name': 'Network Service Discovery',
                'tactic': 'Discovery'
            }
        }
    
    def format_beacon_alert(self, risk_data):
        """Format C2 beacon detection for Wazuh"""
        return {
            'timestamp': risk_data['timestamp'].isoformat(),
            'detection_type': 'C2 Beacon',
            'severity': risk_data['severity'],
            'src_ip': risk_data.get('src_ip', 'Unknown'),
            'dst_ip': risk_data.get('dst_ip', 'Unknown'),
            'interval': risk_data.get('details', 'Unknown'),
            'regularity_score': 0.9,  # Extract from details if available
            'description': risk_data['description'],
            'evidence': risk_data.get('evidence', ''),
            'mitre_attack': {
                'technique_id': 'T1071.001',
                'technique_name': 'Application Layer Protocol: Web Protocols',
                'tactic': 'Command and Control'
            }
        }
    
    def format_exfiltration_alert(self, risk_data):
        """Format data exfiltration detection for Wazuh"""
        return {
            'timestamp': risk_data['timestamp'].isoformat(),
            'detection_type': 'Data Exfiltration',
            'severity': risk_data['severity'],
            'src_ip': risk_data.get('src_ip', 'Unknown'),
            'dst_ip': risk_data.get('dst_ip', 'Unknown'),
            'bytes_transferred': risk_data.get('details', 'Unknown'),
            'exfil_method': 'HTTP POST',  # Extract from context
            'description': risk_data['description'],
            'evidence': risk_data.get('evidence', ''),
            'mitre_attack': {
                'technique_id': 'T1048',
                'technique_name': 'Exfiltration Over Alternative Protocol',
                'tactic': 'Exfiltration'
            }
        }
    
    def format_credential_alert(self, risk_data):
        """Format credential theft detection for Wazuh"""
        return {
            'timestamp': risk_data['timestamp'].isoformat(),
            'detection_type': 'Credential Theft',
            'severity': risk_data['severity'],
            'src_ip': risk_data.get('src_ip', 'Unknown'),
            'credential_type': risk_data.get('type', 'Unknown'),
            'description': risk_data['description'],
            'evidence': risk_data.get('evidence', ''),
            'mitre_attack': {
                'technique_id': 'T1040',
                'technique_name': 'Network Sniffing',
                'tactic': 'Credential Access'
            }
        }
    
    def format_ml_anomaly_alert(self, anomaly_data):
        """Format ML anomaly detection for Wazuh"""
        return {
            'timestamp': anomaly_data.get('timestamp', datetime.utcnow()).isoformat(),
            'detection_type': 'ML Anomaly',
            'severity': 'HIGH' if anomaly_data.get('score', 0) < -0.3 else 'MEDIUM',
            'src_ip': anomaly_data.get('src_ip', 'Unknown'),
            'dst_ip': anomaly_data.get('dst_ip', 'Unknown'),
            'anomaly_score': anomaly_data.get('score', 0),
            'anomaly_description': anomaly_data.get('type', 'Unknown anomaly'),
            'flow_details': anomaly_data.get('flow', ''),
            'description': f"ML detected anomalous behavior: {anomaly_data.get('type', 'Unknown')}",
            'mitre_attack': {
                'technique_id': 'T1071',
                'technique_name': 'Application Layer Protocol',
                'tactic': 'Command and Control'
            }
        }
    
    def format_threat_intel_alert(self, ioc_data):
        """Format threat intelligence match for Wazuh"""
        return {
            'timestamp': datetime.utcnow().isoformat(),
            'detection_type': 'Threat Intelligence Match',
            'severity': 'CRITICAL',
            'threat_intel_match': True,
            'indicator_type': ioc_data.get('type', 'Unknown'),
            'indicator_value': ioc_data.get('value', 'Unknown'),
            'threat_actor': ioc_data.get('threat_actor', 'Unknown'),
            'malware_family': ioc_data.get('malware_family', 'Unknown'),
            'confidence': ioc_data.get('confidence', 'Unknown'),
            'first_seen': ioc_data.get('first_seen', 'Unknown'),
            'description': f"Malicious indicator detected: {ioc_data.get('value', 'Unknown')}",
            'mitre_attack': {
                'technique_id': 'T1071',
                'technique_name': 'Application Layer Protocol',
                'tactic': 'Command and Control'
            }
        }
    
    def export_analysis_for_wazuh(self, analysis_results):
        """Export complete PCAP analysis results for Wazuh ingestion"""
        try:
            # Process risks
            for risk in analysis_results.get('risks', []):
                alert_data = None
                
                if 'Port Scan' in risk['type']:
                    alert_data = self.format_port_scan_alert(risk)
                elif 'Beacon' in risk['type']:
                    alert_data = self.format_beacon_alert(risk)
                elif 'Large Data Transfer' in risk['type'] or 'Exfil' in risk['type']:
                    alert_data = self.format_exfiltration_alert(risk)
                elif 'Credential' in risk['type']:
                    alert_data = self.format_credential_alert(risk)
                else:
                    # Generic alert
                    alert_data = {
                        'timestamp': risk['timestamp'].isoformat(),
                        'detection_type': risk['type'],
                        'severity': risk['severity'],
                        'description': risk['description'],
                        'src_ip': risk.get('src_ip', 'Unknown'),
                        'dst_ip': risk.get('dst_ip', 'Unknown'),
                    }
                
                if alert_data:
                    self.send_alert(alert_data)
            
            # Process ML anomalies
            for anomaly in analysis_results.get('ml_anomalies', []):
                alert_data = self.format_ml_anomaly_alert(anomaly)
                self.send_alert(alert_data)
            
            # Process threat intelligence matches
            for ioc in analysis_results.get('threat_intel_matches', []):
                alert_data = self.format_threat_intel_alert(ioc)
                self.send_alert(alert_data)
            
            logger.info(f"Exported {len(analysis_results.get('risks', []))} alerts to Wazuh")
            return True
        except Exception as e:
            logger.error(f"Failed to export analysis: {e}")
            return False
    
    def generate_dashboard_data(self, analysis_results):
        """Generate data structure optimized for Wazuh dashboards"""
        dashboard_data = {
            'summary': {
                'total_threats': len(analysis_results.get('risks', [])),
                'high_severity': len([r for r in analysis_results.get('risks', []) if r['severity'] == 'HIGH']),
                'medium_severity': len([r for r in analysis_results.get('risks', []) if r['severity'] == 'MEDIUM']),
                'low_severity': len([r for r in analysis_results.get('risks', []) if r['severity'] == 'LOW']),
                'ml_anomalies': len(analysis_results.get('ml_anomalies', [])),
                'threat_intel_matches': len(analysis_results.get('threat_intel_matches', []))
            },
            'threat_distribution': {},
            'mitre_techniques': {},
            'top_sources': {},
            'top_targets': {},
            'timeline': []
        }
        
        # Aggregate threat types
        for risk in analysis_results.get('risks', []):
            threat_type = risk['type']
            dashboard_data['threat_distribution'][threat_type] = \
                dashboard_data['threat_distribution'].get(threat_type, 0) + 1
        
        # Aggregate MITRE techniques
        # (Would need full mapping from analysis)
        
        # Top sources
        for risk in analysis_results.get('risks', []):
            src_ip = risk.get('src_ip', 'Unknown')
            dashboard_data['top_sources'][src_ip] = \
                dashboard_data['top_sources'].get(src_ip, 0) + 1
        
        # Export to file
        dashboard_file = self.log_dir / 'dashboard_data.json'
        with open(dashboard_file, 'w') as f:
            json.dump(dashboard_data, f, indent=2)
        
        return dashboard_data
    
    def close(self):
        """Close connection to Wazuh Manager"""
        if self.socket:
            self.socket.close()
            logger.info("Closed connection to Wazuh Manager")


def export_zeek_logs_to_wazuh(zeek_log_dir='/var/log/zeek/current'):
    """Export Zeek logs in Wazuh-compatible format"""
    wazuh_log_dir = Path('/var/log/pcap_analyzer/zeek')
    wazuh_log_dir.mkdir(parents=True, exist_ok=True)
    
    zeek_logs = ['conn.log', 'http.log', 'dns.log', 'ssl.log', 'files.log']
    
    for log_file in zeek_logs:
        zeek_file = Path(zeek_log_dir) / log_file
        if not zeek_file.exists():
            continue
        
        wazuh_file = wazuh_log_dir / f"{log_file}.json"
        
        # Convert Zeek TSV to JSON
        with open(zeek_file, 'r') as f_in, open(wazuh_file, 'w') as f_out:
            headers = None
            for line in f_in:
                line = line.strip()
                
                # Skip comments and separators
                if line.startswith('#'):
                    if '#fields' in line:
                        headers = line.split('\t')[1:]
                    continue
                
                if not headers:
                    continue
                
                # Parse fields
                fields = line.split('\t')
                if len(fields) == len(headers):
                    log_entry = dict(zip(headers, fields))
                    log_entry['log_type'] = log_file.replace('.log', '')
                    log_entry['source'] = 'zeek'
                    f_out.write(json.dumps(log_entry) + '\n')


def export_suricata_alerts_to_wazuh(suricata_log='/var/log/suricata/eve.json'):
    """Export Suricata alerts in Wazuh-compatible format"""
    wazuh_log_dir = Path('/var/log/pcap_analyzer/suricata')
    wazuh_log_dir.mkdir(parents=True, exist_ok=True)
    
    wazuh_file = wazuh_log_dir / 'alerts.json'
    
    if not Path(suricata_log).exists():
        logger.warning(f"Suricata log not found: {suricata_log}")
        return
    
    # Filter for alerts only
    with open(suricata_log, 'r') as f_in, open(wazuh_file, 'w') as f_out:
        for line in f_in:
            try:
                event = json.loads(line)
                if event.get('event_type') == 'alert':
                    # Add source tag
                    event['source'] = 'suricata'
                    f_out.write(json.dumps(event) + '\n')
            except json.JSONDecodeError:
                continue


if __name__ == "__main__":
    # Example usage
    wazuh = WazuhIntegration(wazuh_manager_ip='192.168.1.100')
    
    if wazuh.connect():
        # Example: Send test alert
        test_alert = {
            'timestamp': datetime.utcnow().isoformat(),
            'detection_type': 'Test Alert',
            'severity': 'LOW',
            'description': 'PCAP Analyzer Wazuh integration test',
            'src_ip': '192.168.1.1',
            'test': True
        }
        
        wazuh.send_alert(test_alert)
        wazuh.close()
