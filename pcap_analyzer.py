#!/usr/bin/env python3
"""
Advanced PCAP Analyzer - Network Threat Detection Tool with ML & Threat Intel
Author: Cybersecurity Training Module
Description: Comprehensive packet analysis with ML anomaly detection, MITRE ATT&CK mapping,
            live IOC enrichment, and session reconstruction
"""

import argparse
import sys
import os
import json
import hashlib
import re
import time
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from pathlib import Path
import warnings
warnings.filterwarnings('ignore')

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    from scapy.layers.tls.all import TLS, TLSClientHello, TLSServerHello
except ImportError:
    print("ERROR: Scapy not installed. Run: pip install scapy")
    sys.exit(1)

try:
    import matplotlib
    matplotlib.use('Agg')  # Non-interactive backend
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
except ImportError:
    print("WARNING: Matplotlib not installed. Run: pip install matplotlib")
    plt = None

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
except ImportError:
    print("WARNING: ReportLab not installed. Run: pip install reportlab")
    SimpleDocTemplate = None

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("WARNING: Requests not installed. IOC enrichment disabled.")

# ML and Advanced Analytics
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    import numpy as np
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("WARNING: scikit-learn not installed. ML anomaly detection disabled.")
    print("         Run: pip install scikit-learn numpy")

# Session reconstruction
try:
    from scapy.sessions import TCPSession
    SESSION_RECONSTRUCTION = True
except ImportError:
    SESSION_RECONSTRUCTION = False
    print("WARNING: Advanced session reconstruction limited")

# STIX/MISP support
try:
    from stix2 import FileSystemSource, Filter
    STIX_AVAILABLE = True
except ImportError:
    STIX_AVAILABLE = False
    print("WARNING: STIX2 not installed. MISP integration disabled.")
    print("         Run: pip install stix2")

# ML and Advanced Analysis
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    import numpy as np
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("WARNING: scikit-learn not available. ML anomaly detection disabled.")
    print("         Install with: pip install scikit-learn numpy")

# Threat Intelligence
try:
    from pymisp import PyMISP
    MISP_AVAILABLE = True
except ImportError:
    MISP_AVAILABLE = False
    print("WARNING: PyMISP not available. MISP integration disabled.")
    print("         Install with: pip install pymisp")

# Session reconstruction
try:
    from scapy.sessions import TCPSession
    SESSION_RECONSTRUCTION = True
except ImportError:
    SESSION_RECONSTRUCTION = False
    print("WARNING: Session reconstruction limited - update Scapy")

# JA3 fingerprinting for TLS C2 detection
try:
    import hashlib
    JA3_AVAILABLE = True
except:
    JA3_AVAILABLE = False


# ============================================================================
# GLOBAL CONFIGURATION
# ============================================================================

# Suspicious TLDs (commonly used in malware/phishing)
SUSPICIOUS_TLDS = ['.xyz', '.top', '.info', '.club', '.online', '.site', '.tk', '.ml', '.ga', '.cf', '.gq']

# Known malicious/suspicious ports
SUSPICIOUS_PORTS = {
    4444: 'Metasploit default',
    6667: 'IRC (potential botnet)',
    31337: 'Back Orifice',
    12345: 'NetBus',
    1337: 'Common backdoor',
    3389: 'RDP (often targeted)',
    445: 'SMB (ransomware vector)',
    135: 'MS RPC',
    139: 'NetBIOS',
    5900: 'VNC'
}

# Insecure protocols
INSECURE_PROTOCOLS = {
    21: 'FTP',
    23: 'Telnet',
    80: 'HTTP',
    69: 'TFTP',
    110: 'POP3',
    143: 'IMAP'
}

# Common scanner user agents
SCANNER_USER_AGENTS = ['nikto', 'nmap', 'sqlmap', 'masscan', 'zap', 'burp', 'acunetix', 'nessus']

# Suspicious URI patterns
SUSPICIOUS_URIS = ['/admin', '/shell', '/cmd', '.php', '.asp', '/wp-admin', '/phpmyadmin', 
                   '/xmlrpc', '../../', '../etc/', '/passwd', '/shadow', 'union select']

# DGA detection - entropy threshold
DGA_ENTROPY_THRESHOLD = 3.5

# MITRE ATT&CK Technique Mapping
MITRE_ATTACK_MAPPING = {
    'Port Scan Detected': {
        'tactic': 'TA0007',
        'tactic_name': 'Discovery',
        'technique': 'T1046',
        'technique_name': 'Network Service Discovery',
        'description': 'Adversaries may attempt to get a listing of services running on remote hosts'
    },
    'Suspicious Port Activity': {
        'tactic': 'TA0011',
        'tactic_name': 'Command and Control',
        'technique': 'T1571',
        'technique_name': 'Non-Standard Port',
        'description': 'Adversaries may communicate using protocols on non-standard ports'
    },
    'Insecure Protocol': {
        'tactic': 'TA0006',
        'tactic_name': 'Credential Access',
        'technique': 'T1040',
        'technique_name': 'Network Sniffing',
        'description': 'Adversaries may sniff network traffic to capture credentials'
    },
    'Cleartext Credentials': {
        'tactic': 'TA0006',
        'tactic_name': 'Credential Access',
        'technique': 'T1040',
        'technique_name': 'Network Sniffing',
        'description': 'Credentials transmitted in cleartext over the network'
    },
    'Suspicious DNS Query': {
        'tactic': 'TA0011',
        'tactic_name': 'Command and Control',
        'technique': 'T1071.004',
        'technique_name': 'Application Layer Protocol: DNS',
        'description': 'Adversaries may use DNS for C2 communications'
    },
    'High DNS Query Volume': {
        'tactic': 'TA0010',
        'tactic_name': 'Exfiltration',
        'technique': 'T1048.003',
        'technique_name': 'Exfiltration Over Alternative Protocol: DNS',
        'description': 'DNS tunneling for data exfiltration'
    },
    'Beacon': {
        'tactic': 'TA0011',
        'tactic_name': 'Command and Control',
        'technique': 'T1071.001',
        'technique_name': 'Application Layer Protocol: Web Protocols',
        'description': 'Regular beaconing to C2 infrastructure'
    },
    'Large Data Transfer': {
        'tactic': 'TA0010',
        'tactic_name': 'Exfiltration',
        'technique': 'T1048',
        'technique_name': 'Exfiltration Over Alternative Protocol',
        'description': 'Large volume data exfiltration'
    },
    'Large HTTP POST': {
        'tactic': 'TA0010',
        'tactic_name': 'Exfiltration',
        'technique': 'T1048.003',
        'technique_name': 'Exfiltration Over Web Service',
        'description': 'Data exfiltration via HTTP POST'
    },
    'Malware Delivery': {
        'tactic': 'TA0001',
        'tactic_name': 'Initial Access',
        'technique': 'T1566',
        'technique_name': 'Phishing',
        'description': 'Malware payload delivery'
    },
    'Executable Download': {
        'tactic': 'TA0002',
        'tactic_name': 'Execution',
        'technique': 'T1204.002',
        'technique_name': 'User Execution: Malicious File',
        'description': 'Downloaded executable file'
    },
    'Scanner Detected': {
        'tactic': 'TA0007',
        'tactic_name': 'Discovery',
        'technique': 'T1595',
        'technique_name': 'Active Scanning',
        'description': 'Automated vulnerability scanning'
    },
    'Weak TLS Version': {
        'tactic': 'TA0011',
        'tactic_name': 'Command and Control',
        'technique': 'T1573',
        'technique_name': 'Encrypted Channel',
        'description': 'Weak encryption may indicate C2 or be exploitable'
    }
}

# Threat Intelligence Sources
THREAT_INTEL_SOURCES = {
    'abuseipdb': 'https://api.abuseipdb.com/api/v2/check',
    'alienvault_otx': 'https://otx.alienvault.com/api/v1/indicators',
    'urlhaus': 'https://urlhaus-api.abuse.ch/v1/url/',
    'threatfox': 'https://threatfox-api.abuse.ch/api/v1/'
}


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def calculate_entropy(string):
    """Calculate Shannon entropy of a string"""
    if not string:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(string.count(chr(x))) / len(string)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy


def is_suspicious_domain(domain):
    """Check if domain appears suspicious"""
    if not domain:
        return False, []
    
    reasons = []
    
    # Check TLD
    for tld in SUSPICIOUS_TLDS:
        if domain.lower().endswith(tld):
            reasons.append(f"Suspicious TLD: {tld}")
    
    # Check entropy (DGA detection)
    domain_parts = domain.split('.')
    if domain_parts:
        subdomain = domain_parts[0]
        if len(subdomain) > 8:
            entropy = calculate_entropy(subdomain)
            if entropy > DGA_ENTROPY_THRESHOLD:
                reasons.append(f"High entropy ({entropy:.2f}) - possible DGA")
    
    # Check length
    if len(domain) > 50:
        reasons.append("Unusually long domain")
    
    # Check character patterns
    if re.search(r'\d{4,}', domain):
        reasons.append("Contains long numeric sequence")
    
    return len(reasons) > 0, reasons


def format_bytes(bytes_val):
    """Format bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_val < 1024.0:
            return f"{bytes_val:.2f} {unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.2f} PB"


def extract_http_info(packet):
    """Extract HTTP information from packet"""
    http_info = {}
    
    if packet.haslayer(HTTPRequest):
        http_info['type'] = 'request'
        http_info['method'] = packet[HTTPRequest].Method.decode() if packet[HTTPRequest].Method else 'UNKNOWN'
        http_info['host'] = packet[HTTPRequest].Host.decode() if packet[HTTPRequest].Host else ''
        http_info['path'] = packet[HTTPRequest].Path.decode() if packet[HTTPRequest].Path else ''
        http_info['user_agent'] = packet[HTTPRequest].User_Agent.decode() if packet[HTTPRequest].User_Agent else ''
        
    elif packet.haslayer(HTTPResponse):
        http_info['type'] = 'response'
        http_info['status_code'] = packet[HTTPResponse].Status_Code.decode() if packet[HTTPResponse].Status_Code else ''
        
    return http_info


def compute_file_hash(data):
    """Compute MD5 and SHA256 hashes"""
    return {
        'md5': hashlib.md5(data).hexdigest(),
        'sha256': hashlib.sha256(data).hexdigest()
    }


# ============================================================================
# ML ANOMALY DETECTION
# ============================================================================

class MLAnomalyDetector:
    """Machine Learning based anomaly detection using Isolation Forest"""
    
    def __init__(self, contamination=0.1):
        self.contamination = contamination
        self.model = None
        self.scaler = StandardScaler()
        self.features = []
        self.anomalies = []
        
    def extract_flow_features(self, flows):
        """Extract ML features from network flows"""
        if not ML_AVAILABLE:
            return []
        
        features = []
        flow_ids = []
        
        for flow_id, stats in flows.items():
            src, sport, dst, dport, proto = flow_id
            
            # Calculate temporal features
            if stats['start_time'] and stats['end_time']:
                duration = (stats['end_time'] - stats['start_time']).total_seconds()
            else:
                duration = 0
            
            avg_packet_size = stats['bytes'] / stats['packets'] if stats['packets'] > 0 else 0
            packets_per_sec = stats['packets'] / duration if duration > 0 else 0
            
            # Feature vector
            feature_vector = [
                stats['packets'],           # Total packets
                stats['bytes'],             # Total bytes
                duration,                   # Flow duration
                avg_packet_size,            # Average packet size
                packets_per_sec,            # Packets per second
                dport,                      # Destination port (can indicate service)
                len(str(src)),              # IP address length (IPv4 vs IPv6)
            ]
            
            features.append(feature_vector)
            flow_ids.append(flow_id)
        
        return np.array(features), flow_ids
    
    def detect_anomalies(self, flows):
        """Detect anomalous flows using Isolation Forest"""
        if not ML_AVAILABLE or not flows:
            return []
        
        print("\n[*] Running ML anomaly detection...")
        
        features, flow_ids = self.extract_flow_features(flows)
        
        if len(features) == 0:
            return []
        
        # Normalize features
        features_scaled = self.scaler.fit_transform(features)
        
        # Train Isolation Forest
        self.model = IsolationForest(
            contamination=self.contamination,
            random_state=42,
            n_estimators=100
        )
        
        predictions = self.model.fit_predict(features_scaled)
        anomaly_scores = self.model.score_samples(features_scaled)
        
        # Find anomalies
        for i, (pred, score) in enumerate(zip(predictions, anomaly_scores)):
            if pred == -1:  # Anomaly detected
                flow_id = flow_ids[i]
                src, sport, dst, dport, proto = flow_id
                
                self.anomalies.append({
                    'flow_id': flow_id,
                    'score': float(score),
                    'src_ip': src,
                    'dst_ip': dst,
                    'dst_port': dport,
                    'protocol': proto,
                    'feature_vector': features[i].tolist()
                })
        
        print(f"[+] ML detected {len(self.anomalies)} anomalous flows (contamination={self.contamination})")
        return self.anomalies


# ============================================================================
# THREAT INTELLIGENCE ENRICHMENT
# ============================================================================

class ThreatIntelligence:
    """Threat intelligence enrichment using multiple sources"""
    
    def __init__(self, api_keys=None):
        self.api_keys = api_keys or {}
        self.enriched_ips = {}
        self.enriched_domains = {}
        self.iocs = []
        
    def check_abuseipdb(self, ip):
        """Check IP against AbuseIPDB"""
        if not REQUESTS_AVAILABLE or 'abuseipdb' not in self.api_keys:
            return None
        
        try:
            headers = {
                'Key': self.api_keys['abuseipdb'],
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90
            }
            
            response = requests.get(
                THREAT_INTEL_SOURCES['abuseipdb'],
                headers=headers,
                params=params,
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('data', {}).get('abuseConfidenceScore', 0) > 0:
                    return {
                        'source': 'AbuseIPDB',
                        'ip': ip,
                        'abuse_score': data['data']['abuseConfidenceScore'],
                        'total_reports': data['data'].get('totalReports', 0),
                        'malicious': data['data']['abuseConfidenceScore'] > 50
                    }
        except Exception as e:
            if self.api_keys.get('verbose'):
                print(f"[-] AbuseIPDB error for {ip}: {str(e)}")
        
        return None
    
    def check_alienvault_otx(self, indicator):
        """Check indicator against AlienVault OTX"""
        if not REQUESTS_AVAILABLE or 'alienvault' not in self.api_keys:
            return None
        
        try:
            headers = {'X-OTX-API-KEY': self.api_keys['alienvault']}
            url = f"{THREAT_INTEL_SOURCES['alienvault_otx']}/IPv4/{indicator}/general"
            
            response = requests.get(url, headers=headers, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('pulse_info', {}).get('count', 0) > 0:
                    return {
                        'source': 'AlienVault OTX',
                        'indicator': indicator,
                        'pulse_count': data['pulse_info']['count'],
                        'malicious': True
                    }
        except Exception as e:
            if self.api_keys.get('verbose'):
                print(f"[-] AlienVault OTX error: {str(e)}")
        
        return None
    
    def enrich_ips(self, ip_list):
        """Enrich list of IPs with threat intelligence"""
        print(f"\n[*] Enriching {len(ip_list)} IPs with threat intelligence...")
        
        for ip in ip_list[:50]:  # Limit to avoid rate limits
            # Check AbuseIPDB
            abuse_result = self.check_abuseipdb(ip)
            if abuse_result:
                self.enriched_ips[ip] = abuse_result
                if abuse_result['malicious']:
                    self.iocs.append({
                        'type': 'ip',
                        'value': ip,
                        'source': 'AbuseIPDB',
                        'confidence': abuse_result['abuse_score']
                    })
            
            # Check AlienVault
            otx_result = self.check_alienvault_otx(ip)
            if otx_result:
                if ip in self.enriched_ips:
                    self.enriched_ips[ip]['otx'] = otx_result
                else:
                    self.enriched_ips[ip] = otx_result
                
                self.iocs.append({
                    'type': 'ip',
                    'value': ip,
                    'source': 'AlienVault OTX',
                    'confidence': 80
                })
        
        print(f"[+] Found {len(self.iocs)} IOCs from threat intelligence")
        return self.enriched_ips


# ============================================================================
# MITRE ATT&CK MAPPING
# ============================================================================

class MITREAttackMapper:
    """Map findings to MITRE ATT&CK framework"""
    
    def __init__(self):
        self.mapped_techniques = {}
        self.attack_chain = []
        self.coverage = defaultdict(list)
        
    def map_risk_to_attack(self, risk):
        """Map a risk finding to MITRE ATT&CK technique"""
        risk_type = risk.get('type', '')
        
        # Find matching technique
        for pattern, mapping in MITRE_ATTACK_MAPPING.items():
            if pattern in risk_type or pattern.lower() in risk_type.lower():
                technique_id = mapping['technique']
                
                if technique_id not in self.mapped_techniques:
                    self.mapped_techniques[technique_id] = {
                        'technique': mapping['technique'],
                        'technique_name': mapping['technique_name'],
                        'tactic': mapping['tactic'],
                        'tactic_name': mapping['tactic_name'],
                        'description': mapping['description'],
                        'findings': []
                    }
                
                self.mapped_techniques[technique_id]['findings'].append({
                    'type': risk['type'],
                    'description': risk['description'],
                    'severity': risk['severity'],
                    'timestamp': risk['timestamp']
                })
                
                # Track tactic coverage
                self.coverage[mapping['tactic']].append(technique_id)
                
                return mapping
        
        return None
    
    def generate_attack_navigator_layer(self):
        """Generate ATT&CK Navigator layer JSON"""
        techniques = []
        
        for technique_id, data in self.mapped_techniques.items():
            # Calculate score based on findings
            score = len(data['findings'])
            
            techniques.append({
                'techniqueID': technique_id,
                'tactic': data['tactic_name'].lower().replace(' ', '-'),
                'score': min(score, 100),
                'color': '#ff6666' if score > 3 else '#ff9999',
                'comment': f"{len(data['findings'])} findings detected",
                'enabled': True,
                'metadata': data['findings']
            })
        
        layer = {
            'name': 'PCAP Analysis - ATT&CK Coverage',
            'versions': {
                'attack': '14',
                'navigator': '4.9',
                'layer': '4.5'
            },
            'domain': 'enterprise-attack',
            'description': 'MITRE ATT&CK techniques detected in network traffic analysis',
            'techniques': techniques,
            'gradient': {
                'colors': ['#ffffff', '#ff6666'],
                'minValue': 0,
                'maxValue': 100
            },
            'legendItems': [
                {'label': 'Detected', 'color': '#ff6666'}
            ]
        }
        
        return layer
    
    def get_coverage_heatmap(self):
        """Generate tactic coverage statistics"""
        heatmap = {}
        
        tactics = ['TA0001', 'TA0002', 'TA0003', 'TA0004', 'TA0005', 'TA0006', 
                  'TA0007', 'TA0008', 'TA0009', 'TA0010', 'TA0011']
        
        tactic_names = {
            'TA0001': 'Initial Access',
            'TA0002': 'Execution',
            'TA0003': 'Persistence',
            'TA0004': 'Privilege Escalation',
            'TA0005': 'Defense Evasion',
            'TA0006': 'Credential Access',
            'TA0007': 'Discovery',
            'TA0008': 'Lateral Movement',
            'TA0009': 'Collection',
            'TA0010': 'Exfiltration',
            'TA0011': 'Command and Control'
        }
        
        for tactic in tactics:
            heatmap[tactic] = {
                'name': tactic_names.get(tactic, tactic),
                'techniques': len(set(self.coverage.get(tactic, []))),
                'findings': len(self.coverage.get(tactic, []))
            }
        
        return heatmap


# ============================================================================
# SESSION RECONSTRUCTION
# ============================================================================

class SessionReconstructor:
    """Reconstruct TCP sessions and extract payloads"""
    
    def __init__(self):
        self.sessions = {}
        self.reconstructed = []
        
    def reconstruct_tcp_sessions(self, packets):
        """Reassemble TCP streams"""
        print("\n[*] Reconstructing TCP sessions...")
        
        streams = defaultdict(lambda: {'data': b'', 'packets': []})
        
        for pkt in packets:
            if pkt.haslayer(TCP) and pkt.haslayer(IP):
                # Create stream identifier
                stream_id = (
                    min(pkt[IP].src, pkt[IP].dst),
                    min(pkt[TCP].sport, pkt[TCP].dport),
                    max(pkt[IP].src, pkt[IP].dst),
                    max(pkt[TCP].sport, pkt[TCP].dport)
                )
                
                if pkt.haslayer(Raw):
                    streams[stream_id]['packets'].append({
                        'seq': pkt[TCP].seq,
                        'data': bytes(pkt[Raw].load)
                    })
        
        # Reassemble streams
        for stream_id, stream in streams.items():
            if len(stream['packets']) > 0:
                # Sort by sequence number
                stream['packets'].sort(key=lambda x: x['seq'])
                
                # Concatenate data
                full_data = b''.join([p['data'] for p in stream['packets']])
                
                self.reconstructed.append({
                    'stream_id': stream_id,
                    'data': full_data,
                    'size': len(full_data),
                    'packets': len(stream['packets'])
                })
        
        print(f"[+] Reconstructed {len(self.reconstructed)} TCP sessions")
        return self.reconstructed
    
    def extract_http_sessions(self, reconstructed_streams):
        """Extract HTTP conversations from reconstructed streams"""
        http_sessions = []
        
        for stream in reconstructed_streams:
            try:
                data = stream['data'].decode('utf-8', errors='ignore')
                
                # Check if it's HTTP
                if 'HTTP/' in data or data.startswith('GET ') or data.startswith('POST '):
                    http_sessions.append({
                        'stream_id': stream['stream_id'],
                        'data': data,
                        'size': stream['size']
                    })
            except:
                pass
        
        return http_sessions


# ============================================================================
# MAIN ANALYZER CLASS
# ============================================================================

class PCAPAnalyzer:
    def __init__(self, pcap_file, verbose=False, virustotal_api_key=None, threat_feeds=None, 
                 enable_ml=False, misp_url=None, misp_key=None):
        self.pcap_file = pcap_file
        self.verbose = verbose
        self.vt_api_key = virustotal_api_key
        self.threat_feeds = threat_feeds or {}
        self.enable_ml = enable_ml and ML_AVAILABLE
        
        # Analysis results storage
        self.packets = []
        self.packet_count = 0
        self.protocol_counts = Counter()
        self.ip_stats = {
            'sources': Counter(),
            'destinations': Counter(),
            'pairs': Counter(),
            'bytes_sent': defaultdict(int),
            'bytes_received': defaultdict(int)
        }
        self.dns_queries = []
        self.dns_responses = []
        self.port_stats = {
            'tcp': Counter(),
            'udp': Counter()
        }
        self.risks = []
        self.time_series = []
        self.flows = defaultdict(lambda: {'packets': 0, 'bytes': 0, 'start_time': None, 'end_time': None})
        self.http_requests = []
        self.http_responses = []
        self.tls_info = []
        self.extracted_files = []
        self.credentials = []
        self.suspicious_packets = []
        
        # Attack chain analysis
        self.attack_chain = []
        self.infection_info = {}
        
        # Advanced features
        self.ml_detector = MLAnomalyDetector() if self.enable_ml else None
        self.threat_intel = ThreatIntelligence(api_keys=threat_feeds) if threat_feeds else None
        self.mitre_mapper = MITREAttackMapper()
        self.session_reconstructor = SessionReconstructor()
        self.ml_anomalies = []
        self.threat_iocs = []
        self.mitre_techniques = {}
        self.reconstructed_sessions = []
        
        self.start_time = None
        self.end_time = None
        
    def load_pcap(self):
        """Load and parse PCAP file with streaming support for large files"""
        print(f"[*] Loading PCAP file: {self.pcap_file}")
        
        if not os.path.exists(self.pcap_file):
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_file}")
        
        # Check file size
        file_size = os.path.getsize(self.pcap_file)
        file_size_mb = file_size / (1024 * 1024)
        print(f"[*] PCAP file size: {file_size_mb:.2f} MB")
        
        try:
            # For large files (>20MB), use streaming with progress
            if file_size > 20 * 1024 * 1024:  # 20MB threshold
                print(f"[*] Large file detected - using streaming mode with progress tracking")
                self._load_pcap_streaming()
            else:
                # Small files - load all at once
                print(f"[*] Loading file into memory...")
                self.packets = rdpcap(self.pcap_file)
                self.packet_count = len(self.packets)
                print(f"[+] Loaded {self.packet_count} packets")
            
            if self.packet_count == 0:
                print("[-] WARNING: PCAP file is empty")
                return
            
            # Get time range from first and last packet
            if len(self.packets) > 0:
                self.start_time = datetime.fromtimestamp(float(self.packets[0].time))
                self.end_time = datetime.fromtimestamp(float(self.packets[-1].time))
                print(f"[+] Capture time: {self.start_time} to {self.end_time}")
                print(f"[+] Duration: {self.end_time - self.start_time}")
            
        except Exception as e:
            raise Exception(f"Failed to load PCAP: {str(e)}")
    
    def _load_pcap_streaming(self):
        """Stream-process large PCAP files in chunks to avoid memory issues"""
        print(f"[*] Streaming PCAP processing (memory efficient mode)...")
        
        chunk_packets = []
        packet_count = 0
        chunk_size = 10000  # Process 10K packets at a time
        
        try:
            # Use PcapReader for streaming
            with PcapReader(self.pcap_file) as pcap_reader:
                for pkt in pcap_reader:
                    chunk_packets.append(pkt)
                    packet_count += 1
                    
                    # Progress indicator every 10K packets
                    if packet_count % 10000 == 0:
                        print(f"[*] Processed {packet_count:,} packets...")
                    
                    # Process chunk when it reaches size limit
                    if len(chunk_packets) >= chunk_size:
                        self._process_packet_chunk(chunk_packets)
                        
                        # Keep only first and last packets for time range
                        if not self.packets:
                            self.packets = [chunk_packets[0], chunk_packets[-1]]
                        else:
                            self.packets[-1] = chunk_packets[-1]  # Update last packet
                        
                        chunk_packets = []
                
                # Process remaining packets
                if chunk_packets:
                    self._process_packet_chunk(chunk_packets)
                    if not self.packets:
                        self.packets = [chunk_packets[0], chunk_packets[-1]]
                    else:
                        self.packets[-1] = chunk_packets[-1]
            
            self.packet_count = packet_count
            print(f"[+] Streaming complete - processed {self.packet_count:,} packets")
            
        except Exception as e:
            print(f"[-] Error during streaming: {str(e)}")
            raise
    
    def _process_packet_chunk(self, packets):
        """Process a chunk of packets for streaming mode"""
        for pkt in packets:
            try:
                # Protocol counting
                if pkt.haslayer(IP):
                    self.protocol_counts['IPv4'] += 1
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    pkt_len = len(pkt)
                    
                    # IP statistics
                    self.ip_stats['sources'][src_ip] += 1
                    self.ip_stats['destinations'][dst_ip] += 1
                    self.ip_stats['pairs'][(src_ip, dst_ip)] += 1
                    self.ip_stats['bytes_sent'][src_ip] += pkt_len
                    self.ip_stats['bytes_received'][dst_ip] += pkt_len
                
                elif pkt.haslayer(IPv6):
                    self.protocol_counts['IPv6'] += 1
                
                # Layer 4
                if pkt.haslayer(TCP):
                    self.protocol_counts['TCP'] += 1
                    sport = pkt[TCP].sport
                    dport = pkt[TCP].dport
                    self.port_stats['tcp'][dport] += 1
                    
                    # Flow tracking
                    if pkt.haslayer(IP):
                        flow_id = (pkt[IP].src, sport, pkt[IP].dst, dport, 'TCP')
                        pkt_time = datetime.fromtimestamp(float(pkt.time))
                        self.flows[flow_id]['packets'] += 1
                        self.flows[flow_id]['bytes'] += len(pkt)
                        if self.flows[flow_id]['start_time'] is None:
                            self.flows[flow_id]['start_time'] = pkt_time
                        self.flows[flow_id]['end_time'] = pkt_time
                    
                    # Port-based protocol detection
                    if dport == 443 or sport == 443:
                        self.protocol_counts['HTTPS'] += 1
                    elif dport == 21 or sport == 21:
                        self.protocol_counts['FTP'] += 1
                    elif dport == 23 or sport == 23:
                        self.protocol_counts['Telnet'] += 1
                    elif dport == 22 or sport == 22:
                        self.protocol_counts['SSH'] += 1
                
                elif pkt.haslayer(UDP):
                    self.protocol_counts['UDP'] += 1
                    sport = pkt[UDP].sport
                    dport = pkt[UDP].dport
                    self.port_stats['udp'][dport] += 1
                    
                    # Flow tracking
                    if pkt.haslayer(IP):
                        flow_id = (pkt[IP].src, sport, pkt[IP].dst, dport, 'UDP')
                        pkt_time = datetime.fromtimestamp(float(pkt.time))
                        self.flows[flow_id]['packets'] += 1
                        self.flows[flow_id]['bytes'] += len(pkt)
                        if self.flows[flow_id]['start_time'] is None:
                            self.flows[flow_id]['start_time'] = pkt_time
                        self.flows[flow_id]['end_time'] = pkt_time
                
                elif pkt.haslayer(ICMP):
                    self.protocol_counts['ICMP'] += 1
                
                # Application layer (only for critical analysis)
                if pkt.haslayer(DNS):
                    self.protocol_counts['DNS'] += 1
                    # Extract DNS queries
                    dns_layer = pkt[DNS]
                    if dns_layer.qr == 0 and pkt.haslayer(DNSQR):
                        query = pkt[DNSQR].qname.decode() if pkt[DNSQR].qname else ''
                        if query.endswith('.'):
                            query = query[:-1]
                        src_ip = pkt[IP].src if pkt.haslayer(IP) else 'Unknown'
                        self.dns_queries.append({
                            'timestamp': datetime.fromtimestamp(float(pkt.time)),
                            'src_ip': src_ip,
                            'query': query,
                            'qtype': pkt[DNSQR].qtype if hasattr(pkt[DNSQR], 'qtype') else 'Unknown'
                        })
                
                if pkt.haslayer(HTTP):
                    self.protocol_counts['HTTP'] += 1
                
                if pkt.haslayer(TLS):
                    self.protocol_counts['TLS/SSL'] += 1
                
                # Time series (sample every 100th packet for efficiency)
                if self.packet_count % 100 == 0:
                    pkt_time = datetime.fromtimestamp(float(pkt.time))
                    bin_time = pkt_time.replace(second=0, microsecond=0)
                    # Just increment counter - will be processed later
                    
            except Exception as e:
                # Skip problematic packets
                if self.verbose:
                    print(f"[-] Error processing packet: {str(e)}")
                continue
    
    def analyze_protocols(self):
        """Analyze protocol distribution (optimized for streaming)"""
        print("\n[*] Analyzing protocols...")
        
        # If already processed in streaming mode, skip re-analysis
        if len(self.protocol_counts) > 0:
            print(f"[+] Protocol analysis already complete (streaming mode)")
            print(f"[+] Found {len(self.protocol_counts)} different protocols")
            return
        
        # Otherwise do full analysis for small files
        for pkt in self.packets:
            # Layer 3
            if pkt.haslayer(IP):
                self.protocol_counts['IPv4'] += 1
            elif pkt.haslayer(IPv6):
                self.protocol_counts['IPv6'] += 1
            
            # Layer 4
            if pkt.haslayer(TCP):
                self.protocol_counts['TCP'] += 1
            elif pkt.haslayer(UDP):
                self.protocol_counts['UDP'] += 1
            elif pkt.haslayer(ICMP):
                self.protocol_counts['ICMP'] += 1
            
            # Application layer
            if pkt.haslayer(DNS):
                self.protocol_counts['DNS'] += 1
            if pkt.haslayer(HTTP):
                self.protocol_counts['HTTP'] += 1
            if pkt.haslayer(TLS):
                self.protocol_counts['TLS/SSL'] += 1
            
            # Check common ports for protocol identification
            if pkt.haslayer(TCP) or pkt.haslayer(UDP):
                dport = pkt[TCP].dport if pkt.haslayer(TCP) else pkt[UDP].dport
                sport = pkt[TCP].sport if pkt.haslayer(TCP) else pkt[UDP].sport
                
                if dport == 443 or sport == 443:
                    self.protocol_counts['HTTPS'] += 1
                elif dport == 21 or sport == 21:
                    self.protocol_counts['FTP'] += 1
                elif dport == 23 or sport == 23:
                    self.protocol_counts['Telnet'] += 1
                elif dport == 22 or sport == 22:
                    self.protocol_counts['SSH'] += 1
                elif dport == 25 or sport == 25:
                    self.protocol_counts['SMTP'] += 1
        
        print(f"[+] Found {len(self.protocol_counts)} different protocols")
    
    def analyze_ip_addresses(self):
        """Analyze IP address statistics (optimized for streaming)"""
        print("\n[*] Analyzing IP addresses...")
        
        # If already processed in streaming mode, just report
        if len(self.ip_stats['sources']) > 0:
            print(f"[+] IP analysis already complete (streaming mode)")
            print(f"[+] Unique source IPs: {len(self.ip_stats['sources'])}")
            print(f"[+] Unique destination IPs: {len(self.ip_stats['destinations'])}")
            print(f"[+] Unique communication pairs: {len(self.ip_stats['pairs'])}")
            return
        
        # Otherwise process for small files
        for pkt in self.packets:
            if pkt.haslayer(IP):
                src = pkt[IP].src
                dst = pkt[IP].dst
                pkt_len = len(pkt)
                
                self.ip_stats['sources'][src] += 1
                self.ip_stats['destinations'][dst] += 1
                self.ip_stats['pairs'][(src, dst)] += 1
                self.ip_stats['bytes_sent'][src] += pkt_len
                self.ip_stats['bytes_received'][dst] += pkt_len
        
        print(f"[+] Unique source IPs: {len(self.ip_stats['sources'])}")
        print(f"[+] Unique destination IPs: {len(self.ip_stats['destinations'])}")
        print(f"[+] Unique communication pairs: {len(self.ip_stats['pairs'])}")
    
    def analyze_dns(self):
        """Analyze DNS queries and responses (with sampling for large files)"""
        print("\n[*] Analyzing DNS traffic...")
        
        # If already processed in streaming mode, skip duplicate queries
        if len(self.dns_queries) > 0:
            print(f"[+] DNS analysis already complete (streaming mode)")
            print(f"[+] DNS queries found: {len(self.dns_queries)}")
            
            # Check for suspicious patterns
            query_count_per_ip = Counter()
            for query in self.dns_queries:
                query_count_per_ip[query['src_ip']] += 1
            
            for ip, count in query_count_per_ip.items():
                if count > 100:
                    self.risks.append({
                        'severity': 'MEDIUM',
                        'type': 'High DNS Query Volume',
                        'description': f"IP {ip} made {count} DNS queries",
                        'details': 'Possible DNS tunneling or C2 communication',
                        'src_ip': ip,
                        'timestamp': datetime.now(),
                        'evidence': f"{count} queries from single IP"
                    })
            return
        
        # For small files, do full analysis
        sample_rate = 1
        if self.packet_count > 100000:
            sample_rate = 10  # Sample every 10th packet for large files
            print(f"[*] Large file - sampling DNS packets (1 in {sample_rate})")
        
        packet_num = 0
        for pkt in self.packets:
            packet_num += 1
            if packet_num % sample_rate != 0:
                continue
                
            if pkt.haslayer(DNS):
                dns_layer = pkt[DNS]
                
                # DNS Query
                if dns_layer.qr == 0 and pkt.haslayer(DNSQR):
                    query = pkt[DNSQR].qname.decode() if pkt[DNSQR].qname else ''
                    if query.endswith('.'):
                        query = query[:-1]
                    
                    src_ip = pkt[IP].src if pkt.haslayer(IP) else 'Unknown'
                    
                    query_info = {
                        'timestamp': datetime.fromtimestamp(float(pkt.time)),
                        'src_ip': src_ip,
                        'query': query,
                        'qtype': pkt[DNSQR].qtype if hasattr(pkt[DNSQR], 'qtype') else 'Unknown'
                    }
                    
                    self.dns_queries.append(query_info)
                    
                    # Check for suspicious domains
                    is_suspicious, reasons = is_suspicious_domain(query)
                    if is_suspicious:
                        self.risks.append({
                            'severity': 'MEDIUM',
                            'type': 'Suspicious DNS Query',
                            'description': f"Query to suspicious domain: {query}",
                            'details': f"Reasons: {', '.join(reasons)}",
                            'src_ip': src_ip,
                            'timestamp': query_info['timestamp'],
                            'evidence': f"DNS query from {src_ip} to {query}"
                        })
                
                # DNS Response
                elif dns_layer.qr == 1 and pkt.haslayer(DNSRR):
                    for i in range(dns_layer.ancount):
                        if pkt.haslayer(DNSRR):
                            answer = pkt[DNSRR]
                            self.dns_responses.append({
                                'timestamp': datetime.fromtimestamp(float(pkt.time)),
                                'name': answer.rrname.decode() if answer.rrname else '',
                                'rdata': answer.rdata if hasattr(answer, 'rdata') else ''
                            })
        
        print(f"[+] DNS queries found: {len(self.dns_queries)}")
        print(f"[+] DNS responses found: {len(self.dns_responses)}")
        
        # Check for high-volume DNS queries from single IP
        query_count_per_ip = Counter()
        for query in self.dns_queries:
            query_count_per_ip[query['src_ip']] += 1
        
        for ip, count in query_count_per_ip.items():
            if count > 100:
                self.risks.append({
                    'severity': 'MEDIUM',
                    'type': 'High DNS Query Volume',
                    'description': f"IP {ip} made {count} DNS queries",
                    'details': 'Possible DNS tunneling or C2 communication',
                    'src_ip': ip,
                    'timestamp': datetime.now(),
                    'evidence': f"{count} queries from single IP"
                })
    
    def analyze_ports(self):
        """Analyze TCP/UDP port usage"""
        print("\n[*] Analyzing port usage...")
        
        port_scan_tracker = defaultdict(set)  # Track unique dst ports per src IP
        
        for pkt in self.packets:
            if pkt.haslayer(TCP):
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                flags = pkt[TCP].flags
                
                self.port_stats['tcp'][dport] += 1
                
                # Track for port scan detection
                if pkt.haslayer(IP):
                    src_ip = pkt[IP].src
                    port_scan_tracker[src_ip].add(dport)
                    
                    # Check for SYN scan
                    if flags == 'S':  # SYN only
                        # Will be analyzed later in aggregate
                        pass
                
                # Check for suspicious ports
                if dport in SUSPICIOUS_PORTS:
                    self.risks.append({
                        'severity': 'HIGH',
                        'type': 'Suspicious Port Activity',
                        'description': f"Traffic to suspicious port {dport}",
                        'details': f"Port {dport}: {SUSPICIOUS_PORTS[dport]}",
                        'src_ip': pkt[IP].src if pkt.haslayer(IP) else 'Unknown',
                        'dst_ip': pkt[IP].dst if pkt.haslayer(IP) else 'Unknown',
                        'timestamp': datetime.fromtimestamp(float(pkt.time)),
                        'evidence': f"Packet to port {dport}"
                    })
                
                # Check for non-standard HTTP ports
                if dport not in [80, 443, 8080, 8443] and pkt.haslayer(HTTP):
                    self.risks.append({
                        'severity': 'LOW',
                        'type': 'Non-standard HTTP Port',
                        'description': f"HTTP traffic on port {dport}",
                        'details': 'HTTP traffic on unusual port',
                        'src_ip': pkt[IP].src if pkt.haslayer(IP) else 'Unknown',
                        'timestamp': datetime.fromtimestamp(float(pkt.time)),
                        'evidence': f"HTTP on port {dport}"
                    })
            
            elif pkt.haslayer(UDP):
                dport = pkt[UDP].dport
                self.port_stats['udp'][dport] += 1
        
        # Detect port scans
        for src_ip, ports in port_scan_tracker.items():
            if len(ports) > 20:  # Threshold for port scan
                self.risks.append({
                    'severity': 'HIGH',
                    'type': 'Port Scan Detected',
                    'description': f"IP {src_ip} scanned {len(ports)} ports",
                    'details': f"Scanned ports: {sorted(list(ports))[:20]}...",
                    'src_ip': src_ip,
                    'timestamp': datetime.now(),
                    'evidence': f"{len(ports)} unique ports targeted"
                })
        
        print(f"[+] Unique TCP ports: {len(self.port_stats['tcp'])}")
        print(f"[+] Unique UDP ports: {len(self.port_stats['udp'])}")
    
    def analyze_security_risks(self):
        """Detect security risks and threats"""
        print("\n[*] Analyzing security risks...")
        
        icmp_count = 0
        large_payloads = []
        
        for pkt in self.packets:
            timestamp = datetime.fromtimestamp(float(pkt.time))
            
            # Check for ICMP floods
            if pkt.haslayer(ICMP):
                icmp_count += 1
            
            # Check for unencrypted protocols
            if pkt.haslayer(TCP) or pkt.haslayer(UDP):
                dport = pkt[TCP].dport if pkt.haslayer(TCP) else pkt[UDP].dport
                sport = pkt[TCP].sport if pkt.haslayer(TCP) else pkt[UDP].sport
                
                if dport in INSECURE_PROTOCOLS or sport in INSECURE_PROTOCOLS:
                    port = dport if dport in INSECURE_PROTOCOLS else sport
                    self.risks.append({
                        'severity': 'MEDIUM',
                        'type': 'Insecure Protocol',
                        'description': f"Unencrypted {INSECURE_PROTOCOLS[port]} traffic detected",
                        'details': f"Port {port} - {INSECURE_PROTOCOLS[port]} transmits data in cleartext",
                        'src_ip': pkt[IP].src if pkt.haslayer(IP) else 'Unknown',
                        'dst_ip': pkt[IP].dst if pkt.haslayer(IP) else 'Unknown',
                        'timestamp': timestamp,
                        'evidence': f"Packet on port {port}"
                    })
            
            # Check for large payloads (potential exfiltration)
            if len(pkt) > 1400:  # MTU threshold
                large_payloads.append({
                    'size': len(pkt),
                    'src': pkt[IP].src if pkt.haslayer(IP) else 'Unknown',
                    'dst': pkt[IP].dst if pkt.haslayer(IP) else 'Unknown',
                    'timestamp': timestamp
                })
        
        # ICMP flood detection
        if icmp_count > 100:
            self.risks.append({
                'severity': 'HIGH',
                'type': 'Excessive ICMP Traffic',
                'description': f"Detected {icmp_count} ICMP packets",
                'details': 'Possible ICMP flood or ping sweep',
                'src_ip': 'Multiple',
                'timestamp': datetime.now(),
                'evidence': f"{icmp_count} ICMP packets in capture"
            })
        
        # Large payload detection
        if len(large_payloads) > 50:
            self.risks.append({
                'severity': 'MEDIUM',
                'type': 'Large Payload Transfer',
                'description': f"Detected {len(large_payloads)} large packets",
                'details': 'Possible data exfiltration',
                'src_ip': 'Multiple',
                'timestamp': datetime.now(),
                'evidence': f"{len(large_payloads)} packets > 1400 bytes"
            })
        
        print(f"[+] Total risks identified: {len(self.risks)}")
    
    def analyze_time_series(self):
        """Generate time-based traffic analysis"""
        print("\n[*] Analyzing time-based traffic patterns...")
        
        if not self.packets or not self.start_time:
            print("[-] No packets to analyze")
            return
        
        # Create 1-minute bins
        time_bins = defaultdict(int)
        
        for pkt in self.packets:
            pkt_time = datetime.fromtimestamp(float(pkt.time))
            # Round to minute
            bin_time = pkt_time.replace(second=0, microsecond=0)
            time_bins[bin_time] += 1
        
        # Sort by time
        self.time_series = sorted(time_bins.items())
        
        print(f"[+] Generated {len(self.time_series)} time bins")
    
    def analyze_flows(self):
        """Analyze network flows"""
        print("\n[*] Analyzing network flows...")
        
        for pkt in self.packets:
            if pkt.haslayer(IP):
                if pkt.haslayer(TCP):
                    proto = 'TCP'
                    sport = pkt[TCP].sport
                    dport = pkt[TCP].dport
                elif pkt.haslayer(UDP):
                    proto = 'UDP'
                    sport = pkt[UDP].sport
                    dport = pkt[UDP].dport
                else:
                    continue
                
                src = pkt[IP].src
                dst = pkt[IP].dst
                
                # Create flow identifier (5-tuple)
                flow_id = (src, sport, dst, dport, proto)
                
                # Update flow stats
                pkt_time = datetime.fromtimestamp(float(pkt.time))
                self.flows[flow_id]['packets'] += 1
                self.flows[flow_id]['bytes'] += len(pkt)
                
                if self.flows[flow_id]['start_time'] is None:
                    self.flows[flow_id]['start_time'] = pkt_time
                self.flows[flow_id]['end_time'] = pkt_time
        
        # Detect anomalies
        for flow_id, stats in self.flows.items():
            src, sport, dst, dport, proto = flow_id
            
            # Beacon detection (periodic traffic)
            if stats['packets'] > 10:
                duration = (stats['end_time'] - stats['start_time']).total_seconds()
                if duration > 0:
                    interval = duration / stats['packets']
                    if 5 < interval < 120:  # Regular interval between 5s and 2min
                        self.risks.append({
                            'severity': 'MEDIUM',
                            'type': 'Potential Beacon Activity',
                            'description': f"Regular traffic pattern detected: {src}:{sport} -> {dst}:{dport}",
                            'details': f"Average interval: {interval:.2f}s, Packets: {stats['packets']}",
                            'src_ip': src,
                            'dst_ip': dst,
                            'timestamp': stats['start_time'],
                            'evidence': f"Flow with {stats['packets']} packets over {duration:.0f}s"
                        })
            
            # Data exfiltration detection (high outbound)
            if stats['bytes'] > 1000000:  # >1MB
                self.risks.append({
                    'severity': 'HIGH',
                    'type': 'Large Data Transfer',
                    'description': f"Large outbound transfer: {format_bytes(stats['bytes'])}",
                    'details': f"From {src}:{sport} to {dst}:{dport} ({proto})",
                    'src_ip': src,
                    'dst_ip': dst,
                    'timestamp': stats['start_time'],
                    'evidence': f"{stats['packets']} packets, {format_bytes(stats['bytes'])}"
                })
        
        print(f"[+] Analyzed {len(self.flows)} unique flows")
    
    def analyze_http(self):
        """Analyze HTTP traffic (with sampling for large files)"""
        print("\n[*] Analyzing HTTP traffic...")
        
        # Sample rate for large files
        sample_rate = 1
        if self.packet_count > 100000:
            sample_rate = 5
            print(f"[*] Large file - sampling HTTP packets (1 in {sample_rate})")
        
        packet_num = 0
        for pkt in self.packets:
            packet_num += 1
            if packet_num % sample_rate != 0:
                continue
            
            if pkt.haslayer(HTTPRequest):
                req_info = {
                    'timestamp': datetime.fromtimestamp(float(pkt.time)),
                    'src_ip': pkt[IP].src if pkt.haslayer(IP) else 'Unknown',
                    'dst_ip': pkt[IP].dst if pkt.haslayer(IP) else 'Unknown',
                    'method': pkt[HTTPRequest].Method.decode() if pkt[HTTPRequest].Method else '',
                    'host': pkt[HTTPRequest].Host.decode() if pkt[HTTPRequest].Host else '',
                    'path': pkt[HTTPRequest].Path.decode() if pkt[HTTPRequest].Path else '',
                    'user_agent': pkt[HTTPRequest].User_Agent.decode() if pkt[HTTPRequest].User_Agent else ''
                }
                
                self.http_requests.append(req_info)
                
                # Check for suspicious URIs
                for pattern in SUSPICIOUS_URIS:
                    if pattern.lower() in req_info['path'].lower():
                        self.risks.append({
                            'severity': 'MEDIUM',
                            'type': 'Suspicious HTTP Request',
                            'description': f"Suspicious URI pattern: {pattern}",
                            'details': f"{req_info['method']} {req_info['path']}",
                            'src_ip': req_info['src_ip'],
                            'dst_ip': req_info['dst_ip'],
                            'timestamp': req_info['timestamp'],
                            'evidence': f"Request to {req_info['host']}{req_info['path']}"
                        })
                        break
                
                # Check for scanner user agents
                ua_lower = req_info['user_agent'].lower()
                for scanner in SCANNER_USER_AGENTS:
                    if scanner in ua_lower:
                        self.risks.append({
                            'severity': 'HIGH',
                            'type': 'Scanner Detected',
                            'description': f"Scanner user agent: {scanner}",
                            'details': f"User-Agent: {req_info['user_agent']}",
                            'src_ip': req_info['src_ip'],
                            'timestamp': req_info['timestamp'],
                            'evidence': f"Scanner activity from {req_info['src_ip']}"
                        })
                        break
                
                # Check for large POST (limit to prevent memory issues)
                if req_info['method'] == 'POST' and pkt.haslayer(Raw):
                    payload_len = len(pkt[Raw].load)
                    if payload_len > 10000:
                        self.risks.append({
                            'severity': 'MEDIUM',
                            'type': 'Large HTTP POST',
                            'description': f"Large POST request: {format_bytes(payload_len)}",
                            'details': f"POST to {req_info['path']}",
                            'src_ip': req_info['src_ip'],
                            'timestamp': req_info['timestamp'],
                            'evidence': f"{format_bytes(payload_len)} payload"
                        })
            
            elif pkt.haslayer(HTTPResponse):
                resp_info = {
                    'timestamp': datetime.fromtimestamp(float(pkt.time)),
                    'status_code': pkt[HTTPResponse].Status_Code.decode() if pkt[HTTPResponse].Status_Code else ''
                }
                self.http_responses.append(resp_info)
        
        print(f"[+] HTTP requests: {len(self.http_requests)}")
        print(f"[+] HTTP responses: {len(self.http_responses)}")
    
    def analyze_tls(self):
        """Analyze TLS/SSL traffic (with sampling for large files)"""
        print("\n[*] Analyzing TLS/SSL traffic...")
        
        # Sample for large files
        sample_rate = 1
        if self.packet_count > 100000:
            sample_rate = 10
            print(f"[*] Large file - sampling TLS packets (1 in {sample_rate})")
        
        packet_num = 0
        for pkt in self.packets:
            packet_num += 1
            if packet_num % sample_rate != 0:
                continue
            
            if pkt.haslayer(TLS):
                # TLS Client Hello
                if pkt.haslayer(TLSClientHello):
                    client_hello = pkt[TLSClientHello]
                    tls_version = client_hello.version if hasattr(client_hello, 'version') else 0
                    
                    tls_info = {
                        'timestamp': datetime.fromtimestamp(float(pkt.time)),
                        'src_ip': pkt[IP].src if pkt.haslayer(IP) else 'Unknown',
                        'dst_ip': pkt[IP].dst if pkt.haslayer(IP) else 'Unknown',
                        'type': 'ClientHello',
                        'version': tls_version
                    }
                    
                    self.tls_info.append(tls_info)
                    
                    # Check for weak TLS versions
                    if tls_version < 0x0303:  # TLS 1.2 = 0x0303
                        version_name = 'TLS 1.0' if tls_version == 0x0301 else 'TLS 1.1' if tls_version == 0x0302 else 'SSL'
                        self.risks.append({
                            'severity': 'HIGH',
                            'type': 'Weak TLS Version',
                            'description': f"Outdated TLS version: {version_name}",
                            'details': f"TLS version {hex(tls_version)} is deprecated",
                            'src_ip': tls_info['src_ip'],
                            'dst_ip': tls_info['dst_ip'],
                            'timestamp': tls_info['timestamp'],
                            'evidence': f"TLS handshake with version {hex(tls_version)}"
                        })
                
                # TLS Server Hello
                elif pkt.haslayer(TLSServerHello):
                    server_hello = pkt[TLSServerHello]
                    tls_version = server_hello.version if hasattr(server_hello, 'version') else 0
                    
                    tls_info = {
                        'timestamp': datetime.fromtimestamp(float(pkt.time)),
                        'src_ip': pkt[IP].src if pkt.haslayer(IP) else 'Unknown',
                        'dst_ip': pkt[IP].dst if pkt.haslayer(IP) else 'Unknown',
                        'type': 'ServerHello',
                        'version': tls_version
                    }
                    
                    self.tls_info.append(tls_info)
        
        print(f"[+] TLS handshakes: {len(self.tls_info)}")
    
    def extract_credentials(self):
        """Search for credentials in cleartext (with sampling for large files)"""
        print("\n[*] Searching for credentials...")
        
        # Limit credential search for very large files
        max_packets = min(len(self.packets), 50000)
        if self.packet_count > 100000:
            print(f"[*] Large file - limiting credential search to first {max_packets} packets")
        
        for pkt in self.packets[:max_packets]:
            if pkt.haslayer(Raw):
                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                    
                    # Search for common credential patterns
                    patterns = {
                        'password': r'password[=:]\s*([^\s&]+)',
                        'username': r'user(?:name)?[=:]\s*([^\s&]+)',
                        'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                        'api_key': r'api[_-]?key[=:]\s*([a-zA-Z0-9]+)',
                    }
                    
                    for cred_type, pattern in patterns.items():
                        matches = re.finditer(pattern, payload, re.IGNORECASE)
                        for match in matches:
                            self.credentials.append({
                                'type': cred_type,
                                'value': match.group(0),
                                'src_ip': pkt[IP].src if pkt.haslayer(IP) else 'Unknown',
                                'dst_ip': pkt[IP].dst if pkt.haslayer(IP) else 'Unknown',
                                'timestamp': datetime.fromtimestamp(float(pkt.time))
                            })
                            
                            self.risks.append({
                                'severity': 'HIGH',
                                'type': 'Cleartext Credentials',
                                'description': f"Found {cred_type} in cleartext",
                                'details': f"Value: {match.group(0)[:50]}...",
                                'src_ip': pkt[IP].src if pkt.haslayer(IP) else 'Unknown',
                                'timestamp': datetime.fromtimestamp(float(pkt.time)),
                                'evidence': 'Credentials transmitted unencrypted'
                            })
                            break  # One alert per packet
                except:
                    pass
        
        print(f"[+] Credentials found: {len(self.credentials)}")
    
    def extract_files(self):
        """Extract files from HTTP traffic (with limits for large files)"""
        print("\n[*] Extracting files from traffic...")
        
        # Limit file extraction for large captures
        max_files = 50
        max_packets = min(len(self.packets), 100000)
        
        if self.packet_count > 100000:
            print(f"[*] Large file - limiting file extraction to first {max_packets} packets")
        
        for pkt in self.packets[:max_packets]:
            if len(self.extracted_files) >= max_files:
                print(f"[*] Reached file extraction limit ({max_files} files)")
                break
            
            if pkt.haslayer(HTTPResponse) and pkt.haslayer(Raw):
                try:
                    # Check for common file signatures
                    payload = pkt[Raw].load
                    
                    file_info = None
                    
                    # PDF
                    if payload.startswith(b'%PDF'):
                        file_info = {'type': 'PDF', 'ext': '.pdf'}
                    # ZIP
                    elif payload.startswith(b'PK\x03\x04'):
                        file_info = {'type': 'ZIP', 'ext': '.zip'}
                    # PNG
                    elif payload.startswith(b'\x89PNG'):
                        file_info = {'type': 'PNG', 'ext': '.png'}
                    # JPEG
                    elif payload.startswith(b'\xff\xd8\xff'):
                        file_info = {'type': 'JPEG', 'ext': '.jpg'}
                    # EXE
                    elif payload.startswith(b'MZ'):
                        file_info = {'type': 'EXE', 'ext': '.exe'}
                    
                    if file_info:
                        hashes = compute_file_hash(payload)
                        
                        self.extracted_files.append({
                            'type': file_info['type'],
                            'size': len(payload),
                            'md5': hashes['md5'],
                            'sha256': hashes['sha256'],
                            'timestamp': datetime.fromtimestamp(float(pkt.time)),
                            'src_ip': pkt[IP].src if pkt.haslayer(IP) else 'Unknown',
                            'dst_ip': pkt[IP].dst if pkt.haslayer(IP) else 'Unknown'
                        })
                        
                        # Flag executable downloads
                        if file_info['type'] == 'EXE':
                            self.risks.append({
                                'severity': 'MEDIUM',
                                'type': 'Executable Download',
                                'description': f"Downloaded executable file",
                                'details': f"MD5: {hashes['md5']}",
                                'src_ip': pkt[IP].dst if pkt.haslayer(IP) else 'Unknown',
                                'timestamp': datetime.fromtimestamp(float(pkt.time)),
                                'evidence': f"EXE file, {format_bytes(len(payload))}"
                            })
                except:
                    pass
        
        print(f"[+] Files extracted: {len(self.extracted_files)}")
        """Analyze HTTP traffic"""
        print("\n[*] Analyzing HTTP traffic...")
        
        for pkt in self.packets:
            if pkt.haslayer(HTTPRequest):
                req_info = {
                    'timestamp': datetime.fromtimestamp(float(pkt.time)),
                    'src_ip': pkt[IP].src if pkt.haslayer(IP) else 'Unknown',
                    'dst_ip': pkt[IP].dst if pkt.haslayer(IP) else 'Unknown',
                    'method': pkt[HTTPRequest].Method.decode() if pkt[HTTPRequest].Method else '',
                    'host': pkt[HTTPRequest].Host.decode() if pkt[HTTPRequest].Host else '',
                    'path': pkt[HTTPRequest].Path.decode() if pkt[HTTPRequest].Path else '',
                    'user_agent': pkt[HTTPRequest].User_Agent.decode() if pkt[HTTPRequest].User_Agent else ''
                }
                
                self.http_requests.append(req_info)
                
                # Check for suspicious URIs
                for pattern in SUSPICIOUS_URIS:
                    if pattern.lower() in req_info['path'].lower():
                        self.risks.append({
                            'severity': 'MEDIUM',
                            'type': 'Suspicious HTTP Request',
                            'description': f"Suspicious URI pattern: {pattern}",
                            'details': f"{req_info['method']} {req_info['path']}",
                            'src_ip': req_info['src_ip'],
                            'dst_ip': req_info['dst_ip'],
                            'timestamp': req_info['timestamp'],
                            'evidence': f"Request to {req_info['host']}{req_info['path']}"
                        })
                        break
                
                # Check for scanner user agents
                ua_lower = req_info['user_agent'].lower()
                for scanner in SCANNER_USER_AGENTS:
                    if scanner in ua_lower:
                        self.risks.append({
                            'severity': 'HIGH',
                            'type': 'Scanner Detected',
                            'description': f"Scanner user agent: {scanner}",
                            'details': f"User-Agent: {req_info['user_agent']}",
                            'src_ip': req_info['src_ip'],
                            'timestamp': req_info['timestamp'],
                            'evidence': f"Scanner activity from {req_info['src_ip']}"
                        })
                        break
                
                # Check for large POST (potential exfiltration)
                if req_info['method'] == 'POST' and pkt.haslayer(Raw):
                    payload_len = len(pkt[Raw].load)
                    if payload_len > 10000:
                        self.risks.append({
                            'severity': 'MEDIUM',
                            'type': 'Large HTTP POST',
                            'description': f"Large POST request: {format_bytes(payload_len)}",
                            'details': f"POST to {req_info['path']}",
                            'src_ip': req_info['src_ip'],
                            'timestamp': req_info['timestamp'],
                            'evidence': f"{format_bytes(payload_len)} payload"
                        })
            
            elif pkt.haslayer(HTTPResponse):
                resp_info = {
                    'timestamp': datetime.fromtimestamp(float(pkt.time)),
                    'status_code': pkt[HTTPResponse].Status_Code.decode() if pkt[HTTPResponse].Status_Code else ''
                }
                self.http_responses.append(resp_info)
        
        print(f"[+] HTTP requests: {len(self.http_requests)}")
        print(f"[+] HTTP responses: {len(self.http_responses)}")
    
    def analyze_tls(self):
        """Analyze TLS/SSL traffic"""
        print("\n[*] Analyzing TLS/SSL traffic...")
        
        for pkt in self.packets:
            if pkt.haslayer(TLS):
                # TLS Client Hello
                if pkt.haslayer(TLSClientHello):
                    client_hello = pkt[TLSClientHello]
                    tls_version = client_hello.version if hasattr(client_hello, 'version') else 0
                    
                    tls_info = {
                        'timestamp': datetime.fromtimestamp(float(pkt.time)),
                        'src_ip': pkt[IP].src if pkt.haslayer(IP) else 'Unknown',
                        'dst_ip': pkt[IP].dst if pkt.haslayer(IP) else 'Unknown',
                        'type': 'ClientHello',
                        'version': tls_version
                    }
                    
                    self.tls_info.append(tls_info)
                    
                    # Check for weak TLS versions
                    if tls_version < 0x0303:  # TLS 1.2 = 0x0303
                        version_name = 'TLS 1.0' if tls_version == 0x0301 else 'TLS 1.1' if tls_version == 0x0302 else 'SSL'
                        self.risks.append({
                            'severity': 'HIGH',
                            'type': 'Weak TLS Version',
                            'description': f"Outdated TLS version: {version_name}",
                            'details': f"TLS version {hex(tls_version)} is deprecated",
                            'src_ip': tls_info['src_ip'],
                            'dst_ip': tls_info['dst_ip'],
                            'timestamp': tls_info['timestamp'],
                            'evidence': f"TLS handshake with version {hex(tls_version)}"
                        })
                
                # TLS Server Hello
                elif pkt.haslayer(TLSServerHello):
                    server_hello = pkt[TLSServerHello]
                    tls_version = server_hello.version if hasattr(server_hello, 'version') else 0
                    
                    tls_info = {
                        'timestamp': datetime.fromtimestamp(float(pkt.time)),
                        'src_ip': pkt[IP].src if pkt.haslayer(IP) else 'Unknown',
                        'dst_ip': pkt[IP].dst if pkt.haslayer(IP) else 'Unknown',
                        'type': 'ServerHello',
                        'version': tls_version
                    }
                    
                    self.tls_info.append(tls_info)
        
        print(f"[+] TLS handshakes: {len(self.tls_info)}")
    
    def extract_credentials(self):
        """Search for credentials in cleartext"""
        print("\n[*] Searching for credentials...")
        
        for pkt in self.packets:
            if pkt.haslayer(Raw):
                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                    
                    # Search for common credential patterns
                    patterns = {
                        'password': r'password[=:]\s*([^\s&]+)',
                        'username': r'user(?:name)?[=:]\s*([^\s&]+)',
                        'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                        'api_key': r'api[_-]?key[=:]\s*([a-zA-Z0-9]+)',
                    }
                    
                    for cred_type, pattern in patterns.items():
                        matches = re.finditer(pattern, payload, re.IGNORECASE)
                        for match in matches:
                            self.credentials.append({
                                'type': cred_type,
                                'value': match.group(0),
                                'src_ip': pkt[IP].src if pkt.haslayer(IP) else 'Unknown',
                                'dst_ip': pkt[IP].dst if pkt.haslayer(IP) else 'Unknown',
                                'timestamp': datetime.fromtimestamp(float(pkt.time))
                            })
                            
                            self.risks.append({
                                'severity': 'HIGH',
                                'type': 'Cleartext Credentials',
                                'description': f"Found {cred_type} in cleartext",
                                'details': f"Value: {match.group(0)[:50]}...",
                                'src_ip': pkt[IP].src if pkt.haslayer(IP) else 'Unknown',
                                'timestamp': datetime.fromtimestamp(float(pkt.time)),
                                'evidence': 'Credentials transmitted unencrypted'
                            })
                except:
                    pass
        
        print(f"[+] Credentials found: {len(self.credentials)}")
    
    def extract_files(self):
        """Extract files from HTTP traffic"""
        print("\n[*] Extracting files from traffic...")
        
        # Simple file extraction from HTTP
        for pkt in self.packets:
            if pkt.haslayer(HTTPResponse) and pkt.haslayer(Raw):
                try:
                    # Check for common file signatures
                    payload = pkt[Raw].load
                    
                    file_info = None
                    
                    # PDF
                    if payload.startswith(b'%PDF'):
                        file_info = {'type': 'PDF', 'ext': '.pdf'}
                    # ZIP
                    elif payload.startswith(b'PK\x03\x04'):
                        file_info = {'type': 'ZIP', 'ext': '.zip'}
                    # PNG
                    elif payload.startswith(b'\x89PNG'):
                        file_info = {'type': 'PNG', 'ext': '.png'}
                    # JPEG
                    elif payload.startswith(b'\xff\xd8\xff'):
                        file_info = {'type': 'JPEG', 'ext': '.jpg'}
                    # EXE
                    elif payload.startswith(b'MZ'):
                        file_info = {'type': 'EXE', 'ext': '.exe'}
                    
                    if file_info:
                        hashes = compute_file_hash(payload)
                        
                        self.extracted_files.append({
                            'type': file_info['type'],
                            'size': len(payload),
                            'md5': hashes['md5'],
                            'sha256': hashes['sha256'],
                            'timestamp': datetime.fromtimestamp(float(pkt.time)),
                            'src_ip': pkt[IP].src if pkt.haslayer(IP) else 'Unknown',
                            'dst_ip': pkt[IP].dst if pkt.haslayer(IP) else 'Unknown'
                        })
                        
                        # Flag executable downloads
                        if file_info['type'] == 'EXE':
                            self.risks.append({
                                'severity': 'MEDIUM',
                                'type': 'Executable Download',
                                'description': f"Downloaded executable file",
                                'details': f"MD5: {hashes['md5']}",
                                'src_ip': pkt[IP].dst if pkt.haslayer(IP) else 'Unknown',
                                'timestamp': datetime.fromtimestamp(float(pkt.time)),
                                'evidence': f"EXE file, {format_bytes(len(payload))}"
                            })
                except:
                    pass
        
        print(f"[+] Files extracted: {len(self.extracted_files)}")
    
    def identify_suspicious_packets(self):
        """Identify and store suspicious packets for detailed analysis"""
        print("\n[*] Identifying suspicious packets...")
        
        # Get packets associated with high-severity risks
        for risk in self.risks:
            if risk['severity'] in ['HIGH', 'MEDIUM']:
                # Find related packets
                for pkt in self.packets:
                    if pkt.haslayer(IP):
                        pkt_time = datetime.fromtimestamp(float(pkt.time))
                        if 'src_ip' in risk and pkt[IP].src == risk['src_ip']:
                            if abs((pkt_time - risk['timestamp']).total_seconds()) < 5:
                                if pkt not in [sp['packet'] for sp in self.suspicious_packets]:
                                    self.suspicious_packets.append({
                                        'packet': pkt,
                                        'risk_type': risk['type'],
                                        'timestamp': pkt_time
                                    })
                                    if len(self.suspicious_packets) >= 20:
                                        break
                    if len(self.suspicious_packets) >= 20:
                        break
                if len(self.suspicious_packets) >= 20:
                    break
        
        print(f"[+] Suspicious packets identified: {len(self.suspicious_packets)}")
    
    def generate_time_graph(self, output_file='traffic_timeline.png'):
        """Generate time-based traffic graph"""
        if plt is None:
            print("[-] Matplotlib not available, skipping graph generation")
            return None
        
        print(f"\n[*] Generating traffic timeline graph...")
        
        if not self.time_series:
            print("[-] No time series data available")
            return None
        
        times = [t[0] for t in self.time_series]
        counts = [t[1] for t in self.time_series]
        
        plt.figure(figsize=(12, 6))
        plt.plot(times, counts, linewidth=2, color='#2E86AB')
        plt.fill_between(times, counts, alpha=0.3, color='#2E86AB')
        
        plt.xlabel('Time', fontsize=12)
        plt.ylabel('Packets per Minute', fontsize=12)
        plt.title('Network Traffic Over Time', fontsize=14, fontweight='bold')
        plt.grid(True, alpha=0.3)
        
        # Format x-axis
        plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
        plt.gcf().autofmt_xdate()
        
        plt.tight_layout()
        plt.savefig(output_file, dpi=150)
        plt.close()
        
        print(f"[+] Graph saved to {output_file}")
        return output_file
    
    def generate_pdf_report(self, output_file='pcap_analysis_report.pdf'):
        """Generate comprehensive PDF report with text analysis"""
        if SimpleDocTemplate is None:
            print("[-] ReportLab not available, skipping PDF generation")
            return None
        
        print(f"\n[*] Generating PDF report...")
        
        doc = SimpleDocTemplate(output_file, pagesize=letter)
        story = []
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=TA_CENTER
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#2E86AB'),
            spaceAfter=12,
            spaceBefore=12
        )
        
        subheading_style = ParagraphStyle(
            'CustomSubheading',
            parent=styles['Heading3'],
            fontSize=12,
            textColor=colors.HexColor('#444444'),
            spaceAfter=8,
            spaceBefore=8
        )
        
        body_style = ParagraphStyle(
            'CustomBody',
            parent=styles['Normal'],
            fontSize=10,
            leading=14,
            spaceAfter=10
        )
        
        finding_style = ParagraphStyle(
            'Finding',
            parent=styles['Normal'],
            fontSize=9,
            leading=12,
            leftIndent=20,
            spaceAfter=8,
            textColor=colors.HexColor('#333333')
        )
        
        # Title
        story.append(Paragraph("PCAP Analysis Report", title_style))
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 
                              ParagraphStyle('subtitle', parent=styles['Normal'], alignment=TA_CENTER)))
        story.append(Spacer(1, 0.2*inch))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", heading_style))
        
        # Generate executive summary text
        high_risks = sum(1 for r in self.risks if r['severity'] == 'HIGH')
        medium_risks = sum(1 for r in self.risks if r['severity'] == 'MEDIUM')
        low_risks = sum(1 for r in self.risks if r['severity'] == 'LOW')
        
        duration_str = str(self.end_time - self.start_time) if self.end_time and self.start_time else 'Unknown'
        
        # Overall assessment
        if high_risks > 5:
            overall_status = "CRITICAL"
            status_color = colors.red
            assessment = "This network capture shows significant security concerns requiring immediate attention."
        elif high_risks > 0 or medium_risks > 10:
            overall_status = "WARNING"
            status_color = colors.orange
            assessment = "This network capture contains security issues that should be investigated."
        elif medium_risks > 0:
            overall_status = "CAUTION"
            status_color = colors.yellow
            assessment = "This network capture shows some security concerns worth reviewing."
        else:
            overall_status = "NORMAL"
            status_color = colors.green
            assessment = "This network capture appears to be relatively clean with minimal security concerns."
        
        story.append(Paragraph(f"<b>Overall Security Status: <font color='{status_color}'>{overall_status}</font></b>", body_style))
        story.append(Paragraph(assessment, body_style))
        story.append(Spacer(1, 0.1*inch))
        
        # Summary narrative
        summary_text = f"""
        This analysis examined <b>{self.packet_count:,} packets</b> captured over a period of <b>{duration_str}</b>, 
        spanning from {self.start_time.strftime('%Y-%m-%d %H:%M:%S') if self.start_time else 'N/A'} to 
        {self.end_time.strftime('%Y-%m-%d %H:%M:%S') if self.end_time else 'N/A'}. 
        The capture involves communication between <b>{len(self.ip_stats['sources'])} unique source IP addresses</b> 
        and <b>{len(self.ip_stats['destinations'])} unique destination IP addresses</b>, 
        representing a total of <b>{len(self.ip_stats['pairs'])} distinct communication flows</b>.
        """
        story.append(Paragraph(summary_text, body_style))
        story.append(Spacer(1, 0.1*inch))
        
        # Risk summary
        if self.risks:
            risk_text = f"""
            The automated analysis identified <b>{len(self.risks)} total security findings</b>, categorized as follows: 
            <font color='red'><b>{high_risks} HIGH severity</b></font>, 
            <font color='orange'><b>{medium_risks} MEDIUM severity</b></font>, and 
            <font color='green'>{low_risks} LOW severity</font> risks. 
            High severity findings require immediate investigation and remediation, while medium severity findings 
            should be reviewed for potential security policy violations or indicators of compromise.
            """
            story.append(Paragraph(risk_text, body_style))
        else:
            story.append(Paragraph("No security risks were automatically identified in this capture.", body_style))
        
        story.append(Spacer(1, 0.2*inch))
        
        # Summary table
        summary_data = [
            ['Metric', 'Value'],
            ['Total Packets Analyzed', f"{self.packet_count:,}"],
            ['Unique Source IPs', f"{len(self.ip_stats['sources']):,}"],
            ['Unique Destination IPs', f"{len(self.ip_stats['destinations']):,}"],
            ['Capture Duration', duration_str],
            ['Start Time', self.start_time.strftime('%Y-%m-%d %H:%M:%S') if self.start_time else 'N/A'],
            ['End Time', self.end_time.strftime('%Y-%m-%d %H:%M:%S') if self.end_time else 'N/A'],
            ['Total Security Findings', f"{len(self.risks)}"],
            ['Critical/High Severity', f"{high_risks}"],
            ['Medium Severity', f"{medium_risks}"],
            ['Low Severity', f"{low_risks}"],
        ]
        
        summary_table = Table(summary_data, colWidths=[3*inch, 3*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2E86AB')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 0.3*inch))
        
        # ATTACK CHAIN NARRATIVE - For non-technical readers
        if self.attack_chain and len(self.attack_chain) > 0:
            story.append(PageBreak())
            story.append(Paragraph("Attack Timeline & Narrative", heading_style))
            
            # Generate narrative for non-technical audience
            attack_narrative = """
            This section provides a plain-language explanation of the cyberattack detected in this network capture, 
            designed to be understood by non-technical stakeholders. The narrative describes what happened, when it 
            happened, and what the attacker was trying to accomplish.
            """
            story.append(Paragraph(attack_narrative, body_style))
            story.append(Spacer(1, 0.15*inch))
            
            # Attack summary for non-technical readers
            story.append(Paragraph("What Happened: Executive Overview", subheading_style))
            
            # Determine attack type
            attack_phases = set([event['phase'] for event in self.attack_chain])
            attack_types = set([event['event'] for event in self.attack_chain])
            
            if len(self.attack_chain) > 3:
                attack_severity = "sophisticated, multi-stage cyberattack"
            elif any('Exfiltration' in event['phase'] for event in self.attack_chain):
                attack_severity = "data breach attempt"
            elif any('Malware' in event['phase'] for event in self.attack_chain):
                attack_severity = "malware infection"
            else:
                attack_severity = "security incident"
            
            overview = f"""
            Network analysis has detected evidence of a <b>{attack_severity}</b> that occurred between 
            {self.attack_chain[0]['timestamp'].strftime('%Y-%m-%d %H:%M:%S UTC')} and 
            {self.attack_chain[-1]['timestamp'].strftime('%H:%M:%S UTC')}. The attack progressed through 
            <b>{len(attack_phases)} distinct phases</b> and involved <b>{len(self.attack_chain)} observable events</b>.
            """
            
            if self.infection_info.get('infected_ip'):
                overview += f"""<br/><br/>
                The primary victim was computer <b>{self.infection_info['infected_ip']}</b>
                {f" (hostname: {self.infection_info['infected_hostname']})" if self.infection_info.get('infected_hostname') else ""}.
                """
            
            if self.infection_info.get('stolen_data_types'):
                overview += f"""<br/><br/>
                <b>Compromised Information:</b> The attacker attempted to steal: {', '.join(self.infection_info['stolen_data_types'])}.
                """
            
            story.append(Paragraph(overview, body_style))
            story.append(Spacer(1, 0.2*inch))
            
            # Step-by-step attack narrative
            story.append(Paragraph("Attack Timeline: What the Attacker Did", subheading_style))
            
            story.append(Paragraph(
                "The following timeline explains each step of the attack in plain language, "
                "showing how the attacker gained access, what they did, and what they tried to steal:",
                body_style))
            story.append(Spacer(1, 0.1*inch))
            
            # Group events by phase
            phases_order = ['Reconnaissance', 'Initial Access', 'Credential Access', 'Malware Delivery', 
                          'Command & Control', 'Exfiltration']
            
            current_phase = None
            step_number = 1
            
            for event in self.attack_chain:
                if event['phase'] != current_phase:
                    current_phase = event['phase']
                    
                    # Phase header with icon
                    phase_icons = {
                        'Reconnaissance': '🔍',
                        'Initial Access': '🚪',
                        'Credential Access': '🔑',
                        'Malware Delivery': '💀',
                        'Command & Control': '📡',
                        'Exfiltration': '📤'
                    }
                    
                    phase_color = colors.red if current_phase in ['Malware Delivery', 'Exfiltration'] else \
                                colors.orange if current_phase in ['Credential Access', 'Command & Control'] else \
                                colors.blue
                    
                    story.append(Spacer(1, 0.15*inch))
                    story.append(Paragraph(
                        f"<b>{phase_icons.get(current_phase, '▶')} PHASE: {current_phase.upper()}</b>",
                        ParagraphStyle(f'phase_{current_phase}', parent=subheading_style, 
                                     textColor=phase_color, fontSize=11)
                    ))
                    story.append(Spacer(1, 0.08*inch))
                
                # Event details - non-technical explanation
                event_time = event['timestamp'].strftime('%H:%M:%S UTC')
                
                event_text = f"""
                <b>Step {step_number} - {event_time}:</b> {event['non_technical']}<br/>
                <i>Technical Detail:</i> {event['technical']}
                """
                
                story.append(Paragraph(event_text, 
                                     ParagraphStyle('event_detail', parent=body_style, 
                                                  fontSize=9, leftIndent=15, spaceBefore=5, spaceAfter=5)))
                
                step_number += 1
            
            story.append(Spacer(1, 0.2*inch))
            
            # Impact assessment
            story.append(Paragraph("Impact Assessment: What This Means", subheading_style))
            
            impact_text = """
            <b>Business Impact:</b><br/>
            """
            
            if 'Exfiltration' in attack_phases:
                impact_text += """
                • <font color='red'><b>Data Breach:</b></font> Sensitive data was transmitted to an external location 
                controlled by the attacker. This may constitute a reportable data breach requiring notification to 
                affected parties and regulatory bodies.<br/>
                """
            
            if 'Malware Delivery' in attack_phases:
                impact_text += """
                • <font color='red'><b>Malware Infection:</b></font> Malicious software was installed on company systems. 
                This malware could provide persistent access to the attacker, encrypt files for ransom, or spread to 
                other systems on the network.<br/>
                """
            
            if 'Credential Access' in attack_phases:
                impact_text += """
                • <font color='orange'><b>Compromised Accounts:</b></font> User credentials (usernames and passwords) 
                were stolen. The attacker can use these to impersonate legitimate users and access other systems.<br/>
                """
            
            if 'Command & Control' in attack_phases:
                impact_text += """
                • <font color='orange'><b>Ongoing Threat:</b></font> The infected system is actively communicating with 
                attacker-controlled servers. This indicates the attack may still be in progress and the attacker retains 
                control over compromised systems.<br/>
                """
            
            impact_text += """
            <br/>
            <b>Recommended Immediate Actions:</b><br/>
            1. <b>Isolate affected systems</b> - Disconnect the infected computer from the network to prevent spread<br/>
            2. <b>Reset all passwords</b> - Change credentials for any accounts used on the compromised system<br/>
            3. <b>Preserve evidence</b> - Do not delete or modify files on affected systems; maintain forensic evidence<br/>
            4. <b>Notify security team</b> - Escalate to incident response team for full investigation<br/>
            5. <b>Check for additional victims</b> - Scan other systems for similar indicators of compromise
            """
            
            story.append(Paragraph(impact_text, body_style))
            story.append(Spacer(1, 0.2*inch))
            
            # Infection details table
            story.append(PageBreak())
            story.append(Paragraph("Incident Response Details", heading_style))
            
            story.append(Paragraph(
                "The following technical details answer key incident response questions and should be used "
                "by security teams for investigation and remediation:",
                body_style))
            story.append(Spacer(1, 0.15*inch))
            
            # Critical questions table
            incident_data = [
                ['Question', 'Answer', 'Response Action'],
                [
                    'When did the infection start?',
                    self.infection_info.get('infection_start_utc', 'Unknown').strftime('%Y-%m-%d %H:%M:%S UTC') 
                        if self.infection_info.get('infection_start_utc') else 'Not detected',
                    'Check logs from this time'
                ],
                [
                    'What is the infected IP address?',
                    self.infection_info.get('infected_ip', 'Not identified'),
                    'Isolate this host immediately'
                ],
                [
                    'What is the infected MAC address?',
                    self.infection_info.get('infected_mac', 'Not detected'),
                    'Use for network tracking'
                ],
                [
                    'What is the infected hostname?',
                    self.infection_info.get('infected_hostname', 'Not detected'),
                    'Identify user and department'
                ],
                [
                    'What is the user account?',
                    self.infection_info.get('user_account', 'Not detected'),
                    'Reset password, review access'
                ],
                [
                    'What data was targeted?',
                    ', '.join(self.infection_info.get('stolen_data_types', ['Unknown'])) if self.infection_info.get('stolen_data_types') else 'Not determined',
                    'Assess data breach scope'
                ]
            ]
            
            incident_table = Table(incident_data, colWidths=[2*inch, 2*inch, 2*inch])
            incident_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#CC0000')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('FONTSIZE', (0, 1), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
            ]))
            story.append(incident_table)
            story.append(Spacer(1, 0.3*inch))
            
            # Attack visualization timeline
            story.append(Paragraph("Attack Timeline Visualization", subheading_style))
            
            timeline_text = "<font face='Courier' size='8'>"
            for i, event in enumerate(self.attack_chain, 1):
                timeline_text += f"{event['timestamp'].strftime('%H:%M:%S')} | "
                timeline_text += f"{'═'*i}▶ {event['phase']}: {event['event']}<br/>"
            timeline_text += "</font>"
            
            story.append(Paragraph(timeline_text, body_style))
        
        story.append(PageBreak())
        
        # Protocol Distribution
        story.append(Paragraph("Protocol Distribution Analysis", heading_style))
        
        # Protocol analysis text
        total_proto = sum(self.protocol_counts.values())
        top_protocol = self.protocol_counts.most_common(1)[0] if self.protocol_counts else ('None', 0)
        
        proto_text = f"""
        The network traffic analysis identified <b>{len(self.protocol_counts)} distinct protocols</b> across all packets. 
        The dominant protocol is <b>{top_protocol[0]}</b>, accounting for <b>{(top_protocol[1]/total_proto*100):.1f}%</b> 
        of all traffic ({top_protocol[1]:,} packets). This distribution provides insights into the primary communication 
        patterns and services being utilized on the network.
        """
        story.append(Paragraph(proto_text, body_style))
        
        # Protocol security commentary
        insecure_protos = []
        for proto in ['FTP', 'Telnet', 'HTTP']:
            if proto in self.protocol_counts and self.protocol_counts[proto] > 0:
                insecure_protos.append(f"{proto} ({self.protocol_counts[proto]} packets)")
        
        if insecure_protos:
            security_note = f"""
            <b>Security Note:</b> The capture contains insecure cleartext protocols: {', '.join(insecure_protos)}. 
            These protocols transmit data without encryption and should be replaced with secure alternatives 
            (SFTP, SSH, HTTPS respectively) to prevent credential theft and data interception.
            """
            story.append(Paragraph(security_note, 
                                 ParagraphStyle('warning', parent=body_style, textColor=colors.red)))
        
        story.append(Spacer(1, 0.1*inch))
        
        protocol_data = [['Protocol', 'Count', 'Percentage', 'Security Status']]
        for proto, count in self.protocol_counts.most_common(10):
            pct = (count / total_proto * 100) if total_proto > 0 else 0
            
            # Determine security status
            if proto in ['HTTPS', 'SSH', 'TLS/SSL']:
                sec_status = '✓ Secure'
            elif proto in ['FTP', 'Telnet', 'HTTP']:
                sec_status = '⚠ Insecure'
            else:
                sec_status = '- Neutral'
            
            protocol_data.append([proto, f"{count:,}", f"{pct:.2f}%", sec_status])
        
        protocol_table = Table(protocol_data, colWidths=[1.5*inch, 1.5*inch, 1.5*inch, 1.5*inch])
        protocol_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2E86AB')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(protocol_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Top Talkers
        story.append(Paragraph("IP Address Analysis - Top Talkers", heading_style))
        
        # Top talkers analysis
        if self.ip_stats['sources']:
            top_src = self.ip_stats['sources'].most_common(1)[0]
            total_bytes = sum(self.ip_stats['bytes_sent'].values())
            
            talker_text = f"""
            Network traffic shows <b>{len(self.ip_stats['sources'])} unique source IP addresses</b> actively 
            transmitting data. The most active host is <b>{top_src[0]}</b>, which generated <b>{top_src[1]:,} packets</b> 
            ({format_bytes(self.ip_stats['bytes_sent'][top_src[0]])}) representing 
            <b>{(top_src[1]/self.packet_count*100):.1f}%</b> of all traffic. This level of activity could indicate 
            a server, heavy workstation, or potentially an infected host exfiltrating data.
            """
            story.append(Paragraph(talker_text, body_style))
            
            # Check for potential data exfiltration
            high_volume_hosts = [ip for ip, bytes_sent in self.ip_stats['bytes_sent'].items() 
                               if bytes_sent > 10000000]  # >10MB
            if high_volume_hosts:
                exfil_warning = f"""
                <b>Data Transfer Alert:</b> {len(high_volume_hosts)} host(s) transferred more than 10MB of data: 
                {', '.join(high_volume_hosts[:5])}. Large outbound transfers warrant investigation for potential 
                data exfiltration, backup operations, or legitimate file transfers.
                """
                story.append(Paragraph(exfil_warning, 
                                     ParagraphStyle('alert', parent=body_style, textColor=colors.orange)))
            
            story.append(Spacer(1, 0.1*inch))
        
        talker_data = [['IP Address', 'Packets Sent', 'Bytes Sent', '% of Traffic']]
        for ip, count in self.ip_stats['sources'].most_common(10):
            pct = (count / self.packet_count * 100) if self.packet_count > 0 else 0
            talker_data.append([
                ip, 
                f"{count:,}", 
                format_bytes(self.ip_stats['bytes_sent'][ip]),
                f"{pct:.2f}%"
            ])
        
        talker_table = Table(talker_data, colWidths=[2*inch, 1.5*inch, 1.5*inch, 1*inch])
        talker_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2E86AB')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(talker_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Top Communication Pairs
        story.append(Paragraph("Communication Flow Analysis", heading_style))
        
        # Flow analysis text
        if self.ip_stats['pairs']:
            total_pairs = len(self.ip_stats['pairs'])
            top_pair = self.ip_stats['pairs'].most_common(1)[0]
            
            flow_text = f"""
            Analysis identified <b>{total_pairs} unique communication flows</b> between source and destination pairs. 
            The most active communication pair is from <b>{top_pair[0][0]}</b> to <b>{top_pair[0][1]}</b> with 
            <b>{top_pair[1]:,} packets</b> exchanged. Communication patterns can reveal client-server relationships, 
            peer-to-peer connections, or potential command-and-control (C2) channels.
            """
            story.append(Paragraph(flow_text, body_style))
            
            # Check for potential C2 patterns
            suspicious_pairs = []
            for (src, dst), count in self.ip_stats['pairs'].items():
                # Check if destination is external and has regular traffic
                if count > 20 and count < 200:  # Regular small bursts could indicate C2
                    suspicious_pairs.append((src, dst, count))
            
            if suspicious_pairs and len(suspicious_pairs) < 5:
                c2_note = f"""
                <b>Behavioral Note:</b> Detected {len(suspicious_pairs)} flow(s) with regular, moderate packet counts 
                that could indicate beaconing behavior. These should be investigated for potential C2 communication.
                """
                story.append(Paragraph(c2_note, 
                                     ParagraphStyle('note', parent=body_style, textColor=colors.blue)))
            
            story.append(Spacer(1, 0.1*inch))
        
        pair_data = [['Source IP', 'Destination IP', 'Packets', 'Communication Type']]
        for (src, dst), count in self.ip_stats['pairs'].most_common(5):
            # Infer communication type
            if count > 1000:
                comm_type = 'Heavy Traffic'
            elif count > 100:
                comm_type = 'Active Session'
            elif count > 20:
                comm_type = 'Regular Connection'
            else:
                comm_type = 'Limited Exchange'
            
            pair_data.append([src, dst, f"{count:,}", comm_type])
        
        pair_table = Table(pair_data, colWidths=[2*inch, 2*inch, 1*inch, 1.5*inch])
        pair_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2E86AB')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(pair_table)
        story.append(PageBreak())
        
        # Port Analysis
        story.append(Paragraph("Port and Service Analysis", heading_style))
        
        # TCP port analysis
        story.append(Paragraph("TCP Port Activity", subheading_style))
        
        if self.port_stats['tcp']:
            top_tcp = self.port_stats['tcp'].most_common(1)[0]
            common_services = {
                80: 'HTTP (Web)', 443: 'HTTPS (Secure Web)', 22: 'SSH', 
                21: 'FTP', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
                3389: 'RDP', 445: 'SMB', 3306: 'MySQL', 5432: 'PostgreSQL'
            }
            
            tcp_text = f"""
            TCP traffic analysis reveals <b>{len(self.port_stats['tcp'])} unique destination ports</b> being accessed. 
            The most frequently targeted port is <b>{top_tcp[0]}</b> ({common_services.get(top_tcp[0], 'Unknown service')}) 
            with <b>{top_tcp[1]:,} packets</b>. TCP port patterns indicate the types of services being accessed and 
            can reveal both legitimate business operations and potential attack vectors.
            """
            story.append(Paragraph(tcp_text, body_style))
            
            # Security assessment
            risky_ports = []
            for port in [21, 23, 445, 3389]:
                if port in self.port_stats['tcp'] and self.port_stats['tcp'][port] > 0:
                    risky_ports.append(f"{port} ({common_services.get(port, 'Unknown')})")
            
            if risky_ports:
                security_warning = f"""
                <b>Security Concern:</b> Detected traffic to high-risk ports: {', '.join(risky_ports)}. 
                These ports are commonly targeted by attackers for lateral movement, brute force attacks, and malware propagation. 
                Verify that this traffic is authorized and implements proper security controls.
                """
                story.append(Paragraph(security_warning, 
                                     ParagraphStyle('warning2', parent=body_style, textColor=colors.red)))
            
            story.append(Spacer(1, 0.1*inch))
        
        tcp_port_data = [['Port', 'Count', 'Service', 'Risk Level']]
        for port, count in self.port_stats['tcp'].most_common(10):
            service = INSECURE_PROTOCOLS.get(port, SUSPICIOUS_PORTS.get(port, 'Standard'))
            
            # Determine risk level
            if port in SUSPICIOUS_PORTS:
                risk = '⚠ HIGH'
            elif port in INSECURE_PROTOCOLS:
                risk = '⚠ MEDIUM'
            elif port in [443, 22, 993, 995]:
                risk = '✓ LOW'
            else:
                risk = '- NORMAL'
            
            tcp_port_data.append([str(port), f"{count:,}", str(service), risk])
        
        tcp_port_table = Table(tcp_port_data, colWidths=[1*inch, 1.2*inch, 2.5*inch, 1.3*inch])
        tcp_port_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2E86AB')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(tcp_port_table)
        story.append(Spacer(1, 0.3*inch))
        
        # UDP Ports
        story.append(Paragraph("UDP Port Activity", subheading_style))
        
        if self.port_stats['udp']:
            udp_text = f"""
            UDP traffic analysis identified <b>{len(self.port_stats['udp'])} unique destination ports</b>. 
            UDP is a connectionless protocol commonly used for DNS queries, VoIP, streaming, and network management. 
            While legitimate, UDP can also be exploited for DDoS amplification attacks and data exfiltration tunneling.
            """
            story.append(Paragraph(udp_text, body_style))
            story.append(Spacer(1, 0.1*inch))
        
        udp_port_data = [['Port', 'Count', 'Service', 'Usage']]
        for port, count in self.port_stats['udp'].most_common(10):
            service = 'DNS' if port == 53 else 'DHCP' if port in [67, 68] else 'NTP' if port == 123 else 'SNMP' if port == 161 else 'Unknown'
            usage = 'Name Resolution' if port == 53 else 'IP Assignment' if port in [67, 68] else 'Time Sync' if port == 123 else 'Network Mgmt' if port == 161 else 'Custom'
            udp_port_data.append([str(port), f"{count:,}", service, usage])
        
        udp_port_table = Table(udp_port_data, colWidths=[1*inch, 1.2*inch, 1.8*inch, 2*inch])
        udp_port_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2E86AB')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(udp_port_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Traffic Timeline Graph
        graph_file = self.generate_time_graph()
        if graph_file and os.path.exists(graph_file):
            story.append(Paragraph("Traffic Timeline", heading_style))
            img = Image(graph_file, width=6*inch, height=3*inch)
            story.append(img)
            story.append(Spacer(1, 0.3*inch))
        
        story.append(PageBreak())
        
        # Security Risks
        story.append(Paragraph("Security Risk Analysis & Threat Assessment", heading_style))
        
        if self.risks:
            # Overall risk assessment narrative
            high_risks_list = [r for r in self.risks if r['severity'] == 'HIGH']
            medium_risks_list = [r for r in self.risks if r['severity'] == 'MEDIUM']
            low_risks_list = [r for r in self.risks if r['severity'] == 'LOW']
            
            risk_summary = f"""
            The automated security analysis engine identified <b>{len(self.risks)} potential security concerns</b> 
            across the network traffic capture. These findings have been categorized by severity to prioritize 
            remediation efforts: <font color='red'><b>{len(high_risks_list)} CRITICAL/HIGH</b></font> severity 
            issues requiring immediate action, <font color='orange'><b>{len(medium_risks_list)} MEDIUM</b></font> 
            severity issues warranting investigation, and <font color='green'>{len(low_risks_list)} LOW</font> 
            severity items for awareness.
            """
            story.append(Paragraph(risk_summary, body_style))
            story.append(Spacer(1, 0.15*inch))
            
            # Risk category breakdown
            risk_types = {}
            for risk in self.risks:
                risk_type = risk['type']
                if risk_type not in risk_types:
                    risk_types[risk_type] = {'count': 0, 'severity': risk['severity']}
                risk_types[risk_type]['count'] += 1
            
            if len(risk_types) > 1:
                category_text = f"""
                <b>Threat Landscape:</b> Analysis detected <b>{len(risk_types)} different threat categories</b>, 
                suggesting potential multi-vector compromise or policy violations. Common attack patterns include: 
                {', '.join(list(risk_types.keys())[:5])}. This diversity indicates either a sophisticated adversary 
                or multiple independent security issues requiring attention.
                """
                story.append(Paragraph(category_text, body_style))
                story.append(Spacer(1, 0.15*inch))
            
            # Group by severity
            for severity, risks_subset in [('HIGH', high_risks_list), ('MEDIUM', medium_risks_list), ('LOW', low_risks_list)]:
                if risks_subset:
                    severity_color = colors.red if severity == 'HIGH' else colors.orange if severity == 'MEDIUM' else colors.green
                    
                    story.append(Paragraph(f"{severity} Severity Risks ({len(risks_subset)} findings)", 
                                         ParagraphStyle(f'{severity}Heading', 
                                                       parent=styles['Heading3'], 
                                                       textColor=severity_color,
                                                       fontSize=12,
                                                       spaceAfter=10)))
                    
                    # Severity-specific guidance
                    if severity == 'HIGH':
                        guidance = """
                        <b>Action Required:</b> High severity findings indicate active threats, policy violations, 
                        or significant security weaknesses. These should be investigated immediately and remediated 
                        within 24-48 hours. Findings may indicate compromise, reconnaissance, or data breach attempts.
                        """
                        story.append(Paragraph(guidance, 
                                             ParagraphStyle('guidance', parent=body_style, 
                                                          textColor=colors.red, fontSize=9, leftIndent=10)))
                    elif severity == 'MEDIUM':
                        guidance = """
                        <b>Recommended Action:</b> Medium severity findings suggest security concerns that should be 
                        reviewed and addressed within one week. While not immediately critical, these issues could 
                        escalate or indicate early-stage attack activity.
                        """
                        story.append(Paragraph(guidance, 
                                             ParagraphStyle('guidance2', parent=body_style, 
                                                          textColor=colors.orange, fontSize=9, leftIndent=10)))
                    
                    story.append(Spacer(1, 0.1*inch))
                    
                    # Risk table for this severity
                    risk_data = [['Finding Type', 'Description', 'Source', 'Evidence']]
                    for risk in risks_subset[:15]:  # Limit to 15 per severity for readability
                        risk_data.append([
                            risk['type'][:25],
                            risk['description'][:45] + ('...' if len(risk['description']) > 45 else ''),
                            risk.get('src_ip', 'N/A')[:20],
                            risk.get('evidence', risk.get('details', 'See JSON'))[:30]
                        ])
                    
                    risk_table = Table(risk_data, colWidths=[1.3*inch, 1.8*inch, 1.3*inch, 1.6*inch])
                    risk_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), severity_color),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, -1), 8),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ]))
                    story.append(risk_table)
                    
                    # Add detailed findings with JSON data
                    story.append(Spacer(1, 0.15*inch))
                    story.append(Paragraph(f"Detailed {severity} Severity Findings:", subheading_style))
                    
                    for i, risk in enumerate(risks_subset[:10], 1):  # Top 10 detailed
                        finding_text = f"""
                        <b>{i}. {risk['type']}</b><br/>
                        <b>Description:</b> {risk['description']}<br/>
                        <b>Details:</b> {risk.get('details', 'N/A')}<br/>
                        <b>Source IP:</b> {risk.get('src_ip', 'Unknown')} | 
                        <b>Destination:</b> {risk.get('dst_ip', 'N/A')} | 
                        <b>Timestamp:</b> {risk['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}<br/>
                        <b>Evidence:</b> {risk.get('evidence', 'Refer to packet capture for full context')}
                        """
                        story.append(Paragraph(finding_text, finding_style))
                        story.append(Spacer(1, 0.08*inch))
                    
                    if len(risks_subset) > 10:
                        story.append(Paragraph(f"<i>+ {len(risks_subset) - 10} additional {severity} severity findings. "
                                             "See JSON export for complete details.</i>", 
                                             ParagraphStyle('note2', parent=body_style, fontSize=9, textColor=colors.grey)))
                    
                    story.append(Spacer(1, 0.2*inch))
            
            # Recommendations section
            story.append(PageBreak())
            story.append(Paragraph("Security Recommendations", heading_style))
            
            recommendations = []
            
            # Generate context-aware recommendations
            if any('Port Scan' in r['type'] for r in self.risks):
                recommendations.append(
                    "• <b>Port Scan Mitigation:</b> Deploy intrusion detection/prevention systems (IDS/IPS) to detect and block port scanning attempts. "
                    "Implement host-based firewalls and reduce attack surface by closing unnecessary ports. Review logs for the scanning source IP."
                )
            
            if any('Insecure Protocol' in r['type'] or 'Cleartext' in r['type'] for r in self.risks):
                recommendations.append(
                    "• <b>Protocol Security:</b> Replace insecure protocols (FTP, Telnet, HTTP) with encrypted alternatives (SFTP, SSH, HTTPS). "
                    "Enforce TLS 1.2+ for all encrypted communications. Implement network policies blocking cleartext authentication."
                )
            
            if any('DNS' in r['type'] for r in self.risks):
                recommendations.append(
                    "• <b>DNS Security:</b> Implement DNS filtering to block known malicious domains. Deploy DNS monitoring for DGA detection. "
                    "Use DNSSEC where possible. Investigate hosts making suspicious DNS queries for potential malware infection."
                )
            
            if any('Large' in r['type'] or 'Transfer' in r['type'] or 'exfil' in r['description'].lower() for r in self.risks):
                recommendations.append(
                    "• <b>Data Loss Prevention:</b> Implement DLP controls to monitor and restrict large outbound data transfers. "
                    "Establish baseline traffic patterns and alert on anomalies. Review identified transfers for unauthorized data exfiltration."
                )
            
            if any('TLS' in r['type'] or 'SSL' in r['type'] for r in self.risks):
                recommendations.append(
                    "• <b>Encryption Standards:</b> Audit and upgrade TLS configurations across all servers. Disable TLS 1.0/1.1 and weak cipher suites. "
                    "Implement certificate pinning where applicable. Regular SSL/TLS security assessments recommended."
                )
            
            if any('Beacon' in r['type'] or 'C2' in r['type'] for r in self.risks):
                recommendations.append(
                    "• <b>C2 Detection:</b> Investigate beacon patterns for malware communication. Deploy network behavior analysis tools. "
                    "Block identified C2 domains/IPs at firewall/proxy. Quarantine and forensically analyze affected hosts."
                )
            
            # Generic recommendations
            recommendations.extend([
                "• <b>Network Monitoring:</b> Implement 24/7 Security Operations Center (SOC) monitoring with automated alerting for detected threat patterns.",
                "• <b>Incident Response:</b> Develop and test incident response procedures for identified threat types. Maintain forensic evidence chain of custody.",
                "• <b>User Training:</b> Conduct security awareness training on phishing, malware, and safe browsing practices.",
                "• <b>Patch Management:</b> Ensure all systems are current with security patches, especially for services identified in this analysis.",
                "• <b>Access Control:</b> Implement least privilege access controls and multi-factor authentication for all critical systems.",
                "• <b>Regular Audits:</b> Conduct periodic network traffic analysis and security assessments to identify evolving threats."
            ])
            
            for rec in recommendations:
                story.append(Paragraph(rec, body_style))
                story.append(Spacer(1, 0.08*inch))
        
        else:
            story.append(Paragraph("No automated security risks were detected in this network capture. "
                                 "However, manual review is still recommended as automated tools cannot detect all threat types.",
                                 body_style))
        
        story.append(PageBreak())
        # DNS Analysis
        if self.dns_queries:
            story.append(Paragraph("DNS Traffic Analysis", heading_style))
            
            # DNS analysis narrative
            unique_domains = len(set([q['query'] for q in self.dns_queries]))
            total_queries = len(self.dns_queries)
            
            dns_narrative = f"""
            Domain Name System (DNS) analysis examined <b>{total_queries} DNS queries</b> requesting resolution for 
            <b>{unique_domains} unique domain names</b>. DNS traffic can reveal browsing habits, application behavior, 
            and potential security threats including malware C2 communication, phishing domains, and data exfiltration tunnels.
            """
            story.append(Paragraph(dns_narrative, body_style))
            
            # Check for suspicious patterns
            suspicious_dns = [q for q in self.dns_queries if any(tld in q['query'].lower() for tld in SUSPICIOUS_TLDS)]
            high_entropy_domains = []
            for q in self.dns_queries:
                domain_parts = q['query'].split('.')
                if domain_parts:
                    subdomain = domain_parts[0]
                    if len(subdomain) > 8 and calculate_entropy(subdomain) > DGA_ENTROPY_THRESHOLD:
                        high_entropy_domains.append(q['query'])
            
            if suspicious_dns or high_entropy_domains:
                threat_text = f"""
                <b>DNS Threat Indicators:</b> Detected {len(suspicious_dns)} queries to suspicious TLDs and 
                {len(set(high_entropy_domains))} high-entropy domains potentially generated by Domain Generation Algorithms (DGA). 
                DGA domains are commonly used by malware for C2 communication to evade blocklists. Immediate investigation recommended.
                """
                story.append(Paragraph(threat_text, 
                                     ParagraphStyle('dns_threat', parent=body_style, textColor=colors.red)))
            
            # Query volume analysis
            query_count_per_ip = {}
            for query in self.dns_queries:
                ip = query['src_ip']
                query_count_per_ip[ip] = query_count_per_ip.get(ip, 0) + 1
            
            high_volume_ips = [ip for ip, count in query_count_per_ip.items() if count > 50]
            if high_volume_ips:
                volume_note = f"""
                <b>High Query Volume:</b> {len(high_volume_ips)} host(s) generated unusually high DNS query volumes (>50 queries). 
                This could indicate DNS tunneling for data exfiltration, malware behavior, or legitimate high-activity applications.
                """
                story.append(Paragraph(volume_note, 
                                     ParagraphStyle('dns_vol', parent=body_style, textColor=colors.orange)))
            
            story.append(Spacer(1, 0.15*inch))
            
            # Top queried domains
            domain_counts = Counter([q['query'] for q in self.dns_queries])
            dns_data = [['Domain', 'Query Count', 'First Seen', 'Risk Assessment']]
            for domain, count in domain_counts.most_common(20):
                # Risk assessment
                is_susp, reasons = is_suspicious_domain(domain)
                risk = 'SUSPICIOUS' if is_susp else 'Normal'
                
                # Find first query time
                first_query = min([q['timestamp'] for q in self.dns_queries if q['query'] == domain])
                
                dns_data.append([
                    domain[:45], 
                    str(count),
                    first_query.strftime('%H:%M:%S'),
                    risk
                ])
            
            dns_table = Table(dns_data, colWidths=[2.5*inch, 1*inch, 1*inch, 1.5*inch])
            dns_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2E86AB')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(dns_table)
            story.append(Spacer(1, 0.3*inch))
        
        # HTTP Analysis
        if self.http_requests:
            story.append(PageBreak())
            story.append(Paragraph("HTTP Traffic Analysis", heading_style))
            
            # HTTP overview
            unique_hosts = len(set([r['host'] for r in self.http_requests if r['host']]))
            unique_uas = len(set([r['user_agent'] for r in self.http_requests if r['user_agent']]))
            methods = Counter([r['method'] for r in self.http_requests])
            
            http_narrative = f"""
            Hypertext Transfer Protocol (HTTP) analysis examined <b>{len(self.http_requests)} HTTP requests</b> 
            to <b>{unique_hosts} unique hosts</b> using <b>{unique_uas} different user agents</b>. 
            HTTP traffic analysis reveals web browsing activity, API usage, and potential web-based attacks. 
            The request method distribution was: {', '.join([f'{m}: {c}' for m, c in methods.most_common(3)])}.
            """
            story.append(Paragraph(http_narrative, body_style))
            
            # Security assessment
            post_requests = [r for r in self.http_requests if r['method'] == 'POST']
            suspicious_paths = [r for r in self.http_requests 
                              if any(pattern in r['path'].lower() for pattern in SUSPICIOUS_URIS)]
            scanner_uas = [r for r in self.http_requests 
                          if any(scanner in r['user_agent'].lower() for scanner in SCANNER_USER_AGENTS)]
            
            security_concerns = []
            if len(post_requests) > 20:
                security_concerns.append(f"{len(post_requests)} POST requests (potential form submissions/data uploads)")
            if suspicious_paths:
                security_concerns.append(f"{len(suspicious_paths)} requests to suspicious URIs (admin panels, shell paths)")
            if scanner_uas:
                security_concerns.append(f"{len(scanner_uas)} requests from known security scanners")
            
            if security_concerns:
                http_security = f"""
                <b>HTTP Security Findings:</b> {'; '.join(security_concerns)}. 
                Suspicious HTTP activity may indicate web application attacks, vulnerability scanning, or 
                unauthorized access attempts. Review server logs and implement Web Application Firewall (WAF) protection.
                """
                story.append(Paragraph(http_security, 
                                     ParagraphStyle('http_sec', parent=body_style, textColor=colors.orange)))
            
            story.append(Spacer(1, 0.15*inch))
            
            # HTTP summary table
            http_summary = [
                ['Metric', 'Value', 'Security Impact'],
                ['Total HTTP Requests', str(len(self.http_requests)), 'Unencrypted - Cleartext'],
                ['Unique Hosts Accessed', str(unique_hosts), 'Web Browsing Scope'],
                ['Unique User Agents', str(unique_uas), 'Client Diversity/Scanners'],
                ['POST Requests', str(len(post_requests)), 'Data Submissions'],
                ['Suspicious Paths', str(len(suspicious_paths)), 'Attack Attempts'],
                ['Scanner Activity', str(len(scanner_uas)), 'Recon/Vulnerability Scan'],
            ]
            
            http_summary_table = Table(http_summary, colWidths=[2*inch, 1.5*inch, 2.5*inch])
            http_summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2E86AB')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(http_summary_table))
            
            # Top accessed hosts
            if unique_hosts > 0:
                story.append(Spacer(1, 0.2*inch))
                story.append(Paragraph("Most Accessed Web Hosts", subheading_style))
                
                host_counts = Counter([r['host'] for r in self.http_requests if r['host']])
                host_data = [['Hostname', 'Request Count', 'Sample Path']]
                for host, count in host_counts.most_common(10):
                    sample_path = next((r['path'] for r in self.http_requests if r['host'] == host), '/')
                    host_data.append([host[:40], str(count), sample_path[:30]])
                
                host_table = Table(host_data, colWidths=[2.5*inch, 1.2*inch, 2.3*inch])
                host_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2E86AB')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                story.append(host_table)
            
            # Suspicious requests detail
            if suspicious_paths:
                story.append(Spacer(1, 0.2*inch))
                story.append(Paragraph("Suspicious HTTP Requests Detected", subheading_style))
                
                for i, req in enumerate(suspicious_paths[:5], 1):
                    susp_detail = f"""
                    <b>{i}.</b> {req['method']} {req['host']}{req['path'][:60]}<br/>
                    Source: {req['src_ip']} | Time: {req['timestamp'].strftime('%H:%M:%S')}<br/>
                    User-Agent: {req['user_agent'][:80] if req['user_agent'] else 'None'}
                    """
                    story.append(Paragraph(susp_detail, finding_style))
                    story.append(Spacer(1, 0.05*inch))
                
                if len(suspicious_paths) > 5:
                    story.append(Paragraph(f"<i>+ {len(suspicious_paths) - 5} additional suspicious requests in JSON export</i>",
                                         ParagraphStyle('note3', parent=body_style, fontSize=8, textColor=colors.grey)))
            
            story.append(Spacer(1, 0.2*inch))
        
        # Extracted Files
        if self.extracted_files:
            story.append(PageBreak())
            story.append(Paragraph("File Extraction & Analysis", heading_style))
            
            # File extraction narrative
            total_size = sum([f['size'] for f in self.extracted_files])
            file_types = Counter([f['type'] for f in self.extracted_files])
            
            file_narrative = f"""
            Automated file carving extracted <b>{len(self.extracted_files)} files</b> from network traffic streams, 
            totaling <b>{format_bytes(total_size)}</b> of transferred data. Extracted file types include: 
            {', '.join([f'{ftype}: {count}' for ftype, count in file_types.most_common()])}.
            """
            story.append(Paragraph(file_narrative, body_style))
            
            # Security assessment
            exe_files = [f for f in self.extracted_files if f['type'] == 'EXE']
            if exe_files:
                exe_warning = f"""
                <b>SECURITY ALERT:</b> Detected <b>{len(exe_files)} executable file(s)</b> transferred over the network. 
                Executable downloads can indicate malware delivery, unauthorized software installation, or legitimate updates. 
                All executables should be scanned with antivirus and submitted to threat intelligence platforms. 
                File hashes are provided below for VirusTotal/MISP lookups.
                """
                story.append(Paragraph(exe_warning, 
                                     ParagraphStyle('exe_warn', parent=body_style, textColor=colors.red)))
            
            story.append(Spacer(1, 0.15*inch))
            
            file_data = [['File Type', 'Size', 'MD5 Hash', 'SHA256 Hash', 'Timestamp']]
            for file_info in self.extracted_files[:20]:
                file_data.append([
                    file_info['type'],
                    format_bytes(file_info['size']),
                    file_info['md5'][:16] + '...',
                    file_info['sha256'][:16] + '...',
                    file_info['timestamp'].strftime('%H:%M:%S')
                ])
            
            file_table = Table(file_data, colWidths=[0.8*inch, 0.9*inch, 1.4*inch, 1.4*inch, 0.8*inch])
            file_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2E86AB')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 7),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(file_table)
            
            # Full hash listing for verification
            story.append(Spacer(1, 0.2*inch))
            story.append(Paragraph("Complete File Hash Listing (for IOC checking)", subheading_style))
            
            hash_text = "<br/>".join([
                f"<b>{f['type']}</b> ({format_bytes(f['size'])}): MD5={f['md5']}, SHA256={f['sha256']}"
                for f in self.extracted_files[:10]
            ])
            story.append(Paragraph(hash_text, 
                                 ParagraphStyle('hash_list', parent=body_style, fontSize=8, leading=11)))
            
            if len(self.extracted_files) > 10:
                story.append(Paragraph(f"<i>+ {len(self.extracted_files) - 10} additional files. Full hash list in JSON export.</i>",
                                     ParagraphStyle('note4', parent=body_style, fontSize=8, textColor=colors.grey)))
        
        # TLS/SSL Analysis
        if self.tls_info:
            story.append(Spacer(1, 0.3*inch))
            story.append(Paragraph("TLS/SSL Encryption Analysis", heading_style))
            
            tls_versions = Counter([hex(t['version']) for t in self.tls_info if 'version' in t])
            
            tls_narrative = f"""
            Transport Layer Security (TLS) analysis identified <b>{len(self.tls_info)} TLS handshakes</b>. 
            TLS version distribution: {', '.join([f'{ver}: {count}' for ver, count in tls_versions.most_common()])}.
            Modern systems should use TLS 1.2 (0x0303) or TLS 1.3 (0x0304) exclusively.
            """
            story.append(Paragraph(tls_narrative, body_style))
            
            # Check for weak TLS
            weak_tls = [t for t in self.tls_info if t.get('version', 0x0304) < 0x0303]
            if weak_tls:
                tls_warning = f"""
                <b>ENCRYPTION WEAKNESS:</b> Detected {len(weak_tls)} connection(s) using outdated TLS versions (< TLS 1.2). 
                Weak encryption can be exploited through various attacks (POODLE, BEAST, etc.). 
                Immediate remediation required: upgrade servers to enforce TLS 1.2+.
                """
                story.append(Paragraph(tls_warning, 
                                     ParagraphStyle('tls_warn', parent=body_style, textColor=colors.red)))
            
            story.append(Spacer(1, 0.2*inch))
        
        # Credentials Analysis
        if self.credentials:
            story.append(Paragraph("Credential Exposure Analysis", heading_style))
            
            cred_types = Counter([c['type'] for c in self.credentials])
            
            cred_narrative = f"""
            <b>CRITICAL SECURITY ISSUE:</b> Cleartext credential analysis discovered <b>{len(self.credentials)} instances</b> 
            of sensitive information transmitted without encryption. Credential types found: 
            {', '.join([f'{ctype}: {count}' for ctype, count in cred_types.most_common()])}.
            """
            story.append(Paragraph(cred_narrative, 
                                 ParagraphStyle('cred_crit', parent=body_style, textColor=colors.red)))
            
            impact_text = """
            <b>Security Impact:</b> Cleartext credentials can be intercepted by attackers through man-in-the-middle attacks, 
            network sniffing, or malicious insiders. Exposed credentials should be immediately changed and systems should 
            enforce encrypted authentication (HTTPS, SSH, TLS).
            """
            story.append(Paragraph(impact_text, body_style))
            
            story.append(Spacer(1, 0.1*inch))
            
            # List credentials (sanitized)
            cred_data = [['Type', 'Source IP', 'Destination', 'Timestamp', 'Protocol']]
            for cred in self.credentials[:10]:
                cred_data.append([
                    cred['type'].upper(),
                    cred['src_ip'],
                    cred['dst_ip'],
                    cred['timestamp'].strftime('%H:%M:%S'),
                    'FTP/Telnet/HTTP'
                ])
            
            cred_table = Table(cred_data, colWidths=[1.2*inch, 1.5*inch, 1.5*inch, 1*inch, 1.3*inch])
            cred_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.red),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(cred_table)
            
            story.append(Paragraph("<i>Note: Actual credential values are NOT displayed for security. "
                                 "Refer to JSON export with appropriate access controls.</i>",
                                 ParagraphStyle('note5', parent=body_style, fontSize=8, textColor=colors.grey)))
            story.append(Spacer(1, 0.2*inch))
        
        # JSON Export Reference
        story.append(PageBreak())
        story.append(Paragraph("JSON Data Export", heading_style))
        
        json_text = f"""
        A complete JSON export has been generated containing all analysis data in structured format. 
        This export file (<b>pcap_analysis.json</b>) includes:
        <br/><br/>
        • Complete listing of all {len(self.risks)} security findings with full details<br/>
        • All {len(self.dns_queries)} DNS queries with timestamps and source IPs<br/>
        • Full HTTP request details including headers and user agents<br/>
        • Complete file hashes for all {len(self.extracted_files)} extracted files<br/>
        • Network flow statistics and communication patterns<br/>
        • Protocol distributions and port usage statistics<br/>
        • Credential findings (with values for authorized analysis)<br/>
        <br/>
        The JSON export can be imported into SIEM systems (Splunk, ELK, QRadar), threat intelligence platforms (MISP), 
        ticketing systems (Jira, ServiceNow), or custom analysis scripts. This enables automated incident response 
        workflows and integration with existing security infrastructure.
        <br/><br/>
        <b>JSON Structure Preview:</b><br/>
        <font face="Courier" size="8">
        {{<br/>
        &nbsp;&nbsp;"summary": {{packet_count, duration, timestamps}},<br/>
        &nbsp;&nbsp;"protocols": {{protocol counts}},<br/>
        &nbsp;&nbsp;"top_source_ips": {{IP statistics}},<br/>
        &nbsp;&nbsp;"dns_queries": [{{query details}}],<br/>
        &nbsp;&nbsp;"risks": [{{severity, type, description, evidence}}],<br/>
        &nbsp;&nbsp;"http_requests": [{{method, host, path, user_agent}}],<br/>
        &nbsp;&nbsp;"extracted_files": [{{type, size, md5, sha256}}]<br/>
        }}
        </font>
        """
        story.append(Paragraph(json_text, body_style))
        
        # Conclusion and Next Steps
        story.append(PageBreak())
        story.append(Paragraph("Conclusion & Recommended Actions", heading_style))
        
        # Generate dynamic conclusion based on findings
        if len(self.risks) > 10 and any(r['severity'] == 'HIGH' for r in self.risks):
            conclusion_severity = "CRITICAL"
            conclusion_color = colors.red
            conclusion = """
            This network traffic analysis reveals <b>critical security concerns requiring immediate action</b>. 
            The combination of high-severity findings and multiple threat vectors suggests either an active security incident, 
            significant policy violations, or systemic security weaknesses. An incident response team should be mobilized 
            immediately to investigate, contain, and remediate identified threats.
            """
        elif len(self.risks) > 5:
            conclusion_severity = "MODERATE"
            conclusion_color = colors.orange
            conclusion = """
            This analysis identified <b>moderate security concerns</b> that warrant investigation within 48-72 hours. 
            While not immediately critical, these findings could indicate early-stage compromise, misconfiguration, 
            or policy violations that may escalate if left unaddressed. Security team review and remediation planning recommended.
            """
        elif len(self.risks) > 0:
            conclusion_severity = "LOW"
            conclusion_color = colors.yellow
            conclusion = """
            This analysis identified <b>minor security concerns</b> primarily consisting of policy violations or potential 
            misconfigurations. While not indicative of active compromise, these findings should be reviewed and addressed 
            as part of regular security hygiene practices.
            """
        else:
            conclusion_severity = "NORMAL"
            conclusion_color = colors.green
            conclusion = """
            This network traffic analysis did not identify any automated security concerns. However, automated tools 
            cannot detect all threat types, and manual review by experienced analysts is still recommended. 
            Continue monitoring for evolving threats and maintain security best practices.
            """
        
        story.append(Paragraph(f"<b>Overall Assessment: <font color='{conclusion_color}'>{conclusion_severity}</font></b>", 
                             ParagraphStyle('conclusion_title', parent=heading_style, fontSize=13)))
        story.append(Paragraph(conclusion, body_style))
        story.append(Spacer(1, 0.2*inch))
        
        # Immediate actions
        story.append(Paragraph("Immediate Actions Required:", subheading_style))
        
        immediate_actions = []
        
        if any(r['severity'] == 'HIGH' for r in self.risks):
            immediate_actions.extend([
                "1. <b>Isolate affected systems:</b> Quarantine any hosts identified in HIGH severity findings",
                "2. <b>Preserve evidence:</b> Create forensic images of affected systems and preserve all logs",
                "3. <b>Block malicious indicators:</b> Update firewalls/IPS with identified malicious IPs and domains",
                "4. <b>Reset compromised credentials:</b> Change passwords for any accounts with cleartext exposure"
            ])
        
        if any('Port Scan' in r['type'] for r in self.risks):
            immediate_actions.append("• <b>Port scan response:</b> Investigate scanning source, review firewall rules, enable IDS/IPS")
        
        if any('DNS' in r['type'] for r in self.risks):
            immediate_actions.append("• <b>DNS investigation:</b> Query suspicious domains against threat feeds, investigate querying hosts")
        
        if self.extracted_files:
            immediate_actions.append(f"• <b>File analysis:</b> Submit {len(self.extracted_files)} extracted file hashes to VirusTotal/MISP for malware analysis")
        
        if not immediate_actions:
            immediate_actions = [
                "• Continue regular security monitoring and log review",
                "• Maintain current security controls and update threat signatures",
                "• Schedule next network traffic analysis in 30 days"
            ]
        
        for action in immediate_actions:
            story.append(Paragraph(action, body_style))
            story.append(Spacer(1, 0.05*inch))
        
        story.append(Spacer(1, 0.2*inch))
        
        # Long-term improvements
        story.append(Paragraph("Long-term Security Improvements:", subheading_style))
        
        long_term = [
            "• <b>Zero Trust Architecture:</b> Implement micro-segmentation and least-privilege access controls",
            "• <b>Encryption Enforcement:</b> Mandate TLS 1.2+ for all communications, phase out legacy protocols",
            "• <b>Continuous Monitoring:</b> Deploy 24/7 SOC with SIEM correlation and automated threat detection",
            "• <b>Security Training:</b> Regular employee training on phishing, malware, and security best practices",
            "• <b>Incident Response:</b> Develop, test, and maintain comprehensive IR playbooks",
            "• <b>Threat Hunting:</b> Proactive hunting for IOCs and behavioral anomalies",
            "• <b>Penetration Testing:</b> Quarterly external and internal penetration tests",
            "• <b>Patch Management:</b> Automated patch deployment with 48-hour SLA for critical updates"
        ]
        
        for item in long_term:
            story.append(Paragraph(item, body_style))
            story.append(Spacer(1, 0.05*inch))
        
        story.append(Spacer(1, 0.3*inch))
        
        # Disclaimer and attribution
        story.append(Paragraph("Analysis Methodology & Disclaimer", subheading_style))
        
        methodology = f"""
        This analysis was performed using automated PCAP analysis tools with signature-based and heuristic detection methods. 
        The tool analyzed <b>{self.packet_count:,} packets</b> against a database of known threats, behavioral patterns, 
        and security best practices. Analysis completed in real-time with results generated on 
        {datetime.now().strftime('%Y-%m-%d at %H:%M:%S')}.
        <br/><br/>
        <b>Analysis Scope:</b> Layer 2-7 protocol analysis, threat signature matching, behavioral anomaly detection, 
        file extraction and hashing, cleartext credential detection, TLS/SSL security assessment.
        <br/><br/>
        <b>Limitations:</b> Automated tools cannot detect all threats, especially zero-day exploits, advanced persistent 
        threats (APTs), or sophisticated evasion techniques. Encrypted traffic (TLS/SSH) can only be analyzed at the 
        handshake level. Manual analysis by experienced security analysts is recommended for comprehensive threat assessment.
        <br/><br/>
        <b>Disclaimer:</b> This report is provided for informational purposes only. Results should be validated by 
        qualified security professionals before taking action. No warranty is provided regarding accuracy or completeness. 
        Organizations should implement appropriate security controls based on their specific risk profile and compliance requirements.
        """
        story.append(Paragraph(methodology, 
                             ParagraphStyle('method', parent=body_style, fontSize=9, leading=12)))
        
        story.append(Spacer(1, 0.3*inch))
        
        # Footer/Attribution
        story.append(Paragraph("─" * 80, 
                             ParagraphStyle('divider', parent=body_style, fontSize=8, alignment=TA_CENTER)))
        story.append(Spacer(1, 0.1*inch))
        
        footer_text = f"""
        <b>Report Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>
        <b>Analysis Tool:</b> PCAP Analyzer v1.0 - Network Threat Detection System<br/>
        <b>PCAP File:</b> {self.pcap_file}<br/>
        <b>Report File:</b> {output_file}<br/>
        <b>JSON Export:</b> pcap_analysis.json<br/>
        <br/>
        <i>This is an automated analysis report. For questions or follow-up investigation, 
        consult with your security operations team or incident response coordinator.</i>
        """
        story.append(Paragraph(footer_text, 
                             ParagraphStyle('footer', parent=body_style, fontSize=8, 
                                          alignment=TA_CENTER, textColor=colors.grey)))
        
        # Build PDF
        doc.build(story)
        print(f"[+] PDF report saved to {output_file}")
        return output_file
    
    def export_json(self, output_file='pcap_analysis.json'):
        """Export comprehensive analysis results to JSON"""
        print(f"\n[*] Exporting results to JSON...")
        
        # Calculate statistics
        high_risks = sum(1 for r in self.risks if r['severity'] == 'HIGH')
        medium_risks = sum(1 for r in self.risks if r['severity'] == 'MEDIUM')
        low_risks = sum(1 for r in self.risks if r['severity'] == 'LOW')
        
        # Determine overall status
        if high_risks > 5:
            overall_status = "CRITICAL"
        elif high_risks > 0 or medium_risks > 10:
            overall_status = "WARNING"
        elif medium_risks > 0:
            overall_status = "CAUTION"
        else:
            overall_status = "NORMAL"
        
        results = {
            'metadata': {
                'report_generated': datetime.now().isoformat(),
                'analyzer_version': '1.0',
                'pcap_file': self.pcap_file,
                'analysis_type': 'Full Network Traffic Analysis'
            },
            'executive_summary': {
                'overall_status': overall_status,
                'total_packets': self.packet_count,
                'start_time': self.start_time.isoformat() if self.start_time else None,
                'end_time': self.end_time.isoformat() if self.end_time else None,
                'duration': str(self.end_time - self.start_time) if self.end_time and self.start_time else None,
                'unique_source_ips': len(self.ip_stats['sources']),
                'unique_destination_ips': len(self.ip_stats['destinations']),
                'total_flows': len(self.flows),
                'security_findings': {
                    'total': len(self.risks),
                    'high_severity': high_risks,
                    'medium_severity': medium_risks,
                    'low_severity': low_risks
                },
                'key_statistics': {
                    'protocols_detected': len(self.protocol_counts),
                    'dns_queries': len(self.dns_queries),
                    'http_requests': len(self.http_requests),
                    'tls_handshakes': len(self.tls_info),
                    'files_extracted': len(self.extracted_files),
                    'credentials_found': len(self.credentials)
                }
            },
            'incident_response': {
                'infection_start_utc': self.infection_info.get('infection_start_utc').isoformat() if self.infection_info.get('infection_start_utc') else None,
                'infected_ip_address': self.infection_info.get('infected_ip'),
                'infected_mac_address': self.infection_info.get('infected_mac'),
                'infected_hostname': self.infection_info.get('infected_hostname'),
                'user_account_name': self.infection_info.get('user_account'),
                'stolen_data_types': self.infection_info.get('stolen_data_types', []),
                'attack_phases_detected': list(set([event['phase'] for event in self.attack_chain])) if self.attack_chain else [],
                'total_attack_events': len(self.attack_chain)
            },
            'attack_chain': [
                {
                    'timestamp': event['timestamp'].isoformat(),
                    'phase': event['phase'],
                    'event_type': event['event'],
                    'severity': event['severity'],
                    'source_ip': event['src_ip'],
                    'destination_ip': event['dst_ip'],
                    'technical_description': event['technical'],
                    'non_technical_description': event['non_technical'],
                    'description': event['description']
                } for event in self.attack_chain
            ],
            'protocols': dict(self.protocol_counts.most_common()),
            'top_source_ips': {
                ip: {
                    'packet_count': count,
                    'bytes_sent': self.ip_stats['bytes_sent'][ip]
                }
                for ip, count in self.ip_stats['sources'].most_common(20)
            },
            'top_dest_ips': {
                ip: {
                    'packet_count': count,
                    'bytes_received': self.ip_stats['bytes_received'][ip]
                }
                for ip, count in self.ip_stats['destinations'].most_common(20)
            },
            'top_communication_pairs': [
                {
                    'source_ip': src,
                    'destination_ip': dst,
                    'packet_count': count
                }
                for (src, dst), count in self.ip_stats['pairs'].most_common(10)
            ],
            'port_statistics': {
                'tcp': dict(self.port_stats['tcp'].most_common(20)),
                'udp': dict(self.port_stats['udp'].most_common(20))
            },
            'dns_queries': [
                {
                    'query': q['query'],
                    'src_ip': q['src_ip'],
                    'timestamp': q['timestamp'].isoformat(),
                    'query_type': q.get('qtype', 'Unknown')
                } for q in self.dns_queries
            ],
            'dns_analysis': {
                'total_queries': len(self.dns_queries),
                'unique_domains': len(set([q['query'] for q in self.dns_queries])),
                'suspicious_domains': [
                    q['query'] for q in self.dns_queries 
                    if is_suspicious_domain(q['query'])[0]
                ]
            },
            'risks': [
                {
                    'severity': r['severity'],
                    'type': r['type'],
                    'description': r['description'],
                    'details': r.get('details', ''),
                    'src_ip': r.get('src_ip', 'N/A'),
                    'dst_ip': r.get('dst_ip', 'N/A'),
                    'timestamp': r['timestamp'].isoformat(),
                    'evidence': r.get('evidence', '')
                } for r in self.risks
            ],
            'risk_categories': {
                category: count for category, count in 
                Counter([r['type'] for r in self.risks]).items()
            },
            'http_requests': [
                {
                    'timestamp': h['timestamp'].isoformat(),
                    'src_ip': h['src_ip'],
                    'dst_ip': h['dst_ip'],
                    'method': h['method'],
                    'host': h['host'],
                    'path': h['path'],
                    'user_agent': h['user_agent']
                } for h in self.http_requests
            ],
            'http_analysis': {
                'total_requests': len(self.http_requests),
                'unique_hosts': len(set([h['host'] for h in self.http_requests if h['host']])),
                'methods': dict(Counter([h['method'] for h in self.http_requests])),
                'suspicious_requests': len([
                    h for h in self.http_requests 
                    if any(pattern in h['path'].lower() for pattern in SUSPICIOUS_URIS)
                ])
            },
            'tls_info': [
                {
                    'timestamp': t['timestamp'].isoformat(),
                    'src_ip': t['src_ip'],
                    'dst_ip': t['dst_ip'],
                    'type': t['type'],
                    'version': hex(t['version']) if 'version' in t else 'Unknown'
                } for t in self.tls_info
            ],
            'extracted_files': [
                {
                    'type': f['type'],
                    'size': f['size'],
                    'md5': f['md5'],
                    'sha256': f['sha256'],
                    'timestamp': f['timestamp'].isoformat(),
                    'src_ip': f['src_ip'],
                    'dst_ip': f['dst_ip']
                } for f in self.extracted_files
            ],
            'credentials': [
                {
                    'type': c['type'],
                    'value': c['value'],  # Include in JSON for authorized analysis
                    'src_ip': c['src_ip'],
                    'dst_ip': c['dst_ip'],
                    'timestamp': c['timestamp'].isoformat()
                } for c in self.credentials
            ],
            'network_flows': [
                {
                    'source_ip': src,
                    'source_port': sport,
                    'destination_ip': dst,
                    'destination_port': dport,
                    'protocol': proto,
                    'packet_count': stats['packets'],
                    'byte_count': stats['bytes'],
                    'duration_seconds': (stats['end_time'] - stats['start_time']).total_seconds() 
                                       if stats['start_time'] and stats['end_time'] else 0
                }
                for (src, sport, dst, dport, proto), stats in 
                sorted(self.flows.items(), key=lambda x: x[1]['bytes'], reverse=True)[:50]
            ],
            'traffic_timeline': [
                {
                    'timestamp': time.isoformat(),
                    'packet_count': count
                } for time, count in self.time_series
            ],
            'recommendations': self._generate_recommendations()
        }
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"[+] JSON export saved to {output_file}")
        return output_file
    
    def _generate_recommendations(self):
        """Generate context-aware security recommendations"""
        recommendations = []
        
        if any('Port Scan' in r['type'] for r in self.risks):
            recommendations.append({
                'category': 'Network Security',
                'priority': 'HIGH',
                'finding': 'Port Scan Detected',
                'recommendation': 'Deploy IDS/IPS, implement host firewalls, reduce attack surface'
            })
        
        if any('Insecure Protocol' in r['type'] for r in self.risks):
            recommendations.append({
                'category': 'Encryption',
                'priority': 'HIGH',
                'finding': 'Insecure Protocols in Use',
                'recommendation': 'Replace FTP/Telnet/HTTP with SFTP/SSH/HTTPS, enforce TLS 1.2+'
            })
        
        if any('DNS' in r['type'] for r in self.risks):
            recommendations.append({
                'category': 'DNS Security',
                'priority': 'MEDIUM',
                'finding': 'Suspicious DNS Activity',
                'recommendation': 'Implement DNS filtering, enable DNSSEC, monitor for DGA patterns'
            })
        
        if self.extracted_files:
            recommendations.append({
                'category': 'File Security',
                'priority': 'MEDIUM',
                'finding': 'Files Extracted from Traffic',
                'recommendation': 'Submit hashes to VirusTotal, scan with antivirus, implement DLP controls'
            })
        
        if self.credentials:
            recommendations.append({
                'category': 'Authentication',
                'priority': 'CRITICAL',
                'finding': 'Cleartext Credentials Detected',
                'recommendation': 'Reset exposed credentials immediately, enforce encrypted authentication'
            })
        
        # Always include baseline recommendations
        recommendations.extend([
            {
                'category': 'Monitoring',
                'priority': 'MEDIUM',
                'finding': 'General Security Posture',
                'recommendation': 'Implement 24/7 SOC monitoring with SIEM correlation'
            },
            {
                'category': 'Incident Response',
                'priority': 'MEDIUM',
                'finding': 'Preparedness',
                'recommendation': 'Develop and test IR playbooks for detected threat types'
            },
            {
                'category': 'User Training',
                'priority': 'LOW',
                'finding': 'Human Factor',
                'recommendation': 'Conduct security awareness training on phishing and malware'
            }
        ])
        
        return recommendations
    
    def print_console_summary(self):
        """Print summary to console"""
        print("\n" + "="*80)
        print(" "*25 + "ANALYSIS SUMMARY")
        print("="*80)
        
        print(f"\n[+] Total Packets: {self.packet_count:,}")
        print(f"[+] Unique Source IPs: {len(self.ip_stats['sources']):,}")
        print(f"[+] Unique Destination IPs: {len(self.ip_stats['destinations']):,}")
        
        print("\n--- Top 5 Protocols ---")
        for proto, count in self.protocol_counts.most_common(5):
            print(f"  {proto}: {count:,}")
        
        print("\n--- Top 5 Source IPs ---")
        for ip, count in self.ip_stats['sources'].most_common(5):
            print(f"  {ip}: {count:,} packets, {format_bytes(self.ip_stats['bytes_sent'][ip])}")
        
        print("\n--- Top 5 TCP Ports ---")
        for port, count in self.port_stats['tcp'].most_common(5):
            print(f"  Port {port}: {count:,}")
        
        print("\n--- Security Risks ---")
        risk_summary = Counter([r['severity'] for r in self.risks])
        print(f"  HIGH: {risk_summary['HIGH']}")
        print(f"  MEDIUM: {risk_summary['MEDIUM']}")
        print(f"  LOW: {risk_summary['LOW']}")
        
        if self.risks:
            print("\n--- Sample Risks ---")
            for risk in self.risks[:5]:
                print(f"  [{risk['severity']}] {risk['type']}: {risk['description']}")
        
        # Attack chain summary
        if self.attack_chain:
            print("\n--- ATTACK CHAIN DETECTED ---")
            print(f"  Total Attack Events: {len(self.attack_chain)}")
            attack_phases = set([event['phase'] for event in self.attack_chain])
            print(f"  Attack Phases: {', '.join(attack_phases)}")
            
            if self.infection_info.get('infected_ip'):
                print(f"\n  🎯 INFECTED HOST IDENTIFIED:")
                print(f"     IP Address: {self.infection_info['infected_ip']}")
                if self.infection_info.get('infected_mac'):
                    print(f"     MAC Address: {self.infection_info['infected_mac']}")
                if self.infection_info.get('infected_hostname'):
                    print(f"     Hostname: {self.infection_info['infected_hostname']}")
                if self.infection_info.get('user_account'):
                    print(f"     User Account: {self.infection_info['user_account']}")
                if self.infection_info.get('infection_start_utc'):
                    print(f"     Infection Start: {self.infection_info['infection_start_utc'].strftime('%Y-%m-%d %H:%M:%S UTC')}")
                if self.infection_info.get('stolen_data_types'):
                    print(f"     Stolen Data: {', '.join(self.infection_info['stolen_data_types'])}")
        
        print("\n" + "="*80)
    
    def reconstruct_attack_chain(self):
        """
        Reconstruct attack timeline and chain of events
        Now using results from InfectionAnalyzer for better accuracy
        """
        print("\n[*] Reconstructing attack chain...")
        
        # If we have attack_chain from infection analysis, use it
        if hasattr(self, 'attack_chain') and self.attack_chain:
            print(f"[+] Using comprehensive attack chain from infection analysis ({len(self.attack_chain)} events)")
            return self.attack_chain
        
        # Otherwise, build basic attack chain from risks
        attack_events = []
        
        # Detect reconnaissance phase
        port_scans = [r for r in self.risks if 'Port Scan' in r['type']]
        if port_scans:
            for scan in port_scans[:3]:  # Limit to first 3
                attack_events.append({
                    'phase': 'Reconnaissance',
                    'timestamp': scan['timestamp'],
                    'event': 'Network Scanning',
                    'description': scan['description'],
                    'src_ip': scan.get('src_ip', 'Unknown'),
                    'dst_ip': scan.get('dst_ip', 'Unknown'),
                    'severity': scan['severity'],
                    'technical': f"Attacker from {scan.get('src_ip', 'Unknown')} performed port scan against {scan.get('dst_ip', 'Unknown')}",
                    'non_technical': f"An attacker probed the network from {scan.get('src_ip', 'Unknown')} looking for open doors (ports) to break into."
                })
        
        # Detect initial access
        initial_access = [r for r in self.risks if any(x in r['type'] for x in ['Suspicious Port', 'Insecure Protocol', 'Weak TLS'])]
        for access in initial_access[:2]:
            attack_events.append({
                'phase': 'Initial Access',
                'timestamp': access['timestamp'],
                'event': access['type'],
                'description': access['description'],
                'src_ip': access.get('src_ip', 'Unknown'),
                'dst_ip': access.get('dst_ip', 'Unknown'),
                'severity': access['severity'],
                'technical': f"Connection established using {access['type']}",
                'non_technical': f"The attacker gained entry to the system using an insecure method: {access['description']}"
            })
        
        # Detect credential theft
        if self.credentials:
            for cred in self.credentials[:2]:
                attack_events.append({
                    'phase': 'Credential Access',
                    'timestamp': cred['timestamp'],
                    'event': 'Credential Theft',
                    'description': f"Stolen {cred['type']} transmitted in cleartext",
                    'src_ip': cred['src_ip'],
                    'dst_ip': cred['dst_ip'],
                    'severity': 'HIGH',
                    'technical': f"Credentials captured from {cred['src_ip']} to {cred['dst_ip']}",
                    'non_technical': f"The attacker intercepted login credentials (username/password) being sent from computer {cred['src_ip']} without encryption."
                })
        
        # Detect malware delivery
        exe_downloads = [f for f in self.extracted_files if f['type'] == 'EXE']
        for exe in exe_downloads[:2]:
            attack_events.append({
                'phase': 'Malware Delivery',
                'timestamp': exe['timestamp'],
                'event': 'Executable Download',
                'description': f"Executable file downloaded ({format_bytes(exe['size'])})",
                'src_ip': exe.get('src_ip', 'Unknown'),
                'dst_ip': exe.get('dst_ip', 'Unknown'),
                'severity': 'CRITICAL',
                'technical': f"PE executable (MD5: {exe['md5']}) downloaded to {exe.get('src_ip', 'Unknown')}",
                'non_technical': f"A malicious program was downloaded to computer {exe.get('src_ip', 'Unknown')}, likely containing malware or ransomware."
            })
        
        # Detect C2 communication
        beacons = [r for r in self.risks if 'Beacon' in r['type']]
        for beacon in beacons[:2]:
            attack_events.append({
                'phase': 'Command & Control',
                'timestamp': beacon['timestamp'],
                'event': 'C2 Beacon',
                'description': beacon['description'],
                'src_ip': beacon.get('src_ip', 'Unknown'),
                'dst_ip': beacon.get('dst_ip', 'Unknown'),
                'severity': 'HIGH',
                'technical': f"Regular beaconing detected from {beacon.get('src_ip', 'Unknown')} to {beacon.get('dst_ip', 'Unknown')}",
                'non_technical': f"The infected computer {beacon.get('src_ip', 'Unknown')} is regularly 'calling home' to an attacker's server, awaiting commands."
            })
        
        # Detect data exfiltration
        exfil = [r for r in self.risks if any(x in r['type'] for x in ['Large Data Transfer', 'Large HTTP POST', 'Exfiltration'])]
        for ex in exfil[:2]:
            attack_events.append({
                'phase': 'Exfiltration',
                'timestamp': ex['timestamp'],
                'event': 'Data Exfiltration',
                'description': ex['description'],
                'src_ip': ex.get('src_ip', 'Unknown'),
                'dst_ip': ex.get('dst_ip', 'Unknown'),
                'severity': 'CRITICAL',
                'technical': f"Large data transfer from {ex.get('src_ip', 'Unknown')} to {ex.get('dst_ip', 'Unknown')}",
                'non_technical': f"Computer {ex.get('src_ip', 'Unknown')} sent a large amount of data to an external location, potentially stealing sensitive information."
            })
        
        # Sort by timestamp
        attack_events.sort(key=lambda x: x['timestamp'])
        
        self.attack_chain = attack_events
        print(f"[+] Reconstructed {len(attack_events)} attack events")
        return attack_events
    
    def analyze_infection(self):
        """Comprehensive infection analysis using InfectionAnalyzer module"""
        print("\n[*] Analyzing infection details...")
        
        try:
            # Import the robust infection analyzer
            from infection_analyzer import InfectionAnalyzer
            
            # Create analyzer instance
            analyzer = InfectionAnalyzer(self.packets)
            
            # Run comprehensive analysis
            infection_info, attack_chain = analyzer.analyze_infection(
                risks=self.risks,
                credentials=self.credentials,
                extracted_files=self.extracted_files,
                http_requests=self.http_requests,
                dns_queries=self.dns_queries
            )
            
            # Store results
            self.infection_info = infection_info
            self.attack_chain = attack_chain
            
            # Print summary
            if infection_info.get('infected_ip'):
                print(f"\n[+] INFECTION ANALYSIS COMPLETE")
                print(f"    Infected IP: {infection_info['infected_ip']}")
                print(f"    MAC Address: {infection_info.get('infected_mac', 'Not found')}")
                print(f"    Hostname: {infection_info.get('infected_hostname', 'Not found')}")
                print(f"    User Account: {infection_info.get('user_account', 'Not found')}")
                print(f"    Infection Start: {infection_info.get('infection_start_utc', 'Unknown')}")
                print(f"    Confidence: {infection_info.get('confidence', 'Unknown')}")
                print(f"    Attack Events: {len(attack_chain)}")
            else:
                print(f"[!] No infected host definitively identified")
                print(f"    This may indicate:")
                print(f"    - No active infection in capture")
                print(f"    - Only external reconnaissance")
                print(f"    - Encrypted/obfuscated traffic")
            
            return infection_info
            
        except ImportError:
            print("[-] InfectionAnalyzer module not found, using fallback method")
            # Fallback to basic analysis
            return self._basic_infection_analysis()
        except Exception as e:
            print(f"[-] Error in infection analysis: {e}")
            return self._basic_infection_analysis()
    
    def _basic_infection_analysis(self):
        """Fallback basic infection analysis if module not available"""
        infection_info = {
            'infection_start_utc': None,
            'infected_ip': None,
            'infected_mac': None,
            'infected_hostname': None,
            'user_account': None,
            'stolen_data_types': [],
            'confidence': 'Low'
        }
        
        # Simple victim identification based on risks
        suspicious_ips = defaultdict(int)
        
        for risk in self.risks:
            if risk['severity'] in ['HIGH', 'CRITICAL']:
                src_ip = risk.get('src_ip')
                if src_ip and src_ip != 'Unknown' and src_ip != 'Multiple':
                    # Check if internal IP
                    if src_ip.startswith('192.168.') or src_ip.startswith('10.') or src_ip.startswith('172.'):
                        suspicious_ips[src_ip] += 10
        
        if suspicious_ips:
            infection_info['infected_ip'] = max(suspicious_ips.items(), key=lambda x: x[1])[0]
            
            # Try to find MAC
            for pkt in self.packets:
                if pkt.haslayer(IP) and pkt[IP].src == infection_info['infected_ip']:
                    if pkt.haslayer(Ether):
                        infection_info['infected_mac'] = pkt[Ether].src
                        break
        
        # Find infection start
        high_severity_times = [r['timestamp'] for r in self.risks if r['severity'] in ['HIGH', 'CRITICAL']]
        if high_severity_times:
            infection_info['infection_start_utc'] = min(high_severity_times)
        
        # Identify stolen data
        if self.credentials:
            infection_info['stolen_data_types'].append('Login Credentials')
        if [r for r in self.risks if 'Exfiltration' in r['type'] or 'Large Data Transfer' in r['type']]:
            infection_info['stolen_data_types'].append('Bulk Data')
        
        self.infection_info = infection_info
        return infection_info
    
    def detect_network_baseline_anomalies(self):
        """Detect anomalies by comparing against network baseline"""
        print("\n[*] Detecting baseline anomalies...")
        
        if not self.packets or not self.flows:
            return
        
        # Establish baselines
        packet_sizes = [len(pkt) for pkt in self.packets]
        avg_packet_size = sum(packet_sizes) / len(packet_sizes) if packet_sizes else 0
        
        flow_packet_counts = [flow['packets'] for flow in self.flows.values()]
        avg_flow_packets = sum(flow_packet_counts) / len(flow_packet_counts) if flow_packet_counts else 0
        
        # Detect packet size anomalies (statistical outliers)
        for pkt in self.packets:
            if len(pkt) > avg_packet_size * 3:  # 3x average
                if pkt.haslayer(IP):
                    self.risks.append({
                        'severity': 'LOW',
                        'type': 'Packet Size Anomaly',
                        'description': f"Unusually large packet: {len(pkt)} bytes (avg: {avg_packet_size:.0f})",
                        'details': f"May indicate data exfiltration or protocol abuse",
                        'src_ip': pkt[IP].src,
                        'dst_ip': pkt[IP].dst,
                        'timestamp': datetime.fromtimestamp(float(pkt.time)),
                        'evidence': f"Packet size {(len(pkt)/avg_packet_size):.1f}x larger than baseline"
                    })
                    break  # Report only once
        
        # Detect flow anomalies
        for flow_id, stats in self.flows.items():
            src, sport, dst, dport, proto = flow_id
            
            # Unusually high packet count for single flow
            if stats['packets'] > avg_flow_packets * 5:
                self.risks.append({
                    'severity': 'MEDIUM',
                    'type': 'Flow Volume Anomaly',
                    'description': f"Flow with abnormally high packet count: {stats['packets']} packets",
                    'details': f"{src}:{sport} -> {dst}:{dport} ({proto})",
                    'src_ip': src,
                    'dst_ip': dst,
                    'timestamp': stats['start_time'],
                    'evidence': f"{stats['packets']} packets ({(stats['packets']/avg_flow_packets):.1f}x above baseline)"
                })
        
        # Check for connection to many different IPs (potential scanning/C2)
        src_to_dests = defaultdict(set)
        for (src, sport, dst, dport, proto) in self.flows.keys():
            src_to_dests[src].add(dst)
        
        for src, dests in src_to_dests.items():
            if len(dests) > 30:  # Connecting to many IPs
                self.risks.append({
                    'severity': 'MEDIUM',
                    'type': 'Excessive Outbound Connections',
                    'description': f"Host contacted {len(dests)} unique destinations",
                    'details': 'May indicate scanning, worm activity, or P2P application',
                    'src_ip': src,
                    'timestamp': datetime.now(),
                    'evidence': f"Connected to {len(dests)} different IPs"
                })
        
        print(f"[+] Baseline analysis complete")
    
    def run_ml_anomaly_detection(self):
        """Run ML-based anomaly detection on network flows"""
        if not self.enable_ml or not ML_AVAILABLE:
            return
        
        print("\n[*] Running ML anomaly detection...")
        
        anomalies = self.ml_detector.detect_anomalies(self.flows)
        
        # Convert ML anomalies to risks
        for anomaly in anomalies:
            self.risks.append({
                'severity': 'MEDIUM',
                'type': 'ML Anomaly Detected',
                'description': f"Unusual flow pattern: {anomaly['src_ip']}:{anomaly['dst_port']} ({anomaly['protocol']})",
                'details': f"ML anomaly score: {anomaly['score']:.3f}",
                'src_ip': anomaly['src_ip'],
                'dst_ip': anomaly['dst_ip'],
                'timestamp': datetime.now(),
                'evidence': f"Flow deviates from normal baseline (Isolation Forest)",
                'ml_score': anomaly['score']
            })
        
        self.ml_anomalies = anomalies
        print(f"[+] ML detection found {len(anomalies)} anomalous flows")
    
    def enrich_with_threat_intel(self):
        """Enrich findings with threat intelligence"""
        if not self.threat_intel:
            return
        
        print("\n[*] Enriching with threat intelligence...")
        
        # Get unique IPs from risks and flows
        suspicious_ips = set()
        for risk in self.risks:
            if risk.get('src_ip') and risk['src_ip'] != 'Unknown':
                suspicious_ips.add(risk['src_ip'])
            if risk.get('dst_ip') and risk['dst_ip'] != 'Unknown':
                suspicious_ips.add(risk['dst_ip'])
        
        # Enrich
        enriched = self.threat_intel.enrich_ips(list(suspicious_ips))
        
        # Add IOC-based risks
        for ioc in self.threat_intel.iocs:
            self.risks.append({
                'severity': 'HIGH',
                'type': 'Known Malicious IP (Threat Intel)',
                'description': f"IP {ioc['value']} flagged by {ioc['source']}",
                'details': f"Confidence: {ioc['confidence']}%",
                'src_ip': ioc['value'],
                'timestamp': datetime.now(),
                'evidence': f"Matched threat intelligence IOC from {ioc['source']}"
            })
        
        self.threat_iocs = self.threat_intel.iocs
        print(f"[+] Threat intelligence found {len(self.threat_iocs)} IOCs")
    
    def map_to_mitre_attack(self):
        """Map all findings to MITRE ATT&CK framework"""
        print("\n[*] Mapping findings to MITRE ATT&CK...")
        
        mapped_count = 0
        for risk in self.risks:
            mapping = self.mitre_mapper.map_risk_to_attack(risk)
            if mapping:
                mapped_count += 1
        
        self.mitre_techniques = self.mitre_mapper.mapped_techniques
        print(f"[+] Mapped {mapped_count} findings to {len(self.mitre_techniques)} ATT&CK techniques")
        
        # Print coverage
        coverage = self.mitre_mapper.get_coverage_heatmap()
        active_tactics = [t for t, data in coverage.items() if data['techniques'] > 0]
        print(f"[+] ATT&CK coverage: {len(active_tactics)}/11 tactics observed")
    
    def reconstruct_sessions(self):
        """Reconstruct TCP sessions for deep analysis"""
        print("\n[*] Reconstructing TCP sessions...")
        
        # Limit for large files
        max_packets = min(len(self.packets), 50000)
        if len(self.packets) > 50000:
            print(f"[*] Large file - limiting session reconstruction to first {max_packets} packets")
        
        reconstructed = self.session_reconstructor.reconstruct_tcp_sessions(self.packets[:max_packets])
        
        # Extract HTTP sessions
        http_sessions = self.session_reconstructor.extract_http_sessions(reconstructed)
        
        self.reconstructed_sessions = reconstructed
        print(f"[+] Reconstructed {len(reconstructed)} sessions ({len(http_sessions)} HTTP)")
        
        # Look for interesting patterns in reconstructed data
        for session in http_sessions:
            data = session['data'].lower()
            
            # Check for API keys
            if 'api' in data and ('key' in data or 'token' in data):
                api_key_match = re.search(r'(?:api[_-]?key|token)["\s:=]+([a-zA-Z0-9\-_]{20,})', data, re.IGNORECASE)
                if api_key_match:
                    self.risks.append({
                        'severity': 'HIGH',
                        'type': 'API Key Exposure',
                        'description': 'API key found in reconstructed HTTP session',
                        'details': f"Key pattern: {api_key_match.group(1)[:20]}...",
                        'src_ip': session['stream_id'][0],
                        'timestamp': datetime.now(),
                        'evidence': 'Sensitive credential in HTTP traffic'
                    })
            
            # Check for ransomware notes
            ransomware_keywords = ['ransom', 'bitcoin', 'decrypt', 'encrypted', 'payment']
            if sum(1 for kw in ransomware_keywords if kw in data) >= 3:
                self.risks.append({
                    'severity': 'CRITICAL',
                    'type': 'Potential Ransomware Communication',
                    'description': 'Ransomware-related keywords in HTTP session',
                    'details': 'Multiple ransomware indicators detected',
                    'src_ip': session['stream_id'][0],
                    'timestamp': datetime.now(),
                    'evidence': 'Session contains ransomware-related communication'
                })
    
    def run_full_analysis(self):
        """Run complete analysis pipeline"""
        print("\n" + "="*80)
        print(" "*20 + "PCAP ANALYZER - STARTING ANALYSIS")
        print("="*80)
        
        # Load PCAP
        self.load_pcap()
        
        if self.packet_count == 0:
            print("\n[-] No packets to analyze. Exiting.")
            return
        
        # Run all analyses
        self.analyze_protocols()
        self.analyze_ip_addresses()
        self.analyze_dns()
        self.analyze_ports()
        self.analyze_flows()
        self.analyze_http()
        self.analyze_tls()
        self.extract_credentials()
        self.extract_files()
        self.analyze_security_risks()
        self.analyze_time_series()
        self.identify_suspicious_packets()
        self.detect_network_baseline_anomalies()
        
        # Advanced analysis
        self.reconstruct_attack_chain()
        self.analyze_infection()
        
        # ML and Threat Intelligence (if enabled)
        if self.enable_ml:
            self.run_ml_anomaly_detection()
        
        if self.threat_intel:
            self.enrich_with_threat_intel()
        
        # MITRE ATT&CK Mapping (always run)
        self.map_to_mitre_attack()
        
        # Session reconstruction
        self.reconstruct_sessions()
        
        # Generate outputs
        self.print_console_summary()


# ============================================================================
# INTERACTIVE MODE
# ============================================================================

def interactive_mode(analyzer):
    """Simple interactive mode for filtering and re-inspecting data"""
    print("\n" + "="*80)
    print(" "*25 + "INTERACTIVE MODE")
    print("="*80)
    print("\nAvailable commands:")
    print("  dns <ip>       - Show DNS queries from specific IP")
    print("  risks <level>  - Show risks by level (high/medium/low)")
    print("  flows          - Show top 10 flows")
    print("  http           - Show HTTP requests")
    print("  stats          - Show overall statistics")
    print("  quit           - Exit interactive mode")
    print("="*80)
    
    while True:
        try:
            cmd = input("\n[Interactive] > ").strip().lower()
            
            if cmd == 'quit':
                break
            
            elif cmd.startswith('dns '):
                ip = cmd.split()[1]
                queries = [q for q in analyzer.dns_queries if q['src_ip'] == ip]
                print(f"\nDNS queries from {ip}: {len(queries)}")
                for q in queries[:20]:
                    print(f"  {q['timestamp']} - {q['query']}")
            
            elif cmd.startswith('risks '):
                level = cmd.split()[1].upper()
                risks = [r for r in analyzer.risks if r['severity'] == level]
                print(f"\n{level} severity risks: {len(risks)}")
                for r in risks[:20]:
                    print(f"  [{r['type']}] {r['description']}")
            
            elif cmd == 'flows':
                print("\nTop 10 Flows:")
                sorted_flows = sorted(analyzer.flows.items(), 
                                    key=lambda x: x[1]['bytes'], reverse=True)
                for (src, sport, dst, dport, proto), stats in sorted_flows[:10]:
                    print(f"  {src}:{sport} -> {dst}:{dport} ({proto})")
                    print(f"    Packets: {stats['packets']}, Bytes: {format_bytes(stats['bytes'])}")
            
            elif cmd == 'http':
                print(f"\nHTTP Requests: {len(analyzer.http_requests)}")
                for req in analyzer.http_requests[:20]:
                    print(f"  {req['method']} {req['host']}{req['path']}")
            
            elif cmd == 'stats':
                analyzer.print_console_summary()
            
            else:
                print("Unknown command. Type 'quit' to exit.")
        
        except KeyboardInterrupt:
            print("\n\nExiting interactive mode...")
            break
        except Exception as e:
            print(f"Error: {e}")


# ============================================================================
# TEST PCAP GENERATOR
# ============================================================================

def generate_test_pcap(output_file='test_capture.pcap'):
    """Generate a synthetic test PCAP with realistic attack scenario"""
    print(f"\n[*] Generating test PCAP with attack scenario: {output_file}")
    
    packets = []
    current_time = time.time()
    
    # Define victim and attacker
    victim_ip = "192.168.1.100"
    victim_mac = "00:0c:29:3a:2b:4c"
    attacker_ip = "203.0.113.50"
    c2_server = "185.220.101.50"
    
    print("[*] Simulating attack chain:")
    print("    Phase 1: Reconnaissance (Port Scan)")
    print("    Phase 2: Initial Access (Telnet)")
    print("    Phase 3: Credential Theft")
    print("    Phase 4: Malware Delivery")
    print("    Phase 5: C2 Communication")
    print("    Phase 6: Data Exfiltration")
    
    # PHASE 1: Reconnaissance - Port Scan (T+0 seconds)
    print("\n[*] Adding reconnaissance phase...")
    for i, port in enumerate(range(20, 100, 5)):
        pkt = Ether(src=victim_mac, dst="ff:ff:ff:ff:ff:ff")/IP(src=attacker_ip, dst=victim_ip)/TCP(sport=60000, dport=port, flags='S')
        pkt.time = current_time + i * 0.1
        packets.append(pkt)
    
    current_time += 10
    
    # Normal traffic mixed in
    for i in range(5):
        pkt = Ether()/IP(src=f"192.168.1.{10+i}", dst="93.184.216.34")/TCP(sport=50000+i, dport=80)/"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        pkt.time = current_time + i
        packets.append(pkt)
    
    current_time += 30
    
    # PHASE 2: Initial Access - Telnet Connection (T+40 seconds)
    print("[*] Adding initial access phase...")
    pkt = Ether(src=victim_mac)/IP(src=victim_ip, dst=attacker_ip)/TCP(sport=50200, dport=23, flags='S')
    pkt.time = current_time
    packets.append(pkt)
    
    pkt = Ether()/IP(src=attacker_ip, dst=victim_ip)/TCP(sport=23, dport=50200, flags='SA')
    pkt.time = current_time + 0.1
    packets.append(pkt)
    
    current_time += 5
    
    # PHASE 3: Credential Theft - Telnet login (T+45 seconds)
    print("[*] Adding credential theft phase...")
    pkt = Ether(src=victim_mac)/IP(src=victim_ip, dst=attacker_ip)/TCP(sport=50200, dport=23)/"login: administrator\r\n"
    pkt.time = current_time
    packets.append(pkt)
    
    pkt = Ether(src=victim_mac)/IP(src=victim_ip, dst=attacker_ip)/TCP(sport=50200, dport=23)/"password: P@ssw0rd123\r\n"
    pkt.time = current_time + 2
    packets.append(pkt)
    
    # FTP credential theft
    pkt = Ether(src=victim_mac)/IP(src=victim_ip, dst="10.0.0.50")/TCP(sport=50100, dport=21)/"USER john.doe\r\n"
    pkt.time = current_time + 5
    packets.append(pkt)
    
    pkt = Ether(src=victim_mac)/IP(src=victim_ip, dst="10.0.0.50")/TCP(sport=50100, dport=21)/"PASS CompanySecret2024\r\n"
    pkt.time = current_time + 6
    packets.append(pkt)
    
    current_time += 20
    
    # PHASE 4: Malware Delivery - Executable Download (T+71 seconds)
    print("[*] Adding malware delivery phase...")
    # HTTP request for malware
    pkt = Ether(src=victim_mac)/IP(src=victim_ip, dst=attacker_ip)/TCP(sport=50300, dport=80)/"GET /payload.exe HTTP/1.1\r\nHost: malicious.xyz\r\n\r\n"
    pkt.time = current_time
    packets.append(pkt)
    
    # Malware download (PE executable)
    malware_payload = b"MZ\x90\x00" + b"\x00" * 5000  # PE header + padding
    pkt = Ether()/IP(src=attacker_ip, dst=victim_ip)/TCP(sport=80, dport=50300)/Raw(load=malware_payload)
    pkt.time = current_time + 1
    packets.append(pkt)
    
    current_time += 30
    
    # DNS queries including suspicious domains (T+101 seconds)
    print("[*] Adding DNS activity...")
    dns_queries = [
        "example.com",
        "malicious-site.xyz",
        "google.com",
        "akjsdh2k3jh4k2j3h4k23jh4.top",  # DGA-like domain
        "c2-server-alpha.info",
        "facebook.com"
    ]
    
    for i, domain in enumerate(dns_queries):
        pkt = Ether(src=victim_mac)/IP(src=victim_ip, dst="8.8.8.8")/UDP(sport=53000+i, dport=53)/DNS(rd=1, qd=DNSQR(qname=domain))
        pkt.time = current_time + i * 2
        packets.append(pkt)
    
    current_time += 15
    
    # PHASE 5: C2 Communication - Beaconing (T+116 seconds)
    print("[*] Adding C2 beacon phase...")
    # Regular beaconing every 30 seconds (5 beacons)
    for i in range(5):
        # Beacon request
        pkt = Ether(src=victim_mac)/IP(src=victim_ip, dst=c2_server)/TCP(sport=52000, dport=443)/Raw(load=b"\x17\x03\x03\x00\x20" + b"A"*32)  # Fake TLS
        pkt.time = current_time + (i * 30)
        packets.append(pkt)
        
        # Beacon response
        pkt = Ether()/IP(src=c2_server, dst=victim_ip)/TCP(sport=443, dport=52000)/Raw(load=b"\x17\x03\x03\x00\x10" + b"B"*16)
        pkt.time = current_time + (i * 30) + 0.5
        packets.append(pkt)
    
    current_time += 160
    
    # PHASE 6: Data Exfiltration - Large POST (T+276 seconds)
    print("[*] Adding data exfiltration phase...")
    exfil_data = b"A" * 15000  # 15KB of "stolen" data
    
    # HTTP POST with exfiltrated data
    post_headers = b"POST /upload HTTP/1.1\r\nHost: attacker.evil\r\nContent-Length: 15000\r\n\r\n"
    pkt = Ether(src=victim_mac)/IP(src=victim_ip, dst=attacker_ip)/TCP(sport=52500, dport=80)/Raw(load=post_headers + exfil_data)
    pkt.time = current_time
    packets.append(pkt)
    
    # Multiple large data transfers
    for i in range(10):
        large_payload = b"X" * 1400
        pkt = Ether(src=victim_mac)/IP(src=victim_ip, dst=attacker_ip)/TCP(sport=52500, dport=443)/Raw(load=large_payload)
        pkt.time = current_time + 5 + (i * 0.5)
        packets.append(pkt)
    
    current_time += 20
    
    # Add some normal HTTPS traffic
    print("[*] Adding normal traffic...")
    for i in range(15):
        pkt = Ether()/IP(src=f"192.168.1.{20+i}", dst="172.217.14.206")/TCP(sport=51000+i, dport=443)/Raw(load=b'\x16\x03\x01')
        pkt.time = current_time + i
        packets.append(pkt)
    
    # Suspicious port activity (Metasploit default)
    pkt = Ether(src=victim_mac)/IP(src=victim_ip, dst=c2_server)/TCP(sport=55555, dport=4444)/"reverse shell established"
    pkt.time = current_time + 20
    packets.append(pkt)
    
    # ICMP activity (some normal pings)
    for i in range(10):
        pkt = Ether()/IP(src=victim_ip, dst="8.8.8.8")/ICMP()
        pkt.time = current_time + 25 + i
        packets.append(pkt)
    
    # More suspicious HTTP requests
    suspicious_paths = ["/admin", "/shell.php", "/wp-admin/install.php"]
    for i, path in enumerate(suspicious_paths):
        pkt = Ether(src=victim_mac)/IP(src=attacker_ip, dst=victim_ip)/TCP(sport=60000+i, dport=80)/f"GET {path} HTTP/1.1\r\nUser-Agent: Nikto\r\n\r\n"
        pkt.time = current_time + 30 + i
        packets.append(pkt)
    
    # Write PCAP
    wrpcap(output_file, packets)
    print(f"\n[+] Generated {len(packets)} packets in {output_file}")
    print(f"[+] Attack scenario spans {int(current_time - time.time() + len(packets))} seconds")
    print("\n[*] Expected detections:")
    print("    - Port scan from 203.0.113.50")
    print("    - Telnet cleartext authentication")
    print("    - FTP cleartext credentials")
    print("    - Malware download (payload.exe)")
    print("    - Suspicious DNS queries (DGA domains)")
    print("    - C2 beaconing to 185.220.101.50")
    print("    - Data exfiltration via HTTP POST")
    print("    - Suspicious port 4444 activity")
    print("    - Scanner activity (Nikto)")
    print("\n[*] Victim host: 192.168.1.100 (00:0c:29:3a:2b:4c)")
    print("    User: administrator, john.doe")
    
    return output_file


# ============================================================================
# MAIN FUNCTION
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Advanced PCAP Analyzer - Network Threat Detection Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s -i capture.pcap
  %(prog)s -i capture.pcap -o report.pdf --verbose
  %(prog)s -i capture.pcap --filter-ip 192.168.1.1 --risk-level high
  %(prog)s --generate-test
  %(prog)s -i test.pcap --interactive
        '''
    )
    
    parser.add_argument('-i', '--input', help='Input PCAP file')
    parser.add_argument('-o', '--output', default='pcap_analysis_report.pdf', 
                       help='Output PDF report file (default: pcap_analysis_report.pdf)')
    parser.add_argument('--json-output', default='pcap_analysis.json',
                       help='Output JSON file (default: pcap_analysis.json)')
    parser.add_argument('--filter-ip', help='Filter analysis for specific IP address')
    parser.add_argument('--filter-port', type=int, help='Filter analysis for specific port')
    parser.add_argument('--risk-level', choices=['high', 'medium', 'low'],
                       help='Show only risks of specified level')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--interactive', action='store_true', 
                       help='Enter interactive mode after analysis')
    parser.add_argument('--generate-test', action='store_true',
                       help='Generate a test PCAP file and exit')
    parser.add_argument('--vt-api-key', help='VirusTotal API key for file hash checking')
    parser.add_argument('--http', action='store_true', help='Enable detailed HTTP analysis')
    parser.add_argument('--tls', action='store_true', help='Enable detailed TLS analysis')
    parser.add_argument('--extract-files', action='store_true', 
                       help='Extract and analyze files from traffic')
    
    # Advanced features
    parser.add_argument('--enable-ml', action='store_true',
                       help='Enable ML anomaly detection (requires scikit-learn)')
    parser.add_argument('--threat-feeds', action='store_true',
                       help='Enable threat intelligence enrichment')
    parser.add_argument('--abuseipdb-key', help='AbuseIPDB API key')
    parser.add_argument('--alienvault-key', help='AlienVault OTX API key')
    parser.add_argument('--misp-url', help='MISP instance URL')
    parser.add_argument('--misp-key', help='MISP API key')
    parser.add_argument('--export-mitre', help='Export MITRE ATT&CK layer JSON file')
    parser.add_argument('--zeek-logs', help='Path to Zeek logs directory for enrichment')
    parser.add_argument('--suricata-logs', help='Path to Suricata logs for enrichment')
    
    args = parser.parse_args()
    
    # Generate test PCAP if requested
    if args.generate_test:
        test_file = generate_test_pcap()
        print(f"\n[+] Test PCAP generated: {test_file}")
        print(f"[+] Run analysis with: python {sys.argv[0]} -i {test_file}")
        return
    
    # Require input file
    if not args.input:
        parser.print_help()
        print("\n[-] Error: Input PCAP file required (use -i)")
        print("[*] To generate a test PCAP, use: --generate-test")
        sys.exit(1)
    
    # Create analyzer
    threat_feeds_config = {}
    if args.threat_feeds:
        if args.abuseipdb_key:
            threat_feeds_config['abuseipdb'] = args.abuseipdb_key
        if args.alienvault_key:
            threat_feeds_config['alienvault'] = args.alienvault_key
        threat_feeds_config['verbose'] = args.verbose
    
    analyzer = PCAPAnalyzer(
        args.input,
        verbose=args.verbose,
        virustotal_api_key=args.vt_api_key,
        threat_feeds=threat_feeds_config if threat_feeds_config else None,
        enable_ml=args.enable_ml,
        misp_url=args.misp_url,
        misp_key=args.misp_key
    )
    
    # Run analysis
    try:
        analyzer.run_full_analysis()
        
        # Generate outputs
        pdf_file = analyzer.generate_pdf_report(args.output)
        json_file = analyzer.export_json(args.json_output)
        
        # Export MITRE ATT&CK Navigator layer if requested
        if args.export_mitre:
            mitre_layer = analyzer.mitre_mapper.generate_attack_navigator_layer()
            with open(args.export_mitre, 'w') as f:
                json.dump(mitre_layer, f, indent=2)
            print(f"[+] MITRE ATT&CK layer exported to {args.export_mitre}")
        
        print("\n" + "="*80)
        print(" "*25 + "ANALYSIS COMPLETE")
        print("="*80)
        if pdf_file:
            print(f"[+] PDF Report: {pdf_file}")
        if json_file:
            print(f"[+] JSON Export: {json_file}")
        if args.export_mitre:
            print(f"[+] MITRE ATT&CK Layer: {args.export_mitre}")
        
        # Print advanced features summary
        if args.enable_ml and analyzer.ml_anomalies:
            print(f"[+] ML Anomalies Detected: {len(analyzer.ml_anomalies)}")
        if args.threat_feeds and analyzer.threat_iocs:
            print(f"[+] Threat Intel IOCs: {len(analyzer.threat_iocs)}")
        if analyzer.mitre_techniques:
            print(f"[+] MITRE ATT&CK Techniques: {len(analyzer.mitre_techniques)}")
        
        print("="*80)
        
        # Interactive mode
        if args.interactive:
            interactive_mode(analyzer)
        
    except Exception as e:
        print(f"\n[-] ERROR: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
