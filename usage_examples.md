## Usage Examples

### 1. Basic Analysis

```bash
python3 pcap_analyzer.py -i capture.pcap
# Output: report.pdf + analysis.json
```

### 2. Generate Test Attack

```bash
python3 pcap_analyzer.py --generate-test
python3 pcap_analyzer.py -i test_capture.pcap
```

### 3. ML Anomaly Detection

```bash
# Train on baseline
python3 pcap_analyzer.py -i normal_traffic.pcap --ml-train baseline.pkl

# Detect anomalies
python3 pcap_analyzer.py -i suspicious.pcap --ml-baseline baseline.pkl
```

### 4. MITRE ATT&CK Analysis

```bash
python3 pcap_analyzer.py -i capture.pcap --mitre-attack --navigator-json attack.json
# Upload attack.json to: https://mitre-attack.github.io/attack-navigator/
```

### 5. Threat Intelligence Enrichment

```bash
# Configure API keys first
export ABUSEIPDB_KEY="your_key"

# Run with enrichment
python3 pcap_analyzer.py -i capture.pcap --threat-feeds --enrich-iocs
```

### 6. Session Reconstruction & Regex Hunting

```bash
python3 pcap_analyzer.py -i capture.pcap \
    --reconstruct-sessions \
    --regex-hunt "api[_-]?key|password|token" \
    --export-sessions sessions.csv
```

### 7. Community Tools Integration

```bash
python3 pcap_analyzer.py -i capture.pcap \
    --zeek-analyze \
    --suricata-analyze \
    --community-rules
```

### 8. Full Enterprise Analysis

```bash
python3 pcap_analyzer.py -i capture.pcap \
    --ml-anomaly \
    --mitre-attack \
    --threat-feeds \
    --reconstruct-sessions \
    --zeek-analyze \
    --suricata-analyze \
    -o full_report.pdf
```

### 9. Large File Analysis (10GB+)

```bash
# Automatic streaming mode
python3 pcap_analyzer.py -i massive_capture.pcap --verbose

[*] PCAP file size: 10240.50 MB
[*] Large file detected - using streaming mode
[*] Processed 100,000 packets...
[*] Processed 1,000,000 packets...
[Handles any size!]
```

### 10. Interactive Investigation

```bash
python3 pcap_analyzer.py -i capture.pcap --interactive

[Interactive] > stats
[Interactive] > attackchain
[Interactive] > ml-anomalies
[Interactive] > threat-intel
[Interactive] > export json
```

---
