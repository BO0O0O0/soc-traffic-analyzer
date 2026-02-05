## Installation Options

### Option 1: Full Enterprise Install (Recommended)

```bash
# Download and run installer
chmod +x install.sh
./install.sh

# Installs:
# - Core analysis (scapy, matplotlib, reportlab)
# - ML features (scikit-learn, numpy, pandas)
# - Threat intel (pymisp, stix2)
# - Community tools (zeek, suricata)
```

### Option 2: Manual Install

```bash
# Core only
pip3 install scapy matplotlib reportlab requests --break-system-packages

# Add ML
pip3 install scikit-learn numpy pandas --break-system-packages

# Add threat intel
pip3 install pymisp stix2 --break-system-packages

# Community tools
sudo apt install zeek suricata
```

### Option 3: Minimal (Core Features Only)

```bash
pip3 install scapy matplotlib reportlab --break-system-packages
# No ML, no threat intel, no community tools
```
