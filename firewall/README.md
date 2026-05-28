# 🛡️ Firewall Enforcer Module (Member B)

This directory contains the automated policy enforcement engine for the Advanced Threat Intelligence Platform (ATIP). It runs as a continuous system service to dynamically mitigate identified threat vectors.

## 📁 Component Architecture
* **`firewall_enforcer.py`**: The core Python execution script. Utilizes system subprocesses to interface with `iptables`, featuring state-checking validation to safely ignore duplicate target streams.
* **`threat-enforcer.service`**: The systemd configuration blueprint used to deploy this engine as a persistent 24/7 background daemon.

## ⚙️ Service Management Commands
To manage this background automation engine, use the following native system utilities:

```bash
# Check runtime service status and live logs
sudo systemctl status threat-enforcer.service

# Restart the daemon after applying code updates
sudo systemctl restart threat-enforcer.service

# Stop the background execution loop
sudo systemctl stop threat-enforcer.service
