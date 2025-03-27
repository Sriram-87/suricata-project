# Suricata Ubuntu Setup (Virtual Box)

## Overview
This repository documents the process of installing and configuring Suricata as an Intrusion Detection System (IDS) on an Ubuntu server. The steps were tested using Suricata version 6.0.8.

## Repository Contents
- **README.md:** Overview and instructions.
- **LICENSE:** Licensing information.
- **docs/**: Detailed documentation including installation and configuration guides, plus screenshots.
  - **installation.md:** Step-by-step installation instructions.
  - **configuration.md:** Overview of configuration changes.
- **config/suricata.yaml:** Customized Suricata configuration file.
- **scripts/run_suricata.sh:** Shell script to run Suricata.
- **logs/**: A directory to store log files.

## Installation Summary
1. **Install Suricata:**
   ```bash
   sudo add-apt-repository ppa:oisf/suricata-stable
   sudo apt-get update
   sudo apt-get install suricata -y
2. **Download and Install Emerging Threats Ruleset**
    cd /tmp/ && curl -LO https://rules.emergingthreats.net/open/suricata-6.0.8/emerging.rules.tar.gz
    sudo tar -xvzf emerging.rules.tar.gz && sudo mv rules/*.rules /etc/suricata/rules/
    sudo chmod 640 /etc/suricata/rules/*.rules
3. **Update Configuration:**:Modify Suricata settings in the /etc/suricata/suricata.yaml file and set the following variables:
    HOME_NET: "<UBUNTU_IP>"
    EXTERNAL_NET: "any"

    default-rule-path: /etc/suricata/rules
    rule-files:
    - "*.rules"

    # Global stats configuration
    stats:
    enabled: Yes

    # Linux high speed capture support
    af-packet:
    - interface: eth0
4. **Restart the Suricata service:**
    sudo systemctl restart suricata