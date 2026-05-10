# Mini SOC - Log Monitor & Threat Detector

A lightweight SOC-style log monitoring tool for Linux that detects:
- SSH brute-force attacks
- Port scanning activity

Built with Python 3, monitors `/var/log/auth.log` and `/var/log/kern.log` 
in real-time using a tail-follow pattern. Generates timestamped alerts 
with severity classification.

## Detection Logic
- **Brute-force:** ≥3 failed SSH logins from same IP in 60s
- **Port scan:** ≥10 SYN packets from same IP in 60s (via iptables logs)

## Usage
sudo python3 detector.py

## Tech Stack
Python 3, regex, iptables, Linux syslog
