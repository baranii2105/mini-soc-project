#!/usr/bin/env python3
"""
Mini SOC - Log Monitor & Threat Detector
Watches auth.log and kern.log for suspicious activity
"""

import re
import time
import os
from collections import defaultdict
from datetime import datetime

import requests
from dotenv import load_dotenv

# Load Telegram credentials from .env
load_dotenv()
TELEGRAM_TOKEN = os.getenv('TELEGRAM_TOKEN')
TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')
TELEGRAM_ENABLED = bool(TELEGRAM_TOKEN and TELEGRAM_CHAT_ID)

# ANSI color codes for terminal output
RED = '\033[91m'
YELLOW = '\033[93m'
GREEN = '\033[92m'
RESET = '\033[0m'

# Detection thresholds
FAILED_LOGIN_THRESHOLD = 3      # alert after 3 failed logins
PORTSCAN_THRESHOLD = 10         # alert after 10 connection attempts
TIME_WINDOW = 60                # within 60 seconds

# Tracking dictionaries
failed_logins = defaultdict(list)   # {ip: [timestamps]}
port_scans = defaultdict(list)      # {ip: [timestamps]}

# Log files to monitor
AUTH_LOG = '/var/log/auth.log'
KERN_LOG = '/var/log/kern.log'
ALERT_FILE = '/home/kali/mini-soc/alerts.log'  # adjust path if needed

def send_telegram_alert(severity, message):
    """Push alert to Telegram"""
    if not TELEGRAM_ENABLED:
        return
    
    # Emoji based on severity
    emoji = '🚨' if severity == 'CRITICAL' else '⚠️'
    
    # Formatted message with Markdown
    text = (
        f"{emoji} *Mini SOC Alert*\n"
        f"━━━━━━━━━━━━━━━\n"
        f"*Severity:* `{severity}`\n"
        f"*Time:* `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`\n"
        f"*Event:*\n{message}"
    )
    
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {
        'chat_id': TELEGRAM_CHAT_ID,
        'text': text,
        'parse_mode': 'Markdown'
    }
    
    try:
        requests.post(url, data=payload, timeout=5)
    except Exception as e:
        print(f"{YELLOW}[!] Telegram send failed: {e}{RESET}")

def write_alert(severity, message):
    """Write alert to file + print to terminal + send to Telegram"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    alert = f"[{timestamp}] [{severity}] {message}"
    
    # Color coding
    color = RED if severity == 'CRITICAL' else YELLOW
    print(f"{color}🚨 {alert}{RESET}")
    
    # Write to alerts file
    with open(ALERT_FILE, 'a') as f:
        f.write(alert + '\n')

    # NEW: Push to Telegram
    send_telegram_alert(severity, message)


def check_failed_logins(ip):
    """Check if an IP crossed the brute-force threshold"""
    now = time.time()
    # Keep only timestamps within the time window
    failed_logins[ip] = [t for t in failed_logins[ip] if now - t < TIME_WINDOW]
    failed_logins[ip].append(now)
    
    if len(failed_logins[ip]) >= FAILED_LOGIN_THRESHOLD:
        write_alert(
            'CRITICAL',
            f"Possible SSH BRUTE-FORCE from {ip} - "
            f"{len(failed_logins[ip])} failed attempts in {TIME_WINDOW}s"
        )
        failed_logins[ip] = []  # reset after alert


def check_port_scan(ip):
    """Check if an IP crossed the port-scan threshold"""
    now = time.time()
    port_scans[ip] = [t for t in port_scans[ip] if now - t < TIME_WINDOW]
    port_scans[ip].append(now)
    
    if len(port_scans[ip]) >= PORTSCAN_THRESHOLD:
        write_alert(
            'CRITICAL',
            f"Possible PORT SCAN from {ip} - "
            f"{len(port_scans[ip])} connection attempts in {TIME_WINDOW}s"
        )
        port_scans[ip] = []


def parse_auth_line(line):
    """Look for failed SSH login patterns"""
    # Matches: "Failed password for [invalid user] X from Y.Y.Y.Y"
    match = re.search(r'Failed password for (?:invalid user )?(\S+) from (\S+)', line)
    if match:
        user, ip = match.groups()
        print(f"{YELLOW}[!] Failed login: user={user} ip={ip}{RESET}")
        check_failed_logins(ip)


def parse_kern_line(line):
    """Look for port scan patterns from iptables logs"""
    if 'PORTSCAN:' in line:
        # Extract source IP from iptables log: "SRC=1.2.3.4"
        match = re.search(r'SRC=(\S+)', line)
        if match:
            ip = match.group(1)
            check_port_scan(ip)


def follow(filepath):
    """Generator that yields new lines as they're added (like tail -f)"""
    with open(filepath, 'r') as f:
        f.seek(0, os.SEEK_END)  # jump to end of file
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line


def monitor_file(filepath, parser):
    """Monitor a single log file with the given parser function"""
    print(f"{GREEN}[+] Monitoring {filepath}{RESET}")
    for line in follow(filepath):
        parser(line)


def main():
    print(f"{GREEN}╔══════════════════════════════════════╗")
    print(f"║   Mini SOC - Threat Detector v1.0    ║")
    print(f"╚══════════════════════════════════════╝{RESET}")
    print(f"[+] Failed login threshold: {FAILED_LOGIN_THRESHOLD} in {TIME_WINDOW}s")
    print(f"[+] Port scan threshold: {PORTSCAN_THRESHOLD} in {TIME_WINDOW}s")
    print(f"[+] Alerts logged to: {ALERT_FILE}")
    print(f"[+] Press Ctrl+C to stop\n")
    
    # Use threading to monitor both files at once
    import threading
    
    t1 = threading.Thread(target=monitor_file, args=(AUTH_LOG, parse_auth_line), daemon=True)
    t2 = threading.Thread(target=monitor_file, args=(KERN_LOG, parse_kern_line), daemon=True)
    
    t1.start()
    t2.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{GREEN}[+] Detector stopped. Check alerts.log for results.{RESET}")


if __name__ == '__main__':
    main()
