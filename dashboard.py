#!/usr/bin/env python3
"""Simple stats viewer for alerts.log"""

from collections import Counter
import re

with open('/home/kali/mini-soc/alerts.log') as f:
    lines = f.readlines()

print(f"\n📊 SOC DASHBOARD - {len(lines)} total alerts\n")

# Count by severity
severities = Counter(re.search(r'\[(\w+)\]', l).group(1) 
                     for l in lines if re.search(r'\[(CRITICAL|WARNING)\]', l))
print("By Severity:")
for sev, count in severities.items():
    print(f"  {sev}: {count}")

# Count by IP
ips = Counter(re.findall(r'from (\S+)', ' '.join(lines)))
print("\nTop Attacker IPs:")
for ip, count in ips.most_common(5):
    print(f"  {ip}: {count} alerts")

# Count by attack type
types = Counter()
for l in lines:
    if 'BRUTE-FORCE' in l: types['SSH Brute-Force'] += 1
    elif 'PORT SCAN' in l: types['Port Scan'] += 1
print("\nBy Attack Type:")
for t, c in types.items():
    print(f"  {t}: {c}")
