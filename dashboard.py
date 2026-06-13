#!/usr/bin/env python3
"""
Mini SOC - Flask Web Dashboard
Reads alerts.log and displays real-time stats
"""

from flask import Flask, render_template_string
from collections import Counter
import re
import os

app = Flask(__name__)

ALERT_FILE = '/home/kali/mini-soc/alerts.log'

def parse_alerts():
    """Parse alerts.log and return structured data"""
    if not os.path.exists(ALERT_FILE):
        return []
    
    alerts = []
    with open(ALERT_FILE, 'r') as f:
        for line in f.readlines():
            line = line.strip()
            if not line:
                continue
            
            # Parse: [2026-06-13 12:54:15] [CRITICAL] message
            match = re.match(r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] \[(\w+)\] (.+)', line)
            if match:
                timestamp, severity, message = match.groups()
                
                # Determine source
                if 'honeypot' in message.lower():
                    source = 'Honeypot'
                else:
                    source = 'System'
                
                # Determine attack type
                if 'BRUTE-FORCE' in message:
                    attack_type = 'SSH Brute-Force'
                elif 'PORT SCAN' in message:
                    attack_type = 'Port Scan'
                elif 'honeypot' in message.lower():
                    attack_type = 'Honeypot Login'
                else:
                    attack_type = 'Unknown'
                
                # Extract IP
                ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', message)
                ip = ip_match.group(1) if ip_match else 'N/A'
                
                alerts.append({
                    'timestamp': timestamp,
                    'severity': severity,
                    'message': message,
                    'source': source,
                    'attack_type': attack_type,
                    'ip': ip
                })
    
    return alerts


HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="10">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mini SOC Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            background: #0a0e1a;
            color: #c9d1d9;
            font-family: 'Courier New', monospace;
            min-height: 100vh;
        }

        /* TOP BAR */
        .topbar {
            background: #0d1117;
            border-bottom: 1px solid #ff4444;
            padding: 14px 32px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .topbar-left {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .pulse {
            width: 10px; height: 10px;
            background: #ff4444;
            border-radius: 50%;
            animation: pulse 1.5s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; box-shadow: 0 0 0 0 rgba(255,68,68,0.4); }
            50% { opacity: 0.6; box-shadow: 0 0 0 6px rgba(255,68,68,0); }
        }
        .topbar h1 {
            font-size: 18px;
            color: #fff;
            letter-spacing: 3px;
            text-transform: uppercase;
        }
        .topbar-right {
            font-size: 12px;
            color: #666;
            letter-spacing: 1px;
        }
        .topbar-right span {
            color: #ff4444;
        }

        /* MAIN */
        .main { padding: 28px 32px; }

        /* STAT CARDS */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 28px;
        }
        .stat-card {
            background: #0d1117;
            border: 1px solid #21262d;
            border-radius: 6px;
            padding: 20px;
            position: relative;
            overflow: hidden;
        }
        .stat-card::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0;
            height: 2px;
        }
        .stat-card.red::before { background: #ff4444; }
        .stat-card.orange::before { background: #ff8c00; }
        .stat-card.blue::before { background: #58a6ff; }
        .stat-card.green::before { background: #3fb950; }

        .stat-label {
            font-size: 11px;
            color: #666;
            letter-spacing: 2px;
            text-transform: uppercase;
            margin-bottom: 10px;
        }
        .stat-value {
            font-size: 36px;
            font-weight: bold;
            color: #fff;
            line-height: 1;
        }
        .stat-card.red .stat-value { color: #ff4444; }
        .stat-card.orange .stat-value { color: #ff8c00; }
        .stat-card.blue .stat-value { color: #58a6ff; }
        .stat-card.green .stat-value { color: #3fb950; }

        /* BOTTOM GRID */
        .bottom-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
            margin-bottom: 28px;
        }

        .panel {
            background: #0d1117;
            border: 1px solid #21262d;
            border-radius: 6px;
            overflow: hidden;
        }
        .panel-header {
            padding: 14px 20px;
            border-bottom: 1px solid #21262d;
            font-size: 11px;
            letter-spacing: 2px;
            text-transform: uppercase;
            color: #8b949e;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .panel-header .dot {
            width: 6px; height: 6px;
            border-radius: 50%;
            background: #ff4444;
        }
        .panel-body { padding: 20px; }

        /* BAR CHART */
        .bar-item {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 14px;
        }
        .bar-label {
            width: 140px;
            font-size: 12px;
            color: #8b949e;
            flex-shrink: 0;
        }
        .bar-track {
            flex: 1;
            background: #21262d;
            border-radius: 2px;
            height: 8px;
            overflow: hidden;
        }
        .bar-fill {
            height: 100%;
            border-radius: 2px;
            transition: width 0.3s ease;
        }
        .bar-fill.red { background: #ff4444; }
        .bar-fill.orange { background: #ff8c00; }
        .bar-fill.blue { background: #58a6ff; }
        .bar-count {
            width: 30px;
            font-size: 12px;
            color: #fff;
            text-align: right;
            flex-shrink: 0;
        }

        /* ALERT TABLE */
        .alert-table-wrap { overflow-x: auto; }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 12px;
        }
        th {
            text-align: left;
            padding: 10px 14px;
            color: #666;
            letter-spacing: 1px;
            text-transform: uppercase;
            font-size: 10px;
            border-bottom: 1px solid #21262d;
        }
        td {
            padding: 10px 14px;
            border-bottom: 1px solid #161b22;
            color: #c9d1d9;
        }
        tr:hover td { background: #161b22; }
        tr:last-child td { border-bottom: none; }

        .badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 10px;
            letter-spacing: 1px;
            font-weight: bold;
        }
        .badge-critical { background: rgba(255,68,68,0.15); color: #ff4444; border: 1px solid rgba(255,68,68,0.3); }
        .badge-honeypot { background: rgba(255,140,0,0.15); color: #ff8c00; border: 1px solid rgba(255,140,0,0.3); }
        .badge-system { background: rgba(88,166,255,0.15); color: #58a6ff; border: 1px solid rgba(88,166,255,0.3); }

        .footer {
            text-align: center;
            font-size: 11px;
            color: #444;
            padding: 16px;
            letter-spacing: 1px;
        }
        .footer span { color: #ff4444; }
    </style>
</head>
<body>

<div class="topbar">
    <div class="topbar-left">
        <div class="pulse"></div>
        <h1>Mini SOC &mdash; Threat Dashboard</h1>
    </div>
    <div class="topbar-right">
        AUTO-REFRESH <span>10s</span> &nbsp;|&nbsp; {{ current_time }}
    </div>
</div>

<div class="main">

    <!-- STAT CARDS -->
    <div class="stats-grid">
        <div class="stat-card red">
            <div class="stat-label">Total Alerts</div>
            <div class="stat-value">{{ total }}</div>
        </div>
        <div class="stat-card orange">
            <div class="stat-label">Honeypot Hits</div>
            <div class="stat-value">{{ honeypot_count }}</div>
        </div>
        <div class="stat-card blue">
            <div class="stat-label">System Alerts</div>
            <div class="stat-value">{{ system_count }}</div>
        </div>
        <div class="stat-card green">
            <div class="stat-label">Unique IPs</div>
            <div class="stat-value">{{ unique_ips }}</div>
        </div>
    </div>

    <!-- CHARTS + TOP IPs -->
    <div class="bottom-grid">

        <!-- Attack Types -->
        <div class="panel">
            <div class="panel-header"><div class="dot"></div>Alerts by Attack Type</div>
            <div class="panel-body">
                {% for atype, count in attack_types.items() %}
                <div class="bar-item">
                    <div class="bar-label">{{ atype }}</div>
                    <div class="bar-track">
                        <div class="bar-fill {% if loop.index == 1 %}red{% elif loop.index == 2 %}orange{% else %}blue{% endif %}"
                             style="width: {{ (count / total * 100) if total > 0 else 0 }}%"></div>
                    </div>
                    <div class="bar-count">{{ count }}</div>
                </div>
                {% endfor %}
                {% if not attack_types %}
                <div style="color:#444; font-size:12px;">No alerts yet</div>
                {% endif %}
            </div>
        </div>

        <!-- Top IPs -->
        <div class="panel">
            <div class="panel-header"><div class="dot"></div>Top Attacker IPs</div>
            <div class="panel-body">
                {% for ip, count in top_ips %}
                <div class="bar-item">
                    <div class="bar-label">{{ ip }}</div>
                    <div class="bar-track">
                        <div class="bar-fill red"
                             style="width: {{ (count / total * 100) if total > 0 else 0 }}%"></div>
                    </div>
                    <div class="bar-count">{{ count }}</div>
                </div>
                {% endfor %}
                {% if not top_ips %}
                <div style="color:#444; font-size:12px;">No IPs detected yet</div>
                {% endif %}
            </div>
        </div>

    </div>

    <!-- ALERT TABLE -->
    <div class="panel">
        <div class="panel-header"><div class="dot"></div>Live Alert Feed — Last 20</div>
        <div class="alert-table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Severity</th>
                        <th>Source</th>
                        <th>Attack Type</th>
                        <th>IP</th>
                        <th>Message</th>
                    </tr>
                </thead>
                <tbody>
                    {% for alert in recent_alerts %}
                    <tr>
                        <td>{{ alert.timestamp }}</td>
                        <td><span class="badge badge-critical">{{ alert.severity }}</span></td>
                        <td><span class="badge {% if alert.source == 'Honeypot' %}badge-honeypot{% else %}badge-system{% endif %}">{{ alert.source }}</span></td>
                        <td>{{ alert.attack_type }}</td>
                        <td>{{ alert.ip }}</td>
                        <td style="color:#8b949e; max-width:400px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">{{ alert.message }}</td>
                    </tr>
                    {% endfor %}
                    {% if not recent_alerts %}
                    <tr><td colspan="6" style="text-align:center; color:#444; padding:30px;">No alerts logged yet</td></tr>
                    {% endif %}
                </tbody>
            </table>
        </div>
    </div>

</div>

<div class="footer">
    MINI SOC &mdash; THREAT DETECTION SYSTEM &nbsp;|&nbsp; REFRESHES EVERY <span>10 SECONDS</span>
</div>

</body>
</html>
'''


@app.route('/')
def dashboard():
    from datetime import datetime
    from collections import Counter

    alerts = parse_alerts()
    total = len(alerts)
    honeypot_count = sum(1 for a in alerts if a['source'] == 'Honeypot')
    system_count = sum(1 for a in alerts if a['source'] == 'System')
    unique_ips = len(set(a['ip'] for a in alerts if a['ip'] != 'N/A'))

    # Attack type counts
    attack_types = Counter(a['attack_type'] for a in alerts)

    # Top 5 IPs
    ip_counter = Counter(a['ip'] for a in alerts if a['ip'] != 'N/A')
    top_ips = ip_counter.most_common(5)

    # Last 20 alerts (newest first)
    recent_alerts = list(reversed(alerts))[:20]

    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    return render_template_string(HTML_TEMPLATE,
        total=total,
        honeypot_count=honeypot_count,
        system_count=system_count,
        unique_ips=unique_ips,
        attack_types=dict(attack_types),
        top_ips=top_ips,
        recent_alerts=recent_alerts,
        current_time=current_time
    )


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
