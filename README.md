# 🛡️ Mini SOC — Honeypot-Based Threat Detection System

A lightweight Security Operations Center (SOC) prototype that demonstrates real-time threat detection using log monitoring, honeypot-based deception technology, and a live web dashboard.

---

## 📌 Overview

This project simulates a real-world SOC environment on a single machine. It combines traditional log-based detection with a Cowrie SSH honeypot to detect, classify, and alert on common attack patterns in real time.

> Built as a Final Year Project for B.E. CSE (Cyber Security) — demonstrating practical implementation of threat detection concepts used in industry.

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      ATTACKER                           │
│         Hydra (Brute Force) │ Nmap (Port Scan)          │
└──────────────┬──────────────┴──────────┬────────────────┘
               │                         │
               ▼                         ▼
┌──────────────────────┐    ┌────────────────────────────┐
│   Real SSH (Port 22) │    │  Cowrie Honeypot (Port 2222)│
│   /var/log/auth.log  │    │  Docker Container           │
└──────────┬───────────┘    └────────────┬───────────────┘
           │                             │
           ▼                             ▼
┌──────────────────────────────────────────────────────────┐
│                    detector.py (SIEM)                    │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │ parse_auth  │  │ parse_kern   │  │ parse_cowrie   │  │
│  │ _line()     │  │ _line()      │  │ _docker_line() │  │
│  └──────┬──────┘  └──────┬───────┘  └───────┬────────┘  │
│         └────────────────┴──────────────────┘           │
│                          │                               │
│                    write_alert()                         │
│              [SOURCE: honeypot/system]                   │
└──────────────────┬───────────────────────────────────────┘
                   │
        ┌──────────┴──────────┐
        ▼                     ▼
┌───────────────┐    ┌─────────────────┐
│  alerts.log   │    │ Telegram Alert  │
│  (persistent) │    │ (real-time push)│
└───────┬───────┘    └─────────────────┘
        │
        ▼
┌───────────────────┐
│  Flask Dashboard  │
│  localhost:5000   │
│  (auto-refresh)   │
└───────────────────┘
```

---

## ✨ Features

- **SSH Brute Force Detection** — Monitors `/var/log/auth.log` for repeated failed login attempts. Triggers CRITICAL alert after 3 failed attempts within 60 seconds.

- **Cowrie SSH Honeypot** — Deploys a fake SSH server on port 2222 via Docker. Logs all login attempts and commands executed by attackers in real time.

- **Port Scan Detection** — Uses iptables rules to tag RST packets in `/var/log/kern.log` and detect nmap-style port scans.

- **Real-Time Alerting** — All detections are logged to `alerts.log` and pushed instantly to Telegram with severity, timestamp, source, and IP.

- **Source Tagging** — Every alert is tagged `[SOURCE: honeypot]` or `[SOURCE: system]` to eliminate false positives and classify attack origin.

- **Flask Web Dashboard** — Live SOC dashboard at `localhost:5000` showing total alerts, honeypot hits, attack type breakdown, top attacker IPs, and a live alert feed. Auto-refreshes every 10 seconds.

- **Custom Honeypot Credentials** — Cowrie is configured to only accept common weak passwords (123456, password, admin) making it realistic — attackers must guess a real weak credential to get in.

---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|-----------|
| Honeypot | Cowrie SSH Honeypot (Docker) |
| Detection Engine | Python 3 |
| Log Monitoring | auth.log, kern.log, docker logs |
| Containerization | Docker + Docker Compose |
| Alerting | Telegram Bot API |
| Dashboard | Flask + HTML/CSS |
| Attack Simulation | Hydra, Nmap |

---

## 📁 Project Structure

```
mini-soc/
├── detector.py          # Main detection engine (SIEM)
├── dashboard.py         # Flask web dashboard
├── docker-compose.yml   # Docker setup for all services
├── Dockerfile           # Container config for detector
├── userdb.txt           # Cowrie honeypot credential config
├── alerts.log           # All generated alerts
├── results.txt          # Before/after research data
├── cowrie-logs/         # Cowrie JSON log output
└── .env                 # Telegram credentials (not committed)
```

---

## ⚙️ Setup & Installation

### Prerequisites
- Kali Linux (or any Debian-based Linux)
- Docker + Docker Compose
- Python 3

### 1. Clone the repo
```bash
git clone https://github.com/baranii2105/mini-soc-project.git
cd mini-soc-project
```

### 2. Set up Telegram alerts (optional)
```bash
cp .env.example .env
nano .env
# Add your TELEGRAM_TOKEN and TELEGRAM_CHAT_ID
```

### 3. Start all services
```bash
docker-compose up -d
```

### 4. Add iptables rule for port scan detection
```bash
sudo iptables -I INPUT 1 -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j LOG --log-prefix "PORTSCAN: "
```

### 5. Run the detector
```bash
sudo python3 detector.py
```

### 6. Run the dashboard
```bash
python3 dashboard.py
# Open http://localhost:5000
```

---

## 🧪 Attack Simulation

### SSH Brute Force (Real SSH — Port 22)
```bash
hydra -l kali -P /usr/share/wordlists/rockyou.txt ssh://localhost:22 -t 4
```

### SSH Brute Force (Honeypot — Port 2222)
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://localhost:2222 -t 4
```

### Port Scan
```bash
sudo nmap -p- --min-rate 1000 localhost
```

### Manual Honeypot Login
```bash
ssh -p 2222 root@localhost
# Password: 123456
```

---

## 📊 Before vs After Results

| Metric | Without Honeypot | With Honeypot |
|--------|-----------------|---------------|
| Attempts before alert | 3 | 3 |
| Time to first alert | ~15 seconds | ~3 seconds |
| Attack visibility | IP only | IP + username + password |
| Command logging | ❌ | ✅ |
| Credentials captured | ❌ | ✅ |
| False positive risk | Higher | Lower (honeypot = always real) |
| Detection speed | Baseline | 5x faster |

**Key Finding:** Honeypot-integrated detection is 5x faster and captures significantly richer attacker intelligence compared to log-based detection alone.

---

## 🔮 Future Scope

- Multi-VM deployment for true SOC simulation (attacker, victim, monitor on separate machines)
- ML-based anomaly detection using Isolation Forest (sklearn) for threshold-free alerting
- GeoIP mapping of attacker IPs on dashboard
- MITRE ATT&CK framework mapping for each detection

---

## 👤 Author

**Barani Priya R C**
B.E. CSE (Cyber Security) — Sri Krishna College of Engineering and Technology
Security Intern @ Adiroha Solutions Pvt. Ltd.

---

## ⚠️ Disclaimer

This project is built for educational purposes only. All attack simulations were performed in a controlled lab environment on systems owned by the author. Do not use these techniques on systems you don't own or have explicit permission to test.
