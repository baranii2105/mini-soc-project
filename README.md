# Mini SOC - Log Monitor & Threat Detector
![Build](https://github.com/baranii2105/mini-soc-project/actions/workflows/docker-build.yml/badge.svg)

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

## Run with Docker

Containerized deployment using Docker and Docker Compose. Detector and dashboard run as separate services sharing a common alerts log.

### Pull pre-built image

```bash
docker pull ghcr.io/baranii2105/mini-soc:latest
```

### Build and run with Compose

```bash
sudo docker compose up --build
```

This starts two containers:
- `mini-soc-detector` — tails host `/var/log/auth.log` and `/var/log/kern.log` (read-only mounts)
- `mini-soc-dashboard` — reads the shared alerts log and renders the CLI dashboard

### Single-container run

```bash
docker build -t mini-soc .
docker run --rm -it \
  -v /var/log/auth.log:/var/log/auth.log:ro \
  -v /var/log/kern.log:/var/log/kern.log:ro \
  -v $(pwd)/alerts.log:/app/alerts.log \
  mini-soc
```

## CI/CD

Every push to `main` triggers a GitHub Actions workflow that builds and publishes a versioned Docker image to GitHub Container Registry, with layer caching for fast incremental builds.
