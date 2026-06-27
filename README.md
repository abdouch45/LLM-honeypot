# LLM Honeypot

<img width="1279" alt="image" src="https://github.com/user-attachments/assets/49476f2b-8515-47ee-b432-5fc49e9c21ee">

A multi-service honeypot designed to detect and analyze LLM-driven hacking agents.

## Overview

LLM Honeypot deploys seven coordinated attack-surface services — each embedding prompt injection traps invisible to human operators but actionable by text-reasoning agents. Detection relies on behavioral signals: an agent that reads hidden instructions and acts on them reveals itself through that very action.

## Services

| Service | Protocol | Port | Technology |
|---|---|---|---|
| SSH honeypot | SSH | 2223 | Cowrie (Python + Twisted) |
| FTP honeypot | FTP | 21 | Custom Python + Twisted |
| DNS honeypot | DNS | 5354 | Twisted names |
| API server | HTTP | 8004 | Raw ASGI (uvicorn) |
| Web app | HTTP | 8081 | Node.js + Express (Docker) |
| MySQL server | MySQL | 3306 | MySQL 8.0 (Docker) |
| Dashboard | HTTP | 8000 | Node.js + Express (Docker) |

## Detection Design

Every service hides a prompt inside an otherwise normal protocol response — text a human operator or deterministic scanner would never act on, but that a text-reasoning agent parsing raw output will read and follow.

Most traps share a common riddle (`last name of the first US president` → `Washington`) as the unlock key. Using the same answer across SSH, FTP, the API server, the database, and the web app is deliberate: an agent that solves it once and reuses it elsewhere demonstrates cross-service, goal-directed reasoning — a much stronger signal than any single service's response in isolation.

Once unlocked, traps return a goal-hijacking payload asking the attacker's own agent to narrate its mission back to the honeypot — turning the agent's reasoning loop against itself as a system-prompt exfiltration attempt.

See [SERVICES_AND_DETECTION.md](SERVICES_AND_DETECTION.md) for a detailed breakdown of each service's implementation and detection mechanism.

## Setup

**1. Install and start the Python-based services (SSH, FTP, DNS, API)**

```bash
make install
make start
```

`make install` clones Cowrie, creates a Python venv with `uv`, and copies all trap configs and command overrides into the Cowrie tree. `make start` launches Cowrie, the FTP server, the DNS honeypot, and the API server as background processes.

**2. Start the containerized services (dashboard, web app, MySQL)**

```bash
docker compose up -d --build
```

> Update the host volume paths in `docker-compose.yml` to match your system before the first run.

**Stop all services**

```bash
make stop
docker compose down
```

## Requirements

- Python 3.10+
- [`uv`](https://github.com/astral-sh/uv)
- Docker + Docker Compose
