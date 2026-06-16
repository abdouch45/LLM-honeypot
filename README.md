# LLM Honeypot

<img width="1279" alt="image" src="https://github.com/user-attachments/assets/49476f2b-8515-47ee-b432-5fc49e9c21ee">


This project extends the Cowrie SSH honeypot to detect and analyze LLM-driven hacking agents.

## What is LLM Honeypot

A modified Cowrie SSH honeypot with multi-stage prompt injection traps. Common reconnaissance commands (pwd, whoami, ps, ls, df) return hidden messages using ANSI escape codes — invisible to human operators but parsed by LLM agents.

Detection relies on Goal Hijacking injection to redirect agent behavior toward verification commands, followed by a System Prompt Stealing stage that attempts to extract the agent's original instructions and objectives.

## Detection Design

Detection uses prompt injections tested across multiple LLM models to identify the most effective patterns. Current implementation includes:
- Hidden ANSI escape sequences (invisible in terminal, visible to agents)
- Indirect verification keys requiring reasoning
- Multi-stage progression to confirm agent behavior

## Setup for ssh service

```bash
make install && make enable && make start
```

## other services

```bash
docker compose up -d --build  # generates docker containers for dashboard, mysql server and webserver(please change the paths accorinding to your system) 
```
