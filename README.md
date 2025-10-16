# Login Brute Force Simulator

## Overview
This is a beginner-friendly cybersecurity project to demonstrate:
- prohibit brute force attacks work
- Account protection using maximum login attempts
# Login-BruteForce-Simulator (Simple Pro)

## What it is
A tiny educational login simulator that:
- Runs a simple CLI login loop and logs every attempt to `attemptslog.txt`.
- Serves a minimal web dashboard (index.html) to view the logs live at `http://127.0.0.1:8000`.

Runs locally. To demo: python loginsimulator.py, open http://127.0.0.1:8000. Use demo creds admin / Cyber123!. This is an educational simulator — do not use against third-party servers. In production, use password hashing, centralized logs, rate-limiting, and MFA.

Demo credentials:
- Username: `admin`
- Password: `Cyber123!`

## Files
- `loginsimulator.py` — main script (runs CLI and tiny web server)
- `index.html` — simple web dashboard that fetches logs
- `attemptslog.txt` — log file (created automatically)
- `README.md` — this file

## Requirements
- Python 3.8+ (no external packages required)

## How to run
1. Open terminal / PowerShell and `cd` into the project folder.

2. Run:
```bash
python loginsimulator.py
