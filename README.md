# Python Interactive SSH Honeypot

A lightweight, multi-threaded Python-based SSH honeypot designed to emulate an Ubuntu server, capture attacker authentication attempts, and log real-time command execution telemetry in structured JSON and flat log formats.

---

## Features

- **Authentication Capture:** Logs all incoming login attempts (IP address, port, username, and password).
- **Interactive Decoy Shell:** Emulates a bash environment with custom responses for common reconnaissance commands (`ls`, `whoami`, `id`).
- **Structured Telemetry Logging:** Generates human-readable text logs (`honeypot_activity.log`) and SIEM-ready JSON logs (`logs/honeypot_events.json`).
- **Session Persistence:** Uses non-blocking thread handling to manage SSH pseudo-terminal (PTY) connections smoothly.

---

## Architecture & Design

The honeypot is built on Python's `paramiko` library using the `ServerInterface` class:

1. **Transport Layer:** Listens on port `2222` and handles the SSH handshake with a persistent RSA host key (`honeypot.key`).
2. **Authentication Interface:** Accepts all password attempts while capturing telemetry.
3. **Execution Thread:** Offloads interactive shell loops to dedicated threads to ensure non-blocking input/output processing.

---

## Getting Started

### Prerequisites
- Python 3.x
- `paramiko` library

