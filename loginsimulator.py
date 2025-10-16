# Simple Login Brute Force Simulator
# Author: Ashenafi Tsge (Cyber Security)
# Date: October 2025
# Writes its logs to "attemptslog.txt"
#!/usr/bin/env python3
"""
Simple Login BruteForce Simulator + tiny web dashboard (no external deps)

- Terminal UI: run login attempts, logs stored in attemptslog.txt
- Web UI: open http://127.0.0.1:8000 to see logs (auto-fetch)
"""

import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import os
from datetime import datetime

# Config
HOST = "127.0.0.1"
PORT = 8000
ATTEMPTS_FILE = "attemptslog.txt"
USERNAME = "admin"
PASSWORD = "Cyber123!"
MAX_ATTEMPTS = 3

# Ensure attempts file exists
if not os.path.exists(ATTEMPTS_FILE):
    with open(ATTEMPTS_FILE, "w", encoding="utf-8") as f:
        f.write("# attempts log - created at {}\n".format(datetime.utcnow().isoformat()))

def log_attempt(username, password, success, note=""):
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{ts} | user:{username} | pass:{password} | {'SUCCESS' if success else 'FAILED'}"
    if note:
        line += f" | {note}"
    with open(ATTEMPTS_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")

class MyHandler(SimpleHTTPRequestHandler):
    """
    Serves files from current directory.
    Handles '/logs' GET to return the attempts file contents.
    Handles '/attempt' POST to receive JSON {username,password}, record the attempt, and respond JSON.
    """
    def do_GET(self):
        if self.path == "/logs":
            try:
                with open(ATTEMPTS_FILE, "r", encoding="utf-8") as f:
                    data = f.read()
            except FileNotFoundError:
                data = ""
            self.send_response(200)
            self.send_header("Content-type", "text/plain; charset=utf-8")
            self.send_header("Content-length", str(len(data.encode("utf-8"))))
            self.end_headers()
            self.wfile.write(data.encode("utf-8"))
        else:
            return super().do_GET()

    def do_POST(self):
        if self.path == "/attempt":
            # read JSON payload
            content_length = int(self.headers.get('Content-Length', 0))
            raw = self.rfile.read(content_length).decode('utf-8') if content_length else ''
            import json
            try:
                payload = json.loads(raw) if raw else {}
            except Exception:
                payload = {}
            username = payload.get('username', '')[:100]
            password = payload.get('password', '')[:200]

            # Determine success
            success = (username == USERNAME and password == PASSWORD)

            # Check for lock state (simple: count recent fails in file)
            # For this minimal version we'll not implement timed locks in the web handler,
            # but we will log LOCKED_NOW if in-memory counter logic in CLI locked it earlier.
            note = ""
            if success:
                message = "Login successful"
            else:
                message = "Login failed"

            # Record the attempt
            log_attempt(username, password, success, note=note)

            # Send JSON response
            resp = {'success': bool(success), 'message': message}
            resp_bytes = json.dumps(resp).encode('utf-8')
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(resp_bytes)))
            self.end_headers()
            self.wfile.write(resp_bytes)
        else:
            # Unknown POST path: 404
            self.send_response(404)
            self.end_headers()


def start_server():
    server = ThreadingHTTPServer((HOST, PORT), MyHandler)
    print(f"[web] Dashboard available at http://{HOST}:{PORT} (press CTRL+C to stop app)")
    server.serve_forever()

def login_cli():
    """
    Simple terminal login loop. Keeps track of consecutive failed attempts per username in-memory.
    Logs every attempt to attemptslog.txt.
    """
    print("=== Login BruteForce Simulator (CLI) ===")
    print(f"Demo credentials: {USERNAME} / {PASSWORD}")
    print("Open web dashboard at: http://{}:{}".format(HOST, PORT))
    # simple in-memory counter; reset when success or when locking occurs
    fail_counters = {}

    try:
        while True:
            username = input("Enter username (or type 'exit' to quit): ").strip()
            if username.lower() == "exit":
                print("Exiting...")
                break
            password = input("Enter password: ").strip()

            # check lock state
            fails = fail_counters.get(username, 0)
            if fails >= MAX_ATTEMPTS:
                note = "ACCOUNT_LOCKED"
                print("🚫 Account locked due to too many failed attempts.")
                log_attempt(username, password, False, note=note)
                continue

            if username == USERNAME and password == PASSWORD:
                print("✅ Login Successful!")
                log_attempt(username, password, True)
                # reset counter on success
                fail_counters[username] = 0
            else:
                fails += 1
                fail_counters[username] = fails
                tries_left = max(0, MAX_ATTEMPTS - fails)
                print(f"❌ Login Failed! Attempts left: {tries_left}")
                if fails >= MAX_ATTEMPTS:
                    print("🚫 Account locked now for demo (you can restart to reset).")
                    log_attempt(username, password, False, note="LOCKED_NOW")
                else:
                    log_attempt(username, password, False)
    except KeyboardInterrupt:
        print("\nInterrupted by user. Shutting down...")

if __name__ == "__main__":
    # Start web server in background thread
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()

    # Run CLI in main thread
    login_cli()

    # When CLI ends, stop program
    print("Goodbye. Note: web server thread is daemon and will exit now.")

