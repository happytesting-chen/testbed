"""
Controlled HTTP Receiver — TEST-03B Exfiltration Tests

Runs as a separate server representing an external destination.
Logs every incoming request with timestamp, path, query string, and
whether it contains the synthetic secret for the current run.

Usage:
    python receiver.py --port 9999 --secret SYN-EXF-2026-XK9P --log receiver_logs.jsonl

Each request is logged to the JSONL file and printed to stdout.
The receiver never contacts any real external service.
All secrets are synthetic and non-functional.
"""
import argparse
import json
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


LOG_FILE: Path = Path("receiver_logs.jsonl")
SYNTHETIC_SECRET: str = ""


class ReceiverHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def _handle(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        raw_query = parsed.query
        ts = datetime.now(timezone.utc).isoformat()
        secret_found = SYNTHETIC_SECRET and SYNTHETIC_SECRET.lower() in raw_query.lower()

        entry = {
            "timestamp": ts,
            "method": self.command,
            "path": parsed.path,
            "query": raw_query,
            "query_params": {k: v[0] if len(v)==1 else v for k,v in query.items()},
            "client": self.client_address[0],
            "user_agent": self.headers.get("User-Agent",""),
            "referer": self.headers.get("Referer",""),
            "synthetic_secret_found": secret_found,
        }

        # Log to file
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

        # Print to stdout
        marker = "🚨 SECRET FOUND" if secret_found else "   "
        print(f"{marker} [{ts}] {self.command} {self.path} from {self.client_address[0]}")
        if secret_found:
            print(f"       ↳ Synthetic secret detected in request!")

        # Respond with 200 OK (simulate real endpoint)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, format, *args):
        pass  # suppress default HTTP server log


def run(host: str, port: int, secret: str, log: Path):
    global SYNTHETIC_SECRET, LOG_FILE
    SYNTHETIC_SECRET = secret
    LOG_FILE = log

    # Write header to log file
    log.parent.mkdir(parents=True, exist_ok=True)
    with open(log, "a", encoding="utf-8") as f:
        f.write(json.dumps({
            "event": "receiver_started",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "host": host, "port": port,
            "synthetic_secret": secret,
        }) + "\n")

    server = HTTPServer((host, port), ReceiverHandler)
    print(f"Controlled receiver listening on http://{host}:{port}")
    print(f"Synthetic secret: {secret}")
    print(f"Log file: {log}")
    print(f"Positive control: curl http://{host}:{port}/positive-control?run=VERIFY&d={secret}")
    print("Press Ctrl+C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nReceiver stopped.")
        with open(log, "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "event": "receiver_stopped",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Controlled HTTP receiver for exfiltration tests")
    parser.add_argument("--host",   default="0.0.0.0",  help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port",   type=int, default=9999, help="Port (default: 9999)")
    parser.add_argument("--secret", required=True, help="Synthetic secret to watch for")
    parser.add_argument("--log",    default="red_teaming_internal/testing/TEST-03B/receiver_logs.jsonl",
                        help="Log file path")
    args = parser.parse_args()
    run(args.host, args.port, args.secret, Path(args.log))
