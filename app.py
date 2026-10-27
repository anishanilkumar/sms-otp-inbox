"""OTP inbox: receives SMS from the forwarder app on the phone, shows them behind a login.

The phone runs "Incoming SMS to URL forwarder" (bogkonstantin/android_income_sms_gateway_webhook),
which POSTs each SMS as JSON to /hook and signs the body with HMAC-SHA256 in X-Signature
(lowercase hex over the UTF-8 body). That signature is the only credential the phone has:
it cannot do an OAuth login, so /hook sits outside the Kanidm login in nginx and is
authenticated here instead. Everything else (the page, /api/) is behind oauth2-proxy.

The app's heartbeat is different: an empty POST with no headers, so it cannot be signed,
and the only place for a credential is the URL (/heartbeat/<token>). That is a secret in
a URL, but a leaked one only lets someone fake "the phone is alive", never read or plant
an SMS, so it gets its own token rather than reusing the HMAC secret.

Standard library only, so the unit needs no Python env. See sms-inbox.nix and CLAUDE.md.
"""

import hashlib
import hmac
import json
import os
import re
import sqlite3
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SECRET = os.environ.get("SMS_HMAC_SECRET", "").encode()
HEARTBEAT_TOKEN = os.environ.get("SMS_HEARTBEAT_TOKEN", "")
# Must match the interval set in the phone app; the page judges "late" from it.
HEARTBEAT_MINUTES = int(os.environ.get("SMS_HEARTBEAT_MINUTES", "5"))
DB_PATH = os.environ.get("SMS_DB", "/var/lib/sms-inbox/sms.db")
PORT = int(os.environ.get("SMS_PORT", "8776"))
# OTPs are useless after minutes and sensitive forever, so nothing is kept for long.
KEEP_DAYS = int(os.environ.get("SMS_KEEP_DAYS", "7"))
MAX_BODY = 64 * 1024
PAGE = (Path(__file__).parent / "index.html").read_bytes()

# A code is only taken from a message that says it is one. Without a keyword, a bare
# number is as likely an amount, a balance or an account suffix, and showing that as
# "the OTP" is worse than showing nothing.
KEYWORD = re.compile(
    r"otp|one[ -]?time|pass ?code|password|verification|verify|code|\bpin\b|token|login|sign[ -]?in|authori[sz]",
    re.I,
)
# 4-8 digits (or 3+3 split by a space or dash), not part of a longer number or word.
CANDIDATE = re.compile(r"(?<![\w.,/])(\d{3}[ -]\d{3}|\d{4,8})(?![\w/]|[.,]\d)")
# Money and account numbers that sit next to a keyword in the same SMS
# ("OTP for Rs 2500 on card XX1234 is 482913").
NOT_A_CODE = re.compile(r"(rs\.?|inr|₹|\$|€|usd|eur|a/?c|acct?|card|xx+|ending|no\.?)\s*$", re.I)


def extract_otp(text):
    keywords = [m.start() for m in KEYWORD.finditer(text)]
    if not keywords:
        return None
    best = None
    for m in CANDIDATE.finditer(text):
        if NOT_A_CODE.search(text[max(0, m.start() - 8):m.start()]):
            continue
        distance = min(abs(m.start() - k) for k in keywords)
        if best is None or distance < best[0]:
            best = (distance, m.group(1))
    return re.sub(r"[ -]", "", best[1]) if best else None


def db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            """CREATE TABLE IF NOT EXISTS sms (
                 id INTEGER PRIMARY KEY,
                 sender TEXT NOT NULL,
                 body TEXT NOT NULL,
                 otp TEXT,
                 sim TEXT,
                 sent_ms INTEGER,
                 received_ms INTEGER NOT NULL,
                 stored_ms INTEGER NOT NULL,
                 -- the phone retries on any non-2xx or dropped connection, so the
                 -- same SMS can arrive twice
                 UNIQUE (sender, body, received_ms)
               )"""
        )
        # What the phone last told us about itself: heartbeat_ms, sms_ms, and the
        # device-health placeholders (battery, power, network, version) if the
        # forwarding rule's JSON template includes them.
        conn.execute("CREATE TABLE IF NOT EXISTS phone (key TEXT PRIMARY KEY, value TEXT)")


def remember(conn, **values):
    conn.executemany(
        "INSERT INTO phone (key, value) VALUES (?, ?) "
        "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        [(k, str(v)) for k, v in values.items() if v is not None and str(v) != ""],
    )


def as_ms(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


class Handler(BaseHTTPRequestHandler):
    server_version = "sms-inbox"

    def log_message(self, fmt, *args):
        # The default logs the request line only, never bodies, so no OTP reaches journald.
        sys.stderr.write("%s\n" % (fmt % args))

    def send(self, status, body=b"", ctype="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            return self.send(200, PAGE, "text/html; charset=utf-8")
        if self.path == "/api/messages":
            with db() as conn:
                rows = conn.execute(
                    "SELECT id, sender, body, otp, sim, sent_ms, received_ms FROM sms "
                    "ORDER BY received_ms DESC, id DESC LIMIT 100"
                ).fetchall()
                phone = dict(conn.execute("SELECT key, value FROM phone").fetchall())
            phone["heartbeat_interval_ms"] = HEARTBEAT_MINUTES * 60_000
            payload = {"now_ms": int(time.time() * 1000), "phone": phone,
                       "messages": [dict(r) for r in rows]}
            return self.send(200, json.dumps(payload).encode())
        self.send(404, b'{"error":"not found"}')

    def do_POST(self):
        if self.path.startswith("/heartbeat/"):
            return self.heartbeat()
        if self.path != "/hook":
            return self.send(404, b'{"error":"not found"}')
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY:
            return self.send(413, b'{"error":"bad length"}')
        raw = self.rfile.read(length)
        expected = hmac.new(SECRET, raw, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, (self.headers.get("X-Signature") or "").lower()):
            # 401 makes the phone retry with backoff; harmless, and a wrong secret
            # shows up in its Syslog view as repeated failures.
            return self.send(401, b'{"error":"bad signature"}')
        try:
            msg = json.loads(raw)
            sender, text = str(msg["from"]), str(msg["text"])
        except (ValueError, KeyError, TypeError):
            # 2xx on purpose: malformed JSON will never become valid on retry.
            return self.send(202, b'{"error":"unparseable, dropped"}')
        now = int(time.time() * 1000)
        received = as_ms(msg.get("receivedStamp")) or now
        with db() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO sms (sender, body, otp, sim, sent_ms, received_ms, stored_ms) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (sender, text, extract_otp(text), str(msg.get("sim", "")),
                 as_ms(msg.get("sentStamp")), received, now),
            )
            conn.execute("DELETE FROM sms WHERE stored_ms < ?", (now - KEEP_DAYS * 86400_000,))
            # A signed SMS proves the phone is up just as well as a heartbeat does.
            remember(conn, sms_ms=now, battery=msg.get("battery"), power=msg.get("power"),
                     network=msg.get("network"), version=msg.get("version"))
        self.send(200, b'{"ok":true}')

    def heartbeat(self):
        token = self.path[len("/heartbeat/"):]
        if not hmac.compare_digest(token.encode(), HEARTBEAT_TOKEN.encode()):
            return self.send(404, b'{"error":"not found"}')
        with db() as conn:
            remember(conn, heartbeat_ms=int(time.time() * 1000))
        self.send(200, b'{"ok":true}')


def main():
    if not SECRET:
        # An empty key would make every forged request verify.
        sys.exit("SMS_HMAC_SECRET is empty; refusing to start")
    if len(HEARTBEAT_TOKEN) < 16:
        # Short or empty would make /heartbeat/ guessable.
        sys.exit("SMS_HEARTBEAT_TOKEN is missing or shorter than 16 characters; refusing to start")
    init_db()
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
