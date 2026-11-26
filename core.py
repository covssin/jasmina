import sqlite3
import time
import secrets
import string
import json
import email
from email import policy
import dkim
import checkdmarc

DB_PATH = "/opt/jasmina/jasmina.db"
DOMAIN = "jasmina.kmucha.pl"
TTL_SECONDS = 1800  # 30 minut

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                address TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'waiting',
                report_json TEXT
            )
        """)

def cleanup_expired():
    now = int(time.time())
    with get_db() as conn:
        # Usuwamy nieużyte wygasłe skrzynki po 30 min; gotowe raporty trzymamy 24h
        conn.execute("DELETE FROM sessions WHERE status = 'waiting' AND expires_at < ?", (now,))
        conn.execute("DELETE FROM sessions WHERE status = 'done' AND expires_at < ?", (now - 86400,))

def create_session():
    cleanup_expired()
    alphabet = string.ascii_lowercase + string.digits
    token = "audyt-" + "".join(secrets.choice(alphabet) for _ in range(8))
    address = f"{token}@{DOMAIN}"
    now = int(time.time())
    expires_at = now + TTL_SECONDS
    with get_db() as conn:
        conn.execute(
            "INSERT INTO sessions (token, address, created_at, expires_at, status) VALUES (?, ?, ?, ?, 'waiting')",
            (token, address, now, expires_at)
        )
    return {"token": token, "address": address, "expires_at": expires_at, "ttl": TTL_SECONDS}

def is_token_valid(recipient: str):
    cleanup_expired()
    addr = recipient.strip().lower()
    if "@" not in addr:
        return None
    token, dom = addr.split("@", 1)
    if dom != DOMAIN:
        return None
    now = int(time.time())
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM sessions WHERE token = ? AND status = 'waiting' AND expires_at >= ?",
            (token, now)
        ).fetchone()
        return dict(row) if row else None

def analyze_and_save(token: str, raw_bytes: bytes, peer_ip: str, tls_info: dict):
    msg = email.message_from_bytes(raw_bytes, policy=policy.default)
    mail_from = msg.get("From", "")
    subject = msg.get("Subject", "(brak tematu)")
    sender_domain = ""
    if "@" in mail_from:
        sender_domain = mail_from.split("@")[-1].strip(" >\"'").lower()

    # 1. Weryfikacja podpisu DKIM na surowych bajtach wiadomości
    dkim_valid = False
    dkim_error = None
    try:
        dkim_valid = bool(dkim.verify(raw_bytes))
    except Exception as e:
        dkim_error = str(e)

    # 2. Analiza DNS (SPF, DMARC, MTA-STS, TLS-RPT, MX STARTTLS, DNSSEC) przez checkdmarc
    dns_audit = {}
    if sender_domain:
        try:
            dns_audit = checkdmarc.check_domains([sender_domain], skip_tls=False)
        except Exception as e:
            dns_audit = {"error": str(e)}

    report = {
        "received_at": int(time.time()),
        "peer_ip": peer_ip,
        "tls": tls_info,
        "mail_from": mail_from,
        "sender_domain": sender_domain,
        "subject": subject,
        "dkim": {
            "valid": dkim_valid,
            "has_signature": "DKIM-Signature" in msg,
            "error": dkim_error
        },
        "dns_audit": dns_audit
    }

    with get_db() as conn:
        conn.execute(
            "UPDATE sessions SET status = 'done', report_json = ? WHERE token = ?",
            (json.dumps(report, ensure_ascii=False, default=str), token)
        )
