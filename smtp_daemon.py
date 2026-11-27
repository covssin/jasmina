# smtp_daemon.py
import asyncio
import json
import logging
import os
import re
import ssl
import time
from pathlib import Path
from typing import Optional

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import Envelope, Session, SMTP

from core import analyze_email, save_audit_result

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] jasmina-smtp: %(message)s",
)
logger = logging.getLogger("jasmina-smtp")

SMTP_HOST = os.getenv("JASMINA_SMTP_HOST", "127.0.0.1")
SMTP_PORT = int(os.getenv("JASMINA_SMTP_PORT", "2525"))
AUDIT_DOMAIN = os.getenv("JASMINA_DOMAIN", "jasmina.kmucha.pl").lower()
AUDIT_DIR = Path(os.getenv("JASMINA_DATA_DIR", "/tmp/jasmina_audits"))
AUDIT_DIR.mkdir(parents=True, exist_ok=True)

TLS_CERT_PATH = os.getenv("JASMINA_TLS_CERT", "/opt/jasmina/certs/fullchain.pem")
TLS_KEY_PATH = os.getenv("JASMINA_TLS_KEY", "/opt/jasmina/certs/privkey.pem")

TOKEN_PATTERN = re.compile(
    rf"^audit-([a-zA-Z0-9_-]+)@{re.escape(AUDIT_DOMAIN)}$", re.IGNORECASE
)


def _build_ssl_context() -> Optional[ssl.SSLContext]:
    cert_file = Path(TLS_CERT_PATH)
    key_file = Path(TLS_KEY_PATH)
    if cert_file.exists() and key_file.exists():
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
        logger.info("STARTTLS enabled using %s", cert_file)
        return ctx
    logger.warning(
        "TLS cert/key not found (%s, %s) — running without STARTTLS",
        cert_file,
        key_file,
    )
    return None


def _extract_valid_token(rcpt_to: str) -> Optional[str]:
    clean_addr = rcpt_to.strip().strip("<>").lower()
    match = TOKEN_PATTERN.match(clean_addr)
    if not match:
        return None

    token = match.group(1)
    session_file = AUDIT_DIR / f"{token}.json"
    if not session_file.exists():
        return None

    try:
        data = json.loads(session_file.read_text(encoding="utf-8"))
        if data.get("expires_at", 0) < time.time():
            return None
        return token
    except Exception:
        return None


class JasminaSMTPHandler:
    async def handle_RCPT(
        self,
        server: SMTP,
        session: Session,
        envelope: Envelope,
        address: str,
        rcpt_options: list[str],
    ) -> str:
        token = _extract_valid_token(address)
        if not token:
            logger.info("Rejected RCPT TO <%s> (unknown or expired token)", address)
            return "550 5.1.1 Unknown or expired audit recipient"

        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(
        self,
        server: SMTP,
        session: Session,
        envelope: Envelope,
    ) -> str:
        peer_ip = session.peer[0] if session.peer else ""
        tls_desc = ""
        if session.ssl:
            cipher = session.ssl.get("cipher")
            if isinstance(cipher, tuple) and len(cipher) >= 2:
                tls_desc = f"{cipher[1]} ({cipher[0]})"

        raw_bytes = envelope.original_content or b""
        mail_from = envelope.mail_from or ""

        processed = 0
        for rcpt in envelope.rcpt_tos:
            token = _extract_valid_token(rcpt)
            if not token:
                continue

            logger.info(
                "Auditing message for token=%s from=<%s> ip=%s tls=%s",
                token,
                mail_from,
                peer_ip,
                tls_desc or "none",
            )
            try:
                report = analyze_email(
                    raw_bytes=raw_bytes,
                    mail_from=mail_from,
                    client_ip=peer_ip,
                    tls_info=tls_desc,
                )
                if save_audit_result(token=token, report=report, data_dir=str(AUDIT_DIR)):
                    processed += 1
                    logger.info("Audit report saved for token=%s (score=%s)", token, report.get("score"))
            except Exception as exc:
                logger.exception("Failed to analyze email for token=%s: %s", token, exc)

        if processed == 0:
            return "550 5.7.1 No active audit session matched"

        return "250 2.0.0 OK: Audit processed"


async def main() -> None:
    ssl_context = _build_ssl_context()
    handler = JasminaSMTPHandler()

    controller = Controller(
        handler,
        hostname=SMTP_HOST,
        port=SMTP_PORT,
        tls_context=ssl_context,
        require_starttls=False,
    )
    controller.start()
    logger.info("Listening on %s:%s for @%s", SMTP_HOST, SMTP_PORT, AUDIT_DOMAIN)

    try:
        while True:
            await asyncio.sleep(3600)
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        controller.stop()
        logger.info("SMTP daemon stopped")


if __name__ == "__main__":
    asyncio.run(main())