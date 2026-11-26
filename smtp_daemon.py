import asyncio
import ssl
import re
import logging
from aiosmtpd.controller import Controller
from core import init_db, analyze_and_save, DOMAIN

logging.basicConfig(level=logging.INFO, format="%(asctime)s [SMTP] %(message)s")

def extract_real_ip(peer_ip: str, raw_bytes: bytes) -> str:
    if peer_ip not in ("127.0.0.1", "::1", "unknown"):
        return peer_ip
    text = raw_bytes.decode("utf-8", errors="ignore")
    for line in text.splitlines():
        if line.lower().startswith("received:"):
            m = re.search(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]", line)
            if m and not m.group(1).startswith(("127.", "10.", "192.168.")):
                return m.group(1)
    return peer_ip

class JasminaHandler:
    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        if not address.lower().endswith(f"@{DOMAIN}"):
            return "550 5.1.1 Relay access denied"
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        raw_peer = session.peer[0] if session.peer else "unknown"
        peer_ip = extract_real_ip(raw_peer, envelope.original_content)
        tls_info = {"encrypted": bool(session.ssl), "protocol": "TLS (STARTTLS)" if session.ssl else None, "cipher": None}

        if isinstance(session.ssl, dict):
            tls_info["protocol"] = session.ssl.get("protocol") or session.ssl.get("version") or "TLS (STARTTLS)"
            c = session.ssl.get("cipher")
            tls_info["cipher"] = c[0] if isinstance(c, (tuple, list)) and c else str(c or "")

        transport = getattr(server, "transport", None)
        if transport:
            ssl_obj = transport.get_extra_info("ssl_object")
            if ssl_obj:
                tls_info["encrypted"] = True
                tls_info["protocol"] = ssl_obj.version()
                c = ssl_obj.cipher()
                if c:
                    tls_info["cipher"] = c[0]

        for rcpt in envelope.rcpt_tos:
            token = rcpt.split("@")[0].lower()
            logging.info(f"Odebrano audyt dla {rcpt} z {peer_ip} (TLS: {tls_info['protocol']})")
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, analyze_and_save, token, envelope.original_content, peer_ip, tls_info)

        return "250 Message accepted for security audit"

def main():
    init_db()
    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_ctx.load_cert_chain(
        certfile="/etc/letsencrypt/live/jasmina.kmucha.pl/fullchain.pem",
        keyfile="/etc/letsencrypt/live/jasmina.kmucha.pl/privkey.pem",
    )
    kw = dict(ident=f"{DOMAIN} ESMTP", server_kwargs={"hostname": DOMAIN}, tls_context=ssl_ctx, require_starttls=False, auth_exclude_mechanism=["LOGIN", "PLAIN"])
    c1 = Controller(JasminaHandler(), hostname="::", port=25, **kw)
    c2 = Controller(JasminaHandler(), hostname="127.0.0.1", port=2525, **kw)
    c1.start()
    c2.start()
    logging.info(f"Odbiornik SMTP uruchomiony dla {DOMAIN}")
    loop = asyncio.new_event_loop()
    try:
        loop.run_forever()
    finally:
        c1.stop()
        c2.stop()

if __name__ == "__main__":
    main()
