# core.py
import email
import json
import re
import urllib.request
from email import policy
from email.utils import parseaddr
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import dns.exception
import dns.resolver

try:
    import dkim  # pakiet dkimpy
    HAS_DKIMPY = True
except ImportError:
    HAS_DKIMPY = False


DNS_TIMEOUT = 4.0


def _dns_txt(qname: str) -> List[str]:
    """Pobiera wszystkie rekordy TXT dla podanej nazwy domenowej (łączy podzielone stringi)."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT
    try:
        answers = resolver.resolve(qname, "TXT")
        records: List[str] = []
        for rdata in answers:
            joined = "".join(
                part.decode("utf-8", errors="replace") if isinstance(part, bytes) else str(part)
                for part in rdata.strings
            )
            records.append(joined.strip())
        return records
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout, Exception):
        return []


def _dns_mx(domain: str) -> List[str]:
    """Pobiera hosty MX posortowane po priorytecie."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT
    try:
        answers = resolver.resolve(domain, "MX")
        sorted_mx = sorted(answers, key=lambda r: r.preference)
        return [str(r.exchange).rstrip(".") for r in sorted_mx]
    except Exception:
        return []


def _extract_domain(addr: str) -> str:
    _, email_addr = parseaddr(addr or "")
    if "@" in email_addr:
        return email_addr.split("@", 1)[1].strip().lower()
    return ""


def _parse_tag_value(record: str) -> Dict[str, str]:
    """Parsuje rekordy w formacie tag=wartość; (np. DMARC, BIMI, MTA-STS)."""
    result: Dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            result[k.strip().lower()] = v.strip()
    return result


# =====================================================================
# 1. ANALIZA SPF
# =====================================================================
def check_spf(envelope_domain: str, header_domain: str) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]], int]:
    domain = envelope_domain or header_domain
    if not domain:
        return (
            {
                "name": "SPF",
                "status": "fail",
                "message": {
                    "pl": "Nie udało się ustalić domeny nadawcy dla weryfikacji SPF.",
                    "en": "Could not determine sender domain for SPF verification.",
                },
            },
            None,
            0,
        )

    txt_records = _dns_txt(domain)
    spf_records = [r for r in txt_records if r.lower().startswith("v=spf1")]

    if not spf_records:
        rec = {
            "severity": "critical",
            "title": {
                "pl": f"Brak rekordu SPF dla domeny {domain}",
                "en": f"Missing SPF record for {domain}",
            },
            "description": {
                "pl": "Bez rekordu SPF serwery odbiorcze nie mogą zweryfikować, czy Twój serwer jest uprawniony do wysyłki poczty w imieniu domeny.",
                "en": "Without an SPF record, receiving servers cannot verify whether your mail server is authorized to send on behalf of your domain.",
            },
            "suggested_dns": f'{domain}. IN TXT "v=spf1 mx a -all"',
        }
        return (
            {
                "name": "SPF",
                "status": "fail",
                "message": {
                    "pl": f"Brak wpisu v=spf1 dla {domain}.",
                    "en": f"No v=spf1 TXT record found for {domain}.",
                },
            },
            rec,
            0,
        )

    if len(spf_records) > 1:
        rec = {
            "severity": "critical",
            "title": {
                "pl": "Wiele rekordów SPF (błąd PermError)",
                "en": "Multiple SPF records detected (PermError)",
            },
            "description": {
                "pl": "RFC 7208 zabrania publikowania więcej niż jednego rekordu v=spf1. Połącz wszystkie mechanizmy w pojedynczy wpis TXT.",
                "en": "RFC 7208 forbids publishing more than one v=spf1 record. Merge all mechanisms into a single TXT entry.",
            },
            "suggested_dns": f'{domain}. IN TXT "{spf_records[0]}"',
        }
        return (
            {
                "name": "SPF",
                "status": "fail",
                "message": {
                    "