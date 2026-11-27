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
    import dkim
    HAS_DKIMPY = True
except ImportError:
    HAS_DKIMPY = False


DNS_TIMEOUT = 4.0


def _dns_txt(qname: str) -> List[str]:
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


def _extract_domain(addr: str) -> str:
    _, email_addr = parseaddr(addr or "")
    if "@" in email_addr:
        return email_addr.split("@", 1)[1].strip().lower()
    return ""


def _parse_tag_value(record: str) -> Dict[str, str]:
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
def check_spf(
    envelope_domain: str, header_domain: str
) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]], int]:
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
                "pl": "Bez rekordu SPF serwery odbiorcze nie mogą zweryfikować uprawnień nadawcy.",
                "en": "Without an SPF record, receiving servers cannot verify sender authorization.",
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
                "pl": "RFC 7208 zabrania publikowania więcej niż jednego rekordu v=spf1.",
                "en": "RFC 7208 forbids publishing more than one v=spf1 record.",
            },
            "suggested_dns": f'{domain}. IN TXT "{spf_records[0]}"',
        }
        return (
            {
                "name": "SPF",
                "status": "fail",
                "message": {
                    "pl": f"Wykryto {len(spf_records)} rekordy SPF — powoduje to błąd PermError.",
                    "en": f"Found {len(spf_records)} SPF records — this triggers an SPF PermError.",
                },
            },
            rec,
            5,
        )

    spf = spf_records[0]
    if "-all" in spf:
        return (
            {
                "name": "SPF",
                "status": "pass",
                "message": {
                    "pl": f"Poprawny rekord SPF z restrykcyjną polityką (-all): {spf}",
                    "en": f"Valid SPF record with strict policy (-all): {spf}",
                },
            },
            None,
            20,
        )

    if "~all" in spf:
        rec = {
            "severity": "warning",
            "title": {
                "pl": "Zaostrz politykę SPF z ~all (SoftFail) na -all (Fail)",
                "en": "Tighten SPF policy from ~all (SoftFail) to -all (Fail)",
            },
            "description": {
                "pl": "Kwalifikator ~all jedynie oznacza nieautoryzowane maile jako podejrzane. Zalecane jest -all.",
                "en": "The ~all qualifier only soft-fails unauthorized senders. Switching to -all is recommended.",
            },
            "suggested_dns": f'{domain}. IN TXT "{spf.replace("~all", "-all")}"',
        }
        return (
            {
                "name": "SPF",
                "status": "warn",
                "message": {
                    "pl": f"Aktywny rekord SPF z łagodnym trybem ~all: {spf}",
                    "en": f"Active SPF record using SoftFail (~all): {spf}",
                },
            },
            rec,
            15,
        )

    rec = {
        "severity": "critical",
        "title": {
            "pl": "Zbyt permisywny rekord SPF (+all lub ?all)",
            "en": "Overly permissive SPF record (+all or ?all)",
        },
        "description": {
            "pl": "Obecny rekord SPF nie blokuje podszywania się pod domenę. Zakończ wpis mechanizmem -all.",
            "en": "Your current SPF record does not block spoofing. End the record with -all.",
        },
        "suggested_dns": f'{domain}. IN TXT "v=spf1 mx a -all"',
    }
    return (
        {
            "name": "SPF",
            "status": "fail",
            "message": {
                "pl": f"Niebezpieczny kwalifikator w rekordzie SPF: {spf}",
                "en": f"Unsafe qualifier in SPF record: {spf}",
            },
        },
        rec,
        5,
    )


# =====================================================================
# 2. ANALIZA DKIM
# =====================================================================
def check_dkim(
    raw_bytes: bytes, msg: email.message.EmailMessage, header_domain: str
) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]], int]:
    dkim_headers = msg.get_all("DKIM-Signature", [])
    domain = header_domain or "domena.pl"

    if not dkim_headers:
        rec = {
            "severity": "critical",
            "title": {
                "pl": "Brak podpisu kryptograficznego DKIM",
                "en": "Missing DKIM cryptographic signature",
            },
            "description": {
                "pl": "Wiadomość nie została podpisana kluczem DKIM. Skonfiguruj podpisywanie na serwerze pocztowym.",
                "en": "The email was not signed with a DKIM key. Enable DKIM signing on your mail server.",
            },
            "suggested_dns": f'default._domainkey.{domain}. IN TXT "v=DKIM1; k=rsa; p=TWÓJ_KLUCZ_PUBLICZNY"',
        }
        return (
            {
                "name": "DKIM",
                "status": "fail",
                "message": {
                    "pl": "Brak nagłówka DKIM-Signature w odebranej wiadomości.",
                    "en": "No DKIM-Signature header present in the received email.",
                },
            },
            rec,
            0,
        )

    sig_tags = _parse_tag_value(dkim_headers[0])
    selector = sig_tags.get("s", "default")
    dkim_domain = sig_tags.get("d", domain)
    dns_key_records = _dns_txt(f"{selector}._domainkey.{dkim_domain}")

    if HAS_DKIMPY:
        try:
            is_valid = dkim.verify(raw_bytes)
        except Exception:
            is_valid = False

        if is_valid:
            return (
                {
                    "name": "DKIM",
                    "status": "pass",
                    "message": {
                        "pl": f"Podpis DKIM zweryfikowany kryptograficznie (s={selector}, d={dkim_domain}).",
                        "en": f"DKIM signature cryptographically verified (s={selector}, d={dkim_domain}).",
                    },
                },
                None,
                25,
            )
        rec = {
            "severity": "critical",
            "title": {
                "pl": f"Niepoprawny podpis DKIM ({selector}._domainkey.{dkim_domain})",
                "en": f"Invalid DKIM signature ({selector}._domainkey.{dkim_domain})",
            },
            "description": {
                "pl": "Weryfikacja kryptograficzna DKIM nie powiodła się. Sprawdź klucz publiczny w DNS.",
                "en": "DKIM cryptographic verification failed. Check your DNS public key record.",
            },
            "suggested_dns": f'{selector}._domainkey.{dkim_domain}. IN TXT "v=DKIM1; k=rsa; p=TWÓJ_KLUCZ_PUBLICZNY"',
        }
        return (
            {
                "name": "DKIM",
                "status": "fail",
                "message": {
                    "pl": f"Weryfikacja kryptograficzna DKIM nie powiodła się (s={selector}, d={dkim_domain}).",
                    "en": f"DKIM cryptographic verification failed (s={selector}, d={dkim_domain}).",
                },
            },
            rec,
            5,
        )

    if dns_key_records and "p=" in dns_key_records[0]:
        return (
            {
                "name": "DKIM",
                "status": "pass",
                "message": {
                    "pl": f"Znaleziono nagłówek DKIM i klucz publiczny w DNS ({selector}._domainkey.{dkim_domain}).",
                    "en": f"DKIM header and DNS public key present ({selector}._domainkey.{dkim_domain}).",
                },
            },
            None,
            25,
        )

    rec = {
        "severity": "critical",
        "title": {
            "pl": f"Brak klucza publicznego DKIM w DNS ({selector}._domainkey.{dkim_domain})",
            "en": f"Missing DKIM public key in DNS ({selector}._domainkey.{dkim_domain})",
        },
        "description": {
            "pl": "Wiadomość ma nagłówek DKIM-Signature, ale rekord TXT w DNS nie istnieje.",
            "en": "The email includes a DKIM-Signature header, but no matching TXT record exists in DNS.",
        },
        "suggested_dns": f'{selector}._domainkey.{dkim_domain}. IN TXT "v=DKIM1; k=rsa; p=TWÓJ_KLUCZ_PUBLICZNY"',
    }
    return (
        {
            "name": "DKIM",
            "status": "fail",
            "message": {
                "pl": f"Brak rekordu TXT dla {selector}._domainkey.{dkim_domain}.",
                "en": f"No TXT record found for {selector}._domainkey.{dkim_domain}.",
            },
        },
        rec,
        5,
    )


# =====================================================================
# 3. ANALIZA DMARC
# =====================================================================
def check_dmarc(header_domain: str) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]], int, str]:
    domain = header_domain
    if not domain:
        return (
            {
                "name": "DMARC",
                "status": "fail",
                "message": {
                    "pl": "Brak domeny w nagłówku From do sprawdzenia DMARC.",
                    "en": "Missing From domain for DMARC lookup.",
                },
            },
            None,
            0,
            "none",
        )

    records = [r for r in _dns_txt(f"_dmarc.{domain}") if r.lower().startswith("v=dmarc1")]
    if not records:
        rec = {
            "severity": "critical",
            "title": {
                "pl": f"Brak rekordu DMARC (_dmarc.{domain})",
                "en": f"Missing DMARC record (_dmarc.{domain})",
            },
            "description": {
                "pl": "DMARC chroni domenę przed spoofingiem. Opublikuj politykę p=quarantine lub p=reject.",
                "en": "DMARC protects your domain from spoofing. Publish p=quarantine or p=reject.",
            },
            "suggested_dns": f'_dmarc.{domain}. IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}; adkim=s; aspf=s; pct=100"',
        }
        return (
            {
                "name": "DMARC",
                "status": "fail",
                "message": {
                    "pl": f"Brak rekordu TXT _dmarc.{domain}.",
                    "en": f"No TXT record found at _dmarc.{domain}.",
                },
            },
            rec,
            0,
            "none",
        )

    dmarc = records[0]
    tags = _parse_tag_value(dmarc)
    policy_p = tags.get("p", "none").lower()
    rua = tags.get("rua", "")

    if policy_p == "reject":
        rec = None
        if not rua:
            rec = {
                "severity": "warning",
                "title": {
                    "pl": "Dodaj raportowanie zbiorcze (rua=) do rekordu DMARC",
                    "en": "Add aggregate reporting (rua=) to your DMARC record",
                },
                "description": {
                    "pl": "Polityka p=reject jest aktywna, ale brakuje adresu rua= do odbierania raportów.",
                    "en": "Policy p=reject is active, but rua= is missing for aggregate reports.",
                },
                "suggested_dns": f'_dmarc.{domain}. IN TXT "{dmarc}; rua=mailto:dmarc@{domain}"',
            }
        return (
            {
                "name": "DMARC",
                "status": "pass",
                "message": {
                    "pl": f"Najwyższy poziom ochrony DMARC (p=reject): {dmarc}",
                    "en": f"Strongest DMARC enforcement active (p=reject): {dmarc}",
                },
            },
            rec,
            25,
            "reject",
        )

    if policy_p == "quarantine":
        rec = {
            "severity": "warning",
            "title": {
                "pl": "Docelowo podnieś politykę DMARC z p=quarantine na p=reject",
                "en": "Upgrade DMARC policy from p=quarantine to p=reject",
            },
            "description": {
                "pl": "Polityka quarantine kieruje podejrzane maile do spamu. Docelowo zalecane jest p=reject.",
                "en": "Quarantine sends suspicious emails to spam. Upgrading to p=reject is recommended.",
            },
            "suggested_dns": f'_dmarc.{domain}. IN TXT "{dmarc.replace("p=quarantine", "p=reject")}"',
        }
        return (
            {
                "name": "DMARC",
                "status": "pass",
                "message": {
                    "pl": f"Aktywna ochrona DMARC w trybie kwarantanny (p=quarantine): {dmarc}",
                    "en": f"DMARC enforcement active in quarantine mode (p=quarantine): {dmarc}",
                },
            },
            rec,
            20,
            "quarantine",
        )

    rec = {
        "severity": "warning",
        "title": {
            "pl": "DMARC działa wyłącznie w trybie monitorowania (p=none)",
            "en": "DMARC is in monitoring-only mode (p=none)",
        },
        "description": {
            "pl": "Polityka p=none nie blokuje fałszywych wiadomości. Zmień politykę na p=quarantine lub p=reject.",
            "en": "Policy p=none does not block spoofed emails. Upgrade to p=quarantine or p=reject.",
        },
        "suggested_dns": f'_dmarc.{domain}. IN TXT "{dmarc.replace("p=none", "p=quarantine")}"',
    }
    return (
        {
            "name": "DMARC",
            "status": "warn",
            "message": {
                "pl": f"Rekord DMARC istnieje, ale ma nieegzekwującą politykę p=none: {dmarc}",
                "en": f"DMARC record exists but uses non-enforcing policy p=none: {dmarc}",
            },
        },
        rec,
        10,
        "none",
    )


# =====================================================================
# 4. ANALIZA TLS
# =====================================================================
def check_tls(
    tls_info: str, msg: email.message.EmailMessage
) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]], int]:
    received_headers = " ".join(msg.get_all("Received", []))
    combined = f"{tls_info} {received_headers}".strip()

    tls_match = re.search(r"(TLSv1\.[23]|TLSv1\.[01]|SSLv3)", combined, re.IGNORECASE)
    cipher_match = re.search(r"cipher=([^\s\)]+)", combined, re.IGNORECASE)

    if tls_match:
        proto = tls_match.group(1)
        cipher = cipher_match.group(1) if cipher_match else ""
        label = f"{proto} ({cipher})" if cipher else proto

        if proto.lower() in ("tlsv1.2", "tlsv1.3"):
            return (
                {
                    "name": "STARTTLS / TLS",
                    "status": "pass",
                    "message": {
                        "pl": f"Połączenie zaszyfrowane nowoczesnym protokołem {label}.",
                        "en": f"Connection encrypted using modern {label}.",
                    },
                },
                None,
                15,
            )
        rec = {
            "severity": "critical",
            "title": {
                "pl": f"Przestarzała wersja protokołu TLS ({proto})",
                "en": f"Deprecated TLS protocol version ({proto})",
            },
            "description": {
                "pl": "Serwer nadawczy użył przestarzałego protokołu szyfrowania. Wymuś minimum TLS 1.2.",
                "en": "The sending server negotiated an obsolete TLS version. Enforce TLS 1.2 minimum.",
            },
            "suggested_dns": None,
        }
        return (
            {
                "name": "STARTTLS / TLS",
                "status": "warn",
                "message": {
                    "pl": f"Wykryto przestarzały protokół szyfrowania: {label}.",
                    "en": f"Outdated encryption protocol negotiated: {label}.",
                },
            },
            rec,
            7,
        )

    rec = {
        "severity": "critical",
        "title": {
            "pl": "Wiadomość przesłana bez szyfrowania STARTTLS",
            "en": "Email transmitted without STARTTLS encryption",
        },
        "description": {
            "pl": "Połączenie SMTP odbyło się otwartym tekstem. Włącz obsługę STARTTLS na serwerze.",
            "en": "The SMTP session occurred in plain text. Enable STARTTLS on your mail server.",
        },
        "suggested_dns": None,
    }
    return (
        {
            "name": "STARTTLS / TLS",
            "status": "fail",
            "message": {
                "pl": "Brak szyfrowania TLS podczas transmisji wiadomości.",
                "en": "No TLS encryption detected during message transmission.",
            },
        },
        rec,
        0,
    )


# =====================================================================
# 5. ANALIZA MTA-STS & TLS-RPT
# =====================================================================
def check_mta_sts(header_domain: str) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]], int]:
    domain = header_domain
    if not domain:
        return (
            {
                "name": "MTA-STS",
                "status": "warn",
                "message": {
                    "pl": "Brak domeny do sprawdzenia MTA-STS.",
                    "en": "Missing domain for MTA-STS check.",
                },
            },
            None,
            0,
        )

    sts_records = [r for r in _dns_txt(f"_mta-sts.{domain}") if r.lower().startswith("v=stsv1")]
    rpt_records = [r for r in _dns_txt(f"_smtp._tls.{domain}") if r.lower().startswith("v=tlsrptv1")]

    if sts_records:
        policy_txt = ""
        try:
            url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
            with urllib.request.urlopen(url, timeout=3) as resp:
                policy_txt = resp.read(2048).decode("utf-8", errors="replace")
        except Exception:
            policy_txt = ""

        if "version: STSv1" in policy_txt:
            mode_match = re.search(r"mode:\s*(enforce|testing|none)", policy_txt, re.IGNORECASE)
            mode = mode_match.group(1).lower() if mode_match else "unknown"
            return (
                {
                    "name": "MTA-STS",
                    "status": "pass",
                    "message": {
                        "pl": f"Rekord DNS _mta-sts oraz plik polityki HTTPS aktywne (tryb: {mode}).",
                        "en": f"DNS _mta-sts record and HTTPS policy file active (mode: {mode}).",
                    },
                },
                None,
                10,
            )

        rec = {
            "severity": "warning",
            "title": {
                "pl": f"Rekord _mta-sts.{domain} istnieje, ale brak pliku polityki HTTPS",
                "en": f"_mta-sts.{domain} DNS record exists, but HTTPS policy file is unreachable",
            },
            "description": {
                "pl": f"Udostępnij plik pod adresem https://mta-sts.{domain}/.well-known/mta-sts.txt.",
                "en": f"Host the policy file at https://mta-sts.{domain}/.well-known/mta-sts.txt.",
            },
            "suggested_dns": f'_smtp._tls.{domain}. IN TXT "v=TLSRPTv1; rua=mailto:tls-rpt@{domain}"' if not rpt_records else None,
        }
        return (
            {
                "name": "MTA-STS",
                "status": "warn",
                "message": {
                    "pl": f"Znaleziono rekord _mta-sts, ale nie udało się pobrać pliku z mta-sts.{domain}.",
                    "en": f"Found _mta-sts DNS record, but failed to fetch policy from mta-sts.{domain}.",
                },
            },
            rec,
            5,
        )

    rec = {
        "severity": "warning",
        "title": {
            "pl": f"Brak konfiguracji MTA-STS dla domeny {domain}",
            "en": f"Missing MTA-STS configuration for {domain}",
        },
        "description": {
            "pl": "MTA-STS chroni ruch przychodzący przed atakami downgrade TLS.",
            "en": "MTA-STS prevents TLS downgrade attacks on incoming mail.",
        },
        "suggested_dns": f'_mta-sts.{domain}. IN TXT "v=STSv1; id=2026112701"',
    }
    return (
        {
            "name": "MTA-STS",
            "status": "warn",
            "message": {
                "pl": f"Brak rekordu _mta-sts.{domain}.",
                "en": f"No _mta-sts.{domain} record found.",
            },
        },
        rec,
        0,
    )


# =====================================================================
# 6. ANALIZA BIMI
# =====================================================================
def check_bimi(header_domain: str, dmarc_policy: str) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]], int]:
    domain = header_domain
    if not domain:
        return (
            {
                "name": "BIMI",
                "status": "warn",
                "message": {
                    "pl": "Brak domeny do sprawdzenia rekordu BIMI.",
                    "en": "Missing domain for BIMI lookup.",
                },
            },
            None,
            0,
        )

    bimi_qname = f"default._bimi.{domain}"
    bimi_records = [r for r in _dns_txt(bimi_qname) if r.lower().startswith("v=bimi1")]

    if not bimi_records:
        prereq_pl = (
            "Wymaga DMARC p=quarantine lub p=reject."
            if dmarc_policy == "none"
            else "Polityka DMARC spełnia wymogi BIMI."
        )
        prereq_en = (
            "Requires DMARC p=quarantine or p=reject."
            if dmarc_policy == "none"
            else "DMARC policy meets BIMI prerequisites."
        )
        rec = {
            "severity": "warning",
            "title": {
                "pl": f"Brak rekordu BIMI ({bimi_qname})",
                "en": f"Missing BIMI DNS record ({bimi_qname})",
            },
            "description": {
                "pl": f"BIMI wyświetla oficjalne logo marki (SVG Tiny PS) obok wiadomości. {prereq_pl}",
                "en": f"BIMI displays your brand logo (SVG Tiny PS) next to emails. {prereq_en}",
            },
            "suggested_dns": f'{bimi_qname}. IN TXT "v=BIMI1; l=https://{domain}/logo-bimi.svg; a=;"',
        }
        return (
            {
                "name": "BIMI",
                "status": "warn",
                "message": {
                    "pl": f"Brak rekordu TXT {bimi_qname}.",
                    "en": f"No TXT record found at {bimi_qname}.",
                },
            },
            rec,
            0,
        )

    bimi_raw = bimi_records[0]
    tags = _parse_tag_value(bimi_raw)
    logo_url = tags.get("l", "")
    cert_url = tags.get("a", "")

    if not logo_url.lower().startswith("https://"):
        rec = {
            "severity": "warning",
            "title": {
                "pl": "Brakujący lub niepoprawny parametr l= (logo SVG) w BIMI",
                "en": "Missing or invalid l= (SVG logo URL) tag in BIMI",
            },
            "description": {
                "pl": "Parametr l= musi wskazywać przez HTTPS na plik w profilu SVG Tiny PS.",
                "en": "The l= tag must point via HTTPS to an SVG Tiny PS logo file.",
            },
            "suggested_dns": f'{bimi_qname}. IN TXT "v=BIMI1; l=https://{domain}/logo-bimi.svg; a=;"',
        }
        return (
            {
                "name": "BIMI",
                "status": "warn",
                "message": {
                    "pl": f"Rekord BIMI istnieje, ale brakuje poprawnego HTTPS logo (l=): {bimi_raw}",
                    "en": f"BIMI record found, but missing valid HTTPS logo URL (l=): {bimi_raw}",
                },
            },
            rec,
            2,
        )

    if dmarc_policy == "none":
        rec = {
            "severity": "warning",
            "title": {
                "pl": "Rekord BIMI nie zadziała przy DMARC p=none",
                "en": "BIMI will be ignored while DMARC policy is p=none",
            },
            "description": {
                "pl": "Odbiorcy ignorują BIMI, dopóki DMARC nie zostanie ustawiony na p=quarantine lub p=reject.",
                "en": "Providers ignore BIMI unless DMARC is set to p=quarantine or p=reject.",
            },
            "suggested_dns": f'_dmarc.{domain}. IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}"',
        }
        return (
            {
                "name": "BIMI",
                "status": "warn",
                "message": {
                    "pl": f"Rekord BIMI poprawny ({logo_url}), ale zablokowany przez DMARC p=none.",
                    "en": f"BIMI record valid ({logo_url}), but blocked by DMARC p=none.",
                },
            },
            rec,
            3,
        )

    vmc_pl = f" (VMC: {cert_url})" if cert_url.lower().startswith("https://") else " (bez VMC — self-asserted)"
    vmc_en = f" (VMC: {cert_url})" if cert_url.lower().startswith("https://") else " (no VMC — self-asserted)"

    return (
        {
            "name": "BIMI",
            "status": "pass",
            "message": {
                "pl": f"Poprawny rekord BIMI z logo {logo_url}{vmc_pl}.",
                "en": f"Valid BIMI record with logo {logo_url}{vmc_en}.",
            },
        },
        None,
        5,
    )


# =====================================================================
# GŁÓWNA FUNKCJA AUDYTU WIADOMOŚCI
# =====================================================================
def analyze_email(
    raw_bytes: bytes,
    mail_from: str = "",
    client_ip: str = "",
    tls_info: str = "",
) -> Dict[str, Any]:
    msg = email.message_from_bytes(raw_bytes, policy=policy.default)

    header_from = str(msg.get("From", ""))
    header_domain = _extract_domain(header_from)
    envelope_domain = _extract_domain(mail_from) or header_domain

    raw_headers_str = "\n".join(f"{k}: {v}" for k, v in msg.items())

    checks: List[Dict[str, Any]] = []
    recommendations: List[Dict[str, Any]] = []
    total_score = 0

    spf_check, spf_rec, spf_pts = check_spf(envelope_domain, header_domain)
    checks.append(spf_check)
    if spf_rec:
        recommendations.append(spf_rec)
    total_score += spf_pts

    dkim_check, dkim_rec, dkim_pts = check_dkim(raw_bytes, msg, header_domain)
    checks.append(dkim_check)
    if dkim_rec:
        recommendations.append(dkim_rec)
    total_score += dkim_pts

    dmarc_check, dmarc_rec, dmarc_pts, dmarc_policy = check_dmarc(header_domain)
    checks.append(dmarc_check)
    if dmarc_rec:
        recommendations.append(dmarc_rec)
    total_score += dmarc_pts

    tls_check, tls_rec, tls_pts = check_tls(tls_info, msg)
    checks.append(tls_check)
    if tls_rec:
        recommendations.append(tls_rec)
    total_score += tls_pts

    sts_check, sts_rec, sts_pts = check_mta_sts(header_domain)
    checks.append(sts_check)
    if sts_rec:
        recommendations.append(sts_rec)
    total_score += sts_pts

    bimi_check, bimi_rec, bimi_pts = check_bimi(header_domain, dmarc_policy)
    checks.append(bimi_check)
    if bimi_rec:
        recommendations.append(bimi_rec)
    total_score += bimi_pts

    recommendations.sort(key=lambda r: 0 if r.get("severity") == "critical" else 1)

    return {
        "score": f"{min(100, total_score)} / 100",
        "meta": {
            "from": header_from or "—",
            "mail_from": mail_from or header_from or "—",
            "client_ip": client_ip or "—",
            "tls": tls_info or "—",
        },
        "checks": checks,
        "recommendations": recommendations,
        "raw_headers": raw_headers_str,
    }


def save_audit_result(
    token: str,
    report: Dict[str, Any],
    data_dir: str = "/tmp/jasmina_audits",
) -> bool:
    safe_token = "".join(c for c in token if c.isalnum() or c in ("-", "_"))
    session_path = Path(data_dir) / f"{safe_token}.json"
    if not session_path.exists():
        return False

    try:
        session_data = json.loads(session_path.read_text(encoding="utf-8"))
        session_data["status"] = "completed"
        session_data["report"] = report
        session_path.write_text(
            json.dumps(session_data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return True
    except Exception:
        return False