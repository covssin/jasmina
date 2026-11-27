# i18n.py
from typing import Dict, Any

SUPPORTED_LANGS = ("pl", "en")
DEFAULT_LANG = "pl"

TRANSLATIONS: Dict[str, Dict[str, Any]] = {
    "pl": {
        "meta_title": "Jasmina — Audyt Bezpieczeństwa Poczty | kmucha.pl",
        "brand_sub": "Audyt bezpieczeństwa poczty e-mail",
        "hero_title": "Zweryfikuj konfigurację swojej domeny",
        "hero_desc": (
            "Wygeneruj tymczasowy adres audytowy i wyślij na niego dowolną wiadomość "
            "ze swojej skrzynki. Przeanalizujemy SPF, DKIM, DMARC, TLS, MTA-STS oraz BIMI."
        ),
        "btn_generate": "Wygeneruj adres audytowy",
        "btn_new": "Nowy audyt",
        "btn_copy": "Kopiuj",
        "btn_copied": "Skopiowano!",
        "address_label": "Twój jednorazowy adres audytowy:",
        "expires_label": "Pozostały czas ważności:",
        "status_waiting": "Oczekiwanie na wiadomość e-mail...",
        "status_waiting_hint": "Wyślij wiadomość na powyższy adres. Wynik pojawi się automatycznie w ciągu kilku sekund od doręczenia.",
        "status_expired": "Czas sesji audytowej upłynął. Wygeneruj nowy adres.",
        "status_done": "Audyt zakończony",
        "summary_title": "Podsumowanie audytu i rekomendacje",
        "score_label": "Wynik:",
        "missing_records_title": "Wykryte braki i zalecane wpisy DNS",
        "no_missing_records": "Wszystkie kluczowe mechanizmy uwierzytelniania poczty są poprawnie skonfigurowane.",
        "recommended_record": "Sugerowany rekord DNS:",
        "details_title": "Szczegóły techniczne i analiza protokołów",
        "raw_headers_title": "Surowe nagłówki wiadomości (Authentication-Results / Received)",
        "raw_json_title": "Pełny raport JSON",
        "check_pass": "Poprawny",
        "check_warn": "Ostrzeżenie",
        "check_fail": "Błąd / Brak",
        "check_info": "Informacja",
        "sender_label": "Nadawca (From):",
        "envelope_label": "Koperta (MAIL FROM):",
        "ip_label": "Serwer nadawczy (IP):",
        "tls_label": "Szyfrowanie połączenia:",
        "footer_powered": "Narzędzie z ekosystemu",
        "footer_scanner": "Skaner bezpieczeństwa stron",
        "err_not_found": "Nie znaleziono sesji audytowej lub wygasła.",
    },
    "en": {
        "meta_title": "Jasmina — Email Security Audit | kmucha.pl",
        "brand_sub": "Email Security & Deliverability Audit",
        "hero_title": "Verify your domain email security",
        "hero_desc": (
            "Generate a temporary audit address and send any test message from your mailbox. "
            "We analyze SPF, DKIM, DMARC, TLS, MTA-STS, and BIMI records."
        ),
        "btn_generate": "Generate audit address",
        "btn_new": "New audit",
        "btn_copy": "Copy",
        "btn_copied": "Copied!",
        "address_label": "Your disposable audit address:",
        "expires_label": "Time remaining:",
        "status_waiting": "Waiting for incoming email...",
        "status_waiting_hint": "Send an email to the address above. Results will appear automatically within seconds of delivery.",
        "status_expired": "Audit session expired. Please generate a new address.",
        "status_done": "Audit completed",
        "summary_title": "Audit Summary & Recommendations",
        "score_label": "Score:",
        "missing_records_title": "Detected Gaps & Recommended DNS Records",
        "no_missing_records": "All core email authentication mechanisms are properly configured.",
        "recommended_record": "Suggested DNS record:",
        "details_title": "Technical Details & Protocol Breakdown",
        "raw_headers_title": "Raw Message Headers (Authentication-Results / Received)",
        "raw_json_title": "Full JSON Report",
        "check_pass": "Pass",
        "check_warn": "Warning",
        "check_fail": "Fail / Missing",
        "check_info": "Info",
        "sender_label": "Sender (From):",
        "envelope_label": "Envelope (MAIL FROM):",
        "ip_label": "Sending Server (IP):",
        "tls_label": "Transport Encryption:",
        "footer_powered": "Part of the",
        "footer_scanner": "Web Security Scanner",
        "err_not_found": "Audit session not found or expired.",
    },
}


def resolve_lang(lang: str | None) -> str:
    if lang and lang.lower() in SUPPORTED_LANGS:
        return lang.lower()
    return DEFAULT_LANG


def get_translations(lang: str | None) -> Dict[str, Any]:
    return TRANSLATIONS[resolve_lang(lang)]