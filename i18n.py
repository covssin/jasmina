# i18n.py
TRANSLATIONS = {
    "pl": {
        "title": "Jasmina — Audyt Bezpieczeństwa Poczty",
        "subtitle": "Wyślij wiadomość na tymczasowy adres, aby zweryfikować SPF, DKIM, DMARC, TLS oraz BIMI.",
        "generate_btn": "Generuj adres audytowy",
        "waiting": "Oczekiwanie na wiadomość e-mail (ważność: 30 min)...",
        "summary_header": "Podsumowanie audytu i rekomendacje",
        "toggle_details": "Pokaż / ukryj szczegóły techniczne",
        "status_pass": "Poprawny",
        "status_warn": "Ostrzeżenie",
        "status_fail": "Błąd / Brak",
    },
    "en": {
        "title": "Jasmina — Email Security Audit",
        "subtitle": "Send an email to the temporary address to verify SPF, DKIM, DMARC, TLS, and BIMI.",
        "generate_btn": "Generate audit address",
        "waiting": "Waiting for incoming email (valid for 30 min)...",
        "summary_header": "Audit Summary & Recommendations",
        "toggle_details": "Show / hide technical details",
        "status_pass": "Pass",
        "status_warn": "Warning",
        "status_fail": "Fail / Missing",
    }
}

def get_t(lang: str) -> dict:
    return TRANSLATIONS.get(lang, TRANSLATIONS["pl"])