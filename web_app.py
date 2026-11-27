# web_app.py
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from i18n import get_translations, resolve_lang

AUDIT_DOMAIN = os.getenv("JASMINA_DOMAIN", "jasmina.kmucha.pl")
AUDIT_TTL_SECONDS = int(os.getenv("JASMINA_TTL", "1800"))  # 30 minut
AUDIT_DIR = Path(os.getenv("JASMINA_DATA_DIR", "/tmp/jasmina_audits"))
AUDIT_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="Jasmina Email Audit", docs_url=None, redoc_url=None)

if Path("static").exists():
    app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")


def _session_file(token: str) -> Path:
    safe_token = "".join(c for c in token if c.isalnum() or c in ("-", "_"))
    return AUDIT_DIR / f"{safe_token}.json"


def _cleanup_expired() -> None:
    now = time.time()
    for file in AUDIT_DIR.glob("*.json"):
        try:
            data = json.loads(file.read_text(encoding="utf-8"))
            if data.get("expires_at", 0) < now - 300:
                file.unlink(missing_ok=True)
        except Exception:
            continue


@app.get("/", response_class=HTMLResponse)
async def index(request: Request, response: Response, lang: str | None = None):
    cookie_lang = request.cookies.get("jasmina_lang")
    active_lang = resolve_lang(lang or cookie_lang)
    t = get_translations(active_lang)

    html_response = templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "lang": active_lang,
            "t": t,
            "translations_json": t,
            "domain": AUDIT_DOMAIN,
            "ttl_seconds": AUDIT_TTL_SECONDS,
        },
    )
    html_response.set_cookie(
        key="jasmina_lang",
        value=active_lang,
        max_age=60 * 60 * 24 * 90,
        httponly=False,
        samesite="lax",
    )
    return html_response


@app.post("/api/session")
async def create_session(request: Request) -> JSONResponse:
    _cleanup_expired()
    token = secrets.token_hex(6)  # np. 12 znaków hex
    now = int(time.time())
    expires_at = now + AUDIT_TTL_SECONDS
    address = f"audit-{token}@{AUDIT_DOMAIN}"

    session_data: Dict[str, Any] = {
        "token": token,
        "address": address,
        "status": "waiting",
        "created_at": now,
        "expires_at": expires_at,
        "report": None,
    }
    _session_file(token).write_text(
        json.dumps(session_data, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return JSONResponse(session_data)


@app.get("/api/status/{token}")
async def get_status(token: str, lang: str | None = None) -> JSONResponse:
    active_lang = resolve_lang(lang)
    t = get_translations(active_lang)
    file_path = _session_file(token)

    if not file_path.exists():
        raise HTTPException(status_code=404, detail=t["err_not_found"])

    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    now = int(time.time())
    remaining = max(0, int(data.get("expires_at", 0)) - now)
    data["remaining_seconds"] = remaining

    if data.get("status") == "waiting" and remaining == 0:
        data["status"] = "expired"

    return JSONResponse(data)


@app.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ok", "service": "jasmina-web"}