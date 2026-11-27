import json
import time
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from core import init_db, create_session, get_db

app = FastAPI(title="Audyt Bezpieczeństwa Poczty — kmucha.pl")

@app.on_event("startup")
def startup():
    init_db()

@app.get("/", response_class=HTMLResponse)
def index():
    with open("/opt/jasmina/templates/index.html", "r", encoding="utf-8") as f:
        return f.read()

@app.post("/api/session")
def new_session():
    return create_session()

@app.get("/api/session/{token}")
def check_session(token: str):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM sessions WHERE token = ?", (token,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Sesja nie istnieje lub wygasła")
    now = int(time.time())
    remaining = max(0, row["expires_at"] - now)
    if row["status"] == "waiting" and remaining == 0:
        return {"status": "expired", "remaining": 0}
    return {
        "status": row["status"],
        "address": row["address"],
        "remaining": remaining,
        "report": json.loads(row["report_json"]) if row["report_json"] else None
    }
# Fragment web_app.py
from fastapi import Request
from i18n import get_t, TRANSLATIONS

@app.get("/")
async def index(request: Request, lang: str = "pl"):
    lang = lang if lang in TRANSLATIONS else "pl"
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "lang": lang,
            "t": get_t(lang),
            "translations_json": TRANSLATIONS[lang],  # dla skryptów JS po stronie klienta
        }
    )