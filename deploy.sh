#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/jasmina"
VENV_DIR="${APP_DIR}/venv"
BRANCH="main"

echo "==> [1/5] Przechodzenie do katalogu ${APP_DIR} i pobieranie zmian z Git (${BRANCH})..."
cd "${APP_DIR}"
git fetch origin "${BRANCH}"
git reset --hard "origin/${BRANCH}"

echo "==> [2/5] Weryfikacja struktury katalogów..."
mkdir -p "${APP_DIR}/static/css" \
         "${APP_DIR}/static/js" \
         "${APP_DIR}/templates" \
         "${APP_DIR}/certs" \
         "/tmp/jasmina_audits"

echo "==> [3/5] Aktualizacja zależności w środowisku wirtualnym..."
if [ ! -d "${VENV_DIR}" ]; then
  python3 -m venv "${VENV_DIR}"
fi
"${VENV_DIR}/bin/pip" install --upgrade pip --quiet
"${VENV_DIR}/bin/pip" install -r "${APP_DIR}/requirements.txt" --quiet

echo "==> [4/5] Walidacja składni modułów Pythona..."
"${VENV_DIR}/bin/python" -m py_compile \
  "${APP_DIR}/i18n.py" \
  "${APP_DIR}/core.py" \
  "${APP_DIR}/web_app.py" \
  "${APP_DIR}/smtp_daemon.py"

echo "==> [5/5] Restart usług systemd (jasmina-web, jasmina-smtp)..."
systemctl daemon-reload
systemctl restart jasmina-web jasmina-smtp

sleep 1
systemctl is-active --quiet jasmina-web && echo "    [OK] jasmina-web działa poprawnie."
systemctl is-active --quiet jasmina-smtp && echo "    [OK] jasmina-smtp działa poprawnie."

echo "==> Wdrożenie zakończone sukcesem."