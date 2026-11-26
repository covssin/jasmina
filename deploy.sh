#!/bin/bash
set -e
cd /opt/jasmina
git pull origin main
systemctl restart jasmina-web jasmina-smtp
echo "Wdrożono najnowszą wersję i zrestartowano usługi."
