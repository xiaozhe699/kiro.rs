#!/usr/bin/env bash
set -euo pipefail

TAG="${1:?Usage: deploy-ghcr-image.sh <image-tag> [image]}"
IMAGE="${2:-ghcr.io/xiaozhe699/kiro-rs:${TAG}}"
APP_DIR="${APP_DIR:-/opt/kiro-rs}"
BACKUP_DIR="${BACKUP_DIR:-/root/kiro-rs-backups}"
SERVICE="${SERVICE:-kiro-rs}"

cd "$APP_DIR"
mkdir -p "$BACKUP_DIR"

backup="${BACKUP_DIR}/kiro-rs-config-$(date +%Y%m%d-%H%M%S).tar.gz"
tar czf "$backup" -C "$APP_DIR" config docker-compose.yml
echo "backup=$backup"

docker pull "$IMAGE"

python3 - "$IMAGE" <<'PY'
import re
import sys
from pathlib import Path

image = sys.argv[1]
path = Path("docker-compose.yml")
content = path.read_text()
updated = re.sub(r"(^\s*image:\s*).*$", rf"\1{image}", content, count=1, flags=re.M)
if updated == content:
    raise SystemExit("No image line found in docker-compose.yml")
path.write_text(updated)
PY

docker compose up -d --no-deps "$SERVICE"
docker inspect "$SERVICE" --format 'image={{.Config.Image}} health={{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}} started={{.State.StartedAt}}'

python3 - <<'PY'
import json

path = "/opt/kiro-rs/config/credentials.json"
with open(path) as f:
    data = json.load(f)
creds = data if isinstance(data, list) else data.get("credentials", [data])
print(f"credentials_count={len(creds)}")
print(f"disabled_count={sum(1 for c in creds if c.get('disabled'))}")
PY
