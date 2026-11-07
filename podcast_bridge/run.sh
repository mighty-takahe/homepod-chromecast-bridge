#!/usr/bin/env bash
set -euo pipefail

OPTIONS_FILE="/data/options.json"

if [ -f "$OPTIONS_FILE" ] && command -v jq >/dev/null 2>&1; then
  export PODCAST_WEB_PORT="$(jq -r '.web_port // 8788' "$OPTIONS_FILE")"
  export PODCAST_BASE_CAST_PORT="$(jq -r '.base_cast_port // 8009' "$OPTIONS_FILE")"
  export PODCAST_BASE_EUREKA_PORT="$(jq -r '.base_eureka_port // 18008' "$OPTIONS_FILE")"
fi

export PODCAST_WEB_PORT="${PODCAST_WEB_PORT:-8788}"
export PYTHONPATH="/app/src:${PYTHONPATH:-}"

echo "[PodCast Bridge] Starting HomePod Mini -> Chromecast Audio Bridge on port ${PODCAST_WEB_PORT}..."
exec uvicorn podcast_bridge.app:app --host 0.0.0.0 --port "${PODCAST_WEB_PORT}"
