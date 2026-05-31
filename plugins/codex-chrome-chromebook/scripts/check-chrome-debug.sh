#!/usr/bin/env bash
set -euo pipefail

PORT="${CHROME_DEBUG_PORT:-9222}"
HOST="${CHROME_DEBUG_HOST:-127.0.0.1}"

usage() {
  cat <<USAGE
Usage: $0 [--host HOST] [--port PORT]

Checks Chromebook/Crostini Chrome automation readiness and probes a Chrome
DevTools Protocol endpoint.

Environment defaults:
  CHROME_DEBUG_HOST=${CHROME_DEBUG_HOST:-127.0.0.1}
  CHROME_DEBUG_PORT=${CHROME_DEBUG_PORT:-9222}
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host)
      HOST="$2"
      shift 2
      ;;
    --port)
      PORT="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

echo "== System =="
if [[ -r /etc/os-release ]]; then
  . /etc/os-release
  echo "OS: ${PRETTY_NAME:-unknown}"
else
  echo "OS: unknown"
fi
printf 'Kernel: '
uname -srmo

echo
echo "== Chrome executables =="
FOUND=0
for candidate in google-chrome google-chrome-stable chromium chromium-browser chrome; do
  if command -v "$candidate" >/dev/null 2>&1; then
    FOUND=1
    path="$(command -v "$candidate")"
    version="$("$path" --version 2>/dev/null || true)"
    echo "FOUND $candidate -> $path ${version:+($version)}"
  fi
done
if [[ "$FOUND" -eq 0 ]]; then
  echo "No Linux Chrome/Chromium executable found in PATH."
fi

echo
echo "== DevTools endpoint =="
URL="http://${HOST}:${PORT}/json/version"
if command -v curl >/dev/null 2>&1 && curl -fsS --max-time 2 "$URL" >/tmp/chrome-debug-version.json 2>/dev/null; then
  echo "Reachable: $URL"
  cat /tmp/chrome-debug-version.json
  echo
else
  echo "Not reachable: $URL"
  echo "Start one with scripts/start-chrome-debug.sh or provide CHROME_DEBUG_HOST/CHROME_DEBUG_PORT."
fi
