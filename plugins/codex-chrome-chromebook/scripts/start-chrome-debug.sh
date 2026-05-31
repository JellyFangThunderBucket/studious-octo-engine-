#!/usr/bin/env bash
set -euo pipefail

PORT="${CHROME_DEBUG_PORT:-9222}"
HOST="${CHROME_DEBUG_HOST:-127.0.0.1}"
PROFILE_DIR="${CHROME_DEBUG_PROFILE:-${TMPDIR:-/tmp}/codex-chrome-profile}"
START_URL="about:blank"
NO_SANDBOX=0
HEADLESS=0

usage() {
  cat <<USAGE
Usage: $0 [--host HOST] [--port PORT] [--profile-dir DIR] [--url URL] [--headless] [--no-sandbox]

Starts a dedicated Linux Chrome/Chromium instance for Codex automation on a
Chromebook Linux environment. The browser exposes a Chrome DevTools Protocol
endpoint at http://HOST:PORT/.
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
    --profile-dir)
      PROFILE_DIR="$2"
      shift 2
      ;;
    --url)
      START_URL="$2"
      shift 2
      ;;
    --headless)
      HEADLESS=1
      shift
      ;;
    --no-sandbox)
      NO_SANDBOX=1
      shift
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

find_chrome() {
  for candidate in google-chrome google-chrome-stable chromium chromium-browser chrome; do
    if command -v "$candidate" >/dev/null 2>&1; then
      command -v "$candidate"
      return 0
    fi
  done
  return 1
}

CHROME_BIN="$(find_chrome || true)"
if [[ -z "$CHROME_BIN" ]]; then
  echo "No Linux Chrome/Chromium executable found in PATH." >&2
  echo "Install Chrome/Chromium inside the Chromebook Linux environment, then retry." >&2
  exit 1
fi

mkdir -p "$PROFILE_DIR"

args=(
  "--remote-debugging-address=${HOST}"
  "--remote-debugging-port=${PORT}"
  "--user-data-dir=${PROFILE_DIR}"
  "--no-first-run"
  "--no-default-browser-check"
  "--disable-background-networking"
)

if [[ "$HEADLESS" -eq 1 ]]; then
  args+=("--headless=new")
fi

if [[ "$NO_SANDBOX" -eq 1 ]]; then
  args+=("--no-sandbox")
fi

echo "Starting: $CHROME_BIN ${args[*]} $START_URL"
echo "Profile: $PROFILE_DIR"
echo "DevTools: http://${HOST}:${PORT}/json/version"
exec "$CHROME_BIN" "${args[@]}" "$START_URL"
