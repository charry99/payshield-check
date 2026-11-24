#!/usr/bin/env bash
# Run the Kane CLI flows for PayShield Check.
# Requires: kane-cli installed AND logged in (`kane-cli login`),
# and TestMu AI credits on the account (10,000 free credits from registration).
# Exit code: 0 = all flows passed, 1 = at least one flow failed.
set -euo pipefail
cd "$(dirname "$0")/.."

# Chrome for headless runs: prefer an explicit KANE_CLI_CHROME_PATH, else the
# Playwright Chromium bundled on this machine (no system Chrome installed).
# The /opt/meta-chromium build exits at startup under kane-cli, so it is not
# used as a fallback.
if [ -z "${KANE_CLI_CHROME_PATH:-}" ] && [ -x "$HOME/.cache/ms-playwright/chromium-1248/chrome-linux64/chrome" ]; then
  export KANE_CLI_CHROME_PATH="$HOME/.cache/ms-playwright/chromium-1248/chrome-linux64/chrome"
fi

APP_URL="${APP_URL:-https://charry99.github.io/payshield-check/}"

kane-cli config set-url "$APP_URL"
kane-cli testrun run --headless tests/*_test.md
