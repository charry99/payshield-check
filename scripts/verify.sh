#!/usr/bin/env bash
# Run the Kane CLI flows for PayShield Check.
# Requires: kane-cli installed AND logged in (`kane-cli login --oauth`),
# and TestMu AI credits on the account (10,000 free credits from registration).
# Exit code: 0 = all flows passed, 1 = at least one flow failed.
set -euo pipefail
cd "$(dirname "$0")/.."

APP_URL="${APP_URL:-https://charry99.github.io/payshield-check/}"

kane-cli config set-url "$APP_URL"
kane-cli testrun run --headless tests/
