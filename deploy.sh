#!/usr/bin/env bash
# Ship the OTP inbox to the server.
#
#   ./deploy.sh            test, upload, restart
#   ./deploy.sh --no-test  skip the tests
#
# The target comes from .deploy.env (gitignored; see .deploy.env.example). The
# server side (systemd units, nginx, Kanidm client) is declared in nixos-config
# (sms-inbox.nix), not here.
set -euo pipefail
cd "$(dirname "$0")"

[[ -f .deploy.env ]] || { echo "Missing .deploy.env. Copy .deploy.env.example and fill it in." >&2; exit 1; }
# shellcheck disable=SC1091
source .deploy.env
: "${DEPLOY_HOST:?set in .deploy.env}" "${DEPLOY_USER:?set in .deploy.env}"
: "${DEPLOY_APP_DIR:=/home/anish/sms_application}"
target="$DEPLOY_USER@$DEPLOY_HOST"

if [[ "${1:-}" != "--no-test" ]]; then
  echo "==> Tests"
  python3 -m unittest -q test_app
fi

echo "==> Uploading"
ssh "$target" "mkdir -p '$DEPLOY_APP_DIR'"
rsync -az app.py index.html "$target:$DEPLOY_APP_DIR/"

echo "==> Restarting"
# The demo is restarted only where the server already declares it.
ssh "$target" 'sudo systemctl restart sms-inbox && systemctl is-active sms-inbox
  if systemctl cat sms-inbox-demo >/dev/null 2>&1; then sudo systemctl restart sms-inbox-demo && systemctl is-active sms-inbox-demo; fi'
echo "Deployed."
