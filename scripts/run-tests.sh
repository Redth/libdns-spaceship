#!/usr/bin/env bash
set -euo pipefail

# Load .env if present (export variables defined there)
if [ -f .env ]; then
  # shellcheck disable=SC1091
  set -o allexport
  # shellcheck disable=SC1091
  source .env
  set +o allexport
fi

# Minimal safeguard: ensure required secrets are present; do not print them.
if [ -z "${LIBDNS_SPACESHIP_APIKEY:-}" ] || [ -z "${LIBDNS_SPACESHIP_APISECRET:-}" ]; then
  echo "LIBDNS_SPACESHIP_APIKEY and LIBDNS_SPACESHIP_APISECRET must be set to run tests" >&2
  exit 1
fi

# Run the test suite. Pass-through any provided arguments (e.g. -run, -v).
# Avoid printing any secrets.
echo "Running go test (tests will use env vars or .env file)."
exec go test ./... "$@"
