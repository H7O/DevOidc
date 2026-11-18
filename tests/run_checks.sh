#!/usr/bin/env bash
# Starts DevOidc with a certificate made for this run, runs the 41 checks against it, and stops it.
# For Linux, where no ASP.NET Core development certificate is trusted. On Windows, start DevOidc
# yourself and run test_devoidc.py, as the README shows.
#
#   tests/run_checks.sh                      the source in this folder, built first
#   tests/run_checks.sh ./DevOidc            a downloaded program
#   tests/run_checks.sh dotnet DevOidc.dll   the portable build
#
# It needs openssl, and either uv or a python3 that has the packages cryptography and truststore.
# The certificate lives in a temporary folder and is trusted by the checks only: nothing is added
# to the machine's trusted certificates, and the folder is removed at the end.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(dirname "$here")"
config="$root/devoidc.example.json"
port="${DEVOIDC_PORT:-5443}"
work="$(mktemp -d)"
pid=""

cleanup() {
  if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
  rm -rf "$work"
}
trap cleanup EXIT

if ! openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout "$work/key.pem" -out "$work/cert.pem" > "$work/openssl.log" 2>&1; then
  echo "openssl could not make the certificate:"; cat "$work/openssl.log"; exit 1
fi

if [ $# -eq 0 ]; then
  dotnet publish "$root/DevOidc.csproj" --configuration Release --output "$work/app" --nologo --verbosity quiet
  set -- dotnet "$work/app/DevOidc.dll"
fi

"$@" --config "$config" --port "$port" --cert-pem "$work/cert.pem" --key-pem "$work/key.pem" > "$work/devoidc.log" 2>&1 &
pid=$!

# DevOidc prints the line that starts with " Key" once it is listening.
for _ in $(seq 1 240); do
  if grep -q '^ Key ' "$work/devoidc.log"; then break; fi
  if ! kill -0 "$pid" 2>/dev/null; then echo "DevOidc did not start:"; cat "$work/devoidc.log"; exit 1; fi
  sleep 0.25
done
if ! grep -q '^ Key ' "$work/devoidc.log"; then echo "DevOidc was not up after a minute:"; cat "$work/devoidc.log"; exit 1; fi

# --cert, not the environment variable SSL_CERT_FILE: uv obeys that variable for its own downloads,
# and could then no longer fetch the package the checks need.
if command -v uv >/dev/null 2>&1; then
  uv run --with cryptography "$here/test_devoidc.py" --config "$config" --issuer "https://localhost:$port" --cert "$work/cert.pem"
else
  python3 "$here/test_devoidc.py" --config "$config" --issuer "https://localhost:$port" --cert "$work/cert.pem"
fi
