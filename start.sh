#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p logs data
exec node server.js >> logs/server.log 2>&1
