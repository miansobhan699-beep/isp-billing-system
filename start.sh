#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/.."
python3 -m uvicorn adapter.app:app --host 0.0.0.0 --port 8080
