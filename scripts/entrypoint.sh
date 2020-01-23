#!/bin/sh
set -e

if [ -f /etc/redhat-release ]; then
    source scl_source enable python27 && python /app/scripts/wait.py
    source scl_source enable python27 && python /app/scripts/entrypoint.py
else
    python /app/scripts/wait.py
    python /app/scripts/entrypoint.py
fi
