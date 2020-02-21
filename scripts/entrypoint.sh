#!/bin/sh
set -e

if [ -z $1 ]; then
    cmd="init"
else
    cmd="$@"
fi

if [ -f /etc/redhat-release ]; then
    source scl_source enable python27 && python /app/scripts/entrypoint.py "$cmd"
else
    python /app/scripts/entrypoint.py "$cmd"
fi
