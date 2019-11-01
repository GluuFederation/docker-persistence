#!/bin/sh
set -e

run_entrypoint() {
    touch /deploy/touched
}

cat << LICENSE_ACK

# ================================================================================= #
# Gluu License Agreement: https://www.gluu.org/support-license/                     #
# The use of Gluu Server Enterprise Edition is subject to the Gluu Support License. #
# ================================================================================= #

LICENSE_ACK

if [ -f /etc/redhat-release ]; then
    source scl_source enable python27 && python /app/scripts/wait.py
    source scl_source enable python27 && python /app/scripts/entrypoint.py
else
    python /app/scripts/wait.py
    python /app/scripts/entrypoint.py
fi
