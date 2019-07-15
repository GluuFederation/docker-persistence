#!/bin/sh
set -e

cat << LICENSE_ACK

# ========================================================================================= #
# Gluu License Agreement: https://github.com/GluuFederation/gluu-docker/blob/4.0.0/LICENSE. #
# The use of Gluu Server Docker Edition is subject to the Gluu Support License.             #
# ========================================================================================= #

LICENSE_ACK

# check persistence type
case "${GLUU_PERSISTENCE_TYPE}" in
    # ldap|couchbase|hybrid)
    couchbase|hybrid)
        ;;
    *)
        # echo "unsupported GLUU_PERSISTENCE_TYPE value; please choose 'ldap', 'couchbase', or 'hybrid'"
        echo "unsupported GLUU_PERSISTENCE_TYPE value; please choose 'couchbase' or 'hybrid'"
        exit 1
        ;;
esac

# check mapping used by LDAP
if [ "${GLUU_PERSISTENCE_TYPE}" = "hybrid" ]; then
    case "${GLUU_PERSISTENCE_LDAP_MAPPING}" in
        default|user|cache|site|statistic)
            ;;
        *)
            echo "unsupported GLUU_PERSISTENCE_LDAP_MAPPING value; please choose 'default', 'user', 'cache', 'site', or 'statistic'"
            exit 1
            ;;
    esac
fi

# run wait_for functions
deps="config,secret"

if [ "${GLUU_PERSISTENCE_TYPE}" = "hybrid" ]; then
    # deps="${deps},ldap,couchbase"
    deps="${deps},couchbase"
else
    deps="${deps},${GLUU_PERSISTENCE_TYPE}"
fi

if [ -f /etc/redhat-release ]; then
    source scl_source enable python27 && python /app/scripts/wait_for.py --deps="$deps"
else
    python /app/scripts/wait_for.py --deps="$deps"
fi

if [ -f /etc/redhat-release ]; then
    source scl_source enable python27 && python /app/scripts/entrypoint.py
else
    python /app/scripts/entrypoint.py
fi
