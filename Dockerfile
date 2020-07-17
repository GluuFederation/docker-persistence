FROM alpine:3.11

# ===============
# Alpine packages
# ===============

RUN apk update \
    && apk add --no-cache py3-pip curl tini \
    && apk add --no-cache --virtual build-deps git wget

# ======
# Python
# ======

RUN apk add --no-cache py3-cryptography
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install -U pip \
    && pip3 install --no-cache-dir -r /tmp/requirements.txt

# =======
# Cleanup
# =======

RUN apk del build-deps \
    && rm -rf /var/cache/apk/*

# =======
# License
# =======

RUN mkdir -p /licenses
COPY LICENSE /licenses/

# ==========
# Config ENV
# ==========

ENV GLUU_CONFIG_ADAPTER=consul \
    GLUU_CONFIG_CONSUL_HOST=localhost \
    GLUU_CONFIG_CONSUL_PORT=8500 \
    GLUU_CONFIG_CONSUL_CONSISTENCY=stale \
    GLUU_CONFIG_CONSUL_SCHEME=http \
    GLUU_CONFIG_CONSUL_VERIFY=false \
    GLUU_CONFIG_CONSUL_CACERT_FILE=/etc/certs/consul_ca.crt \
    GLUU_CONFIG_CONSUL_CERT_FILE=/etc/certs/consul_client.crt \
    GLUU_CONFIG_CONSUL_KEY_FILE=/etc/certs/consul_client.key \
    GLUU_CONFIG_CONSUL_TOKEN_FILE=/etc/certs/consul_token \
    GLUU_CONFIG_KUBERNETES_NAMESPACE=default \
    GLUU_CONFIG_KUBERNETES_CONFIGMAP=gluu \
    GLUU_CONFIG_KUBERNETES_USE_KUBE_CONFIG=false

# ==========
# Secret ENV
# ==========

ENV GLUU_SECRET_ADAPTER=vault \
    GLUU_SECRET_VAULT_SCHEME=http \
    GLUU_SECRET_VAULT_HOST=localhost \
    GLUU_SECRET_VAULT_PORT=8200 \
    GLUU_SECRET_VAULT_VERIFY=false \
    GLUU_SECRET_VAULT_ROLE_ID_FILE=/etc/certs/vault_role_id \
    GLUU_SECRET_VAULT_SECRET_ID_FILE=/etc/certs/vault_secret_id \
    GLUU_SECRET_VAULT_CERT_FILE=/etc/certs/vault_client.crt \
    GLUU_SECRET_VAULT_KEY_FILE=/etc/certs/vault_client.key \
    GLUU_SECRET_VAULT_CACERT_FILE=/etc/certs/vault_ca.crt \
    GLUU_SECRET_KUBERNETES_NAMESPACE=default \
    GLUU_SECRET_KUBERNETES_SECRET=gluu \
    GLUU_SECRET_KUBERNETES_USE_KUBE_CONFIG=false

# ===============
# Persistence ENV
# ===============

ENV GLUU_PERSISTENCE_TYPE=couchbase \
    GLUU_PERSISTENCE_LDAP_MAPPING=default \
    GLUU_COUCHBASE_URL=localhost \
    GLUU_COUCHBASE_USER=admin \
    GLUU_COUCHBASE_CERT_FILE=/etc/certs/couchbase.crt \
    GLUU_COUCHBASE_PASSWORD_FILE=/etc/gluu/conf/couchbase_password \
    GLUU_LDAP_URL=localhost:1636

# ===========
# Generic ENV
# ===========

ENV GLUU_CACHE_TYPE=NATIVE_PERSISTENCE \
    GLUU_REDIS_URL=localhost:6379 \
    GLUU_REDIS_TYPE=STANDALONE \
    GLUU_REDIS_USE_SSL=false \
    GLUU_REDIS_SSL_TRUSTSTORE="" \
    GLUU_REDIS_SENTINEL_GROUP="" \
    GLUU_MEMCACHED_URL=localhost:11211 \
    GLUU_WAIT_SLEEP_DURATION=10 \
    GLUU_OXTRUST_API_ENABLED=false \
    GLUU_OXTRUST_API_TEST_MODE=false \
    GLUU_CASA_ENABLED=false \
    GLUU_PASSPORT_ENABLED=false \
    GLUU_RADIUS_ENABLED=false \
    GLUU_SAML_ENABLED=false \
    GLUU_SCIM_ENABLED=false \
    GLUU_SCIM_TEST_MODE=false \
    GLUU_PERSISTENCE_SKIP_EXISTING=true \
    GLUU_OXD_SERVER_URL=localhost:8443

# ====
# misc
# ====

LABEL name="Persistence" \
    maintainer="Gluu Inc. <support@gluu.org>" \
    vendor="Gluu Federation" \
    version="4.2.0" \
    release="01" \
    summary="Gluu Persistence" \
    description="Generate initial data for persistence layer"

RUN mkdir -p /app/tmp /etc/certs /etc/gluu/conf

COPY scripts /app/scripts
COPY static /app/static
COPY templates /app/templates
RUN chmod +x /app/scripts/entrypoint.sh

ENTRYPOINT ["tini", "-g", "--"]
CMD ["sh", "/app/scripts/entrypoint.sh"]
