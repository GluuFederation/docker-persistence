## Overview

Persistence is a special container to load initial data for LDAP or Couchbase.

## Versions

See [Releases](https://github.com/GluuFederation/docker-persistence/releases) for stable versions.
For bleeding-edge/unstable version, use `gluufederation/persistence:4.2.3_dev`.

## Environment Variables

The following environment variables are supported by the container:

- `GLUU_CONFIG_ADAPTER`: The config backend adapter, can be `consul` (default) or `kubernetes`.
- `GLUU_CONFIG_CONSUL_HOST`: hostname or IP of Consul (default to `localhost`).
- `GLUU_CONFIG_CONSUL_PORT`: port of Consul (default to `8500`).
- `GLUU_CONFIG_CONSUL_CONSISTENCY`: Consul consistency mode (choose one of `default`, `consistent`, or `stale`). Default to `stale` mode.
- `GLUU_CONFIG_CONSUL_SCHEME`: supported Consul scheme (`http` or `https`).
- `GLUU_CONFIG_CONSUL_VERIFY`: whether to verify cert or not (default to `false`).
- `GLUU_CONFIG_CONSUL_CACERT_FILE`: path to Consul CA cert file (default to `/etc/certs/consul_ca.crt`). This file will be used if it exists and `GLUU_CONFIG_CONSUL_VERIFY` set to `true`.
- `GLUU_CONFIG_CONSUL_CERT_FILE`: path to Consul cert file (default to `/etc/certs/consul_client.crt`).
- `GLUU_CONFIG_CONSUL_KEY_FILE`: path to Consul key file (default to `/etc/certs/consul_client.key`).
- `GLUU_CONFIG_CONSUL_TOKEN_FILE`: path to file contains ACL token (default to `/etc/certs/consul_token`).
- `GLUU_CONFIG_KUBERNETES_NAMESPACE`: Kubernetes namespace (default to `default`).
- `GLUU_CONFIG_KUBERNETES_CONFIGMAP`: Kubernetes configmaps name (default to `gluu`).
- `GLUU_CONFIG_KUBERNETES_USE_KUBE_CONFIG`: Load credentials from `$HOME/.kube/config`, only useful for non-container environment (default to `false`).
- `GLUU_SECRET_ADAPTER`: The secrets adapter, can be `vault` or `kubernetes`.
- `GLUU_SECRET_VAULT_SCHEME`: supported Vault scheme (`http` or `https`).
- `GLUU_SECRET_VAULT_HOST`: hostname or IP of Vault (default to `localhost`).
- `GLUU_SECRET_VAULT_PORT`: port of Vault (default to `8200`).
- `GLUU_SECRET_VAULT_VERIFY`: whether to verify cert or not (default to `false`).
- `GLUU_SECRET_VAULT_ROLE_ID_FILE`: path to file contains Vault AppRole role ID (default to `/etc/certs/vault_role_id`).
- `GLUU_SECRET_VAULT_SECRET_ID_FILE`: path to file contains Vault AppRole secret ID (default to `/etc/certs/vault_secret_id`).
- `GLUU_SECRET_VAULT_CERT_FILE`: path to Vault cert file (default to `/etc/certs/vault_client.crt`).
- `GLUU_SECRET_VAULT_KEY_FILE`: path to Vault key file (default to `/etc/certs/vault_client.key`).
- `GLUU_SECRET_VAULT_CACERT_FILE`: path to Vault CA cert file (default to `/etc/certs/vault_ca.crt`). This file will be used if it exists and `GLUU_SECRET_VAULT_VERIFY` set to `true`.
- `GLUU_SECRET_KUBERNETES_NAMESPACE`: Kubernetes namespace (default to `default`).
- `GLUU_SECRET_KUBERNETES_SECRET`: Kubernetes secrets name (default to `gluu`).
- `GLUU_SECRET_KUBERNETES_USE_KUBE_CONFIG`: Load credentials from `$HOME/.kube/config`, only useful for non-container environment (default to `false`).
- `GLUU_WAIT_MAX_TIME`: How long the startup "health checks" should run (default to `300` seconds).
- `GLUU_WAIT_SLEEP_DURATION`: Delay between startup "health checks" (default to `10` seconds).
- `GLUU_OXTRUST_CONFIG_GENERATION`: Whether to generate oxShibboleth configuration or not (default to `true`).
- `GLUU_CACHE_TYPE`: Supported values are `IN_MEMORY`, `REDIS`, `MEMCACHED`, and `NATIVE_PERSISTENCE` (default to `NATIVE_PERSISTENCE`).
- `GLUU_REDIS_URL`: URL of Redis server, format is host:port (optional; default to `localhost:6379`).
- `GLUU_REDIS_TYPE`: Redis service type, either `STANDALONE` or `CLUSTER` (optional; default to `STANDALONE`).
- `GLUU_MEMCACHED_URL`: URL of Memcache server, format is host:port (optional; default to `localhost:11211`).
- `GLUU_PERSISTENCE_TYPE`: Persistence backend being used (one of `ldap`, `couchbase`, or `hybrid`; default to `ldap`).
- `GLUU_PERSISTENCE_LDAP_MAPPING`: Specify data that should be saved in LDAP (one of `default`, `user`, `cache`, `site`, `token`, or `session`; default to `default`). Note this environment only takes effect when `GLUU_PERSISTENCE_TYPE` is set to `hybrid`.
- `GLUU_PERSISTENCE_SKIP_EXISTING`: skip initialization if backend already initialized (default to `True`).
- `GLUU_LDAP_URL`: Address and port of LDAP server (default to `localhost:1636`); required if `GLUU_PERSISTENCE_TYPE` is set to `ldap` or `hybrid`.
- `GLUU_COUCHBASE_URL`: Address of Couchbase server (default to `localhost`); required if `GLUU_PERSISTENCE_TYPE` is set to `couchbase` or `hybrid`.
- `GLUU_COUCHBASE_USER`: Username of Couchbase server (default to `admin`); required if `GLUU_PERSISTENCE_TYPE` is set to `couchbase` or `hybrid`.
- `GLUU_COUCHBASE_SUPERUSER`: Superuser of Couchbase server (default to empty-string); required if `GLUU_PERSISTENCE_TYPE` is set to `couchbase` or `hybrid`. Fallback to `GLUU_COUCHBASE_USER`.
- `GLUU_COUCHBASE_CERT_FILE`: Couchbase root certificate location (default to `/etc/certs/couchbase.crt`); required if `GLUU_PERSISTENCE_TYPE` is set to `couchbase` or `hybrid`.
- `GLUU_COUCHBASE_PASSWORD_FILE`: Path to file contains Couchbase password (default to `/etc/gluu/conf/couchbase_password`); required if `GLUU_PERSISTENCE_TYPE` is set to `couchbase` or `hybrid`.
- `GLUU_COUCHBASE_SUPERUSER_PASSWORD_FILE`: Path to file contains Couchbase superuser password (default to `/etc/gluu/conf/couchbase_superuser_password`); required if `GLUU_PERSISTENCE_TYPE` is set to `couchbase` or `hybrid`.
- `GLUU_COUCHBASE_INDEX_NUM_REPLICA`: Specify the number of replica for Couchbase indexes (default to `0`).
- `GLUU_OXTRUST_API_ENABLED`: Enable oxTrust API (default to `false`).
- `GLUU_OXTRUST_API_TEST_MODE`: Enable oxTrust API test mode; not recommended for production (default to `false`). If set to `false`, UMA mode is activated. See [oxTrust API docs](https://gluu.org/docs/oxtrust-api/4.1/) for reference.
- `GLUU_COUCHBASE_BUCKET_PREFIX`: Prefix for Couchbase buckets (default to `gluu`).
- `GLUU_CASA_ENABLED`: Enable Casa-related features; custom scripts, ACR, UI menu, etc. (default to `false`).
- `GLUU_PASSPORT_ENABLED`: Enable Passport-related features; custom scripts, ACR, UI menu, etc. (default to `false`).
- `GLUU_RADIUS_ENABLED`: Enable Radius-related features; UI menu, etc. (default to `false`).
- `GLUU_SAML_ENABLED`: Enable SAML-related features; UI menu, etc. (default to `false`).
- `GLUU_DOCUMENT_STORE_TYPE`: Document store type (one of `LOCAL` or `JCA`; default to `LOCAL`).
- `GLUU_JACKRABBIT_URL`: URL to remote repository (default to `http://localhost:8080`).
- `GLUU_JACKRABBIT_ADMIN_ID_FILE`: Absolute path to file contains ID for admin user (default to `/etc/gluu/conf/jackrabbit_admin_id`).
- `GLUU_JACKRABBIT_ADMIN_PASSWORD_FILE`: Absolute path to file contains password for admin user (default to `/etc/gluu/conf/jackrabbit_admin_password`).

## Initializing Data

### LDAP

Deploy Wren:DS container:

```sh
docker run -d \
    --network container:consul \
    --name ldap \
    -e GLUU_CONFIG_ADAPTER=consul \
    -e GLUU_CONFIG_CONSUL_HOST=consul \
    -e GLUU_SECRET_ADAPTER=vault \
    -e GLUU_SECRET_VAULT_HOST=vault \
    -v /path/to/opendj/config:/opt/opendj/config \
    -v /path/to/opendj/db:/opt/opendj/db \
    -v /path/to/opendj/logs:/opt/opendj/logs \
    -v /path/to/opendj/ldif:/opt/opendj/ldif \
    -v /path/to/opendj/backup:/opt/opendj/bak \
    -v /path/to/vault_role_id.txt:/etc/certs/vault_role_id \
    -v /path/to/vault_secret_id.txt:/etc/certs/vault_secret_id \
    gluufederation/opendj:4.2.3_dev
```

Run the following command to initialize data and save it to LDAP:

```sh
docker run --rm \
    --network container:consul \
    --name persistence \
    -e GLUU_CONFIG_ADAPTER=consul \
    -e GLUU_CONFIG_CONSUL_HOST=consul \
    -e GLUU_SECRET_ADAPTER=vault \
    -e GLUU_SECRET_VAULT_HOST=vault \
    -e GLUU_PERSISTENCE_TYPE=ldap \
    -e GLUU_LDAP_URL=ldap:1636 \
    -v /path/to/vault_role_id.txt:/etc/certs/vault_role_id \
    -v /path/to/vault_secret_id.txt:/etc/certs/vault_secret_id \
    gluufederation/persistence:4.2.3_dev
```

The process may take awhile, check the output of the `persistence` container log.

### Couchbase

Assuming there is Couchbase instance running hosted at `192.168.100.2` address, setup the cluster:

1. Set the username and password of Couchbase cluster
1. Configure the instance to use Query, Data, and Index services

Once cluster has been configured successfully, do the following steps:

1. Pass the address of Couchbase server in `GLUU_COUCHBASE_URL` (omit the port)
1. Pass the Couchbase superuser in `GLUU_COUCHBASE_SUPERUSER`
1. Save the password into `/path/to/couchbase_superuser_password` file
1. Get the certificate root of Couchbase and save it into `/path/to/couchbase.crt` file

Run the following command to initialize data and save it to Couchbase:

```sh
docker run --rm \
    --network container:consul \
    --name persistence \
    -e GLUU_CONFIG_ADAPTER=consul \
    -e GLUU_CONFIG_CONSUL_HOST=consul \
    -e GLUU_SECRET_ADAPTER=vault \
    -e GLUU_SECRET_VAULT_HOST=vault \
    -e GLUU_PERSISTENCE_TYPE=couchbase \
    -e GLUU_COUCHBASE_URL=192.168.100.2 \
    -e GLUU_COUCHBASE_SUPERUSER=admin \
    -v /path/to/couchbase.crt:/etc/certs/couchbase.crt \
    -v /path/to/couchbase_superuser_password:/etc/gluu/conf/couchbase_superuser_password \
    -v /path/to/vault_role_id.txt:/etc/certs/vault_role_id \
    -v /path/to/vault_secret_id.txt:/etc/certs/vault_secret_id \
    gluufederation/persistence:4.2.3_dev
```

The process may take awhile, check the output of the `persistence` container log.

### Hybrid

Hybrid is a mix of LDAP and Couchbase persistence backend. To initialize data for this type of persistence:

1.  Deploy LDAP container:

    ```sh
    docker run -d \
        --network container:consul \
        --name ldap \
        -e GLUU_CONFIG_ADAPTER=consul \
        -e GLUU_CONFIG_CONSUL_HOST=consul \
        -e GLUU_SECRET_ADAPTER=vault \
        -e GLUU_SECRET_VAULT_HOST=vault \
        -v /path/to/opendj/config:/opt/opendj/config \
        -v /path/to/opendj/db:/opt/opendj/db \
        -v /path/to/opendj/logs:/opt/opendj/logs \
        -v /path/to/opendj/ldif:/opt/opendj/ldif \
        -v /path/to/opendj/backup:/opt/opendj/bak \
        -v /path/to/vault_role_id.txt:/etc/certs/vault_role_id \
        -v /path/to/vault_secret_id.txt:/etc/certs/vault_secret_id \
        gluufederation/opendj:4.2.3_dev
    ```

1.  Prepare Couchbase cluster.

    Assuming there is Couchbase instance running hosted at `192.168.100.2` address, setup the cluster:

    1. Set the username and password of Couchbase cluster
    1. Configure the instance to use Query, Data, and Index services

    Once cluster has been configured successfully, do the following steps:

    1. Pass the address of Couchbase server in `GLUU_COUCHBASE_URL` (omit the port)
    1. Pass the Couchbase user in `GLUU_COUCHBASE_SUPERUSER`
    1. Save the password into `/path/to/couchbase_superuser_password` file
    1. Get the certificate root of Couchbase and save it into `/path/to/couchbase.crt` file

1.  Determine which data goes to LDAP backend by specifying it using `GLUU_PERSISTENCE_LDAP_MAPPING` environment variable. For example, if `user` data should be saved into LDAP, set `GLUU_PERSISTENCE_LDAP_MAPPING=user`. This will make other data saved into Couchbase.

1.  Run the following command to initialize data and save it to LDAP and Couchbase:

    ```sh
    docker run --rm \
        --network container:consul \
        --name persistence \
        -e GLUU_CONFIG_ADAPTER=consul \
        -e GLUU_CONFIG_CONSUL_HOST=consul \
        -e GLUU_SECRET_ADAPTER=vault \
        -e GLUU_SECRET_VAULT_HOST=vault \
        -e GLUU_PERSISTENCE_TYPE=hybrid \
        -e GLUU_PERSISTENCE_LDAP_MAPPING=user \
        -e GLUU_LDAP_URL=ldap:1636 \
        -e GLUU_COUCHBASE_URL=192.168.100.2 \
        -e GLUU_COUCHBASE_SUPERUSER=admin \
        -v /path/to/couchbase.crt:/etc/certs/couchbase.crt \
        -v /path/to/couchbase_superuser_password:/etc/gluu/conf/couchbase_superuser_password \
        -v /path/to/vault_role_id.txt:/etc/certs/vault_role_id \
        -v /path/to/vault_secret_id.txt:/etc/certs/vault_secret_id \
        gluufederation/persistence:4.2.3_dev
    ```
