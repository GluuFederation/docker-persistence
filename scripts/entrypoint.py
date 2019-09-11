import json
import logging
import logging.config
import os
import sys
import time
from collections import OrderedDict

import requests
from ldap3 import BASE
from ldap3 import Connection
from ldap3 import Server
from ldap3.core.exceptions import LDAPSessionTerminatedByServerError
from ldap3.core.exceptions import LDAPSocketOpenError
from ldif3 import LDIFParser

from pygluu.containerlib import get_manager
from pygluu.containerlib.utils import decode_text
from pygluu.containerlib.utils import safe_render
from pygluu.containerlib.utils import generate_base64_contents
from pygluu.containerlib.utils import as_boolean
from pygluu.containerlib.persistence.couchbase import get_couchbase_user
from pygluu.containerlib.persistence.couchbase import get_couchbase_password

from cbm import CBM
from settings import LOGGING_CONFIG

GLUU_CACHE_TYPE = os.environ.get("GLUU_CACHE_TYPE", "NATIVE_PERSISTENCE")
GLUU_REDIS_URL = os.environ.get('GLUU_REDIS_URL', 'localhost:6379')
GLUU_REDIS_TYPE = os.environ.get('GLUU_REDIS_TYPE', 'STANDALONE')
GLUU_MEMCACHED_URL = os.environ.get('GLUU_MEMCACHED_URL', 'localhost:11211')

GLUU_OXTRUST_CONFIG_GENERATION = os.environ.get("GLUU_OXTRUST_CONFIG_GENERATION", True)
GLUU_PERSISTENCE_TYPE = os.environ.get("GLUU_PERSISTENCE_TYPE", "couchbase")
GLUU_PERSISTENCE_LDAP_MAPPING = os.environ.get("GLUU_PERSISTENCE_LDAP_MAPPING", "default")
GLUU_COUCHBASE_URL = os.environ.get("GLUU_COUCHBASE_URL", "localhost")
GLUU_LDAP_URL = os.environ.get("GLUU_LDAP_URL", "localhost:1636")

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("entrypoint")


def get_key_from(dn):
    # for example: `"inum=29DA,ou=attributes,o=gluu"`
    # becomes `["29DA", "attributes"]`
    dns = [i.split("=")[-1] for i in dn.split(",") if i != "o=gluu"]
    dns.reverse()

    # the actual key
    return '_'.join(dns) or "_"


def get_bucket_mappings():
    bucket_mappings = OrderedDict({
        "default": {
            "bucket": "gluu",
            "files": [
                "base.ldif",
                "attributes.ldif",
                "scopes.ldif",
                "scripts.ldif",
                "configuration.ldif",
                "scim.ldif",
                "oxidp.ldif",
                "oxtrust_api.ldif",
                "passport.ldif",
                "oxpassport-config.ldif",
                "gluu_radius_base.ldif",
                "gluu_radius_server.ldif",
                "clients.ldif",
                "oxtrust_api_clients.ldif",
                "scim_clients.ldif",
                "o_metric.ldif",
                "gluu_radius_clients.ldif",
                "passport_clients.ldif",
                "scripts_casa.ldif",
            ],
            "mem_alloc": 100,
            "document_key_prefix": [],
        },
        "user": {
            "bucket": "gluu_user",
            "files": [
                "people.ldif",
                "groups.ldif",
            ],
            "mem_alloc": 300,
            "document_key_prefix": ["groups_", "people_"],
        },
        "site": {
            "bucket": "gluu_site",
            "files": [
                "o_site.ldif",
            ],
            "mem_alloc": 100,
            "document_key_prefix": ["site_", "cache-refresh_"],
        },
        "token": {
            "bucket": "gluu_token",
            "files": [],
            "mem_alloc": 300,
            "document_key_prefix": ["tokens_"],
        },
        "cache": {
            "bucket": "gluu_cache",
            "files": [],
            "mem_alloc": 300,
            "document_key_prefix": ["cache_"],
        },
    })

    if GLUU_PERSISTENCE_TYPE != "couchbase":
        bucket_mappings = OrderedDict({
            name: mapping for name, mapping in bucket_mappings.iteritems()
            if name != GLUU_PERSISTENCE_LDAP_MAPPING
        })
    return bucket_mappings


def prepare_list_attrs():
    attrs = ["member"]

    with open("/app/static/gluu_schema.json") as f:
        gluu_schema = json.loads(f.read())

    for type_, objects in gluu_schema.iteritems():
        if type_ not in ("objectClasses", "attributeTypes"):
            continue

        for obj in objects:
            if not obj.get("multivalued"):
                continue
            attrs += obj["names"]

    # make the list
    return list(set(attrs))


def transform_values(seq):
    values = []
    for item in seq:
        if item in ("true", "false"):
            item = as_boolean(item)
        values.append(item)
    return values


def transform_entry(entry, list_attrs):
    for k, v in entry.iteritems():
        v = transform_values(v)

        if len(v) < 2 and k not in list_attrs:
            entry[k] = v[0]

        if k != "objectClass":
            continue

        entry[k].remove("top")
        ocs = entry[k]

        for oc in ocs:
            remove_oc = any(["Custom" in oc, "gluu" not in oc.lower()])
            if len(ocs) > 1 and remove_oc:
                ocs.remove(oc)
        entry[k] = ocs[0]
    return entry


def render_ldif(src, dst, ctx):
    with open(src) as f:
        txt = f.read()

    with open(dst, "w") as f:
        f.write(safe_render(txt, ctx))


def get_base_ctx(manager):
    passport_oxtrust_config = '''
    "passportUmaClientId":"%(passport_rs_client_id)s",
    "passportUmaClientKeyId":"",
    "passportUmaResourceId":"%(passport_resource_id)s",
    "passportUmaScope":"https://%(hostname)s/oxauth/restv1/uma/scopes/passport_access",
    "passportUmaClientKeyStoreFile":"%(passport_rs_client_jks_fn)s",
    "passportUmaClientKeyStorePassword":"%(passport_rs_client_jks_pass_encoded)s",
''' % {
        "passport_rs_client_id": manager.config.get("passport_rs_client_id"),
        "passport_resource_id": manager.config.get("passport_resource_id"),
        "hostname": manager.config.get("hostname"),
        "passport_rs_client_jks_fn": manager.config.get("passport_rs_client_jks_fn"),
        "passport_rs_client_jks_pass_encoded": manager.secret.get("passport_rs_client_jks_pass_encoded")
    }

    ctx = {
        'cache_provider_type': GLUU_CACHE_TYPE,
        'redis_url': GLUU_REDIS_URL,
        'redis_type': GLUU_REDIS_TYPE,
        'memcached_url': GLUU_MEMCACHED_URL,
        'ldap_hostname': manager.config.get('ldap_init_host', "localhost"),
        'ldaps_port': manager.config.get('ldap_init_port', 1636),
        'ldap_binddn': manager.config.get('ldap_binddn'),
        'encoded_ox_ldap_pw': manager.secret.get('encoded_ox_ldap_pw'),
        'jetty_base': manager.config.get('jetty_base'),
        'orgName': manager.config.get('orgName'),
        'oxauth_client_id': manager.config.get('oxauth_client_id'),
        'oxauthClient_encoded_pw': manager.secret.get('oxauthClient_encoded_pw'),
        'hostname': manager.config.get('hostname'),
        'idp_client_id': manager.config.get('idp_client_id'),
        'idpClient_encoded_pw': manager.secret.get('idpClient_encoded_pw'),
        'oxauth_openid_key_base64': manager.secret.get('oxauth_openid_key_base64'),
        'passport_rs_client_id': manager.config.get('passport_rs_client_id'),
        'passport_rs_client_base64_jwks': manager.secret.get('passport_rs_client_base64_jwks'),
        'passport_rp_client_id': manager.config.get('passport_rp_client_id'),
        'passport_rp_client_base64_jwks': manager.secret.get('passport_rp_client_base64_jwks'),
        "passport_rp_client_jks_fn": manager.config.get("passport_rp_client_jks_fn"),
        "passport_rp_client_jks_pass": manager.secret.get("passport_rp_client_jks_pass"),
        "encoded_ldap_pw": manager.secret.get('encoded_ldap_pw'),
        'scim_rs_client_id': manager.config.get('scim_rs_client_id'),
        'scim_rs_client_base64_jwks': manager.secret.get('scim_rs_client_base64_jwks'),
        'scim_rp_client_id': manager.config.get('scim_rp_client_id'),
        'scim_rp_client_base64_jwks': manager.secret.get('scim_rp_client_base64_jwks'),
        'scim_resource_oxid': manager.config.get('scim_resource_oxid'),
        'passport_rp_ii_client_id': manager.config.get("passport_rp_ii_client_id"),
        'api_rs_client_base64_jwks': manager.secret.get("api_rs_client_base64_jwks"),
        'api_rp_client_base64_jwks': manager.secret.get("api_rp_client_base64_jwks"),

        'admin_email': manager.config.get('admin_email'),
        'shibJksFn': manager.config.get('shibJksFn'),
        'shibJksPass': manager.secret.get('shibJksPass'),
        'oxTrustConfigGeneration': "true" if as_boolean(GLUU_OXTRUST_CONFIG_GENERATION) else "false",
        'encoded_shib_jks_pw': manager.secret.get('encoded_shib_jks_pw'),
        'scim_rs_client_jks_fn': manager.config.get('scim_rs_client_jks_fn'),
        'scim_rs_client_jks_pass_encoded': manager.secret.get('scim_rs_client_jks_pass_encoded'),
        'passport_rs_client_jks_fn': manager.config.get('passport_rs_client_jks_fn'),
        'passport_rs_client_jks_pass_encoded': manager.secret.get('passport_rs_client_jks_pass_encoded'),
        'shibboleth_version': manager.config.get('shibboleth_version'),
        'idp3Folder': manager.config.get('idp3Folder'),
        'ldap_site_binddn': manager.config.get('ldap_site_binddn'),
        'api_rs_client_jks_fn': manager.config.get("api_rs_client_jks_fn"),
        'api_rs_client_jks_pass_encoded': manager.secret.get("api_rs_client_jks_pass_encoded"),

        "oxtrust_requesting_party_client_id": manager.config.get("oxtrust_requesting_party_client_id"),
        "oxtrust_resource_server_client_id": manager.config.get("oxtrust_resource_server_client_id"),
        "oxtrust_resource_id": manager.config.get("oxtrust_resource_id"),
        "passport_resource_id": manager.config.get("passport_resource_id"),
        "passport_oxtrust_config": passport_oxtrust_config,

        "gluu_radius_client_id": manager.config.get("gluu_radius_client_id"),
        "gluu_ro_encoded_pw": manager.secret.get("gluu_ro_encoded_pw"),
        "super_gluu_ro_session_script": manager.config.get("super_gluu_ro_session_script"),
        "super_gluu_ro_script": manager.config.get("super_gluu_ro_script"),
        "enableRadiusScripts": "false",
        "gluu_ro_client_base64_jwks": manager.secret.get("gluu_ro_client_base64_jwks"),

        "gluuPassportEnabled": "false",
        "gluuRadiusEnabled": "false",
        "gluuSamlEnabled": "false",

        "pairwiseCalculationKey": manager.secret.get("pairwiseCalculationKey"),
        "pairwiseCalculationSalt": manager.secret.get("pairwiseCalculationSalt"),
        "default_openid_jks_dn_name": manager.secret.get("default_openid_jks_dn_name"),
        "oxauth_openid_jks_fn": manager.config.get("oxauth_openid_jks_fn"),
        "oxauth_openid_jks_pass": manager.secret.get("oxauth_openid_jks_pass"),
        "oxauth_legacyIdTokenClaims": manager.config.get("oxauth_legacyIdTokenClaims"),
        "passportSpTLSCert": manager.config.get("passportSpTLSCert"),
        "passportSpTLSKey": manager.config.get("passportSpTLSKey"),
        "oxauth_openidScopeBackwardCompatibility": manager.config.get("oxauth_openidScopeBackwardCompatibility"),
        "fido2ConfigFolder": manager.config.get("fido2ConfigFolder"),
    }
    return ctx


def merge_extension_ctx(ctx):
    basedir = "/app/static/extension"

    for ext_type in os.listdir(basedir):
        ext_type_dir = os.path.join(basedir, ext_type)

        for fname in os.listdir(ext_type_dir):
            filepath = os.path.join(ext_type_dir, fname)
            ext_name = "{}_{}".format(
                ext_type, os.path.splitext(fname)[0].lower()
            )

            with open(filepath) as fd:
                ctx[ext_name] = generate_base64_contents(fd.read())
    return ctx


def merge_radius_ctx(ctx):
    basedir = "/app/static/radius"
    file_mappings = {
        "super_gluu_ro_session_script": "super_gluu_ro_session.py",
        "super_gluu_ro_script": "super_gluu_ro.py",
    }

    for key, file_ in file_mappings.iteritems():
        fn = os.path.join(basedir, file_)
        with open(fn) as f:
            ctx[key] = generate_base64_contents(f.read())
    return ctx


def merge_oxtrust_ctx(ctx):
    basedir = '/app/templates/oxtrust'
    file_mappings = {
        'oxtrust_cache_refresh_base64': 'oxtrust-cache-refresh.json',
        'oxtrust_config_base64': 'oxtrust-config.json',
        'oxtrust_import_person_base64': 'oxtrust-import-person.json',
    }

    for key, file_ in file_mappings.iteritems():
        file_path = os.path.join(basedir, file_)
        with open(file_path) as fp:
            ctx[key] = generate_base64_contents(fp.read() % ctx)
    return ctx


def merge_oxauth_ctx(ctx):
    basedir = '/app/templates/oxauth'
    file_mappings = {
        'oxauth_config_base64': 'oxauth-config.json',
        'oxauth_static_conf_base64': 'oxauth-static-conf.json',
        'oxauth_error_base64': 'oxauth-errors.json',
    }

    for key, file_ in file_mappings.iteritems():
        file_path = os.path.join(basedir, file_)
        with open(file_path) as fp:
            ctx[key] = generate_base64_contents(fp.read() % ctx)
    return ctx


def merge_oxidp_ctx(ctx):
    basedir = '/app/templates/oxidp'
    file_mappings = {
        'oxidp_config_base64': 'oxidp-config.json',
    }

    for key, file_ in file_mappings.iteritems():
        file_path = os.path.join(basedir, file_)
        with open(file_path) as fp:
            ctx[key] = generate_base64_contents(fp.read() % ctx)
    return ctx


def merge_passport_ctx(ctx):
    basedir = '/app/templates/passport'
    file_mappings = {
        'passport_central_config_base64': 'passport-central-config.json',
    }

    for key, file_ in file_mappings.iteritems():
        file_path = os.path.join(basedir, file_)
        with open(file_path) as fp:
            ctx[key] = generate_base64_contents(fp.read() % ctx)
    return ctx


def prepare_template_ctx(manager):
    ctx = get_base_ctx(manager)
    ctx = merge_extension_ctx(ctx)
    ctx = merge_radius_ctx(ctx)
    ctx = merge_oxauth_ctx(ctx)
    ctx = merge_oxtrust_ctx(ctx)
    ctx = merge_oxidp_ctx(ctx)
    ctx = merge_passport_ctx(ctx)
    return ctx


class CouchbaseBackend(object):
    def __init__(self, manager):
        hostname = GLUU_COUCHBASE_URL
        user = get_couchbase_user(manager)
        password = get_couchbase_password(manager)
        self.client = CBM(hostname, user, password)
        self.manager = manager

    def configure_couchbase(self):
        logger.info("Initializing Couchbase Node")
        req = self.client.initialize_node()
        if not req.ok:
            logger.warn("Failed to initilize Couchbase Node, reason={}".format(req.text))

        logger.info("Renaming Couchbase Node")
        req = self.client.rename_node()
        if not req.ok:
            logger.warn("Failed to rename Couchbase Node, reason={}".format(req.text))

        logger.info("Setting Couchbase index storage mode")
        req = self.client.set_index_storage_mode()
        if not req.ok:
            logger.warn("Failed to set Couchbase index storage mode; reason={}".format(req.text))

        logger.info("Setting Couchbase indexer memory quota")
        req = self.client.set_index_memory_quta()
        if not req.ok:
            logger.warn("Failed to set Couchbase indexer memory quota; reason={}".format(req.text))

        logger.info("Setting up Couchbase Services")
        req = self.client.setup_services()
        if not req.ok:
            logger.warn("Failed to setup Couchbase services; reason={}".format(req.text))

        logger.info("Setting Couchbase Admin password")
        req = self.client.set_admin_password()
        if not req.ok:
            logger.warn("Failed to set Couchbase admin password; reason={}".format(req.text))

    def import_cert(self):
        logger.info("Updating certificates")

        txt = self.manager.secret.get("couchbase_cluster_cert")
        base_url = "https://{}:18091".format(GLUU_COUCHBASE_URL)

        with requests.Session() as session:
            session.auth = (self.client.auth.username, self.client.auth.password)
            session.verify = False

            req = session.post(
                "{}/controller/uploadClusterCA".format(base_url),
                headers={"Content-Type": "application/octet-stream"},
                data=txt,
            )
            if not req.ok:
                logger.warn("Unable to upload cluster cert; reason={}".format(req.text))

            time.sleep(5)
            req = session.post("{}/node/controller/reloadCertificate".format(base_url))
            if not req.ok:
                logger.warn("Unable to reload node cert; reason={}".format(req.text))

            # req = session.post(
            #     "{}/settings/clientCertAuth".format(base_url),
            #     json={"state": "enable", "prefixes": [
            #         {"path": "subject.cn", "prefix": "", "delimiter": ""},
            #     ]},
            # )
            # if not req.ok:
            #     logger.warn("Unable to set client cert auth; reason={}".format(req.text))

    def create_buckets(self, bucket_mappings, bucket_type="couchbase"):
        sys_info = self.client.get_system_info()
        ram_info = sys_info["storageTotals"]["ram"]

        total_mem = (ram_info['quotaTotal'] - ram_info['quotaUsed']) / (1024 * 1024)
        # the minimum memory is a sum of required buckets + minimum mem for `gluu` bucket
        min_mem = sum([value["mem_alloc"] for value in bucket_mappings.values()]) + 100

        logger.info("Memory size for Couchbase buckets was determined as {} MB".format(total_mem))
        logger.info("Minimum memory size for Couchbase buckets was determined as {} MB".format(min_mem))

        if total_mem < min_mem:
            logger.error("Available quota on couchbase server is less than {} MB; exiting ...".format(min_mem))
            sys.exit(1)

        # always create `gluu` bucket even when `default` mapping stored in LDAP
        if GLUU_PERSISTENCE_TYPE == "hybrid" and GLUU_PERSISTENCE_LDAP_MAPPING == "default":
            memsize = 100

            logger.info("Creating bucket {0} with type {1} and RAM size {2}".format("gluu", bucket_type, memsize))
            req = self.client.add_bucket("gluu", memsize, bucket_type)
            if not req.ok:
                logger.warn("Failed to create bucket {}; reason={}".format("gluu", req.text))

        req = self.client.get_buckets()
        if req.ok:
            remote_buckets = tuple([bckt["name"] for bckt in req.json()])
        else:
            remote_buckets = tuple([])

        for name, mapping in bucket_mappings.iteritems():
            if mapping["bucket"] in remote_buckets:
                continue

            memsize = int((mapping["mem_alloc"] / float(min_mem)) * total_mem)

            logger.info("Creating bucket {0} with type {1} and RAM size {2}".format(mapping["bucket"], bucket_type, memsize))
            req = self.client.add_bucket(mapping["bucket"], memsize, bucket_type)
            if not req.ok:
                logger.warn("Failed to create bucket {}; reason={}".format(mapping["bucket"], req.text))

    def create_indexes(self, bucket_mappings):
        buckets = [mapping["bucket"] for _, mapping in bucket_mappings.iteritems()]

        with open("/app/static/couchbase_index.json") as f:
            indexes = json.loads(f.read())

        for bucket in buckets:
            if bucket not in indexes:
                continue

            query_file = "/app/tmp/index_{}.n1ql".format(bucket)

            logger.info("Running Couchbase index creation for {} bucket (if not exist)".format(bucket))

            with open(query_file, "w") as f:
                index_list = indexes.get(bucket, {})
                index_names = []

                for index in index_list.get("attributes", []):
                    index_name = "def_{0}_{1}".format(bucket, index)
                    f.write('CREATE INDEX %s ON `%s`(%s) USING GSI WITH {"defer_build":true};\n' % (index_name, bucket, index))
                    index_names.append(index_name)

                if index_names:
                    f.write('BUILD INDEX ON `%s` (%s) USING GSI;\n' % (bucket, ', '.join(index_names)))

                sic = 1
                for attribs, wherec in index_list.get("static", []):
                    attrquoted = ['`{}`'.format(a) for a in attribs]
                    attrquoteds = ', '.join(attrquoted)
                    f.write('CREATE INDEX `{0}_static_{1:02d}` ON `{0}`({2}) WHERE ({3})\n'.format(bucket, sic, attrquoteds, wherec))

            # exec query
            with open(query_file) as f:
                for line in f:
                    query = line.strip()
                    if not query:
                        continue
                    req = self.client.exec_query(query)
                    if not req.ok:
                        # the following code should be ignored
                        # - 4300: index already exists
                        # - 5000: index already built
                        error = req.json()["errors"][0]
                        if error["code"] in (4300, 5000):
                            continue
                        logger.warn("Failed to execute query, reason={}".format(error["msg"]))

    def import_ldif(self, bucket_mappings):
        ctx = prepare_template_ctx(self.manager)
        list_attrs = prepare_list_attrs()

        for _, mapping in bucket_mappings.iteritems():
            for file_ in mapping["files"]:
                src = "/app/templates/ldif/{}".format(file_)
                dst = "/app/tmp/{}".format(file_)
                render_ldif(src, dst, ctx)
                parser = LDIFParser(open(dst))

                query_file = "/app/tmp/{}.n1ql".format(file_)

                with open(query_file, "a+") as f:
                    for dn, entry in parser.parse():
                        if len(entry) <= 2:
                            continue

                        key = get_key_from(dn)
                        entry["dn"] = [dn]
                        entry = transform_entry(entry, list_attrs)
                        data = json.dumps(entry)
                        # using INSERT will cause duplication error, but the data is left intact
                        query = 'INSERT INTO `%s` (KEY, VALUE) VALUES ("%s", %s);\n' % (mapping["bucket"], key, data)
                        f.write(query)

                # exec query
                logger.info("Importing {} file into {} bucket (if needed)".format(file_, mapping["bucket"]))
                with open(query_file) as f:
                    for line in f:
                        query = line.strip()
                        if not query:
                            continue

                        req = self.client.exec_query(query)
                        if not req.ok:
                            logger.warn("Failed to execute query, reason={}".format(req.json()))

    def initialize(self):
        bucket_mappings = get_bucket_mappings()

        # self.configure_couchbase()

        # time.sleep(5)
        # self.import_cert()

        time.sleep(5)
        self.create_buckets(bucket_mappings)

        time.sleep(5)
        self.create_indexes(bucket_mappings)

        time.sleep(5)
        self.import_ldif(bucket_mappings)


class LDAPBackend(object):
    def __init__(self, manager):
        host = GLUU_LDAP_URL
        user = manager.config.get("ldap_binddn")
        password = decode_text(
            manager.secret.get("encoded_ox_ldap_pw"),
            manager.secret.get("encoded_salt"),
        )

        server = Server(host, port=1636, use_ssl=True)
        self.conn = Connection(server, user, password)
        self.manager = manager

    def check_indexes(self, mapping):
        if mapping == "site":
            index_name = "oxScriptType"
            backend = "site"
        # elif mapping == "statistic":
        #     index_name = "oxMetricType"
        #     backend = "metric"
        else:
            index_name = "del"
            backend = "userRoot"

        dn = "ds-cfg-attribute={},cn=Index,ds-cfg-backend-id={}," \
             "cn=Backends,cn=config".format(index_name, backend)

        max_wait_time = 300
        sleep_duration = 10

        for i in range(0, max_wait_time, sleep_duration):
            try:
                with self.conn as conn:
                    conn.search(
                        search_base=dn,
                        search_filter="(objectClass=*)",
                        search_scope=BASE,
                        attributes=["1.1"],
                        size_limit=1,
                    )
                    if conn.result["description"] == "success":
                        return
                    reason = conn.result["message"]
            except (LDAPSessionTerminatedByServerError, LDAPSocketOpenError) as exc:
                reason = exc

            logger.warn("Waiting for index to be ready; reason={}; "
                        "retrying in {} seconds".format(reason, sleep_duration))
            time.sleep(sleep_duration)

    def import_ldif(self):
        ldif_mappings = {
            "default": [
                "base.ldif",
                "attributes.ldif",
                "scopes.ldif",
                "scripts.ldif",
                "configuration.ldif",
                "scim.ldif",
                "oxidp.ldif",
                "oxtrust_api.ldif",
                "passport.ldif",
                "oxpassport-config.ldif",
                "gluu_radius_base.ldif",
                "gluu_radius_server.ldif",
                "clients.ldif",
                "oxtrust_api_clients.ldif",
                "scim_clients.ldif",
                "o_metric.ldif",
                "gluu_radius_clients.ldif",
                "passport_clients.ldif",
                "scripts_casa.ldif",
            ],
            "user": [
                "people.ldif",
                "groups.ldif",
            ],
            "site": [
                "o_site.ldif",
            ],
            "cache": [],
            "token": [],
        }

        # hybrid means only a subsets of ldif are needed
        if GLUU_PERSISTENCE_TYPE == "hybrid":
            mapping = GLUU_PERSISTENCE_LDAP_MAPPING
            ldif_mappings = {mapping: ldif_mappings[mapping]}

            # these mappings require `base.ldif`
            opt_mappings = ("user", "token",)

            # `user` mapping requires `o=gluu` which available in `base.ldif`
            if mapping in opt_mappings and "base.ldif" not in ldif_mappings[mapping]:
                ldif_mappings[mapping].insert(0, "base.ldif")

        ctx = prepare_template_ctx(self.manager)

        for mapping, files in ldif_mappings.iteritems():
            self.check_indexes(mapping)

            for file_ in files:
                logger.info("Importing {} file".format(file_))
                src = "/app/templates/ldif/{}".format(file_)
                dst = "/app/tmp/{}".format(file_)
                render_ldif(src, dst, ctx)

                parser = LDIFParser(open(dst))
                for dn, entry in parser.parse():
                    self.add_entry(dn, entry)

    def add_entry(self, dn, attrs):
        max_wait_time = 300
        sleep_duration = 10

        for i in range(0, max_wait_time, sleep_duration):
            try:
                with self.conn as conn:
                    conn.add(dn, attributes=attrs)
                    if conn.result["result"] != 0:
                        logger.warn("Unable to add entry with DN {0}; reason={1}".format(
                            dn, conn.result["message"],
                        ))
                    return
            except (LDAPSessionTerminatedByServerError, LDAPSocketOpenError) as exc:
                logger.warn("Unable to add entry with DN {0}; reason={1}; "
                            "retrying in {2} seconds".format(dn, exc, sleep_duration))
            time.sleep(sleep_duration)

    def initialize(self):
        self.import_ldif()


class HybridBackend(object):
    def __init__(self, manager):
        self.ldap_backend = LDAPBackend(manager)
        self.couchbase_backend = CouchbaseBackend(manager)

    def initialize(self):
        self.ldap_backend.initialize()
        self.couchbase_backend.initialize()


def main():
    manager = get_manager()

    backend_classes = {
        "ldap": LDAPBackend,
        "couchbase": CouchbaseBackend,
        "hybrid": HybridBackend,
    }

    # initialize the backend
    backend_cls = backend_classes.get(GLUU_PERSISTENCE_TYPE)
    if not backend_cls:
        raise ValueError("unsupported backend")

    backend = backend_cls(manager)
    backend.initialize()


if __name__ == "__main__":
    main()
