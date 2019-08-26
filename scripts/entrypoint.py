import json
import logging
import logging.config
import os
import time
from collections import OrderedDict

import requests
from ldif3 import LDIFParser

from pygluu.containerlib import get_manager
from pygluu.containerlib.utils import decode_text
from pygluu.containerlib.utils import safe_render
from pygluu.containerlib.utils import generate_base64_contents
from pygluu.containerlib.utils import as_boolean

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

manager = get_manager()

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("entrypoint")


def get_key_from(dn):
    # for example: `"inum=29DA,ou=attributes,o=gluu"`
    # becomes `["29DA", "attributes"]`
    dns = [i.split("=")[-1] for i in dn.split(",") if i != "o=gluu"]
    dns.reverse()

    # the actual key
    return '_'.join(dns) or "_"


def configure_couchbase(cbm):
    logger.info("Initializing Couchbase Node")
    req = cbm.initialize_node()
    if not req.ok:
        logger.warn("Failed to initilize Couchbase Node, reason={}".format(req.text))

    logger.info("Renaming Couchbase Node")
    req = cbm.rename_node()
    if not req.ok:
        logger.warn("Failed to rename Couchbase Node, reason={}".format(req.text))

    logger.info("Setting Couchbase index storage mode")
    req = cbm.set_index_storage_mode()
    if not req.ok:
        logger.warn("Failed to set Couchbase index storage mode; reason={}".format(req.text))

    logger.info("Setting Couchbase indexer memory quota")
    req = cbm.set_index_memory_quta()
    if not req.ok:
        logger.warn("Failed to set Couchbase indexer memory quota; reason={}".format(req.text))

    logger.info("Setting up Couchbase Services")
    req = cbm.setup_services()
    if not req.ok:
        logger.warn("Failed to setup Couchbase services; reason={}".format(req.text))

    logger.info("Setting Couchbase Admin password")
    req = cbm.set_admin_password()
    if not req.ok:
        logger.warn("Failed to set Couchbase admin password; reason={}".format(req.text))


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
            ],
            "mem_alloc": [0.05, 100],
        },
        "user": {
            "bucket": "gluu_user",
            "files": [
                "people.ldif",
                "groups.ldif",
            ],
            "mem_alloc": [0.25, 500],
        },
        "cache": {
            "bucket": "gluu_cache",
            "files": [],
            "mem_alloc": [0.15, 400],
        },
        "statistic": {
            "bucket": "gluu_statistic",
            "files": [
                "o_metric.ldif",
            ],
            "mem_alloc": [0.05, 100],
        },
        "site": {
            "bucket": "gluu_site",
            "files": [
                "o_site.ldif",
            ],
            "mem_alloc": [0.05, 100],
        },
        "authorization": {
            "bucket": "gluu_authorization",
            "files": [],
            "mem_alloc": [0.15, 400],
        },
        "token": {
            "bucket": "gluu_token",
            "files": [],
            "mem_alloc": [0.25, 500],
        },
        "client": {
            "bucket": "gluu_client",
            "files": [
                "clients.ldif",
                "oxtrust_api_clients.ldif",
                "scim_clients.ldif",
                "gluu_radius_clients.ldif",
                "passport_clients.ldif",
            ],
            "mem_alloc": [0.05, 100],
        },
    })

    if GLUU_PERSISTENCE_TYPE != "couchbase":
        bucket_mappings = OrderedDict({
            name: mapping for name, mapping in bucket_mappings.iteritems()
            if name != GLUU_PERSISTENCE_LDAP_MAPPING
        })

    return bucket_mappings


def calculate_bucket_memory(name, bucket_mappings, server_mem):
    min_bucket_mem = 100

    total_ratio = int(
        sum([v["mem_alloc"][0] for v in bucket_mappings.values()])
    )

    mem_alloc = bucket_mappings[name]["mem_alloc"]
    calc_size = int((mem_alloc[0] / total_ratio) * server_mem)

    # if server_mem >= default_server_mem:
    #     calc_size = max(size, mem_alloc[1])
    # else:
    #     calc_size = max(size, min_bucket_mem)
    return max(calc_size, min_bucket_mem)


def create_buckets(cbm, bucket_mappings, bucket_type="couchbase"):
    sys_info = cbm.get_system_info()
    # NOTE: the RAM has been taken by index memory (256M)
    total_memsize = sys_info["memoryQuota"] - 256

    logger.info("Memory size for Couchbase buckets was determined as {} MB".format(total_memsize))

    if GLUU_PERSISTENCE_TYPE == "hybrid" and GLUU_PERSISTENCE_LDAP_MAPPING == "default":
        # always create `gluu` bucket
        memsize = 100
        total_memsize -= memsize

        logger.info("Creating bucket {0} with type {1} and RAM size {2}".format("gluu", bucket_type, memsize))
        req = cbm.add_bucket("gluu", memsize, bucket_type)
        if not req.ok:
            logger.warn("Failed to create bucket {}; reason={}".format("gluu", req.text))

    req = cbm.get_buckets()
    if req.ok:
        remote_buckets = tuple([bckt["name"] for bckt in req.json()])
    else:
        remote_buckets = tuple([])

    for name, mapping in bucket_mappings.iteritems():
        if mapping["bucket"] in remote_buckets:
            continue

        memsize = calculate_bucket_memory(name, bucket_mappings, total_memsize)

        logger.info("Creating bucket {0} with type {1} and RAM size {2}".format(mapping["bucket"], bucket_type, memsize))
        req = cbm.add_bucket(mapping["bucket"], memsize, bucket_type)
        if not req.ok:
            logger.warn("Failed to create bucket {}; reason={}".format(mapping["bucket"], req.text))


def create_indexes(cbm, bucket_mappings):
    buckets = [mapping["bucket"] for _, mapping in bucket_mappings.iteritems()]

    with open("/app/static/index.json") as f:
        indexes = json.loads(f.read())

    for bucket in buckets:
        if bucket not in indexes:
            continue

        query_file = "/app/tmp/index_{}.n1ql".format(bucket)

        logger.info("Running Couchbase index creation for {} bucket (if not exist)".format(bucket))

        with open(query_file, "w") as f:
            f.write('CREATE PRIMARY INDEX def_primary on `%s` USING GSI WITH {"defer_build":true};\n' % (bucket))

            index_list = indexes[bucket]
            if "dn" not in index_list:
                index_list.insert(0, "dn")

            index_names = ["def_primary"]
            for index in index_list:
                index_name = "def_{0}_{1}".format(bucket, index)
                f.write('CREATE INDEX %s ON `%s`(%s) USING GSI WITH {"defer_build":true};\n' % (index_name, bucket, index))
                index_names.append(index_name)

            f.write('BUILD INDEX ON `%s` (%s) USING GSI;\n' % (bucket, ', '.join(index_names)))

        # exec query
        with open(query_file) as f:
            for line in f:
                query = line.strip()
                if not query:
                    continue
                req = cbm.exec_query(query)
                if not req.ok:
                    # the following code should be ignored
                    # - 4300: index already exists
                    # - 5000: index already built
                    error = req.json()["errors"][0]
                    if error["code"] in (4300, 5000):
                        continue
                    logger.warn("Failed to execute query, reason={}".format(error["msg"]))


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


def import_ldif(cbm, bucket_mappings):
    ctx = prepare_template_ctx()
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
                    # using INSERT will cause duplication error,
                    # but the data is left intact
                    query = 'INSERT INTO `%s` (KEY, VALUE) VALUES ("%s", %s);\n' % (mapping["bucket"], key, data)
                    f.write(query)

            # exec query
            logger.info("Importing {} file into {} bucket (if needed)".format(file_, mapping["bucket"]))
            with open(query_file) as f:
                for line in f:
                    query = line.strip()
                    if not query:
                        continue

                    req = cbm.exec_query(query)
                    if not req.ok:
                        logger.warn("Failed to execute query, reason={}".format(req.json()))


def render_ldif(src, dst, ctx):
    with open(src) as f:
        txt = f.read()

    with open(dst, "w") as f:
        f.write(safe_render(txt, ctx))


def prepare_template_ctx():
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
        'ldap_hostname': manager.config.get('ldap_init_host', ""),
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
        'oxauth_config_base64': manager.secret.get('oxauth_config_base64'),
        'oxauth_static_conf_base64': manager.config.get('oxauth_static_conf_base64'),
        'oxauth_openid_key_base64': manager.secret.get('oxauth_openid_key_base64'),
        'oxauth_error_base64': manager.config.get('oxauth_error_base64'),
        'oxtrust_config_base64': manager.secret.get('oxtrust_config_base64'),
        'oxtrust_cache_refresh_base64': manager.secret.get('oxtrust_cache_refresh_base64'),
        'oxtrust_import_person_base64': manager.config.get('oxtrust_import_person_base64'),
        'oxidp_config_base64': manager.secret.get('oxidp_config_base64'),
        'passport_central_config_base64': manager.secret.get("passport_central_config_base64"),
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

        # scripts.ldif
        "person_authentication_usercertexternalauthenticator": manager.config.get("person_authentication_usercertexternalauthenticator"),
        "person_authentication_passportexternalauthenticator": manager.config.get("person_authentication_passportexternalauthenticator"),
        "dynamic_scope_dynamic_permission": manager.config.get("dynamic_scope_dynamic_permission"),
        "id_generator_samplescript": manager.config.get("id_generator_samplescript"),
        "dynamic_scope_org_name": manager.config.get("dynamic_scope_org_name"),
        "dynamic_scope_work_phone": manager.config.get("dynamic_scope_work_phone"),
        "cache_refresh_samplescript": manager.config.get("cache_refresh_samplescript"),
        "person_authentication_yubicloudexternalauthenticator": manager.config.get("person_authentication_yubicloudexternalauthenticator"),
        "uma_rpt_policy_uma_rpt_policy": manager.config.get("uma_rpt_policy_uma_rpt_policy"),
        "uma_claims_gathering_uma_claims_gathering": manager.config.get("uma_claims_gathering_uma_claims_gathering"),
        "person_authentication_basiclockaccountexternalauthenticator": manager.config.get("person_authentication_basiclockaccountexternalauthenticator"),
        "person_authentication_uafexternalauthenticator": manager.config.get("person_authentication_uafexternalauthenticator"),
        "person_authentication_otpexternalauthenticator": manager.config.get("person_authentication_otpexternalauthenticator"),
        "person_authentication_duoexternalauthenticator": manager.config.get("person_authentication_duoexternalauthenticator"),
        "update_user_samplescript": manager.config.get("update_user_samplescript"),
        "user_registration_samplescript": manager.config.get("user_registration_samplescript"),
        "user_registration_confirmregistrationsamplescript": manager.config.get("user_registration_confirmregistrationsamplescript"),
        "person_authentication_googleplusexternalauthenticator": manager.config.get("person_authentication_googleplusexternalauthenticator"),
        "person_authentication_u2fexternalauthenticator": manager.config.get("person_authentication_u2fexternalauthenticator"),
        "person_authentication_supergluuexternalauthenticator": manager.config.get("person_authentication_supergluuexternalauthenticator"),
        "person_authentication_basicexternalauthenticator": manager.config.get("person_authentication_basicexternalauthenticator"),
        "scim_samplescript": manager.config.get("scim_samplescript"),
        "person_authentication_samlexternalauthenticator": manager.config.get("person_authentication_samlexternalauthenticator"),
        "client_registration_samplescript": manager.config.get("client_registration_samplescript"),
        "person_authentication_twilio2fa": manager.config.get("person_authentication_twilio2fa"),
        "application_session_samplescript": manager.config.get("application_session_samplescript"),
        "uma_rpt_policy_umaclientauthzrptpolicy": manager.config.get("uma_rpt_policy_umaclientauthzrptpolicy"),
        "person_authentication_samlpassportauthenticator": manager.config.get("person_authentication_samlpassportauthenticator"),
        "consent_gathering_consentgatheringsample": manager.config.get("consent_gathering_consentgatheringsample"),
        "person_authentication_thumbsigninexternalauthenticator": manager.config.get("person_authentication_thumbsigninexternalauthenticator"),
        "resource_owner_password_credentials_resource_owner_password_credentials": manager.config.get("resource_owner_password_credentials_resource_owner_password_credentials"),
        "person_authentication_fido2externalauthenticator": manager.config.get("person_authentication_fido2externalauthenticator"),
        "introspection_introspection": manager.config.get("introspection_introspection"),

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
    }
    return ctx


def oxtrust_config():
    ctx = prepare_template_ctx()

    oxtrust_template_base = '/app/templates/oxtrust'

    key_and_jsonfile_map = {
        'oxtrust_cache_refresh_base64': 'oxtrust-cache-refresh.json',
        'oxtrust_config_base64': 'oxtrust-config.json',
        'oxtrust_import_person_base64': 'oxtrust-import-person.json'
    }

    for key, json_file in key_and_jsonfile_map.iteritems():
        json_file_path = os.path.join(oxtrust_template_base, json_file)
        with open(json_file_path, 'r') as fp:
            if json_file == "oxtrust-import-person.json":
                ctx_manager = manager.config
            else:
                ctx_manager = manager.secret
            ctx_manager.set(key, generate_base64_contents(fp.read() % ctx))


def import_cert(cbm, user, password):
    logger.info("Updating certificates")

    txt = manager.secret.get("couchbase_cluster_cert")
    base_url = "https://{}:18091".format(GLUU_COUCHBASE_URL)

    with requests.Session() as session:
        session.auth = (user, password)
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


def main():
    hostname = GLUU_COUCHBASE_URL
    user = manager.config.get("couchbase_server_user")
    password = decode_text(
        manager.secret.get("encoded_couchbase_server_pw"),
        manager.secret.get("encoded_salt"),
    )
    cbm = CBM(hostname, user, password)

    configure_couchbase(cbm)

    time.sleep(5)
    import_cert(cbm, user, password)

    time.sleep(5)
    bucket_mappings = get_bucket_mappings()
    create_buckets(cbm, bucket_mappings)

    time.sleep(5)
    create_indexes(cbm, bucket_mappings)

    time.sleep(5)
    oxtrust_config()

    time.sleep(5)
    import_ldif(cbm, bucket_mappings)


if __name__ == "__main__":
    main()
