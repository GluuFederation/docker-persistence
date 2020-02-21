import logging.config
import os
import time
from collections import namedtuple

from ldap3 import Connection
from ldap3 import Server
from ldap3 import SUBTREE

from pygluu.containerlib import get_manager
from pygluu.containerlib import wait_for
from pygluu.containerlib.utils import decode_text

import json
import utils
from settings import LOGGING_CONFIG
from initializer import CouchbaseBackend

GLUU_PERSISTENCE_TYPE = os.environ.get("GLUU_PERSISTENCE_TYPE", "couchbase")
GLUU_PERSISTENCE_LDAP_MAPPING = os.environ.get("GLUU_PERSISTENCE_LDAP_MAPPING", "default")

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("migrator")

Entry = namedtuple("Entry", ["id", "attrs"])


class LDAPBackend(object):
    def __init__(self, manager):
        host = os.environ.get("GLUU_LDAP_URL", "localhost:1636")
        user = manager.config.get("ldap_binddn")
        password = decode_text(
            manager.secret.get("encoded_ox_ldap_pw"),
            manager.secret.get("encoded_salt"),
        )

        server = Server(host, port=1636, use_ssl=True)
        self.conn = Connection(server, user, password)
        self.manager = manager

    def all(self, key="", filter_="", attrs=None, **kwargs):
        key = key or "o=gluu"

        attrs = None or ["*"]
        filter_ = filter_ or "(objectClass=*)"

        with self.conn as conn:
            conn.search(
                search_base=key,
                search_filter=filter_,
                search_scope=SUBTREE,
                attributes=attrs,
            )

            for entry in conn.entries:
                id_ = entry.entry_dn
                attrs = entry.entry_attributes_as_dict

                for k, v in attrs.items():
                    attrs[k] = v
                yield Entry(id_, attrs)


class Migrator(object):
    def __init__(self, manager):
        self.ldap_backend = LDAPBackend(manager)
        self.couchbase_backend = CouchbaseBackend(manager)

    def migrate(self):
        bucket_mappings = utils.get_bucket_mappings()
        time.sleep(5)
        self.couchbase_backend.create_buckets(bucket_mappings)
        time.sleep(5)
        self.couchbase_backend.create_indexes(bucket_mappings)

        attr_processor = utils.AttrProcessor()

        for entry in self.ldap_backend.all():
            if len(entry.attrs) <= 2:
                continue

            _entry = entry.attrs
            key = utils.get_key_from(entry.id)
            _entry["dn"] = [entry.id]
            _entry = utils.transform_entry(_entry, attr_processor)
            data = json.dumps(_entry)

            # determine bucket
            prefix = key.split("_")[0] + "_"
            if prefix in ("groups_", "people_", "authorizations_"):
                bucket = "gluu_user"
            elif prefix in ("site_", "cache-refresh_"):
                bucket = "gluu_site"
            elif prefix in ("tokens_",):
                bucket = "gluu_token"
            elif prefix in ("cache_",):
                bucket = "gluu_cache"
            else:
                bucket = "gluu"

            query = 'INSERT INTO `%s` (KEY, VALUE) VALUES ("%s", %s);\n' % (bucket, key, data)
            logger.info("Importing {} document into {} bucket".format(key, bucket))
            req = self.couchbase_backend.client.exec_query(query)
            if not req.ok:
                logger.warn("Failed to execute query, reason={}".format(req.json()))


def wait(manager):
    deps = [
        "ldap_conn",
        "couchbase_conn",
    ]
    wait_for(manager, deps)


def migrate():
    manager = get_manager()
    wait(manager)
    migrator = Migrator(manager)
    migrator.migrate()
