import datetime
import json
import os
from collections import OrderedDict

from ldap3.utils.dn import parse_dn as str2dn


def get_key_from(dn):
    # for example: `"inum=29DA,ou=attributes,o=gluu"`
    # becomes `["29DA", "attributes"]`
    dns = [
        rd[1] for rd in str2dn(dn)
        if rd[0] != "o" and rd[1] != "gluu"
    ]
    dns.reverse()
    return '_'.join(dns) or "_"


class AttrProcessor(object):
    def __init__(self):
        self._attrs = {}

    @property
    def syntax_types(self):
        return {
            '1.3.6.1.4.1.1466.115.121.1.7': 'boolean',
            '1.3.6.1.4.1.1466.115.121.1.27': 'integer',
            '1.3.6.1.4.1.1466.115.121.1.24': 'datetime',
        }

    def process(self):
        attrs = {}

        with open("/app/static/opendj_types.json") as f:
            attr_maps = json.loads(f.read())
            for type_, names in attr_maps.iteritems():
                for name in names:
                    attrs[name] = {"type": type_, "multivalued": False}

        with open("/app/static/gluu_schema.json") as f:
            gluu_schema = json.loads(f.read()).get("attributeTypes", {})
            for schema in gluu_schema:
                if schema.get("json"):
                    type_ = "json"
                elif schema["syntax"] in self.syntax_types:
                    type_ = self.syntax_types[schema["syntax"]]
                else:
                    type_ = "string"

                multivalued = schema.get("multivalued", False)
                for name in schema["names"]:
                    attrs[name] = {
                        "type": type_,
                        "multivalued": multivalued,
                    }

        # override `member`
        attrs["member"]["multivalued"] = True
        return attrs

    @property
    def attrs(self):
        if not self._attrs:
            self._attrs = self.process()
        return self._attrs

    def is_multivalued(self, name):
        return self.attrs.get(name, {}).get("multivalued", False)

    def get_type(self, name):
        return self.attrs.get(name, {}).get("type", "string")


def transform_values(name, values, attr_processor):
    def as_dict(val):
        return json.loads(val)

    def as_bool(val):
        return val in (True, "TRUE".lower(), "YES".lower(), "1", "ON".lower())

    def as_int(val):
        try:
            val = int(val)
        except (TypeError, ValueError):
            pass
        return val

    def as_datetime(val):
        try:
            if '.' in val:
                date_format = '%Y%m%d%H%M%S.%fZ'
            else:
                date_format = '%Y%m%d%H%M%SZ'
            if not val.lower().endswith('z'):
                val += 'Z'

            val = datetime.datetime.strptime(val, date_format)
        except TypeError:
            # maybe datetime.datetime
            pass
        return val.isoformat()

    callbacks = {
        "json": as_dict,
        "boolean": as_bool,
        "integer": as_int,
        "datetime": as_datetime,
    }

    type_ = attr_processor.get_type(name)
    callback = callbacks.get(type_)

    # maybe string
    if not callable(callback):
        return values

    return [callback(item) for item in values]


def transform_entry(entry, attr_processor):
    for k, v in entry.iteritems():
        v = transform_values(k, v, attr_processor)

        if len(v) == 1 and attr_processor.is_multivalued(k) is False:
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
            "document_key_prefix": ["groups_", "people_", "authorizations_"],
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

    persistence_type = os.environ.get("GLUU_PERSISTENCE_TYPE", "ldap")
    ldap_mapping = os.environ.get("GLUU_PERSISTENCE_LDAP_MAPPING", "default")

    if persistence_type != "couchbase":
        bucket_mappings = OrderedDict({
            name: mapping for name, mapping in bucket_mappings.iteritems()
            if name != ldap_mapping
        })
    return bucket_mappings
