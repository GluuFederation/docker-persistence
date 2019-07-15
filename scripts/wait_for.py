import argparse
import base64
import logging
import os
import sys
import time

import pyDes

from cbm import CBM
from gluulib import get_manager

logger = logging.getLogger("wait_for")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
fmt = logging.Formatter('%(levelname)s - %(name)s - %(asctime)s - %(message)s')
ch.setFormatter(fmt)
logger.addHandler(ch)


def wait_for_config(manager, max_wait_time, sleep_duration):
    for i in range(0, max_wait_time, sleep_duration):
        try:
            reason = "config 'hostname' is not available"
            if manager.config.get("hostname"):
                logger.info("Config backend is ready.")
                return
        except Exception as exc:
            reason = exc

        logger.warn("Config backend is not ready; reason={}; "
                    "retrying in {} seconds.".format(reason, sleep_duration))
        time.sleep(sleep_duration)

    logger.error("Config backend is not ready after {} seconds.".format(max_wait_time))
    sys.exit(1)


def wait_for_secret(manager, max_wait_time, sleep_duration):
    for i in range(0, max_wait_time, sleep_duration):
        try:
            reason = "secret 'ssl_cert' is not available"
            if manager.secret.get("ssl_cert"):
                logger.info("Secret backend is ready.")
                return
        except Exception as exc:
            reason = exc

        logger.warn("Secret backend is not ready; reason={}; "
                    "retrying in {} seconds.".format(reason, sleep_duration))
        time.sleep(sleep_duration)

    logger.error("Secret backend is not ready after {} seconds.".format(max_wait_time))
    sys.exit(1)


def wait_for_couchbase(manager, max_wait_time, sleep_duration):
    def cb_password(encoded_password, encoded_salt):
        cipher = pyDes.triple_des(
            b"{}".format(encoded_salt),
            pyDes.ECB,
            padmode=pyDes.PAD_PKCS5
        )
        encrypted_text = b"{}".format(base64.b64decode(encoded_password))
        return cipher.decrypt(encrypted_text)

    hostname = os.environ.get("GLUU_COUCHBASE_URL", "localhost")
    user = manager.config.get("couchbase_server_user")
    salt = manager.secret.get("encoded_salt")
    password = manager.secret.get("encoded_couchbase_server_pw")
    cbm = CBM(hostname, user, cb_password(password, salt))

    for i in range(0, max_wait_time, sleep_duration):
        try:
            if cbm.test_connection():
                logger.info("Couchbase backend is ready.")
                return
            else:
                reason = "Connection is not ready"
        except Exception as exc:
            reason = exc

        logger.warn("Couchbase backend is not ready; reason={}; "
                    "retrying in {} seconds.".format(reason, sleep_duration))
        time.sleep(sleep_duration)

    logger.error("Couchbase backend is not ready after {} seconds.".format(max_wait_time))
    sys.exit(1)


def wait_for(manager, deps=None):
    deps = deps or []

    try:
        max_wait_time = int(os.environ.get("GLUU_WAIT_MAX_TIME", 300))
    except ValueError:
        max_wait_time = 300

    try:
        sleep_duration = int(os.environ.get("GLUU_WAIT_SLEEP_DURATION", 5))
    except ValueError:
        sleep_duration = 5

    if "config" in deps:
        wait_for_config(manager, max_wait_time, sleep_duration)

    if "secret" in deps:
        wait_for_secret(manager, max_wait_time, sleep_duration)

    if "couchbase" in deps:
        wait_for_couchbase(manager, max_wait_time, sleep_duration)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--deps", help="Comma-separated dependencies to wait for.")
    args = parser.parse_args()

    deps = set(filter(
        None,
        [dep.strip() for dep in args.deps.split(",") if dep]
    ))

    manager = get_manager()
    wait_for(manager, deps)
