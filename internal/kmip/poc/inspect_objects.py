#!/usr/bin/env python3
"""List the managed objects visible to one KMIP client identity, with their
type, state, name and group. Use it to see what Percona MongoDB or MySQL
stored in OpenBao.

    python3 inspect_objects.py mongod     # identity = a client certificate CN

Objects are only visible to the identity that created them, so inspect as the
same identity the database uses (mongod, mysqld, ...).
"""
import os
import sys

from kmip import enums
from kmip.pie import client as pie_client

POC_DIR = os.environ.get("POC_DIR", os.path.join(os.getcwd(), "kmip-poc-run"))
HOST = os.environ.get("KMIP_HOST", "localhost")
PORT = int(os.environ.get("KMIP_PORT", "5696"))


def main():
    identity = sys.argv[1] if len(sys.argv) > 1 else "pykmip"
    certs = os.path.join(POC_DIR, "certs")
    conf = os.path.join(POC_DIR, "pykmip.conf")
    if not os.path.exists(conf):
        with open(conf, "w") as f:
            f.write("[client]\n")

    c = pie_client.ProxyKmipClient(
        hostname=HOST, port=PORT,
        cert=os.path.join(certs, f"client-{identity}.pem"),
        key=os.path.join(certs, f"client-{identity}.key"),
        ca=os.path.join(certs, "ca.pem"),
        config_file=conf,
        kmip_version=enums.KMIPVersion.KMIP_1_4,
    )
    with c:
        uids = c.locate()
        print(f"{len(uids)} object(s) visible to '{identity}'")
        for uid in uids:
            _, attrs = c.get_attributes(
                uid, ["Object Type", "State", "Name", "Object Group", "Cryptographic Algorithm", "Cryptographic Length"]
            )
            info = {}
            for a in attrs:
                v = a.attribute_value
                v = getattr(v, "value", v)
                v = getattr(v, "name", v)
                if hasattr(v, "name_value"):
                    v = v.name_value.value
                info[a.attribute_name.value] = v
            print(f"  {uid}")
            for k, v in info.items():
                print(f"      {k}: {v}")


if __name__ == "__main__":
    main()
