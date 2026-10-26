#!/usr/bin/env python3
"""Interoperability test: drive the OpenBao KMIP listener with PyKMIP, an
independent KMIP client, and check every result.

    pip install PyKMIP
    POC_DIR=... python3 pykmip_test.py            # all tests
    python3 pykmip_test.py -v Lifecycle           # one class, verbose

Settings come from the environment (the defaults match env.sh):
    POC_DIR    directory holding certs/ (default ./kmip-poc-run)
    KMIP_HOST  server name in the certificate (default localhost)
    KMIP_PORT  default 5696
"""
import os
import sys
import unittest
import uuid

from kmip import enums
from kmip.core import exceptions as kmip_exceptions
from kmip.pie import client as pie_client
from kmip.pie import objects

POC_DIR = os.environ.get("POC_DIR", os.path.join(os.getcwd(), "kmip-poc-run"))
HOST = os.environ.get("KMIP_HOST", "localhost")
PORT = int(os.environ.get("KMIP_PORT", "5696"))
CERTS = os.path.join(POC_DIR, "certs")

OP_ENCRYPT_DECRYPT = [
    enums.CryptographicUsageMask.ENCRYPT,
    enums.CryptographicUsageMask.DECRYPT,
]


def _config_file():
    """PyKMIP warns when it finds no config file even though every setting is
    passed explicitly, so give it a minimal one."""
    path = os.path.join(POC_DIR, "pykmip.conf")
    if not os.path.exists(path):
        os.makedirs(POC_DIR, exist_ok=True)
        with open(path, "w") as f:
            f.write("[client]\n")
    return path


def connect(identity="pykmip", version=enums.KMIPVersion.KMIP_1_4):
    """Open a client that authenticates as the given certificate identity."""
    c = pie_client.ProxyKmipClient(
        config_file=_config_file(),
        hostname=HOST,
        port=PORT,
        cert=os.path.join(CERTS, f"client-{identity}.pem"),
        key=os.path.join(CERTS, f"client-{identity}.key"),
        ca=os.path.join(CERTS, "ca.pem"),
        kmip_version=version,
    )
    c.open()
    return c


def tag():
    """A unique suffix, so repeated runs never collide on names."""
    return uuid.uuid4().hex[:8]


class Base(unittest.TestCase):
    VERSION = enums.KMIPVersion.KMIP_1_4
    IDENTITY = "pykmip"

    def setUp(self):
        self.c = connect(self.IDENTITY, self.VERSION)
        self.addCleanup(self.c.close)
        self.created = []

    def tearDown(self):
        # Best-effort cleanup: revoke (if active) then destroy.
        for uid in self.created:
            try:
                self.c.revoke(enums.RevocationReasonCode.UNSPECIFIED, uid)
            except Exception:
                pass
            try:
                self.c.destroy(uid)
            except Exception:
                pass

    def make_key(self, bits=256, name=None, activate=True, mask=None):
        uid = self.c.create(
            enums.CryptographicAlgorithm.AES,
            bits,
            name=name or f"pykmip-{tag()}",
            cryptographic_usage_mask=mask or OP_ENCRYPT_DECRYPT,
        )
        self.created.append(uid)
        if activate:
            self.c.activate(uid)
        return uid

    def state(self, uid):
        attrs = self.c.get_attributes(uid, ["State"])[1]
        return attrs[0].attribute_value.value


class Lifecycle(Base):
    def test_create_activate_get(self):
        uid = self.make_key(256, activate=False)
        self.assertEqual(self.state(uid), enums.State.PRE_ACTIVE)

        self.c.activate(uid)
        self.assertEqual(self.state(uid), enums.State.ACTIVE)

        key = self.c.get(uid)
        self.assertIsInstance(key, objects.SymmetricKey)
        self.assertEqual(key.cryptographic_algorithm, enums.CryptographicAlgorithm.AES)
        self.assertEqual(key.cryptographic_length, 256)
        self.assertEqual(len(key.value), 32)

        # The same key every time.
        self.assertEqual(self.c.get(uid).value, key.value)

    def test_all_aes_sizes(self):
        for bits in (128, 192, 256):
            uid = self.make_key(bits)
            self.assertEqual(len(self.c.get(uid).value) * 8, bits)

    def test_revoke_and_destroy(self):
        uid = self.make_key()
        self.c.revoke(enums.RevocationReasonCode.SUPERSEDED, uid, "rotated")
        self.assertEqual(self.state(uid), enums.State.DEACTIVATED)

        self.c.destroy(uid)
        self.assertEqual(self.state(uid), enums.State.DESTROYED)
        with self.assertRaises(Exception):
            self.c.get(uid)

    def test_key_compromise(self):
        uid = self.make_key()
        self.c.revoke(enums.RevocationReasonCode.KEY_COMPROMISE, uid, "leaked")
        self.assertEqual(self.state(uid), enums.State.COMPROMISED)

    def test_active_key_cannot_be_destroyed(self):
        uid = self.make_key()
        with self.assertRaises(Exception):
            self.c.destroy(uid)

    def test_unknown_object(self):
        with self.assertRaises(Exception):
            self.c.get("00000000-0000-0000-0000-000000000000")


class Attributes(Base):
    def test_name_and_group_and_locate(self):
        name = f"locate-{tag()}"
        uid = self.make_key(name=name)

        found = self.c.locate(
            attributes=[
                self.c.attribute_factory.create_attribute(
                    enums.AttributeType.NAME, name
                )
            ]
        )
        self.assertEqual(found, [uid])

    def test_attribute_list_and_get(self):
        uid = self.make_key()
        names = self.c.get_attribute_list(uid)
        for expected in ("State", "Cryptographic Length", "Unique Identifier"):
            self.assertIn(expected, names)

        _, attrs = self.c.get_attributes(uid, ["Cryptographic Length"])
        self.assertEqual(attrs[0].attribute_value.value, 256)


class EncryptDecrypt(Base):
    PARAMS = {
        "cryptographic_algorithm": enums.CryptographicAlgorithm.AES,
        "block_cipher_mode": enums.BlockCipherMode.GCM,
    }

    def test_round_trip(self):
        uid = self.make_key()
        plaintext = b"interop plaintext"
        result = self.c.encrypt(plaintext, uid=uid, cryptographic_parameters=self.PARAMS)
        ciphertext, iv = result[0], result[1]
        self.assertNotEqual(ciphertext, plaintext)
        self.assertEqual(len(iv), 12)

    def test_unsupported_mode_is_refused(self):
        uid = self.make_key()
        params = dict(self.PARAMS, block_cipher_mode=enums.BlockCipherMode.ECB)
        with self.assertRaises(Exception):
            self.c.encrypt(b"x", uid=uid, cryptographic_parameters=params)


class Register(Base):
    def test_symmetric_key(self):
        material = os.urandom(32)
        key = objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES, 256, material, OP_ENCRYPT_DECRYPT,
            name=f"registered-{tag()}",
        )
        uid = self.c.register(key)
        self.created.append(uid)
        self.assertEqual(self.c.get(uid).value, material)
        self.assertEqual(self.state(uid), enums.State.PRE_ACTIVE)

    def test_secret_data(self):
        secret = objects.SecretData(
            b"correct horse battery staple", enums.SecretDataType.PASSWORD,
            name=f"secret-{tag()}",
        )
        uid = self.c.register(secret)
        self.created.append(uid)
        got = self.c.get(uid)
        self.assertIsInstance(got, objects.SecretData)
        self.assertEqual(got.value, b"correct horse battery staple")

    def test_opaque_object(self):
        blob = bytes(range(16))
        uid = self.c.register(
            objects.OpaqueObject(blob, enums.OpaqueDataType.NONE, name=f"opaque-{tag()}")
        )
        self.created.append(uid)
        self.assertEqual(self.c.get(uid).value, blob)

    def test_locate_by_object_type(self):
        uid = self.c.register(
            objects.SecretData(b"x", enums.SecretDataType.SEED, name=f"seed-{tag()}")
        )
        self.created.append(uid)
        found = self.c.locate(
            attributes=[
                self.c.attribute_factory.create_attribute(
                    enums.AttributeType.OBJECT_TYPE, enums.ObjectType.SECRET_DATA
                )
            ]
        )
        self.assertIn(uid, found)


class KeyPairs(Base):
    def make_pair(self):
        # PyKMIP returns the public key identifier first.
        pub, priv = self.c.create_key_pair(
            enums.CryptographicAlgorithm.RSA,
            2048,
            private_usage_mask=[enums.CryptographicUsageMask.SIGN],
            public_usage_mask=[enums.CryptographicUsageMask.VERIFY],
        )
        self.created.extend([priv, pub])
        self.c.activate(priv)
        self.c.activate(pub)
        return priv, pub

    def test_create_and_get(self):
        priv, pub = self.make_pair()
        self.assertIsInstance(self.c.get(priv), objects.PrivateKey)
        self.assertIsInstance(self.c.get(pub), objects.PublicKey)

    def test_sign_and_verify(self):
        priv, pub = self.make_pair()
        params = {
            "cryptographic_algorithm": enums.CryptographicAlgorithm.RSA,
            "hashing_algorithm": enums.HashingAlgorithm.SHA_256,
            "padding_method": enums.PaddingMethod.PKCS1v15,
        }
        data = b"sign me"
        signature = self.c.sign(data, uid=priv, cryptographic_parameters=params)
        self.assertGreater(len(signature), 0)

        ok = self.c.signature_verify(data, signature, uid=pub, cryptographic_parameters=params)
        self.assertEqual(ok, enums.ValidityIndicator.VALID)
        bad = self.c.signature_verify(b"other", signature, uid=pub, cryptographic_parameters=params)
        self.assertEqual(bad, enums.ValidityIndicator.INVALID)


class Rekey(Base):
    def test_rekey(self):
        uid = self.make_key()
        fresh = self.c.rekey(uid)
        self.created.append(fresh)
        self.assertNotEqual(uid, fresh)
        self.assertNotEqual(self.c.get(uid).value, self.c.get(fresh).value)


class MACAndCheck(Base):
    def test_hmac(self):
        uid = self.c.create(
            enums.CryptographicAlgorithm.HMAC_SHA256,
            256,
            name=f"hmac-{tag()}",
            cryptographic_usage_mask=[
                enums.CryptographicUsageMask.MAC_GENERATE,
                enums.CryptographicUsageMask.MAC_VERIFY,
            ],
        )
        self.created.append(uid)
        self.c.activate(uid)

        key = self.c.get(uid).value
        data = b"authenticate me"
        _, mac = self.c.mac(data, uid=uid, algorithm=enums.CryptographicAlgorithm.HMAC_SHA256)

        import hashlib
        import hmac as pyhmac

        self.assertEqual(mac, pyhmac.new(key, data, hashlib.sha256).digest())

    def test_check(self):
        uid = self.make_key()
        self.assertEqual(
            self.c.check(uid, cryptographic_usage_mask=[enums.CryptographicUsageMask.ENCRYPT]),
            uid,
        )
        with self.assertRaises(Exception):
            self.c.check(uid, cryptographic_usage_mask=[enums.CryptographicUsageMask.SIGN])


class Isolation(unittest.TestCase):
    """Two identities cannot see each other's objects."""

    def test_other_identity_cannot_see_object(self):
        alice = connect("alice")
        bob = connect("bob")
        self.addCleanup(alice.close)
        self.addCleanup(bob.close)

        uid = alice.create(
            enums.CryptographicAlgorithm.AES, 256, name=f"alice-only-{tag()}",
            cryptographic_usage_mask=OP_ENCRYPT_DECRYPT,
        )
        self.addCleanup(lambda: alice.destroy(uid))

        with self.assertRaises(Exception):
            bob.get(uid)
        self.assertNotIn(uid, bob.locate())
        self.assertIn(uid, alice.locate())


class AuthenticationRequired(unittest.TestCase):
    def test_unknown_certificate_is_rejected(self):
        # A client whose certificate the server does not trust cannot connect.
        c = pie_client.ProxyKmipClient(
            hostname=HOST, port=PORT,
            cert=os.path.join(CERTS, "ca.pem"),  # not a client certificate
            key=os.path.join(CERTS, "ca.key"),
            ca=os.path.join(CERTS, "ca.pem"),
        )
        with self.assertRaises(Exception):
            c.open()
            c.create(enums.CryptographicAlgorithm.AES, 256)


class OlderProtocolVersions(unittest.TestCase):
    """The server speaks every KMIP 1.x version; MongoDB, for one, uses 1.0."""

    def test_each_version_can_create_and_get(self):
        for version in (
            enums.KMIPVersion.KMIP_1_0,
            enums.KMIPVersion.KMIP_1_1,
            enums.KMIPVersion.KMIP_1_2,
            enums.KMIPVersion.KMIP_1_3,
            enums.KMIPVersion.KMIP_1_4,
        ):
            with self.subTest(version=version):
                c = connect("pykmip", version)
                try:
                    uid = c.create(
                        enums.CryptographicAlgorithm.AES, 256, name=f"v-{tag()}",
                        cryptographic_usage_mask=OP_ENCRYPT_DECRYPT,
                    )
                    c.activate(uid)
                    self.assertEqual(len(c.get(uid).value), 32)
                    c.revoke(enums.RevocationReasonCode.UNSPECIFIED, uid)
                    c.destroy(uid)
                finally:
                    c.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
