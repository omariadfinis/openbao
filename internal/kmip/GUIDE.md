# KMIP 1.4 for OpenBao: proof of concept and test guide

This is a proof of concept that lets KMIP clients use OpenBao as their key
manager. A KMIP client connects over mutual TLS, authenticates with its client
certificate, and manages keys, secrets and cryptographic operations. Everything
it does runs through OpenBao's normal request path, so policies, audit and
namespaces apply.

> **Not for upstream.** The repository's `AGENTS.md` rejects AI-generated
> contributions. This code is a local proof of concept: do not open it as a pull
> request. If you ever want to propose KMIP support upstream, that work needs to
> be written by a person, in their own words.

## Contents

1. [What was built](#what-was-built)
2. [Quick start](#quick-start)
3. [Supported operations](#supported-operations)
4. [Configuration](#configuration)
5. [Identity and ownership](#identity-and-ownership)
6. [Running the automated tests](#running-the-automated-tests)
7. [Testing with PyKMIP](#testing-with-pykmip)
8. [Testing with Percona Server for MongoDB](#testing-with-percona-server-for-mongodb)
9. [Testing with Percona Server for MySQL](#testing-with-percona-server-for-mysql)
10. [Other KMIP clients](#other-kmip-clients)
11. [Troubleshooting](#troubleshooting)
12. [Known limitations](#known-limitations)
13. [What production would still need](#what-production-would-still-need)

## What was built

```
 KMIP client ──TLS 1.2+, client certificate──▶  kmip listener            internal/kmip
 (Percona, PyKMIP, ...)                          │  TTLV codec + batches   (ovh/kmip-go v0.9.2)
                                                 │  per-request login: cert auth, inline authentication
                                                 ▼
                                          Core.HandleRequest              policies, audit, namespaces
                                                 ▼
                                          kmip secrets engine            internal/builtin/logical/kmip
                                            objects, attributes, lifecycle state, ownership,
                                            key generation, AES-GCM, signatures, HMAC
```

| Piece | Where | What it does |
|---|---|---|
| Protocol listener | [internal/kmip](.) | Decodes TTLV, runs batches (including ID Placeholder), translates each KMIP operation into a request to the engine. |
| Config block | [internal/kmip/kmipconfig](kmipconfig) | The `kmip { ... }` block of the server configuration. |
| `kmip` secrets engine | [internal/builtin/logical/kmip](../builtin/logical/kmip) | Stores managed objects. Enforces the lifecycle, attribute rules and ownership. Registered as a builtin engine named `kmip`. |
| Server wiring | [internal/command/server.go](../command/server.go), [server/config.go](../command/server/config.go), [builtinplugins/registry.go](../helper/builtinplugins/registry.go) | Starts and stops the listener with the server, and registers the engine as a builtin. `registry_test.go` and `scripts/gen_openapi.sh` list it like the other builtin engines. |
| PoC scripts | [poc](poc) | Certificates, server start, setup, PyKMIP suite, Percona runners. |

How authentication works: KMIP has no bearer token. For every request the
listener builds an OpenBao request carrying the client's TLS certificate and
OpenBao's **inline authentication** headers, which makes core log in to the cert
auth method first and run the request as the resulting identity. No token is
stored, so a certificate that stops matching its role stops working on the next
request.

## Quick start

You need Go, `openssl`, Python 3, and (for the Percona databases) Docker.

```sh
# 1. Build the binary from this branch (repository root).
go build -o /tmp/bao .

# 2. Run everything: server, setup, and the PyKMIP interoperability suite.
cd internal/kmip/poc
BAO=/tmp/bao ./run-all.sh

# 3. Add the Percona databases (starts containers; pulls images on first use).
BAO=/tmp/bao WITH_PERCONA=1 ./run-all.sh

# 4. Clean up.
BAO=/tmp/bao ./cleanup.sh
```

`run-all.sh` keeps its files in `./kmip-poc-run` (override with `POC_DIR`). A
complete run, including both Percona databases, takes about 20 seconds once the
images are pulled.

The pieces, if you prefer them one at a time:

| Script | Purpose |
|---|---|
| `env.sh` | Shared settings: paths, ports, client names. Override any variable in the environment. |
| `gen-certs.sh` | Creates a CA, a server certificate and one certificate per client identity with `openssl`. |
| `start-server.sh` | Starts `bao server -dev` with the `kmip` block, in the background. |
| `setup-bao.sh` | Enables cert auth, mounts the `kmip` engine, writes a policy and a cert auth role. |
| `pykmip_test.py` | 22 PyKMIP tests against the running server. |
| `percona-mongodb.sh`, `percona-mysql.sh` | `up`, `verify`, `logs`, `down` for each database. |
| `inspect_objects.py` | Lists the objects one client identity can see. |
| `stop-server.sh`, `cleanup.sh` | Stop the server; remove containers and volumes. |

Set `KMIP_LOG_MESSAGES=true` before `start-server.sh` to log every KMIP request
and response as XML. That log contains key material, so use it for debugging
only.

## Supported operations

| KMIP operation | Status | Notes |
|---|---|---|
| Discover Versions, Query | Supported | Versions 1.4 down to 1.0. Query lists the real operations and object types. Both work without a client certificate when `tls_require_client_cert = false`. |
| Create | Supported | AES 128/192/256 and HMAC-SHA1/224/256/384/512 (128 to 1024 bits). New keys are Pre-Active. |
| Create Key Pair | Supported | RSA 2048/3072/4096, ECDSA P-256/384/521. Two linked objects. The curve may be given as a length or as Cryptographic Domain Parameters. |
| Register | Supported | Symmetric key, secret data (password, seed), opaque object, private and public keys. Key formats: Raw, Opaque, PKCS #1, PKCS #8, X.509, EC private key, transparent symmetric key. An Activation Date in the past registers the object as Active. |
| Re-key, Re-key Key Pair | Supported | Creates a new object linked both ways to the old one, which is left untouched. An activation offset is refused. |
| Get | Supported | Honours Extractable and Sensitive. Raw, PKCS #1/#8, X.509, EC private key, transparent symmetric key. Key wrapping and compression are refused. |
| Locate | Supported | Filter by any attribute, including custom ones. Paging with Maximum Items and Offset Items. Only the caller's own objects. |
| Get Attributes, Get Attribute List | Supported | |
| Add, Modify, Delete Attribute | Supported | Name, Object Group, Description, Comment, Cryptographic Usage Mask, Sensitive and custom `x-`/`y-` attributes. Server-managed attributes are read-only. |
| Activate, Revoke, Destroy | Supported | Full KMIP lifecycle, see below. |
| Check | Supported | State and usage mask only; usage limits and leases are refused. |
| Encrypt, Decrypt | Supported | AES-GCM only, with a server-chosen 96-bit IV, a 12 to 16 byte tag and optional additional data. Needs KMIP 1.4 (the tag field does not exist before). Other modes, client-supplied IVs and multi-part requests are refused. |
| Sign, Signature Verify | Supported | RSA PKCS #1 v1.5 and PSS, ECDSA, with SHA-224/256/384/512, over data or a digest. SHA-1 and MD5 are refused. |
| MAC, MAC Verify | Supported | HMAC keys. Defined locally, because the library has no payloads for them. |
| Hash | Supported | SHA-224/256/384/512. |
| RNG Retrieve | Supported | Up to 64 KiB per request. |
| Certify, Re-certify, Derive Key, Validate, Archive, Recover, Obtain Lease, Get Usage Allocation, Cancel, Poll, RNG Seed, Notify, Put, Import, Export, Split key operations | Not supported | Answered with Operation Not Supported (verified for Archive, Recover, Obtain Lease, Get Usage Allocation and Export). |

Object types: Symmetric Key, Secret Data, Opaque Object, Private Key, Public
Key. Not supported: Certificate, Split Key, PGP Key, Template.

**Lifecycle.** Pre-Active, then Active, Deactivated or Compromised, then
Destroyed or Destroyed Compromised.

- Activate moves Pre-Active to Active.
- Revoke with any reason except key compromise deactivates an Active object.
  Key compromise marks a Pre-Active, Active or Deactivated object Compromised.
- Destroy removes the key material but keeps the object as a tombstone. An
  Active object must be revoked first.
- Encrypt, Sign and MAC need an Active key. Decrypt, Signature Verify and MAC
  Verify also work on Deactivated and Compromised keys, so data protected
  earlier stays readable.
- Illegal state changes return Illegal Operation. KMIP 1.4 has no "Wrong Key
  Lifecycle State" result reason.

## Configuration

Add a `kmip` block to the server configuration (the PoC scripts generate one):

```hcl
kmip {
  address            = "0.0.0.0:5696"             # default 127.0.0.1:5696
  tls_cert_file      = "/path/to/server.pem"
  tls_key_file       = "/path/to/server.key"
  tls_client_ca_file = "/path/to/clients-ca.pem"  # the CA that issues client certificates
  auth_path          = "auth/cert/login"          # default
  auth_role          = "kmip-clients"             # optional cert auth role
  auth_namespace     = ""                         # optional
  mount_path         = "kmip/"                    # default
  tls_require_client_cert = true                  # default; false lets Query work without a certificate
  log_messages       = false                      # debugging only: logs key material
}
```

Then configure OpenBao (this is what `setup-bao.sh` does):

```sh
bao auth enable cert
bao secrets enable -path=kmip kmip

bao policy write kmip-client - <<'EOF'
path "kmip/*" { capabilities = ["create", "read", "update", "list"] }
EOF

bao write auth/cert/certs/kmip-clients \
    certificate=@ca.pem \
    allowed_common_names="mongod,mysqld,pykmip" \
    token_policies=kmip-client
```

Each KMIP operation is its own path in the engine, so policies can be narrow:
`kmip/create`, `kmip/register`, `kmip/get/*`, `kmip/encrypt/*`, `kmip/sign/*`,
and so on. For example, a client that may only encrypt and decrypt:

```hcl
path "kmip/encrypt/*" { capabilities = ["update"] }
path "kmip/decrypt/*" { capabilities = ["update"] }
path "kmip/locate"    { capabilities = ["update"] }
```

The engine can also be used over the plain HTTP API, which is handy for
debugging, but only as an identity that has an entity (see below).

## Identity and ownership

Each client certificate maps through the cert auth role to an OpenBao entity,
and **a managed object is only visible to the entity that created it**. That is
KMIP's default operation policy.

- Another identity gets "Item Not Found" for Get, Activate, Destroy and every
  other operation on someone else's object, and its Locate never lists it. It
  cannot tell the object exists.
- A database must therefore use the **same certificate identity** every time. If
  `mongod` restarts with a certificate that has a different common name, it will
  not find its master key.
- The scripts give each client its own common name (`mongod`, `mysqld`,
  `pykmip`, `alice`, `bob`) so you can see this isolation.
- A request with no entity (for example one made with the root token) is refused
  by the engine: objects must have an owner.

## Running the automated tests

```sh
# The Go tests (unit, engine, and end-to-end with real KMIP clients and a real core).
go test -race ./internal/kmip/... ./internal/builtin/logical/kmip/... ./internal/command/server/
```

| Package | Tests | Coverage | What it covers |
|---|---|---|---|
| `internal/builtin/logical/kmip` | 65 | 87% | Lifecycle, attributes, ownership, Register of every type and format, key pairs, Sign/Verify (checked against Go's own verifiers), MAC (checked against an independent HMAC), AES-GCM (checked against `crypto/cipher`), Re-key, Locate, Check. |
| `internal/kmip` | 76 | 82% | Mutual TLS, certificate login against a real unsealed core, every operation through the real `ovh/kmip-go` client, ID Placeholder batches, protocol versions 1.0 to 1.4, scripted replays of the Percona MySQL (1.4) and MongoDB (1.0) sessions, the config block and listener start. |
| `internal/kmip/kmipconfig` | 6 | 81% | Parsing and defaults of the `kmip` block. |

All pass with the race detector. The Go tests use the same library for client
and server, so they cannot catch a mistake both sides share. That is why the
suites below use independent clients.

## Testing with PyKMIP

[PyKMIP](https://github.com/OpenKMIP/PyKMIP) is an independent Python client and
is the KMIP server that Percona itself tests against.

```sh
cd internal/kmip/poc
BAO=/tmp/bao ./run-all.sh          # creates the virtualenv and runs the suite
# or, against a server you already started:
POC_DIR=$PWD/kmip-poc-run python3 pykmip_test.py -v
```

Result on this branch: **22 of 22 tests pass** (PyKMIP 0.11.0). They cover:
create, activate, get and destroy; all AES sizes; revoke and key compromise;
register of a symmetric key, secret data and an opaque object; locate by name and
by object type; RSA key pairs with sign and verify; HMAC; AES-GCM encrypt;
re-key; Check; isolation between two identities; rejection of an untrusted
certificate; and create, activate and get on each of KMIP 1.0, 1.1, 1.2, 1.3
and 1.4.

PyKMIP's attribute setters use KMIP 2.0's Set Attribute, which is outside this
1.4 implementation. Add, Modify and Delete Attribute are covered by the Go
tests instead.

## Testing with Percona Server for MongoDB

Tested with `percona/percona-server-mongodb:7.0`. Percona's KMIP client speaks
KMIP **1.0**. It generates an AES-256 key, registers it (Pre-Active), activates
it, and polls its state.

```sh
cd internal/kmip/poc
export BAO=/tmp/bao
./start-server.sh && ./setup-bao.sh      # skip if run-all.sh already did this
./percona-mongodb.sh up                  # mongod --enableEncryption --kmipServerName host.docker.internal ...
./percona-mongodb.sh verify
```

What `up` runs (the container reaches the host as `host.docker.internal`, which
is in the server certificate's SANs):

```sh
mongod --bind_ip_all --enableEncryption \
  --kmipServerName host.docker.internal --kmipPort 5696 \
  --kmipServerCAFile /certs/ca.pem \
  --kmipClientCertificateFile /certs/client-mongod-combined.pem
```

Observed on this branch:

- `db.serverStatus().encryptionAtRest` reports `encryptionEnabled: true`, cipher
  `AES256-CBC`, and a `kmip` key id.
- The key is visible in OpenBao as an AES-256 `SYMMETRIC_KEY` in state `ACTIVE`,
  owned by the `mongod` identity (`./inspect_objects.py mongod`).
- Restarting the container logs "Master encryption key has been read from the
  key management facility", and previously written documents are still readable.
- Master key rotation (`--kmipRotateMasterKey`) logs "Rotated master encryption
  key": a new key is created, the old one stays `ACTIVE`, and data remains
  readable under the new key id.

Operations observed on the wire: Register (symmetric key), Activate, Get
Attributes (State) on first start; Get on restart.

Notes: MongoDB can only enable encryption on an empty data directory, so `up`
removes the volume first. The certificate and key must be in one file, which
`gen-certs.sh` writes as `client-mongod-combined.pem`.

## Testing with Percona Server for MySQL

Tested with `percona/percona-server:8.4` (8.4.11-11) and its
`component_keyring_kmip`. Percona's component speaks KMIP **1.4**.

```sh
cd internal/kmip/poc
export BAO=/tmp/bao
./start-server.sh && ./setup-bao.sh
./percona-mysql.sh up
./percona-mysql.sh verify
```

`up` writes two files and mounts them into the container: a manifest
(`mysqld.my`, next to the `mysqld` binary) that loads the component early, and
the component's own config:

```json
{ "server_addr": "host.docker.internal", "server_port": "5696",
  "client_ca": "/certs/client-mysqld.pem",
  "client_key": "/certs/client-mysqld.key",
  "server_ca": "/certs/ca.pem" }
```

(`client_ca` is the client's own certificate, despite its name.)

Observed on this branch:

- `performance_schema.keyring_component_status` shows `Component_status: Active`.
- `CREATE TABLE ... ENCRYPTION='Y'` works, and `ALTER INSTANCE ROTATE INNODB
  MASTER KEY` creates a second master key. Both appear in OpenBao as AES-256
  `SYMMETRIC_KEY` objects named `INNODBKey-<server-uuid>-1` and `-2`, `ACTIVE`.
- After a restart, the encrypted table is still readable (the master key is
  located and fetched from OpenBao).
- With the `keyring_udf` plugin, `keyring_key_store('x','SECRET',...)` stores a
  `SECRET_DATA` object and `keyring_key_generate('y','AES',32)` an AES key.
  `keyring_key_remove` revokes ("Deleting the key", reason Unspecified) and then
  destroys the object, which ends in state `DESTROYED`.

Operations observed on the wire: Query on connect, Register (symmetric key or
secret data, with Name and optionally Object Group), Activate, Locate by Object
Type (repeatedly, with Maximum Items 256, 64 and 16), Get, Get Attributes
(Name, State), Revoke and Destroy.

**A limit of the client, not of this server.** After a restart,
`keyring_key_fetch()` on a *user* key stored with `keyring_key_store` returns
`NULL`, and removing it fails. The server answers every Locate, Get and Get
Attributes call correctly, and the reference PyKMIP server gives the identical
result, so this is how the component reloads owner-scoped user keys. InnoDB
master keys, which are what encrypt data, are unaffected.

## Other KMIP clients

| Client | Status |
|---|---|
| PyKMIP 0.11.0 (Python) | Tested, 22 of 22. |
| Percona Server for MongoDB 7.0 (KMIP 1.0) | Tested: create, restart, rotate. |
| Percona Server for MySQL 8.4 (KMIP 1.4) | Tested: encrypted tables, rotation, restart, secrets, removal. |
| `ovh/kmip-go` v0.9.2 client (Go) | Tested by the Go test suite, which uses it for every operation. |
| libkmip 0.2.1 demos (C) | `demo_create`, `demo_get` and `demo_destroy` pass (KMIP 1.0). `demo_query` aborts inside the demo's own cleanup ("pointer being freed was not allocated") after receiving a successful response, so it says nothing about the server. |
| MongoDB Enterprise, VMware vSphere/vSAN, NetApp, Oracle TDE, Kubernetes KMIP providers | Not tested here. Point them at the same address with a client certificate for a common name allowed by the cert auth role. Their operation needs are covered by the table above; the first thing to check is which KMIP version and which operations they send (`KMIP_LOG_MESSAGES=true`). |

To try another client, issue a certificate with `gen-certs.sh` (add its common
name to `KMIP_CLIENTS`), allow it in the cert auth role (`setup-bao.sh`), and
give the client the CA (`ca.pem`), its certificate and its key.

## Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| Client fails the TLS handshake with a hostname error | The server certificate needs a SAN for the name the client uses. Add it to `KMIP_HOSTS` and regenerate with `FORCE=1 ./gen-certs.sh`. |
| `bad certificate` or an immediate disconnect | The client certificate is not signed by `tls_client_ca_file`, or lacks the `clientAuth` extended key usage. |
| "Permission Denied" on every operation | The cert auth role does not allow the certificate's common name (`allowed_common_names`), the role name in `auth_role` is wrong, or the policy lacks the path. |
| "Item Not Found" for an object you just created | A different certificate identity is asking. Objects belong to the identity that created them. |
| Containers cannot reach the server | The listener must bind `0.0.0.0` (the default in the scripts) and the container needs `--add-host=host.docker.internal:host-gateway`. |
| mongod cannot read its certificate | The private key must be readable by the container user. `docker-certs.sh` makes world-readable copies for the PoC only. |
| `mongod` says encryption can only be enabled on an empty directory | Remove the data volume (`percona-mongodb.sh down`). |
| Keys are gone after restarting the server | The PoC uses a dev server with in-memory storage. A database that registered its key with a previous run will not find it. Use a persistent storage backend for anything longer-lived. |
| A client sends something unexpected | Set `KMIP_LOG_MESSAGES=true`, restart, and read the XML in `bao.log`. |

## Known limitations

- **Dev-mode server and in-memory storage** in the PoC scripts. The engine
  itself stores objects through the normal barrier-encrypted storage.
- **One login per request.** Inline authentication is correct and simple, but
  logs in on every operation. A short per-certificate cache would help.
- **AES-GCM only** for Encrypt and Decrypt, with random 96-bit IVs and no cap on
  the number of encryptions per key (the same property transit has).
- **Single-shot cryptographic operations.** No streaming (Correlation Value,
  Init and Final Indicator).
- **Locate scans every object** and filters in memory.
- **Key material is stored raw** in the engine's records, not through `keysutil`,
  so these keys cannot be used from the transit API.
- **The library drops the connection** when it cannot decode a request, instead
  of replying with an error. This was seen with a malformed Import request.
- **Re-key Key Pair modifies the old public key without locking it**, so a
  concurrent change to that one object could be lost.
- **Get releases key material** unless an object is created with
  `extractable = false` or `sensitive = true`. KMIP clients such as Percona's
  databases rely on Get, so the default is extractable, as KMIP specifies.
- **A Create Key Pair that fails midway** leaves nothing behind when the storage
  supports transactions; with non-transactional storage it could leave one half.

## What production would still need

- A real storage backend and a decision about **HA**: KMIP has no redirect
  mechanism, so clients should reach the active node, or the listener should
  forward.
- **Certificate reload** without a restart, revocation checks (OCSP or CRL) at
  the TLS layer, and an operator-friendly way to manage client identities.
- **Audit review**: confirm that key material in Get, Register, Encrypt and
  Decrypt requests is HMAC'd in every audit device.
- **Fuzzing and size limits** on the TTLV decoder, which runs before
  authentication, and a limit on concurrent connections.
- **Conformance testing** against the OASIS KMIP 1.4 profile test cases before
  claiming any profile (Baseline Server, Symmetric Key Lifecycle Server, Basic
  Cryptographic Server).
- Metrics for the listener and the per-operation latency.
