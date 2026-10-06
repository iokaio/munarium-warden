# Experimental Warden runtime

This increment implements Warden's identity, grant, activation, suspension and broker
operations as a Rust library. It follows the hub's **proposed** ADRs 0002, 0003 and
0005. It does not claim an accepted wire contract or a qualified platform composition.
The user-authorized scope includes grants, brokering and activation; the earlier
identity-only preparation packet is historical.

## Run it

Use Rust 1.98.1 and a native C/C++ linker (SQLite and ring compile native code).
Fetch the locked public dependencies once, then run offline:

```console
cargo fetch --locked
cargo build --offline --locked
cargo test --offline --locked -- --nocapture
```

The ordinary suite uses real SQLite files, independent connections, an abrupt-exit
child process, Ed25519 signatures and local HTTP fixtures. No sibling checkout,
provider account or production credential is required. Two ignored helper functions
are invoked by their parent tests in subprocesses; they are not missing coverage.

For the actual OpenBao broker path, start Docker and run:

```console
docker pull ghcr.io/openbao/openbao:2.4.4@sha256:01bdba095690b1fe7cc1ec956ca422cfe01fd9a994ea28d9a6a2f84886dc9569
cargo test --offline --locked --test broker openbao_live_broker_flow -- --ignored --exact --nocapture
```

This test creates a uniquely named `warden-test-*` container, publishes an ephemeral
port only on `127.0.0.1`, seeds a fictional random credential, runs activation and
issuance, retrieves that value through `OpenBao`, delivers it to a child process,
and verifies refusal after suspension. It removes its own container and anonymous
volumes on completion or assertion failure. It preserves the downloaded image cache.
There are no host mounts or changes to existing stacks. An interrupted test may leave
its named container; inspect that exact name before removing it. Do not prune Docker.

OpenBao [dev mode](https://openbao.org/docs/concepts/dev-server/) is disposable and
in-memory. The pinned public image is a test input, not a supported production version.
The integration uses loopback HTTP and a fictional dev token. The normal client
constructor requires HTTPS, verifies certificates, disables redirects/proxies and
bounds connection time, request time and response size.

## Implemented behavior

| Operation | Implementation and exercised boundary |
|---|---|
| Verify identity | [principal.rs](../src/principal.rs): strict Ed25519 verification with provisioned keys; canonical, bounded envelopes; issuer, tenant, deployment, audience, peer, time and purpose checks; non-human origins; unique registered delegation edges, depth, task/policy and scope/resource narrowing. |
| Issue a grant | [authority.rs](../src/authority.rs): authenticate the durable Gate claim through an adapter, compare the complete binding, verify current identity, check activation/suspension, and commit one issuance before returning. Concurrent identical retries return the same identifier and original expiry. |
| Validate online | Reverify current identity and keys; require stored issuance, current epochs, Gate consumption, worker/fence, lease and exact acknowledged predispatch digest. Tickets last at most five seconds and never extend the original grant. |
| Activate | Verify the scoped Council transition and still-held Gate barrier through the control adapter; compare expected prior epoch; persist policy/mode/recovery epoch and return Warden's acknowledgement. Changed retries and stale epochs conflict. Observe/advise cannot issue grants. |
| Suspend | Authenticated instance, agent-version, deployment or tenant requests create durable tombstones. Subsequent issuance and validation refuse affected work, including after reopening the store. No automatic restoration is implemented. |
| Broker | [credential.rs](../src/credential.rs): exact resource-to-OpenBao URL mapping; intended connector audience; online validation before and after secret retrieval; delivery only to a privileged connector adapter; sanitized errors and credential-free receipts. |

Identity tests preserve the hub's 32 signed vectors and verify the LF-normalized
source digest. `valid-bootstrap` is deliberately refused because this implementation
supports non-human decision authority only; the golden expected value is unchanged.
Other positive vectors must pass. Additional component tests cover decision-path
refusals, current key purpose, registration ambiguity and task/policy boundaries.

## Integration boundary

`Gate`, `ControlPlane`, `LiveIdentity`, `SecretProvider` and `Connector` are **trusted
application adapters**. They are not agent request objects. No network service accepts
caller-supplied booleans as proof of authentication. Applications must provision these
adapters inside the Warden/connector privilege domain and authenticate their peers.
No concrete authenticated Gate/Council/Registry transport is claimed by this library.

`ControlPlane::activation` must verify Council's attestation and Gate's durable pause
for the exact tenant, deployment, cell, transition and epochs. `Store::activate`
installs Warden's part only. Council must collect Registry and Warden acknowledgements;
Gate applies the epoch and resumes separately. A Warden receipt cannot resume Gate.

`LiveIdentity` must fetch current key and Registry authority and verify the signed
chain on **each** call. The library compares its verified task/policy and principal
digest with the grant binding. An unavailable or stale adapter must return an error.
The signed principal path is implemented; external OIDC federation, provider-subject
mapping and attribution-only forwarding from ADR 0005 are not implemented here.

Gate owns atomic consumption, worker acquisition, action reservations and final send
admission. A connector must perform Gate's final compare-and-swap for the exact live
invocation immediately before its one send attempt. A ticket or previous successful
receipt is not reusable dispatch permission. The tests use explicit Gate/Council
fixtures; they do not establish these other components' transaction guarantees.

The child-process probe exercises an owned credential channel and checks stdout,
stderr and the child's environment. It does **not** establish a separate OS security
principal, hostile-agent isolation, all prompt/memory/trace channels, mTLS termination,
or an effect-producing connector. Production credential isolation remains unqualified.
KV v2 supplies a reusable secret; neither the provider nor the secret is called
single-use. Secret buffers use best-effort zeroization; HTTP/JSON libraries and the OS
can retain copies, so memory erasure is not a security claim.
Any error after connector delivery begins becomes `Unresolved`; the broker does not
retry the delivery or equate an acknowledgement failure with proven no effect.

## Persistence, recovery and time

SQLite uses WAL, full synchronous commits and immediate write transactions. Stores
are bound to one tenant/deployment/cell. The backend is a single-node experiment;
it does not implement the hub's proposed PostgreSQL reference deployment, replication,
rolling upgrades, availability or cross-cell authority.

The control adapter obtains the recovery epoch **outside** the database. It must report
unhealthy on startup until the operator's recovery procedure excludes rollback,
restored snapshots and old dispatchers. An old database cannot establish its own
health. Tests restore an actual older database and require quarantine or an externally
advanced epoch to refuse its old grants. This does not implement external epoch custody
or authorize automatic recovery. Suspensions have no deletion/resume API.

The proposed bounds are a 30-second grant, five-second ticket and two-second clock
uncertainty margin. The test clock is controlled; admission requires `now + 2 < expiry`.
Local suspension timings are observations of this process/store only. They do not
establish the proposed seven-second distributed admission bound or recall an already
admitted target effect. A deployment must qualify its clock, adapter freshness and
final Gate admission behavior before claiming that bound.

## Review and evidence

The change exceeds 500 lines because the security properties span signature
verification, durable issuance, activation, revocation and credential delivery.
These form one executable authority slice with shared negative tests. There is no
merge/release request, human acceptance claim or independent review recorded here.
The work remains an experimental, non-publishable local change.

See [validation](validation.md), the [retained local run](evidence/2026-10-06-local.txt)
and [dependency notices](../THIRD_PARTY_NOTICES.md). Local checks do not establish
remote CI. The original foundation fixtures and their approval history are unchanged.

The [Rust workflow](../.github/workflows/rust.yml) fetches locked public dependencies
before its offline build, lint, test and documentation checks. The
[contributor guide](../CONTRIBUTING.md) describes the same setup. These build-support
changes were authorized on 6 October 2026; workflow permissions and existing gates
remain unchanged. See the [local build-support check](evidence/2026-10-06-build-support.txt).
