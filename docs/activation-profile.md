# Experimental Stage 2 activation participant

Warden now has a separate authenticated participant adapter for the unchanged
[Stage 2 candidate](../contracts/stage2-v1/README.md), following hub
[ADR 0014](https://github.com/iokaio/munarium-platform/blob/main/docs/decisions/0014-stage2-service-integration.md).
Hub input is `27c3e6c`, Council `6ea0822` and Registry `eb08f75`.
This does not mount grant issuance, credential brokering or connector routes.
The older authority library experiment remains separate and is not wired into
this participant's epoch. Future grant integration must use this admitted state.

## Configuration and requests

The existing service configuration accepts an optional `activation` object:
`database` (absolute SQLite path), `service`, and HTTPS `council_endpoint`,
`gate_endpoint`, `registry_endpoint`. It reuses the enrolled mTLS identity and
Server endpoint. Omitting it leaves activation unavailable and preserves identity
issuance.

Current Server governing bindings at `stage2:<service>` must contain `scope`
(domain, tenant, deployment, cell), `coordinator` (Council's enrolled service),
`readers`, `initial_epoch` and `initial_artifact_set_digest`. Admit those bindings
through the existing non-agent governing ceremony. An enrolled reader cannot apply;
an ordinary agent credential cannot become a coordinator.

POST `/v1/activation` takes `{"tenant":"tenant-a","action":{...}}`:

| Operation | Additional fields | Result |
|---|---|---|
| `apply` | `transition`: canonical activation JSON string | Original durable Warden applied receipt |
| `lookup` | `transition_id` | Historical exact receipt; no state mutation |
| `head` | none | Current participant epoch/set; `cell_resumed:false` |

For apply, Warden independently reads current Council ratification, Gate's matching
pause and current paused head, and Registry's applied receipt and current head.
It verifies exact transition, qualified scope, hashes, participant membership and
the validity window including two seconds of clock uncertainty. A governing
revision change during dependency lookups refuses. No caller receipt is accepted
as a substitute for those authenticated lookups.

## Durability and support boundary

Additive `stage2_*` tables use SQLite WAL, full synchronous writes and immediate
transactions. Expected-head comparison, epoch installation, original receipt and
local outbox commit together. Two connections applying competing transitions have
one winner. Retry returns the original receipt; changed bytes under the same
transition ID conflict. The original enrollment is retained separately from the
evolving head and cannot be reset by config reload. Restart returns committed
receipts. Lookup never establishes global activation.

Pending outbox records remain local; acknowledged Server event delivery is still
required. The complete Council/Registry/Gate/Server/Warden composition, Server's
participant route, snapshot quarantine, revocation/issuance integration and target
effects are not qualified here. Expired/revoked authority refuses new apply even
when a historical receipt remains readable. A process restart is not proof of
safe snapshot restoration.

## Validation

```console
cargo test --offline --locked --test activation
cargo build --offline --locked
python scripts/test_activation_service.py -v
```

Rust cases exercise independent candidate bindings, restart and exact outbox
recovery, competing connections, scope refusal and missing/stale dependency
evidence. The native test runs the real Warden binary with disposable certificates,
kills and restarts it, and probes unregistered, agent, reader and foreign-tenant
access. Its Council, Gate, Registry and Server dependencies are synthetic
authenticated test servers; this is component evidence, not REF-18 qualification.
CI retains identity package tests and adds the native participant scenario.
All test keys, databases and listeners are local, synthetic and temporary; the
test owns their cleanup and uses no paid or production resources.

## Participant audit delivery

The coordinator may POST `flush` to the existing activation route (Gate uses
`/v1/actions`). Each call delivers at most one pending applied receipt. A reader
cannot flush. The response reports `delivered:1` with the exact Server
acknowledgement, or `delivered:0` when no intent remains pending. Retry until zero;
dependency failure or an invalid acknowledgement keeps the oldest event pending.
Expiry of the transition does not invalidate historical delivery authority.
Current Server identity/stream admission still applies to every append.

Add the optional top-level service configuration `delivery` with `server_service`,
`warden_endpoint` (an HTTPS origin), `provider_id` and absolute
`provider_token_file`. The file is operator-supplied and never logged. Warden's
provider enrollment must bind the actual service peer to the Server audience,
`propose` scope and `action-records:<tenant>` resource. Server must enroll this
peer for recording and admit its current identity in `identity:<Server service>`.
No caller assertion or forwarding header supplies the recorder identity.

The current `action-records:<Server service>` binding must register exactly one
stream for this service/producer with only `activation-applied` in `kinds`.
Source generation and stream are pinned by the first materialized event. A changed
registration refuses rather than rewriting pending history or guessing a new
sequence. The stream must be dedicated to this owner database.

Operational receipts and intent remain atomic. Additive delivery tables retain
canonical event bytes before sending, then the exact acknowledgement after closed
schema, event/payload hash, qualified scope and ledger-position validation. The
event timestamp is the first durable delivery observation. A lost response retries
the same event, source sequence and timestamp; concurrent flushes are duplicates,
not new facts. Receipt intent remains retained after acknowledgement. Server must
already hold the Council transition, normally archived by Server's participant
apply. Gate pause/resume history has no invented candidate event type.

This is audit delivery, not execution admission or snapshot reconciliation. Missing
source history and changed generations fail closed. Component restart/negative
acknowledgement tests and Harness's real-service delivery test exercise this path.
No production trust, target effect or recovery qualification is claimed.

## Prepared release grant and custody adapter

The opt-in `/v1/grants` and `/v1/custody` routes require Server's current signed
`execution:<service>` binding: `scope`, enrolled `gate` and `connector`, dedicated
`stream`/`generation`, external `recovery`, exact `target` and `blocked` operation
IDs. Without that binding they refuse. The actual mTLS peer, not a supplied worker
name, determines which operation may run. Gate alone issues/validates; the enrolled
connector alone receives credential bytes from the separate custody endpoint.

Issuance independently fetches Gate's claim and exact Server custody plus Council's
current approval. The local activation set must match. SQLite commits the original
thirty-second grant and canonical `grant-issued` event together. Lost replies,
restart and retry preserve the original expiry and bytes. `flush` delivers pending
issuance evidence even after expiry without creating current authority.

Custody requires actual consumption, the owning connector/fence, exact predispatch
acknowledgement, current approval, unblocked operation and matching recovery. It
binds one invocation for at most five seconds; retry cannot renew it. Optional
operator configuration `broker` pins `endpoint`, `token_file` and `resource` for
OpenBao KV v2. `loopback_test:true` only permits the existing literal-loopback HTTP
disposable test constructor. Credentials are returned as a non-cacheable binary
response on the connector-authenticated custody endpoint, never in a grant or audit
record. The adapter revalidates after provider I/O and before returning bytes.

The existing generic authority/broker APIs remain compatible. This new single-node
SQLite adapter is experimental; mTLS enrollment is not proof of OS isolation.
Restored stores cannot choose their own recovery generation or renew old grants.
Automatic rollback detection and reconciled reopening are not implemented here.
Harness provides real-service PostgreSQL/SQLite/OpenBao/target composition evidence;
component tests cover immutable issuance, custody binding, expiry and generation
refusals. No production credential or target is authorized by these tests.
