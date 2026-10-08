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
