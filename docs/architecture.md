# Munarium Warden implementation architecture

**Proposed design with an experimental library implementation.** Based on section 9 of the
[platform plan, revision 4](https://github.com/iokaio/munarium-platform/blob/main/docs/platform-plan.md), with lifecycle and failure rules in
sections 17–19 and 22. See the hub's
[scaffold decision proposal](https://github.com/iokaio/munarium-platform/blob/main/docs/decisions/0001-scaffold-boundaries.md)
for the distinction between local interfaces and normative contracts.

## Responsibility and current boundary

Verified principal chains, claim-bound grants, isolated credential brokering, and bounded revocation. Warden belongs to the **authority plane**.
The crate implements signed identity verification, SQLite issuance and activation,
suspension and OpenBao retrieval. Its [runtime guide](experimental-runtime.md) states
the exact trust-adapter boundary. No production listener or target dispatcher exists.

The original associated-type interfaces remain provisional. Concrete experimental
types are in `principal`, `authority` and `credential`; they are not a released Rust API
or a second definition of a shared wire contract. Trait signatures do not enforce
transport authentication. The experiment uses blocking HTTPS and single-node SQLite;
the supported platform deployment profile remains open.

## Module map

| Source | Proposed interface | Responsibility |
|---|---|---|
| [identity](../src/identity.rs) | `IdentityVerifier` | Validate issuer, audience, expiry, tenant, delegation depth and narrowing. Self-reported actor arrays are not identity evidence. |
| [grants](../src/grants.rs) | `GrantIssuer` | A grant must bind exact request, audience, scope and time. Its single-use property depends on atomic consumption, not on a signature alone. |
| [broker](../src/broker.rs) | `CredentialBroker` | The output belongs only in the connector privilege domain. Do not expose raw target secrets through agent APIs, diagnostics, or derived Debug output. |
| [revocation](../src/revocation.rs) | `SuspensionAuthority` | Measure admission and outstanding-grant rejection separately; restoration needs its own authorized path. |

## Planned flow and state ownership

Verify identity with a trusted provider → narrow the delegation chain → validate durable claim and current policy → issue request/audience/time-bound grant → consume under the shared protocol → bind credential only in connector zone. Authenticated suspension narrows admission and outstanding unconsumed grants.

Own issuance, validation and revocation state plus identity trust configuration.
Under hub ADR 0002, Gate owns atomic consumption and final dispatch admission.
Use an existing identity provider and secret service. Do not store a new general-purpose
vault here or expose target secrets in the authoritative ledger.

## Dependencies and failure behavior

| Dependency | Required input or service | Failure rule |
|---|---|---|
| Identity provider and trust roots | Verifiable origin, actor chain, issuer/audience/expiry | Unknown issuer, ambiguous identity, invalid time, or unsupported chain is refused. |
| Gate / Server | Matching durable claim and required records | No claim, no grant; no fabricated acknowledgement. |
| Registry / Council | Registered scope and permitted authority transitions | An agent-derived chain cannot become a human ratifier. |
| Secret service / connector host | Narrow target capability in an isolated process | Broker failure stops execution; never fall back to agent-held secrets. |

Dependencies are pinned in Cargo.lock and listed in the repository notices.
Released supported contract versions are **none**.
Future adapters must consume a reviewed, versioned contract and identify its digest;
a floating hub branch is design context, never deployment authority.

## Threat assumptions

Treat agent code, supplied content and self-reported identity as untrusted.
Host administrators, release roots and required signing authorities remain explicit
trust assumptions of a qualified deployment. Process separation alone does not prove
independent administration.

| Threat | Required control to implement and test |
|---|---|
| Forged or laundered actor chain | Established verification library, explicit origin and narrowing at every hop. |
| Secret leakage from broker | Isolated connector identities; scrub diagnostics and test all agent-visible channels. |
| Replay or stale revocation | Atomic state and measured revocation/clock bounds; fail closed outside them. |

The [validation specification](validation.md) connects these requirements to the hub
invariants. No test evidence is implied by this design.

## Decisions needed before implementation

Choose one existing identity library and broker; define the claim-consumption transaction with Gate; define clock tolerance, revocation propagation, cache bounds, and key retirement before issuing usable grants.

A cross-component semantic change starts in a hub decision record. Keep publication,
activation and component implementation separate. Use expand, migrate, remove for
future breaking contract changes; never duplicate hashing, identity or grant rules.

## Deferred scope

Multiple identity/PAM vendors, HSM integrations, and high-consequence qualification without independent identity review.

The [implementation plan](implementation-plan.md) sequences the first useful increment.
No deployment recipe, service port or live-provider configuration is supplied at this stage.
