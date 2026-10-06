# Munarium Warden build plan

**Proposed work; no functional milestone is complete.** The design baseline is the
[public platform plan, revision 4](https://github.com/iokaio/munarium-platform/blob/main/docs/platform-plan.md), section 9, and its
stage sequence in section 25. Warden's initial delivery belongs to **Stage 1 interfaces; 2 action path**.
Calendar windows are planning targets; acceptance evidence controls advancement.

The current authorized implementation includes identity, grants, brokering, activation
and suspension in one [experimental runtime slice](experimental-runtime.md). The
packet sequence below is the original roadmap; its identity-only restriction does
not describe the present local scope. Full platform milestones remain unqualified.

## Preparation present in this checkout

- A non-publishable Cargo library with experimental implementations and pinned dependencies.
- An [architecture map](architecture.md) naming ownership, trust assumptions and failures.
- An [acceptance specification](validation.md) and automatic Rust build checks.
- Existing contribution, security, support and repository-hygiene processes.

These artifacts prepare implementation; they do not complete Stage 0 foundation qualification
or advance this repository beyond the hub's **repository created** catalog state.

## First work packet: WARDEN-01: verify one identity path and reject widened delegation

The [6 October 2026 readiness record](warden-01-readiness.md) pins the inspected
hub candidates and maps acceptance cases. Those inputs remain proposed; the authorized
experiment proceeds without claiming contract acceptance or release readiness.

**Prerequisites:** accepted hub decisions and the specific contracts named in
[Architecture](architecture.md); record the exact revisions used. All fixtures must be synthetic
or authorized public inputs. The hub [contract backlog](https://github.com/iokaio/munarium-platform/blob/main/docs/architecture/contract-backlog.md)
tracks unresolved cross-component definitions.

**Work:** Once the principal-context decision is accepted, integrate one established identity library with a disposable provider. Preserve service origins without inventing human identities. Exercise issuer, audience, expiry, tenant, depth, cycles, and allowed delegation transitions; keep grant issuance and brokering unwired.

**Permitted scope:** the relevant modules under `src/`, component-local tests/fixtures,
and their documentation. Add dependencies, runtime wiring, or migrations only when the packet
requires them and its owner has reviewed the design. Do not copy sibling implementations.

**Acceptance:** A valid chain yields the expected bounded principal context; unsigned claims, cycles, wrong audiences, excessive depth, tenant substitution, and ratifier-role escalation are rejected. No target credential enters this test.

**Handoff:** retain commands, exit codes, fixture/contract revisions, limitations and the
diff for review. A test specification is not a passed test. Publishing, deployment, live
provider calls, signing changes and policy activation are separate operations.

## Subsequent packets

| Packet | Implementation scope | Exit condition |
|---|---|---|
| WARDEN-02 | Implement claim-bound grant issuance and atomic consumption with Gate. | Missing claim, request/audience substitution, replay, and concurrent redemption fail. |
| WARDEN-03 | Integrate one isolated broker and explicit credential assurance metadata. | Agent-visible prompts, files, memory, logs, traces, and errors contain no target credential. |
| WARDEN-04 | Implement suspension, key rotation, and recorded recovery. | Publish measured revocation bounds; retired keys cannot issue new authority and restored storage cannot revive consumption. |

Each packet gets a concrete component issue and links to the coordinating hub issue when
execution begins. The identifiers above are local planning references, not claims that remote
issues or approvals already exist. Work advances one coherent capability slice at a time.

## Integration and operational readiness

Before any runtime capability is advertised, document its supported contracts, immutable source
revision, accepted dependency versions and deployment boundary. Demonstrate relevant failure
paths from [Validation](validation.md), then add the component runbook: required identities,
health and dependency states, migration order, backup/restore, key rotation where applicable,
and unresolved-work investigation.

A component result alone is not platform qualification. The hub's
[delivery sequence](https://github.com/iokaio/munarium-platform/blob/main/docs/build-plan.md) requires composition evidence, including the
Server/Matrix foundation and the authority path required by the selected consequence class.
Multiple identity/PAM vendors, HSM integrations, and high-consequence qualification without independent identity review.

## Completion criteria for the first functional increment

- The documented local recipe works from a clean clone using bounded disposable inputs.
- The acceptance cases are executable, retain their intended oracle, and include refusal paths.
- Unsupported operations remain explicit; logs and reports expose no credentials or private data.
- The README links the actual evidence before any capability or release label changes.
