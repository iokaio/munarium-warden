# Munarium Warden

**Workload identity, delegation, just-in-time credentials, kill switches.** Warden is the
authority-plane component of the Munarium Governance Platform that connects an authenticated actor
to a narrowly bounded capability. It verifies who is acting and on whose behalf, issues
request-bound execution grants against durable claims, brokers the target credential to an isolated
connector so the agent never holds it, and suspends an instance, agent version, deployment or tenant
within a measured bound. It does not replace the enterprise identity provider or secrets manager.

> **Status: Stage 1 identity service implemented.** The authenticated service/client
> profile is implemented and covered by component and separate-process tests.
> See the [service profile](docs/service-profile.md). Candidates remain inactive;
> the Stage 1 API remains identity-only. Human acceptance and production qualification
> remain pending.

An experimental [Stage 2 activation participant](docs/activation-profile.md) now
adds durable expected-head application and exact receipts. It is separate from
the original grant-library experiment. The opt-in
[prepared release adapter](docs/activation-profile.md) adds live issuance and
connector-only OpenBao custody for disposable integration tests.

Warden is one of nine components built around the existing Munarium foundation, Munarium Server
and Munarium Matrix. Their shared architecture, normative contracts, decision records, roadmap and
composition evidence live in the public hub,
[iokaio/munarium-platform](https://github.com/iokaio/munarium-platform). This repository will hold
Warden's implementation, its unit and component tests, the migrations it owns, operational
diagnostics, package definitions, a local development recipe and release evidence. It is open
source from its first public commit, under the Apache License 2.0, with no proprietary edition.

## Start building

Read the [development index](docs/README.md), then the [architecture](docs/architecture.md),
[implementation plan](docs/implementation-plan.md) and [validation guide](docs/validation.md).
They map the public platform plan to source modules, dependencies, a first bounded work item
and acceptance cases. Start the [experimental runtime](docs/experimental-runtime.md)
with the local test commands. Released supported contract versions remain **none**.

## What Warden is for

The platform separates four powers: **read**, **governed write**, **act** and **govern**. Warden
is the authority behind *act*: an agent may propose an external action without possessing the
target credential, and a service may execute an approved request without holding the power to
approve a broader one. The platform's most important proof point is that **the agent's environment
contains no credential that can directly execute the governed target action**. Warden is how that
becomes true.

Separating credentials is necessary but not sufficient. Two credentials controlled by one person
are not two independent reviewers; two services sharing an unrestricted administrator account are
not independent because their process names differ. A deployment must describe who can actually
alter each boundary, and Warden's records must make that describable.

## The design, as planned

### Principals and delegation

The principal model identifies a tenant, a user where present, an agent definition, an agent
version, a deployment and an instance. Service workloads have separate identities. A background
agent may operate under an explicitly registered service delegation rather than a human user, and
that distinction is recorded; **the system never fabricates a human principal for attribution**.

OAuth token exchange (RFC 8693) can express subject and actor relationships, but the narrowing rules
are platform requirements Warden enforces, not benefits supplied by choosing the protocol.
**Effective authority is the intersection** of the originating authority, each delegated actor's
permitted scope, the registered task and the target policy. The actor chain is signed or otherwise
verified; a self-reported array in an agent's request is not identity evidence.

The first implementation validates issuer, audience, expiry, tenant, actor-chain depth and allowed
delegation transitions. It rejects cycles, ambiguous identities and attempts to convert an
agent-derived credential into a human ratification role. Registry's maximum delegation depth and
per-task scope are explicit inputs.

### Grants are not target credentials

A platform **execution grant** is time-limited, bound to a durable claim and request hash, and
accepted only by the intended connector audience. **Single-use behavior requires an atomic
consumption check**; a signed token with an expiry is not single-use because its documentation
says so.

A modern target may support a short-lived, sender-constrained credential. Another may accept only a
long-lived service-account secret. Warden's broker exposes that difference in the connector's
assurance metadata: a legacy password can remain isolated from the agent while still carrying
residual risk in the connector zone, and the plan does not label the password itself single-use.
Where supported, mutual TLS or DPoP (RFC 9449) constrain token use to a key holder; they do not
replace request binding, authorization or the claim journal.

### Revocation and recovery

Warden supports suspension of an instance, agent version, deployment or tenant. Revocation affects
grant admission and outstanding unconsumed grants within a **measured interval**. Short token
lifetimes alone are not immediate revocation.

The initial target is a published, tested revocation bound for one reference topology, with clock
tolerance, network partition behavior, cache lifetime and dependency assumptions stated. If the
bound cannot be maintained, new consequential grants stop. Already completed actions are not undone
by revoking the token that authorized them; compensation, where possible, is a new governed action.

Signing-key rotation preserves verification of historical receipts while preventing new grants
under retired keys. Recovery from lost keys is a recorded, human-controlled ceremony; a key is never
restored into an agent-accessible workspace because doing so is easier.

### Kill switches

Sentinel, an authorized operator, or an external SIEM or SOAR may submit a **circuit-breaker
request** naming caller, scope, reason, triggering evidence and requested duration. Warden
authenticates and enforces the suspension under a previously approved policy. Automatic action may
narrow capability; it may never restore broader authority. Restoration after a serious suspension
follows the applicable human or deterministic approval path.

### The solo implementation boundary

Warden uses a real identity library and established secrets infrastructure rather than bespoke
cryptography or a new password vault. The first broker may use a local test vault or an agreed
cloud secret service. HSM integration, multiple PAM vendors and broad workload federation remain
open roadmap work, not closed-edition features. **Independent identity review is a
production-readiness gate** for high-consequence use; agreement among coding models does not
replace it.

## First public increment

**One verified identity path and one isolated credential broker.** During Stage 1 the repository
carries Warden's interfaces and a bounded prototype while production dispatch remains disabled.
Stage 2 delivers the first real identity and broker path as part of the platform's first complete
governed action, with one narrow connector, one reference identity system and one deployment
profile.

Target window: Stage 2 (months 4–6); interfaces and a bounded prototype during Stage 1.

## Capability status

The labels are evidence labels, not editions: **Planned**, **Experimental**, **Conformance-tested**,
**Reference-qualified**, **Independently reviewed**. In the hub's component catalog this
repository is at **repository created**.

| Capability | Status | Evidence |
|---|---|---|
| Principal model and verified actor chains (issuer, audience, expiry, tenant, depth, allowed transitions) | Experimental | [Ed25519 and pinned-vector tests](tests/principal.rs); non-human decision profile only |
| One identity federation path with a reference identity provider | Planned | none |
| Request-bound, claim-bound, audience-bound execution grants with atomic consumption | Experimental issuance; Gate consumption integration pending | [Durable issuance and validation tests](tests/authority.rs) |
| One isolated credential broker path (local test vault or agreed cloud secret service) | Experimental; OS security boundary unqualified | [OpenBao and child-process tests](tests/broker.rs) |
| Connector assurance metadata describing the credential type and residual risk | Experimental | [Receipt labels a reusable secret](src/credential.rs) |
| Suspension by instance, agent version, deployment or tenant, with a published revocation bound | Experimental local enforcement; distributed bound unqualified | [Persistent scope tests](tests/authority.rs) |
| Warden activation epoch and mode installation | Experimental | [Scoped, idempotent activation tests](tests/authority.rs); Council/barrier authentication supplied by trusted adapters |
| Authenticated circuit-breaker requests under pre-authorized policy | Planned | none |
| Signing-key rotation preserving historical verification; recorded recovery ceremony | Planned | none |
| Sender-constrained tokens (mutual TLS, DPoP) where the target supports them | Planned, later | none |
| HSM integration, multiple PAM vendors, broad workload federation | Deferred | none |

Released contract versions: **none**. External identity federation remains unsupported.
OpenBao KV v2 has a [disposable integration test](docs/experimental-runtime.md).
Available library operations: principal verification, issuance, online validation,
activation installation, suspension, and broker delivery. No production listener is supplied.

## Acceptance evidence for the first release

| Test | Required outcome |
|---|---|
| Agent-visible prompts, memory, exceptions, traces, environment variables and logs | Contain no target credential |
| Audience substitution | Grant refused by the unintended connector |
| Token replay | Second redemption refused; the first consumption is recorded |
| Delegation widening | Effective authority stays the intersection; refused |
| Stale-key acceptance | Grants under a retired key refused; historical receipts still verify |
| Concurrent grant redemption | Exactly one consumption succeeds |
| Self-reported actor chain, cycle, ambiguous identity | Refused |
| Agent-derived credential presented as a human ratifier | Refused |
| Grant requested without a matching durable claim | Refused |
| Authenticated suspension | New affected grants refused within the published bound; the fate of outstanding grants matches the contract |
| Bound cannot be maintained | New consequential grants stop |

A blank evidence field means unverified, not passed. Independent identity review is recorded with
its revision and scope; its absence is stated in the release, not implied away.

## Invariants

| ID | Required property | Owner and first gate |
|---|---|---|
| INV-03 | Every accepted action has a verified tenant and principal context | Warden, Gate, Server; stages 1–2 |
| INV-07 | No qualified target credential is readable from the agent environment | Warden and deployment profile; stage 2 |
| INV-08 | No grant is issued without a durable, matching execution claim | Gate and Warden; stage 2 |
| INV-10 | A grant cannot be concurrently consumed for multiple dispatches | Warden and Gate; stage 2 |
| INV-12 | Revoked authority stops new affected work within the qualified bound | Warden and Sentinel; stages 2–3 |
| INV-13 | A delegated principal cannot widen its originating scope or become its own ratifier | Warden and Council; stage 2 |
| INV-19 | Restore cannot silently reactivate a consumed grant or erase an unresolved claim | Gate, Warden, Server; stage 4 |
| INV-22 | A release advertises only the profiles and capabilities supported by its evidence | every component; every stage |

## Contracts, dependencies and neighbors

- **Contracts.** The hub's contracts directory is normative for the principal chain, the grant
  shape and the circuit-breaker request; Warden implements them. Supported contract versions:
  none yet.
- **Foundation.** Munarium Server 1.3.0's capability tokens are the existing token model; the
  hub's S3 (record verified principal chains) and S7 (authenticate service-to-service channels,
  qualifying one mTLS deployment including any proxy termination) are the Server changes Warden
  depends on. Platform-wide federation and key discovery are not equivalent to Server's existing
  token model, and the plan says so.
- **Gate** records the durable claim a grant binds to and runs the connector that consumes it;
  **Registry** supplies maximum delegation depth and per-task scope; **Council** is the ratifier an
  agent-derived identity can never become; **Sentinel** submits breaker requests; **Console**
  submits suspensions through the same API as any client.
- **External dependencies.** An established identity library and secrets infrastructure, chosen
  by the first implementation and recorded in the hub.

## Not in scope

- Being an identity provider, a user directory, or a secrets vault.
- Bespoke cryptography.
- Calling a legacy long-lived secret single-use because the platform grant that released it was.
- Treating short token lifetimes as revocation.
- Restoring broader authority automatically after a suspension.
- Independent dual-human review inside a one-person organization: the software supports multiple
  people; the founder's own operation does not pretend to contain them, and the corresponding
  claims stay unqualified until an external reviewer or customer authority participates.

## Roadmap position

| Stage | Warden's part |
|---|---|
| 0 · month 1 | This repository; the principal-chain and grant contracts drafted in the hub |
| 1 · months 2–3 | Interfaces and a bounded prototype; verified principal context for Gate's decision-only slice; production dispatch disabled |
| 2 · months 4–6 | One real identity path and one broker: the first complete governed action, with revoked-grant and concurrent-redemption tests |
| 3 · months 7–9 | Measured suspension propagation with Sentinel; suspension through Console |
| 4 · months 10–12 | Key rotation and restore exercises in the reference composition |
| 5 · months 13+ | Additional identity brokers, sender-constrained tokens, HSM and PAM adapters, federation, demand-led |

Credential isolation and required distinct authority are never removed to preserve a date.

## Repository layout

| Path | What exists |
|---|---|
| [Cargo.toml](Cargo.toml), [Cargo.lock](Cargo.lock) | Independent library, version 0.1.0-dev, publishing disabled, exact direct dependency pins |
| [src/lib.rs](src/lib.rs) | Experimental implementations and documented trust adapters |
| [docs/](docs/README.md) | Architecture, implementation sequence and acceptance specifications |
| [CONTRIBUTING.md](CONTRIBUTING.md), [AGENTS.md](AGENTS.md), [CLAUDE.md](CLAUDE.md) | Contribution process and aligned development guidance |
| [.github/workflows/](.github/workflows/) | Automatic Rust, repository-hygiene and DCO checks |
| [scripts/](scripts/), [check_license.py](check_license.py) | Existing documentation, private-material and license checks |
| [LICENSE](LICENSE), [NOTICE](NOTICE), [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) | Licensing and dependency notices |

Subsystem modules: [identity](src/identity.rs), [grants](src/grants.rs), [broker](src/broker.rs), [revocation](src/revocation.rs).
Behavioral tests and public fixtures live under [tests/](tests/). SQLite schema creation
belongs to the authority store. The library defines no released shared wire types and
depends on no sibling checkout.

## Development

Use Rust 1.98.1 with rustfmt, Clippy and the platform's native linker. From this repository root:

```console
cargo fetch --locked
cargo fmt --all --check
cargo build --offline --locked
cargo clippy --offline --locked --all-targets -- -D warnings
cargo test --offline --locked
cargo doc --offline --locked --no-deps
```

The [validation guide](docs/validation.md) separates ordinary behavioral tests,
the opt-in Docker integration and remaining composition requirements. Fetch populates
the dependency cache; subsequent Rust gates run offline against the lockfile.

Also run the existing hygiene gates:

```console
py check_license.py
py scripts/private_material_scan.py
py scripts/docs_linkcheck.py
gitleaks dir . --config .gitleaks.toml --no-banner --redact --exit-code 1
git diff --check
```

Use `python` or `python3` where `py` is unavailable. The new
[Rust workflow](.github/workflows/rust.yml) runs on main pushes and pull requests alongside
the existing [repository hygiene](.github/workflows/repo-hygiene.yml) and
[DCO](.github/workflows/dco.yml) workflows. They provide build and repository checks, not a
qualified runtime. No package is published or service deployed by these workflows.
Local checks do not imply hosted CI success. See [CONTRIBUTING.md](CONTRIBUTING.md).

## The platform

| Repository | Plane | Role |
|---|---|---|
| [iokaio/munarium-platform](https://github.com/iokaio/munarium-platform) | hub | Architecture, normative contracts, decision records, roadmap and composition evidence for the whole platform |
| [iokaio/munarium](https://github.com/iokaio/munarium) | foundation (mediation) | Munarium Server: governed memory, the append-only ledger, and the Server client libraries |
| [iokaio/munarium-matrix](https://github.com/iokaio/munarium-matrix) | foundation (mediation) | Munarium Matrix: governed, read-only structured evidence from enterprise data sources |
| [iokaio/munarium-registry](https://github.com/iokaio/munarium-registry) | authority | Inventory of agents, tools, manifests, and policy bundles |
| [iokaio/munarium-harness](https://github.com/iokaio/munarium-harness) | agent | SDKs that make the governed path easy for honest agents |
| [iokaio/munarium-warden](https://github.com/iokaio/munarium-warden) | authority | Workload identity, delegation, just-in-time credentials, kill switches |
| [iokaio/munarium-gate](https://github.com/iokaio/munarium-gate) | mediation | Policy decision and enforcement point for every tool call |
| [iokaio/munarium-gateway](https://github.com/iokaio/munarium-gateway) | mediation | Model-call mediation: routing, BYOK, budgets, screening |
| [iokaio/munarium-council](https://github.com/iokaio/munarium-council) | authority | Approvals, policy lifecycle, ratified governance transitions |
| [iokaio/munarium-sentinel](https://github.com/iokaio/munarium-sentinel) | assurance | Telemetry, anomaly detection, circuit breakers, incident replay |
| [iokaio/munarium-assure](https://github.com/iokaio/munarium-assure) | assurance | Control-framework mapping and evidence packs |
| [iokaio/munarium-console](https://github.com/iokaio/munarium-console) | assurance | One interface for approvers, operators, and auditors |
| [iokaio/munarium-clients-publish](https://github.com/iokaio/munarium-clients-publish) | tooling | The one place Munarium client packages are built for release and published from |
| [iokaio/munarium-demo](https://github.com/iokaio/munarium-demo) | examples | Munarium Demo: working applications and bundled datasets for evaluating the foundation |

The development tool VCP ([iokaio/vcp](https://github.com/iokaio/vcp)) is separate: not one of the
nine components and not a runtime dependency for adopters. Ioka's private repositories hold
planning material awaiting publication review and the proprietary Matrix analytics adapters;
nothing from them is copied into a public repository without that review.

## Licensing

Apache-2.0 ([LICENSE](LICENSE), [NOTICE](NOTICE)). The names are not part of that grant:
[TRADEMARK.md](TRADEMARK.md) says what you may do without asking, which is most things. There is
no proprietary edition of this component and none is planned; a capability that arrives later is
deferred roadmap work, not a commercial restriction.

## Contributing, support, security

Signed-off pull requests, no CLA ([CONTRIBUTING.md](CONTRIBUTING.md)). Questions go to Discussions,
defects and design findings to Issues, and suspected vulnerabilities to the private channel
[SECURITY.md](SECURITY.md) names, never a public issue. What is and is not supported:
[SUPPORT.md](SUPPORT.md). Conduct: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Release history,
such as it is: [CHANGELOG.md](CHANGELOG.md).
