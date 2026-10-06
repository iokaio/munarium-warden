# WARDEN-01 readiness and acceptance mapping

**Historical preparation record, followed by an authorized implementation.**
The later request explicitly includes grants, brokering and activation. See the
[experimental runtime](experimental-runtime.md) for implemented operations, tests and
current limitations. The intake tables and identity-only scope below record the
earlier preparation state; they are not a restriction on the current authorized build.

**Initial observation, 6 October 2026: scaffold validated; runtime packet in design.**
The hub's [parallel build plan][parallel] assigns Warden identity verification and
delegation attenuation to the first component pair, after foundation qualification
and accepted HUB-01/02 definitions. This record applies that sequence to Warden;
it does not accept a contract or qualify an identity path.

## Inspected inputs

| Input | Exact revision or digest | Observation |
|---|---|---|
| Warden base | `b404e150001fa3656a80498e206c2e4df3b9a1a6` | Clean starting checkout; freshly fetched `origin/main` matched the base. |
| Public hub | `eaa33e8dfafc53f2874fecaa5b62e69208d45793` | Clean at intake; subsequent contract proposal described below. |
| ADR 0003 / DEC-01 | [Bootstrap and principal context][principal] at the hub revision above | Explicitly proposed, not accepted. |
| ADR 0004 / HUB-02 | [Decision-only contracts][decision] at the same revision | Explicitly proposed, not accepted or published. |
| Candidate bundle | `5ee201e48a2390b7cf66fdf6aa8750f751f1ec9241e9e04131b6632745612238` | Declared by the [candidate lock][lock]; not a released contract digest. |
| Identity vectors | `a60f52749ad657fea82abdddc79955b235946391bb1a7a76373a705bba111c2d` | LF-normalized file hash in that lock; 32 candidate cases subsequently exercised in the hub, not by Warden. |

The subsequent hub test run verified the file and bundle hashes against this lock.
Revalidate the accepted bundle at implementation intake. Do not regenerate candidate
fixtures or copy the hub's fixture verifier into Warden as a runtime implementation.

Following the request to create the missing contract, the hub's local
`proposal/warden-identity-contract` branch adds `docs/decisions/warden-identity-contract.md`
and consumer-boundary checks against these unchanged candidates. The initial full
Python suite passed 48 test methods, including the existing signed cases, with exit 0.
The proposal is uncommitted and unaccepted; pin its reviewed revision before intake.
This does not supply Warden runtime evidence or close the gates below.

The subsequent preparation review adds proposed hub ADR 0005 for provider identity
mapping, per-edge delegation registration and attribution-only forwarding. It has
separate `warden-admission.schema.json`, `warden-admission-vectors.json` and
`warden-admission-lock.json` review artifacts; the existing foundation candidate is
unchanged. Its additive bundle digest is
`9ed4a12563d064e5d2068658b903a8b8813ffe49e8cd66356931af1447080283`.
Thirteen assertion-consumer checks now cover exact leaf output/digest, clock boundaries,
malformed encoding/JSON, signature sizes and refusal paths. The full hub suite passed
58 test methods with exit 0, including 45 new admission vector cases exercised inside
one method. These counts are not Warden conformance results.
The hub also passed independent Draft 2020-12 meta-validation and 48 shape comparisons
with `jsonschema` 4.26.0. Its ADR 0005 retains the initial new-lock filename-ordering
failure and the correction; the original foundation lock and signed fixtures did not change.

The preparation deliverables now cover the assertion contract, proposed admission
records, synthetic acceptance/refusal cases, digest pins and reproducible checks.
Remaining work before runtime is explicit: maintainer disposition, concrete provider
and library pins, trusted registration/evidence custody, foundation evidence and the
implementation allocation. These are not supplied by passing candidate tests.

## Runtime intake gates

| Required input | Current disposition | What closes the gate |
|---|---|---|
| Accepted principal and decision-only definitions | Missing in the inspected revision | Maintainer disposition of the exact ADRs, compatible published contract/vector pins and ADR 0001 disposition. |
| Foundation readiness | Not established by this work | Link FOUNDATION-01 observations and the S1 gate; identify S2 record shapes, S3 verification and S4 lineage inputs for integration. |
| Identity provider and verification library | Unselected | Reviewed, pinned artifacts, provenance/license/security assessment and a disposable-provider recipe under minimum DEC-07. Keycloak is only a hub proposal. |
| Identity admission and forwarding | ADR 0005 proposed with schema/vector checks | Accept provider mapping, registration bindings, body limits and attribution-only forwarding; qualify their trusted inputs in the selected profile. |
| Authenticated transport and trust configuration | Proposed topology only | Accepted peer/audience binding, operator-provisioned trust roots and refusal behavior when required authority state is unavailable. |
| Accountable owner and acceptance reviewer | Not assigned in this packet | Named human owner/reviewer and component/coordinating issue references. |
| Implementation and review estimates; time/spend ceiling | Not supplied | Owner sets the bounded implementation/review allocation after the decisions and provider choice. |

These gates come from the hub's [work-packet rules][build] and Warden's
[implementation plan](implementation-plan.md). Missing fields keep implementation
in design. A merged proposal or successful fixture test cannot substitute for acceptance.

## Scope after intake

Implement one verified identity path through [identity.rs](../src/identity.rs),
with component-local tests and documentation. Dependency manifest/lock changes
belong to the reviewed library selection. Preserve the existing `IdentityVerifier`
seam unless the packet explicitly reviews a necessary interface change; leave
`GrantIssuer`, `CredentialBroker` and `SuspensionAuthority` unchanged.

Use the accepted hub types, bounds and rejection rules. Separate untrusted evidence
from verified principal output. Obtain tenant, audience, peer and issuer policy
from trusted configuration and authenticated transport, never the submitted claims.
Use an established verification library; no bespoke cryptography or identity provider.
The provider test must preserve service origins without fabricating a human subject.

Permitted changes are the identity implementation, required reviewed dependencies,
component-local tests/fictional fixtures and their documentation. Wire contracts,
candidate oracles, protected files and sibling repositories remain outside this packet.
No target credential, broker, grant issuance/consumption, production listener,
activation, deployment, publishing or signing-configuration change belongs to it.
Stage 2 WARDEN-02–04 still depend on HUB-03 and the accepted execution protocol.

## Acceptance mapping for review

Candidate IDs below refer to the pinned [identity vectors][vectors]. They are
review inputs to adopt only after acceptance, not Warden test results. Bootstrap
transition persistence remains Server's responsibility.

| Warden acceptance property | Existing candidate cases or remaining test design |
|---|---|
| A verified delegation produces exactly bounded authority | `valid-delegation`; assert the actual principal, origin, scopes, resources and expiry, not just success. Add an explicitly registered service-origin provider case. |
| Signature and key selection cannot be supplied by an untrusted request | `forged`, `substituted-payload`, `unknown-key`, `algorithm-confusion`, `header-key-url`; add unsigned/malformed evidence cases using the accepted parser rules. |
| Tenant, issuer, audience and transport peer remain bound | `wrong-tenant`, `wrong-issuer`, `wrong-audience`, `wrong-peer`; exercise these independently on the decision assertion path, not only bootstrap fixtures. |
| Current time and authority state bound acceptance | `expired`, `future`, `expiry-uncertainty`, `long-lifetime`, `retired-key`, `unavailable`; test the accepted boundary values on decision assertions and provider failures. |
| Every hop attenuates authority | `wider-scope`, `wider-resource`, `longer-delegation`; add registered-task and target-policy intersection cases once their accepted inputs are defined. |
| Origin, ancestry and depth cannot be laundered | `false-root`, `changed-origin`, `cycle`, `parent-substitution`, `four-edges`, `fifth-edge`; use accepted depth limits rather than locally choosing them. |
| Delegation cannot create human ratification authority | `delegated-ratifier`, `agent-bootstrap`; add ambiguous-identity and service-origin laundering refusals on the selected provider path. |
| Missing dependencies never manufacture verified identity | Refuse missing evidence, unknown required forms and unavailable trust/authority checks; inspect errors and diagnostics for credential exposure. |

Use real signed evidence and the selected library for cryptographic tests. The
disposable provider and authenticated service hop need their own integration tests;
in-process fixture success cannot establish provider custody, transport isolation,
revocation propagation, Server persistence or platform REF-01 completion.

## Local scaffold observation

At the Warden base above, Windows/MSVC with Rust and Cargo 1.98.1 passed these
commands, each with exit status 0. Command output is retained in the task transcript.

| Command | Observed result |
|---|---|
| `cargo fmt --all --check` | Passed. |
| `cargo build --offline --locked` | Built the dependency-free library. |
| `cargo clippy --offline --locked --all-targets -- -D warnings` | Passed. |
| `cargo test --offline --locked` | Zero unit tests and zero doc tests; no identity behavior exercised. |
| `cargo doc --offline --locked --no-deps` with `RUSTDOCFLAGS=-D warnings` | Generated API documentation without warnings. |

Python 3.13.12 ran `py check_license.py`, `py scripts/private_material_scan.py`
and `py scripts/docs_linkcheck.py`, each with exit 0. The documentation-change
checks also passed `gitleaks dir . --config .gitleaks.toml --no-banner --redact --exit-code 1`
with gitleaks 8.30.1 and `git diff --check`, each with exit 0.
The sandbox initially could not launch Python/gitleaks; installed tools were
accessible outside it. No toolchain installation or dependency addition was needed.
Rust output remains in the ordinary ignored `target/` build cache. No provider,
container, key, database, port or target credential was created. Hosted CI and
identity acceptance were not run; supported contracts and capabilities remain none.

At runtime handoff, retain the exact source/contract/fixture pins, tool versions,
commands, exit statuses and output, plus expected/actual principal results and all
failed or unavailable checks. The acceptance reviewer must assess those results
before advancing evidence labels or starting the next capability slice.

[parallel]: https://github.com/iokaio/munarium-platform/blob/eaa33e8dfafc53f2874fecaa5b62e69208d45793/docs/parallel-build-plan.md
[build]: https://github.com/iokaio/munarium-platform/blob/eaa33e8dfafc53f2874fecaa5b62e69208d45793/docs/build-plan.md#work-packets-and-capacity
[principal]: https://github.com/iokaio/munarium-platform/blob/eaa33e8dfafc53f2874fecaa5b62e69208d45793/docs/decisions/0003-bootstrap-principal-context.md
[decision]: https://github.com/iokaio/munarium-platform/blob/eaa33e8dfafc53f2874fecaa5b62e69208d45793/docs/decisions/0004-decision-only-contracts.md
[lock]: https://github.com/iokaio/munarium-platform/blob/eaa33e8dfafc53f2874fecaa5b62e69208d45793/docs/decisions/candidates/candidate-lock.json
[vectors]: https://github.com/iokaio/munarium-platform/blob/eaa33e8dfafc53f2874fecaa5b62e69208d45793/docs/decisions/candidates/identity-vectors.json
