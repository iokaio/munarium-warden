# Munarium Warden validation

## Build and test locally

Use Rust **1.98.1** with Cargo, rustfmt and Clippy, plus the platform's native linker.
The manifest requires Rust 1.98. CI installs 1.98.1 explicitly. Fetch the pinned public
dependencies once; then ordinary tests need no provider account, external database,
model key, container or sibling checkout:

```console
cargo fetch --locked
cargo fmt --all --check
cargo build --offline --locked
cargo clippy --offline --locked --all-targets -- -D warnings
cargo test --offline --locked
cargo doc --offline --locked --no-deps
```

`Cargo.lock` is checked in. Do not regenerate it to bypass a locked-build failure.
The lock pins the complete dependency graph. Direct pins and license inventory are
recorded in [third-party notices](../THIRD_PARTY_NOTICES.md).

Behavioral tests exercise signed identity, durable grants, activation, suspension,
recovery and broker failure paths. The [runtime guide](experimental-runtime.md) provides
the separate real OpenBao test command and documents which boundaries remain fixtures.
`cargo doc` produces local API documentation under `target/doc/`.

Run the existing repository checks too:

```console
py check_license.py
py scripts/private_material_scan.py
py scripts/docs_linkcheck.py
gitleaks dir . --config .gitleaks.toml --no-banner --redact --exit-code 1
git diff --check
```

Use `python` or `python3` if the `py` launcher is unavailable. The secret command scans
the working tree; the existing hygiene workflow also scans Git history. No local result
is evidence that hosted CI passed.

## Automatic coverage

The new [Rust workflow](../.github/workflows/rust.yml) runs formatting, build, lint, tests
and warning-free API documentation on pushes to main and pull requests. It uses read-only
repository permissions and has no publishing, deployment or provider steps.
The existing [hygiene workflow](../.github/workflows/repo-hygiene.yml) and
[DCO workflow](../.github/workflows/dco.yml) retain their independent checks.

## Required behavioral acceptance cases

These are **full-composition requirements**, only partly covered by the local tests.
See the [retained run](evidence/2026-10-06-local.txt) for actual commands and outcomes.
Invariant IDs refer to the catalog in
[platform plan revision 4, Appendix C](https://github.com/iokaio/munarium-platform/blob/main/docs/platform-plan.md) and the
[hub catalog](https://github.com/iokaio/munarium-platform/blob/main/README.md#the-invariant-catalog). No contract bundle has been released.

| Invariant | Scenario | Required observation |
|---|---|---|
| INV-03 / INV-13 | Forge identity, widen scope, cycle actors, or delegate into a ratifier role. | Verified origin and scope intersection required; no role laundering. |
| INV-07 | Inspect every agent-visible channel during successful and failed broker calls. | No target credential exposed. |
| INV-08 / INV-10 | Issue without matching durable claim; race or replay grant redemption. | No unbound grant and no multiple dispatch ownership. |
| INV-12 | Suspend with unconsumed grants during cache/network/clock faults. | Measured bound or refusal of new consequential grants. |
| INV-19 | Restore consumed grant state and exercise stale signing keys. | No revived authority; historical verification remains explicitly scoped. |

INV-21 (protected development authority) and INV-22 (claims bounded by evidence)
apply to every packet in addition to the component-specific cases.

## Evidence to retain

Record source and contract digests, toolchain, fixture identifiers, command/exit status,
environment, declared trust boundary, expected and actual outcome, and remaining gaps.
Concurrency, crash/restart, identity, network and storage claims require their real test
environment; an in-memory fake cannot certify them. A live integration needs its own
authorization and qualification record.

Keep operational credentials and raw private payloads out of test artifacts. Distinguish
a local pass, unavailable coverage, a failing case, and an independently reviewed result.
Capability status must identify the boundary actually exercised; a local library or
child-process test does not qualify the platform's production invariants.
