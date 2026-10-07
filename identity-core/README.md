# Warden decision verifier package

This non-publishable package compiles the existing owner-maintained
[principal verifier](../src/principal.rs) and [encoding code](../src/encoding.rs).
The original Warden package/API is unchanged. There is one verification implementation,
not a copied or separately maintained consumer. Its small error type contains only the
three possible verification failures.
The separate [dependency inventory](THIRD_PARTY_NOTICES.md) covers this package's lock.

Stage 1 consumers need verification without SQLite grants, OpenBao or a network client.
This package avoids the native SQLite link conflict between Warden's grant store and
Server's SQLx dependency graph in the experimental in-process composition. Ordinary
Warden tests still exercise the shared source; Harness also runs Registry's 32 signed
interoperability vectors against this package. This package introduces no provider
enrollment or identity issuance.

```console
cargo fetch --manifest-path identity-core/Cargo.toml --locked
cargo clippy --manifest-path identity-core/Cargo.toml --offline --locked --all-targets -- -D warnings
cargo test --offline --locked --test principal
```

Every delegation edge binds its own child service. Every ancestor must fit inside the
current task/policy interval. The regression test includes mixed intermediary services,
service substitution, and ancestors predating/outliving current authority. Compile-time
module reuse does not establish independent identity review or production qualification.
