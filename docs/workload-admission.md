# Workload admission and assertion issuance

The [admission module](../src/admission.rs) verifies the bounded workload JWT
profile recorded in hub ADR 0008. It uses strict Ed25519 verification, exact
issuer/audience/key selection and conservative validity checks. The upstream key
configuration separately enrolls each exact subject as an agent or service.
No request field can declare a human kind, supply a trusted public key or choose
its governing task/policy context.

Root issuance requires exactly one current ADR-0005 provider binding. Requested
scopes and resources must fit the provider binding and current task/policy limits.
Its expiry fits every contributing validity interval and the 60-second assertion
limit. Assertions start at issuance time; clients wait for the two-second clock
uncertainty window instead of receiving backdated credentials.

Delegation verifies the complete parent chain and its actual presenter, requires
a registered child actor/service edge, and retains the original origin and parent
digest. It cannot widen authority or exceed any ancestor/registration/depth limit.
Every issued result is checked by the same principal verifier before return.

`cargo test --offline --locked --test admission` exercises real signatures, wrong
issuer/subject/audience, missing enrollment, invented human claims, expired input,
duplicate mappings, task/policy limits, revoked keys and registered delegation.
This module supplies no HTTP endpoint by itself. Service deployment must obtain
fresh governing snapshots and authenticate transport before constructing its
trusted context. Provider keys are independent of platform assertion-signing keys.

Server consumes a content-addressed export of the identity-only verifier using
`scripts/export_identity.py`; the exported files retain their license and notice.
Consumers check the source lock and do not hand-edit owner-maintained files.
