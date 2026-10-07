# Stage 1 identity service

Build `cargo build --locked` and run `munarium-warden ABSOLUTE_CONFIG_PATH`.
The closed JSON configuration contains `tls`, `server_endpoint`, `deployment`,
`signing_key_file` (a protected raw 32-byte Ed25519 seed) and `key_id`.
No signing seed or provider token belongs in source or diagnostic output.

`tls` contains `listen`, PEM `certificate_file`, `private_key_file`, `ca_file` and
`peers`, a map from lowercase SHA-256 client leaf fingerprints to `{service, tenants}`.
Every request requires a valid enrolled client certificate. Warden uses its own
certificate for current authority reads from Server. Failed authority reads are
503; invalid identities are sanitized 403 responses. No stale trust cache is used.

`POST /v1/identity` accepts `{tenant, audience, action}`. A root action contains
`operation: "root"`, `provider_id`, the original provider `token`, `scopes` and
`resources`. A delegation action contains `operation: "delegate"`, the original
signed `chain`, child `actor`, child presenter `service`, `scopes` and `resources`.
Roots require the [workload admission profile](workload-admission.md); delegations
require a current registered edge and attenuation at every ancestor.

Server's operator artifact supplies `warden.providers` (enrolled issuer, audience,
key ID, public key and exact subject kinds), `warden.bindings` (provider-to-platform
registrations), and `identity:<audience>` policy. The provider selects none of these
trust facts. The response contains `chain`, `usable_at` and `authority_revision`.
Wait until `usable_at` before using the assertion; newly issued roots are not backdated.

The service mounts no grant, broker or connector endpoint. Existing later-stage
library experiments remain separate. Requests are bounded to 64 KiB and 32 concurrent
admissions; TLS handshakes have a five-second deadline and 64 concurrent slots.

Harness owns [separate-process tests](https://github.com/iokaio/munarium-harness/blob/main/docs/service-profile.md)
covering actual mTLS peers, provider signature/mapping refusal, current revocation,
dependency outage and both memory/PostgreSQL Server profiles. Local success is not
contract acceptance, remote CI success or production qualification.
