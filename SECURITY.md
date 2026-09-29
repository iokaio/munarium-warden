# Security

Do not file a vulnerability as an issue or a pull request.

Report a suspected vulnerability in anything in this repository privately, by either route:

- GitHub's private vulnerability reporting ("Report a vulnerability" under the Security tab), or
- email to **info@ioka.io** with "security" in the subject.

Say what you found, where, and how to reproduce it. Do not include live credentials, customer data,
or a proof of concept run against a system you do not operate. You will get an acknowledgement
within two business days, and a fix, or a recorded decision, on the affected path before any related
release. Credit is given if you ask for it.

## Supported versions

Munarium Warden has no release. Until the first tagged release, `main` is the only line and a fix
lands there. Once releases exist, security fixes go to the current minor release and to the previous
one for six months after its successor ships; an older release gets a fix only where the
vulnerability is in a contract it still speaks.

A finding in the design is welcome now, through the same private channel if it has security
consequences and as an ordinary issue otherwise. The threat model this component is built against
is in [README.md](README.md) and, for the platform as a whole, in the hub
([iokaio/munarium-platform](https://github.com/iokaio/munarium-platform)).

## What matters most here

As runtime behavior is implemented, these are the classes of finding taken most seriously and most
quickly:

- **A target credential readable from the agent environment**: prompts, memory, exceptions, traces, environment variables, logs. This is the platform's most important proof point.
- **Audience substitution, token replay, delegation widening, stale-key acceptance, or concurrent grant redemption** succeeding against the broker.
- **A self-reported actor chain accepted as identity evidence**, a cycle or ambiguous identity admitted, or an agent-derived credential converted into a human ratification role.
- **A grant issued without a matching durable claim**, or a grant treated as single-use because its documentation says so rather than because an atomic consumption check exists.
- **Revocation that does not stop new affected grants within the published bound**, or a suspension that does not reach outstanding unconsumed grants as the contract states.
- **A retired signing key still minting grants**, or a lost key restored into an agent-accessible workspace.

## What is deliberate, and is not a defect

- **Warden is not an identity provider and not a secrets vault.** It federates with the enterprise identity provider and brokers from established secrets infrastructure. A report that Warden "does not authenticate users" or "does not store secrets" describes the design.
- **A platform grant is not a target credential.** A legacy target may accept only a long-lived secret; Warden isolates it from the agent and states the residual risk in the connector's assurance metadata rather than calling the secret single-use.
- **Short token lifetimes are not revocation.** The published revocation bound, with its clock, partition, cache and dependency assumptions, is the claim; when the bound cannot be maintained, new consequential grants stop.

When a local development profile exists, its test identity provider, test broker, disposable target
and generated sample credentials are development conveniences confined to that profile. They are
not vulnerabilities in themselves. A path by which they reach a production deployment unnoticed is.

## Findings that cross components

A contract ambiguity that lets two components disagree about authority, a canonicalization
difference between clients, or a gap between what a release advertises and what its evidence
supports is still a security finding. Report it here, or to any other Munarium repository, through
the same private channel; it is routed to the hub and the affected repositories together. Do not
open a public issue for it in the hub.

## Secrets

If you have committed a token or key, treat it as compromised: rotate it first, then report it.
