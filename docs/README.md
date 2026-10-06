# Munarium Warden development documentation

Start with the [repository README](../README.md) for scope and capability status.
The [public platform plan, revision 4](https://github.com/iokaio/munarium-platform/blob/main/docs/platform-plan.md) is the design baseline;
section 9 covers Warden. A plan or a compiling interface does not establish a capability.

| Document | Purpose |
|---|---|
| [Architecture](architecture.md) | Proposed modules, state ownership, dependencies, threats and open decisions |
| [Implementation plan](implementation-plan.md) | First bounded work item, delivery sequence and acceptance criteria |
| [WARDEN-01 readiness](warden-01-readiness.md) | Pinned preparation inputs, implementation blockers and identity acceptance mapping |
| [Validation](validation.md) | Local build recipe, automatic checks and future acceptance specifications |
| [Experimental runtime](experimental-runtime.md) | Implemented operations, runnable broker test, trust boundaries and retained evidence |

The [source](../src/lib.rs) implements experimental identity, grants, activation,
suspension and brokering. Released contracts, qualified deployment profiles and
production capabilities remain **none**.
