// SPDX-License-Identifier: Apache-2.0
//! Munarium Warden: experimental authority library.
//!
//! Verified principal chains, claim-bound grants, isolated credential brokering, and bounded revocation.
//!
//! Signed principal verification, durable SQLite issuance and activation, suspension,
//! online tickets and OpenBao credential retrieval. No production path is qualified.
//! See `docs/architecture.md` and `docs/implementation-plan.md` in this repository.
//!
//! The interfaces are experimental and may change before the first accepted contract.
//! Concrete cross-component types must follow an accepted hub decision and contract.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod activation;
pub mod activation_wire;

pub mod admission;
pub mod authority;
pub mod broker;
pub mod credential;
pub mod encoding;
pub mod error;
pub mod grants;
pub mod identity;
pub mod policy;
pub mod principal;
pub mod revocation;
