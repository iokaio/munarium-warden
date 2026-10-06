// SPDX-License-Identifier: Apache-2.0
//! Stable, redacted errors at authority boundaries.

/// Refusal categories contain no submitted identity, secret or dependency payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Input is malformed, ambiguous, unsupported or exceeds a bound.
    InvalidInput,
    /// Signature or authenticated identity binding failed.
    Identity,
    /// Current authority or policy does not permit the operation.
    Denied,
    /// Required time or freshness bounds cannot be established.
    Expired,
    /// The immutable operation identifier was reused with changed content.
    Conflict,
    /// A required dependency failed; its raw error is deliberately discarded.
    Unavailable,
    /// Connector delivery may have occurred; reconcile before any further send.
    Unresolved,
    /// Recovery or activation has paused admission.
    Quarantined,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}

impl From<rusqlite::Error> for Error {
    fn from(_: rusqlite::Error) -> Self {
        Self::Unavailable
    }
}
