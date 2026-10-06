// SPDX-License-Identifier: Apache-2.0
//! Narrow authority through an authenticated bounded suspension.
//!
//! Measure admission and outstanding-grant rejection separately; restoration needs its own authorized path.
//!
//! [`crate::authority::Store::suspend`] implements durable, scope-specific suspension.
//! The original generic interface below remains provisional; it is not a wire format.

pub use crate::authority::{ControlPlane, Scope};

/// Proposed boundary for: narrow authority through an authenticated bounded suspension.
///
/// Implementations and concrete types await the component design and hub contracts.
/// This declaration does not enforce authentication, authorization, or durability.
pub trait SuspensionAuthority {
    /// Input whose concrete shape and validation rules are still to be specified.
    type SuspensionRequest;
    /// Output whose concrete shape and evidence requirements are still to be specified.
    type SuspensionRecord;
    /// Failure reported without manufacturing a successful or authorized result.
    type Error;

    /// Narrow authority through an authenticated bounded suspension.
    ///
    /// # Errors
    ///
    /// Implementations must report failed validation or unavailable required dependencies.
    fn suspend(
        &mut self,
        input: &Self::SuspensionRequest,
    ) -> Result<Self::SuspensionRecord, Self::Error>;
}
