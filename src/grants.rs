// SPDX-License-Identifier: Apache-2.0
//! Issue authority against a verified durable claim.
//!
//! A grant must bind exact request, audience, scope and time. Its single-use property depends on atomic consumption, not on a signature alone.
//!
//! Proposed local interface only. No implementation or wire format is provided.

/// Proposed boundary for: issue authority against a verified durable claim.
///
/// Implementations and concrete types await the component design and hub contracts.
/// This declaration does not enforce authentication, authorization, or durability.
pub trait GrantIssuer {
    /// Input whose concrete shape and validation rules are still to be specified.
    type ClaimEvidence;
    /// Output whose concrete shape and evidence requirements are still to be specified.
    type ExecutionGrant;
    /// Failure reported without manufacturing a successful or authorized result.
    type Error;

    /// Issue authority against a verified durable claim.
    ///
    /// # Errors
    ///
    /// Implementations must report failed validation or unavailable required dependencies.
    fn issue(&mut self, input: &Self::ClaimEvidence) -> Result<Self::ExecutionGrant, Self::Error>;
}
