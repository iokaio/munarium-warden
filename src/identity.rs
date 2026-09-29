// SPDX-License-Identifier: Apache-2.0
//! Verify identity evidence into a bounded principal context.
//!
//! Validate issuer, audience, expiry, tenant, delegation depth and narrowing. Self-reported actor arrays are not identity evidence.
//!
//! Proposed local interface only. No implementation or wire format is provided.

/// Proposed boundary for: verify identity evidence into a bounded principal context.
///
/// Implementations and concrete types await the component design and hub contracts.
/// This declaration does not enforce authentication, authorization, or durability.
pub trait IdentityVerifier {
    /// Input whose concrete shape and validation rules are still to be specified.
    type IdentityEvidence;
    /// Output whose concrete shape and evidence requirements are still to be specified.
    type VerifiedPrincipal;
    /// Failure reported without manufacturing a successful or authorized result.
    type Error;

    /// Verify identity evidence into a bounded principal context.
    ///
    /// # Errors
    ///
    /// Implementations must report failed validation or unavailable required dependencies.
    fn verify(
        &self,
        input: &Self::IdentityEvidence,
    ) -> Result<Self::VerifiedPrincipal, Self::Error>;
}
