// SPDX-License-Identifier: Apache-2.0
//! Bind target authority to an isolated connector.
//!
//! The output belongs only in the connector privilege domain. Do not expose raw target secrets through agent APIs, diagnostics, or derived Debug output.
//!
//! Proposed local interface only. No implementation or wire format is provided.

/// Proposed boundary for: bind target authority to an isolated connector.
///
/// Implementations and concrete types await the component design and hub contracts.
/// This declaration does not enforce authentication, authorization, or durability.
pub trait CredentialBroker {
    /// Input whose concrete shape and validation rules are still to be specified.
    type ConnectorRequest;
    /// Output whose concrete shape and evidence requirements are still to be specified.
    type ConnectorBinding;
    /// Failure reported without manufacturing a successful or authorized result.
    type Error;

    /// Bind target authority to an isolated connector.
    ///
    /// # Errors
    ///
    /// Implementations must report failed validation or unavailable required dependencies.
    fn bind(
        &mut self,
        input: &Self::ConnectorRequest,
    ) -> Result<Self::ConnectorBinding, Self::Error>;
}
