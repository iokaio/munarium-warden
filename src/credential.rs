// SPDX-License-Identifier: Apache-2.0
//! OpenBao KV v2 retrieval and delivery across a trusted connector boundary.
//!
//! Only the broker/connector privilege domain may load this module. No agent-facing
//! endpoint exposes secret values. Adapters must never put them in logs or diagnostics.

use crate::{
    authority::{ControlPlane, Gate, Grant, LiveIdentity, Store, Ticket},
    encoding::MAX_BODY,
    error::Error,
};
use reqwest::{Url, blocking::Client, redirect::Policy};
use serde::Deserialize;
use std::{io::Read, time::Duration};
use zeroize::{Zeroize, Zeroizing};

/// Secret bytes confined to the trusted broker and connector process.
/// No cloning, display, serialization or Debug implementation is provided.
pub struct Credential(Zeroizing<Vec<u8>>);

impl Credential {
    /// Create a credential inside a trusted secret-provider adapter.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, Error> {
        let bytes = Zeroizing::new(bytes);
        if bytes.is_empty() || bytes.len() > 16384 {
            return Err(Error::Unavailable);
        }
        Ok(Self(bytes))
    }
    /// Borrow only inside an isolated connector's authenticated delivery path.
    pub fn expose_to_connector(&self) -> &[u8] {
        &self.0
    }
}

/// Mature external secret-provider integration; never an agent-controlled callback.
pub trait SecretProvider {
    /// Fetch the secret mapped by trusted configuration to this exact resource.
    fn fetch(&self, resource: &str) -> Result<Credential, Error>;
}

/// Authenticated channel to an isolated connector, provisioned by the operator.
///
/// The connector must compare the complete binding, obtain Gate's final admission CAS
/// for this live invocation, and attempt at most one target send. An uncertain reply
/// is unresolved, never permission to resend. This trait cannot establish OS isolation.
pub trait Connector {
    /// Identity authenticated by the channel, not supplied by the requesting agent.
    fn audience(&self) -> &str;
    /// Deliver through the protected channel. Do not expose credentials in errors.
    fn deliver(&mut self, ticket: &Ticket, credential: &Credential) -> Result<(), Error>;
}

/// Delivery receipt contains no target credential or provider response.
/// It does not certify a target effect; Gate owns the action outcome.
#[derive(Debug, PartialEq, Eq)]
pub struct Receipt {
    /// Grant used for this delivery.
    pub grant_id: String,
    /// Exact request digest, suitable for correlation.
    pub request_digest: String,
    /// Credential assurance for KV v2: isolated reusable secret, not single-use.
    pub credential_kind: &'static str,
}

/// Retrieve and deliver a credential only after current online admission checks.
/// Revalidates after vault I/O so a slow provider cannot bypass suspension/expiry.
/// Gate's final CAS belongs inside the connector implementation, not this function.
pub fn deliver(
    store: &mut Store,
    grant: &Grant,
    identity: &impl LiveIdentity,
    gate: &impl Gate,
    control: &impl ControlPlane,
    provider: &impl SecretProvider,
    connector: &mut impl Connector,
) -> Result<Receipt, Error> {
    if connector.audience() != grant.binding.audience {
        return Err(Error::Denied);
    }
    store.validate(grant, identity, gate, control)?;
    let credential = provider.fetch(&grant.binding.resource)?;
    let ticket = store.validate(grant, identity, gate, control)?;
    // Once the protected delivery starts, an error can be a lost acknowledgement.
    // Never report it as a retryable provider failure or automatically resend.
    connector
        .deliver(&ticket, &credential)
        .map_err(|_| Error::Unresolved)?;
    Ok(Receipt {
        grant_id: grant.id.clone(),
        request_digest: grant.binding.request_digest.clone(),
        credential_kind: "isolated-reusable-secret",
    })
}

/// OpenBao KV v2 client with bounded responses, no redirects and finite timeouts.
/// URL and resource are operator-pinned; no request-controlled path interpolation.
pub struct OpenBao {
    client: Client,
    url: Url,
    token: Zeroizing<String>,
    resource: String,
}

impl OpenBao {
    /// Configure HTTPS using an operator-provisioned token and optional private CA.
    /// `endpoint` is the exact `/v1/<mount>/data/<path>` URL for one resource.
    pub fn https(
        endpoint: &str,
        token: String,
        resource: &str,
        ca: Option<reqwest::Certificate>,
    ) -> Result<Self, Error> {
        Self::configured(endpoint, token, resource, ca, false)
    }

    /// Explicit disposable-test escape hatch: only literal loopback HTTP is permitted.
    /// Never use this constructor with production credentials or expose the test vault.
    pub fn loopback_test(endpoint: &str, token: String, resource: &str) -> Result<Self, Error> {
        Self::configured(endpoint, token, resource, None, true)
    }

    fn configured(
        endpoint: &str,
        token: String,
        resource: &str,
        ca: Option<reqwest::Certificate>,
        loopback: bool,
    ) -> Result<Self, Error> {
        let token = Zeroizing::new(token);
        let url = Url::parse(endpoint).map_err(|_| Error::InvalidInput)?;
        let local = matches!(url.host_str(), Some("127.0.0.1" | "[::1]"));
        if (url.scheme() != "https" && !(loopback && local && url.scheme() == "http"))
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.path().starts_with("/v1/")
            || !url.path().contains("/data/")
            || token.is_empty()
            || token.len() > 8192
            || !crate::encoding::identifier(resource)
        {
            return Err(Error::InvalidInput);
        }
        let mut builder = Client::builder()
            .redirect(Policy::none())
            .no_proxy()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(3));
        if let Some(ca) = ca {
            builder = builder.add_root_certificate(ca);
        }
        let client = builder.build().map_err(|_| Error::Unavailable)?;
        Ok(Self {
            client,
            url,
            token,
            resource: resource.into(),
        })
    }
}

#[derive(Deserialize)]
struct VaultResponse {
    data: VaultData,
}
#[derive(Deserialize)]
struct VaultData {
    data: VaultSecret,
}
#[derive(Deserialize)]
struct VaultSecret {
    credential: String,
}
impl Drop for VaultSecret {
    fn drop(&mut self) {
        self.credential.zeroize();
    }
}

impl SecretProvider for OpenBao {
    fn fetch(&self, resource: &str) -> Result<Credential, Error> {
        if resource != self.resource {
            return Err(Error::Denied);
        }
        let mut token =
            reqwest::header::HeaderValue::from_str(&self.token).map_err(|_| Error::Unavailable)?;
        token.set_sensitive(true);
        let response = self
            .client
            .get(self.url.clone())
            .header("X-Vault-Token", token)
            .send()
            .map_err(|_| Error::Unavailable)?;
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|n| n > MAX_BODY as u64)
        {
            return Err(Error::Unavailable);
        }
        let mut raw = Zeroizing::new(Vec::new());
        response
            .take(MAX_BODY as u64 + 1)
            .read_to_end(&mut raw)
            .map_err(|_| Error::Unavailable)?;
        if raw.len() > MAX_BODY {
            return Err(Error::Unavailable);
        }
        let mut value: VaultResponse =
            serde_json::from_slice(&raw).map_err(|_| Error::Unavailable)?;
        Credential::from_bytes(std::mem::take(&mut value.data.data.credential).into_bytes())
    }
}
