// SPDX-License-Identifier: Apache-2.0
//! Verified workload JWT admission and bounded decision assertion issuance.
//! Provider facts are opaque, and neither provider tokens nor requests select trust.
use crate::{
    encoding::{canonical, current, decode, digest, identifier},
    error::Error,
    principal::{self, Trust},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;

/// Current operator-selected upstream JWT verification key.
pub struct ProviderKey {
    /// Exact upstream issuer, independent of the platform issuer.
    pub issuer: String,
    /// Exact workload API audience of Warden.
    pub audience: String,
    /// Exact protected header key identifier.
    pub key_id: String,
    /// Ed25519 public key bytes only.
    pub public_key: [u8; 32],
    /// Current upstream enrollment: exact subject to agent/service kind.
    pub subjects: std::collections::BTreeMap<String, String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    kid: String,
    typ: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Claims {
    iss: String,
    sub: String,
    aud: String,
    iat: i64,
    nbf: i64,
    exp: i64,
}
/// Verified protocol facts, constructed only by the provider verifier.
pub struct ProviderIdentity {
    claims: Claims,
    kind: String,
}

/// Verify the narrow workload JWT profile with the current independently selected key.
/// Unknown/duplicate fields, noncanonical encodings, wrong recipient and expired tokens refuse.
pub fn verify_provider(
    token: &str,
    key: &ProviderKey,
    now: i64,
) -> Result<ProviderIdentity, Error> {
    if token.len() > 65536 {
        return Err(Error::Identity);
    }
    let parts: Vec<_> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(Error::Identity);
    }
    let header: Header =
        serde_json::from_value(canonical(&decode(parts[0])?)?).map_err(|_| Error::Identity)?;
    if header.alg != "EdDSA" || header.typ != "at+jwt" || header.kid != key.key_id {
        return Err(Error::Identity);
    }
    VerifyingKey::from_bytes(&key.public_key)
        .map_err(|_| Error::Identity)?
        .verify_strict(
            format!("{}.{}", parts[0], parts[1]).as_bytes(),
            &Signature::from_slice(&decode(parts[2])?).map_err(|_| Error::Identity)?,
        )
        .map_err(|_| Error::Identity)?;
    let claims: Claims =
        serde_json::from_value(canonical(&decode(parts[1])?)?).map_err(|_| Error::Identity)?;
    if claims.iss != key.issuer
        || claims.aud != key.audience
        || claims.sub.is_empty()
        || claims.sub.len() > 512
        || claims.iat < 0
        || claims.iat > claims.nbf
        || !current(claims.nbf, claims.exp, now)
    {
        return Err(Error::Identity);
    }
    let kind = key
        .subjects
        .get(&claims.sub)
        .filter(|kind| matches!(kind.as_str(), "agent" | "service"))
        .ok_or(Error::Identity)?
        .clone();
    Ok(ProviderIdentity { claims, kind })
}

/// Operator-admitted ADR-0005 provider binding; never accepted from issuance input.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderBinding {
    /// Exactly version one.
    pub schema_version: u8,
    /// Unique admitted registration identifier.
    pub binding_id: String,
    /// Trusted deployment.
    pub deployment: String,
    /// Trusted tenant.
    pub tenant: String,
    /// Exact upstream issuer.
    pub provider_issuer: String,
    /// Exact opaque upstream subject.
    pub provider_subject: String,
    /// Explicitly enrolled agent or service kind, never a token claim.
    pub origin_kind: String,
    /// Registered root actor.
    pub origin: String,
    /// Transport-authenticated requester permitted to present this identity.
    pub peer_service: String,
    /// Exact permitted recipients.
    pub audiences: Vec<String>,
    /// Permitted decision scopes.
    pub scopes: Vec<String>,
    /// Exact permitted resources.
    pub resources: Vec<String>,
    /// Earliest validity.
    pub nbf: i64,
    /// Exclusive expiry.
    pub exp: i64,
}
fn subset(child: &[String], parent: &[String]) -> bool {
    !child.is_empty()
        && child.iter().all(|v| parent.contains(v))
        && child.iter().collect::<BTreeSet<_>>().len() == child.len()
}
fn sign(payload: &Value, key: &SigningKey, kid: &str) -> Result<String, Error> {
    let header = json!({"alg":"Ed25519","kid":kid,"typ":"munarium-principal+jws"});
    let raw = serde_json::to_vec(payload).map_err(|_| Error::InvalidInput)?;
    canonical(&raw)?;
    let input = format!(
        "{}.{}",
        B64.encode(serde_json::to_vec(&header).map_err(|_| Error::InvalidInput)?),
        B64.encode(raw)
    );
    Ok(format!(
        "{input}.{}",
        B64.encode(key.sign(input.as_bytes()).to_bytes())
    ))
}
fn issuer<'a>(trust: &'a Trust, key: &SigningKey, kid: &str) -> Result<&'a str, Error> {
    if !trust.available {
        return Err(Error::Unavailable);
    }
    let registered = trust.keys.get(kid).ok_or(Error::Identity)?;
    if !registered.decision || registered.public_key != key.verifying_key().to_bytes() {
        return Err(Error::Identity);
    }
    Ok(&registered.issuer)
}

/// Issue a root using verified provider facts and a fresh governing snapshot.
/// The result is not usable until the conservative two-second clock window elapses.
pub fn issue_root(
    identity: &ProviderIdentity,
    bindings: &[ProviderBinding],
    trust: &Trust,
    scopes: &[String],
    resources: &[String],
    key: &SigningKey,
    kid: &str,
) -> Result<String, Error> {
    let issuer = issuer(trust, key, kid)?;
    if bindings.len() > 128 || !current(identity.claims.nbf, identity.claims.exp, trust.now) {
        return Err(Error::Identity);
    }
    let bindings: Vec<_> = bindings
        .iter()
        .filter(|b| {
            b.deployment == trust.deployment
                && b.tenant == trust.tenant
                && b.provider_issuer == identity.claims.iss
                && b.provider_subject == identity.claims.sub
        })
        .collect();
    if bindings.len() != 1 {
        return Err(Error::Identity);
    }
    let b = bindings[0];
    if b.schema_version != 1
        || !identifier(&b.binding_id)
        || !identifier(&b.origin)
        || b.origin_kind != identity.kind
        || b.peer_service != trust.peer_service
        || !b.audiences.contains(&trust.audience)
        || !current(b.nbf, b.exp, trust.now)
        || !current(trust.not_before, trust.expires, trust.now)
        || !subset(scopes, &b.scopes)
        || !subset(resources, &b.resources)
        || !subset(scopes, &trust.scopes)
        || !subset(resources, &trust.resources)
    {
        return Err(Error::Denied);
    }
    let expires = [
        trust.now.checked_add(60).ok_or(Error::Expired)?,
        b.exp,
        identity.claims.exp,
        trust.expires,
    ]
    .into_iter()
    .min()
    .ok_or(Error::Expired)?;
    let token = sign(
        &json!({"schema_version":1,"deployment":trust.deployment,"tenant":trust.tenant,
        "issuer":issuer,"audience":trust.audience,"origin":b.origin,"actor":b.origin,
        "origin_kind":b.origin_kind,"service":trust.peer_service,"purpose":"decision",
        "scopes":scopes,"resources":resources,"iat":trust.now,"nbf":trust.now,"exp":expires,
        "parent_digest":null,"bootstrap":null}),
        key,
        kid,
    )?;
    let mut future = trust.clone();
    future.now = trust.now.checked_add(2).ok_or(Error::Expired)?;
    principal::verify(std::slice::from_ref(&token), &future)?;
    Ok(token)
}

/// Attenuate a currently verified chain through an independently admitted delegation edge.
/// The actual presenter must match the parent. Child service and actor require a registration.
pub struct Delegate<'a> {
    /// Requested child actor, checked against the current registration.
    pub actor: &'a str,
    /// Requested presenting service, checked against the current registration.
    pub service: &'a str,
    /// Requested narrowed scopes.
    pub scopes: &'a [String],
    /// Requested narrowed resources.
    pub resources: &'a [String],
}
/// Issue the registered child assertion while retaining the complete parent chain.
pub fn issue_delegate(
    chain: &[String],
    trust: &Trust,
    child: Delegate<'_>,
    key: &SigningKey,
    kid: &str,
) -> Result<Vec<String>, Error> {
    let Delegate {
        actor,
        service,
        scopes,
        resources,
    } = child;
    let issuer = issuer(trust, key, kid)?;
    let parent = principal::verify(chain, trust)?;
    if !subset(scopes, parent.scopes()) || !subset(resources, parent.resources()) {
        return Err(Error::Denied);
    }
    let registrations: Vec<_> = trust
        .delegations
        .iter()
        .filter(|d| {
            d.deployment == trust.deployment
                && d.tenant == trust.tenant
                && d.origin == parent.origin()
                && d.origin_kind == parent.origin_kind()
                && d.from == parent.actor()
                && d.to == actor
                && d.service == service
                && d.audience == trust.audience
                && d.task_digest == trust.task_digest
                && d.policy_digest == trust.policy_digest
        })
        .collect();
    if registrations.len() != 1 {
        return Err(Error::Denied);
    }
    let edge = registrations[0];
    if !current(edge.not_before, edge.expires, trust.now) {
        return Err(Error::Denied);
    }
    let expires = [
        parent.expires(),
        edge.expires,
        trust.expires,
        trust.now.checked_add(60).ok_or(Error::Expired)?,
    ]
    .into_iter()
    .min()
    .ok_or(Error::Expired)?;
    let token = sign(
        &json!({"schema_version":1,"deployment":trust.deployment,"tenant":trust.tenant,
        "issuer":issuer,"audience":trust.audience,"origin":parent.origin(),"actor":actor,
        "origin_kind":parent.origin_kind(),"service":service,"purpose":"decision",
        "scopes":scopes,"resources":resources,"iat":trust.now,"nbf":trust.now,"exp":expires,
        "parent_digest":digest(chain.last().ok_or(Error::Identity)?.as_bytes()),"bootstrap":null}),
        key,
        kid,
    )?;
    let mut result = chain.to_vec();
    result.push(token);
    let mut future = trust.clone();
    future.now = trust.now.checked_add(2).ok_or(Error::Expired)?;
    future.peer_service = service.into();
    principal::verify(&result, &future)?;
    Ok(result)
}
