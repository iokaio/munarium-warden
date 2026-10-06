// SPDX-License-Identifier: Apache-2.0
//! Durable, single-node Warden issuance and activation experiment.
//!
//! Adapter traits are privileged authentication boundaries, not request DTOs.
//! Gate remains the sole owner of consumption and final dispatch admission.

use crate::{
    encoding::{current, identifier, valid_digest},
    error::Error,
    principal::Principal,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use std::{path::Path, time::Duration};

/// Exact immutable binding obtained from Gate's authenticated durable journal.
/// Serialization is a private SQLite storage format, not a platform wire contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    /// Tenant.
    pub tenant: String,
    /// Deployment.
    pub deployment: String,
    /// Gate cell identifier.
    pub cell: String,
    /// External recovery epoch.
    pub recovery_epoch: i64,
    /// Stable durable claim identifier.
    pub claim: String,
    /// Complete canonical request digest.
    pub request_digest: String,
    /// Verified principal envelope digest.
    pub principal_digest: String,
    /// Registered workload instance.
    pub instance: String,
    /// Registered agent version.
    pub agent_version: String,
    /// Exact target resource.
    pub resource: String,
    /// Required principal scope.
    pub scope: String,
    /// Intended isolated connector audience.
    pub audience: String,
    /// Active policy digest.
    pub policy_digest: String,
    /// Exact registered task revision.
    pub task_digest: String,
    /// Activation epoch pinned by Gate.
    pub activation_epoch: i64,
    /// Actual enforcement mode.
    pub mode: String,
}

impl Binding {
    fn valid(&self) -> bool {
        [
            &self.tenant,
            &self.deployment,
            &self.cell,
            &self.claim,
            &self.instance,
            &self.agent_version,
            &self.resource,
            &self.audience,
        ]
        .iter()
        .all(|s| identifier(s))
            && [
                &self.request_digest,
                &self.principal_digest,
                &self.policy_digest,
                &self.task_digest,
            ]
            .iter()
            .all(|s| valid_digest(s))
            && matches!(self.scope.as_str(), "read" | "evaluate" | "propose")
            && matches!(self.mode.as_str(), "guard" | "enforce" | "assure")
            && self.activation_epoch > 0
            && self.recovery_epoch > 0
    }
}

/// Persisted issuance result; an opaque identifier, never a target credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    /// Random, stable issuance identifier.
    pub id: String,
    /// Original exclusive expiry; identical retries cannot extend it.
    pub expires: i64,
    /// Exact immutable claim binding.
    pub binding: Binding,
}

/// Current authenticated journal state following atomic consumption at Gate.
pub struct Consumption {
    /// Immutable durable claim binding.
    pub binding: Binding,
    /// Grant consumed in Gate's transaction.
    pub grant_id: String,
    /// Current worker identity.
    pub worker: String,
    /// Current worker fencing token.
    pub fence: i64,
    /// Exclusive worker lease deadline.
    pub lease_expires: i64,
    /// Exact acknowledged predispatch event digest; absent acknowledgement refuses.
    pub acknowledged_event: Option<String>,
}

/// Privileged adapter to an authenticated, current Gate journal.
/// Implementations must reject unavailable/stale evidence and authenticate the peer.
pub trait Gate {
    /// Look up a durable, still admissible claim, not a caller assertion.
    fn claim(&self, binding: &Binding) -> Result<Binding, Error>;
    /// Introspect atomic consumption, live worker and Server acknowledgement.
    /// Only `dispatch-admitted` may validate; dispatching, terminal or unresolved
    /// claims must refuse. A successful lookup never substitutes for final admission.
    fn consumption(&self, grant: &Grant) -> Result<Consumption, Error>;
}

/// Privileged adapter that re-verifies signed identity and current Registry/key state.
/// Called on every issuance and ticket request; never return a cached authorization.
pub trait LiveIdentity {
    /// Verify the exact bound principal against current keys, peer and policy context.
    fn verify(&self, binding: &Binding) -> Result<Principal, Error>;
}

/// Fresh authority state obtained outside Warden's restorable database.
pub struct Snapshot {
    /// Trusted Unix clock; uncertainty must be at most two seconds.
    pub now: i64,
    /// Current externally fenced recovery epoch.
    pub recovery_epoch: i64,
    /// False for unavailable authority, uncertain clocks, restore or split brain.
    pub healthy: bool,
}

/// Council-authorized activation after Gate's durable admission barrier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Activation {
    /// Tenant named by the attestation and barrier.
    pub tenant: String,
    /// Deployment named by the attestation and barrier.
    pub deployment: String,
    /// Cell named by the attestation and barrier.
    pub cell: String,
    /// Stable transition identifier.
    pub transition: String,
    /// Expected previous activation epoch; zero for initial installation.
    pub previous_epoch: i64,
    /// New epoch; strictly greater than the previous epoch.
    pub epoch: i64,
    /// New policy digest.
    pub policy_digest: String,
    /// New mode, including observe/advise which disable grants.
    pub mode: String,
    /// Externally established recovery epoch.
    pub recovery_epoch: i64,
}

/// Suspension scope. Suspensions are durable tombstones with no automatic expiry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scope {
    /// All work in this store's tenant.
    Tenant,
    /// All work in this store's deployment.
    Deployment,
    /// One registered workload instance.
    Instance(String),
    /// One registered agent version.
    AgentVersion(String),
}

impl Scope {
    fn parts(&self) -> (&str, &str) {
        match self {
            Self::Tenant => ("tenant", "*"),
            Self::Deployment => ("deployment", "*"),
            Self::Instance(v) => ("instance", v),
            Self::AgentVersion(v) => ("version", v),
        }
    }
}

/// Authenticated control-plane adapter, configured by the operator, never the agent.
///
/// Scope every response to the store's tenant/deployment/cell. Activation must verify
/// Council's attestation and Gate's durable pause for this exact transition and epoch.
/// Startup must remain unhealthy until external recovery custody excludes rollback,
/// restored snapshots and old dispatchers; persisted state alone is insufficient.
pub trait ControlPlane {
    /// Fresh authority, clock and externally held recovery epoch.
    fn snapshot(&self) -> Result<Snapshot, Error>;
    /// Verify current Council authority and the still-held Gate admission barrier.
    fn activation(&self, transition: &str) -> Result<Activation, Error>;
    /// Verify an authenticated, authorized request to narrow the supplied scope.
    fn suspension(&self, request: &str, scope: &Scope) -> Result<(), Error>;
}

/// Short-lived in-process validation ticket; no public constructor or deserializer.
pub struct Ticket {
    grant: Grant,
    worker: String,
    fence: i64,
    expires: i64,
    event: String,
}

impl Ticket {
    /// Exact issued grant and all immutable request bindings.
    pub fn grant(&self) -> &Grant {
        &self.grant
    }
    /// Live owner checked with Gate.
    pub fn worker(&self) -> &str {
        &self.worker
    }
    /// Live owner's fencing token.
    pub fn fence(&self) -> i64 {
        self.fence
    }
    /// Exclusive deadline, bounded by five seconds, grant and worker lease.
    pub fn expires(&self) -> i64 {
        self.expires
    }
    /// Exact predispatch acknowledgement digest.
    pub fn event(&self) -> &str {
        &self.event
    }
}

/// Transactional SQLite issuance store for one tenant/deployment/cell.
/// SQLite is an experimental single-node backend, not the proposed reference topology.
pub struct Store {
    db: Connection,
    tenant: String,
    deployment: String,
    cell: String,
}

impl Store {
    /// Open/create durable storage. Opening a database does not activate authority.
    pub fn open(
        path: impl AsRef<Path>,
        tenant: &str,
        deployment: &str,
        cell: &str,
    ) -> Result<Self, Error> {
        if ![tenant, deployment, cell].iter().all(|s| identifier(s)) {
            return Err(Error::InvalidInput);
        }
        let mut db = Connection::open(path)?;
        db.busy_timeout(Duration::from_millis(250))?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS owner (id INTEGER PRIMARY KEY CHECK(id=1), tenant TEXT NOT NULL, deployment TEXT NOT NULL, cell TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS activation (epoch INTEGER PRIMARY KEY, transition TEXT UNIQUE NOT NULL, body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS issuance (recovery INTEGER NOT NULL, claim TEXT NOT NULL, id TEXT UNIQUE NOT NULL, body TEXT NOT NULL, expires INTEGER NOT NULL, PRIMARY KEY(recovery,claim));
            CREATE TABLE IF NOT EXISTS suspension (kind TEXT NOT NULL, subject TEXT NOT NULL, request TEXT NOT NULL, accepted INTEGER NOT NULL, PRIMARY KEY(kind,subject));")?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT OR IGNORE INTO owner VALUES(1,?1,?2,?3)",
            params![tenant, deployment, cell],
        )?;
        let owner: (String, String, String) = tx.query_row(
            "SELECT tenant,deployment,cell FROM owner WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        if owner != (tenant.into(), deployment.into(), cell.into()) {
            return Err(Error::Conflict);
        }
        tx.commit()?;
        Ok(Self {
            db,
            tenant: tenant.into(),
            deployment: deployment.into(),
            cell: cell.into(),
        })
    }

    /// Install an authenticated activation with compare-and-swap and idempotent retries.
    /// Returns the acknowledgement Council needs before Gate may resume. This does not
    /// activate Registry or resume Gate, and failed transitions leave their barrier held.
    pub fn activate(
        &mut self,
        transition: &str,
        control: &impl ControlPlane,
    ) -> Result<Activation, Error> {
        if !identifier(transition) {
            return Err(Error::InvalidInput);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let a = control.activation(transition)?;
        let now = healthy(control)?;
        if a.tenant != self.tenant
            || a.deployment != self.deployment
            || a.cell != self.cell
            || a.transition != transition
            || a.previous_epoch < 0
            || a.epoch <= a.previous_epoch
            || a.recovery_epoch != now.recovery_epoch
            || !valid_digest(&a.policy_digest)
            || !matches!(
                a.mode.as_str(),
                "observe" | "advise" | "guard" | "enforce" | "assure"
            )
        {
            return Err(Error::Denied);
        }
        let body = serde_json::to_string(&a).map_err(|_| Error::InvalidInput)?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT body FROM activation WHERE transition=?1",
                [transition],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            if existing != body {
                return Err(Error::Conflict);
            }
            let latest: i64 =
                tx.query_row("SELECT max(epoch) FROM activation", [], |r| r.get(0))?;
            if latest != a.epoch {
                return Err(Error::Conflict);
            }
            return Ok(a);
        }
        let previous: i64 =
            tx.query_row("SELECT coalesce(max(epoch),0) FROM activation", [], |r| {
                r.get(0)
            })?;
        if previous != a.previous_epoch {
            return Err(Error::Conflict);
        }
        tx.execute(
            "INSERT INTO activation VALUES(?1,?2,?3)",
            params![a.epoch, transition, body],
        )?;
        tx.commit()?;
        Ok(a)
    }

    /// Issue once against a matching durable claim and freshly verified principal.
    /// The identity adapter reverifies current keys and Registry state on each call.
    pub fn issue(
        &mut self,
        binding: &Binding,
        identity: &impl LiveIdentity,
        gate: &impl Gate,
        control: &impl ControlPlane,
    ) -> Result<Grant, Error> {
        self.owner(binding)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let snapshot = healthy(control)?;
        check(&tx, binding, &snapshot)?;
        let principal = identity.verify(binding)?;
        principal_matches(binding, &principal, snapshot.now)?;
        if gate.claim(binding)? != *binding {
            return Err(Error::Denied);
        }
        let body = serde_json::to_string(binding).map_err(|_| Error::InvalidInput)?;
        let existing: Option<(String, String, i64)> = tx
            .query_row(
                "SELECT id,body,expires FROM issuance WHERE recovery=?1 AND claim=?2",
                params![binding.recovery_epoch, binding.claim],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        if let Some((id, old, expires)) = existing {
            if old != body {
                return Err(Error::Conflict);
            }
            if !current(0, expires, snapshot.now) {
                return Err(Error::Expired);
            }
            return Ok(Grant {
                id,
                expires,
                binding: binding.clone(),
            });
        }
        let expires = snapshot
            .now
            .checked_add(30)
            .ok_or(Error::Unavailable)?
            .min(principal.expires());
        if !current(0, expires, snapshot.now) {
            return Err(Error::Expired);
        }
        let mut random = [0u8; 32];
        getrandom::fill(&mut random).map_err(|_| Error::Unavailable)?;
        let id = crate::encoding::digest(&random);
        tx.execute(
            "INSERT INTO issuance VALUES(?1,?2,?3,?4,?5)",
            params![binding.recovery_epoch, binding.claim, id, body, expires],
        )?;
        tx.commit()?;
        Ok(Grant {
            id,
            expires,
            binding: binding.clone(),
        })
    }

    /// Revalidate stored issuance, live principal, consumption, revocation and epochs.
    /// A ticket does not consume a grant or authorize a send without Gate's final CAS.
    pub fn validate(
        &mut self,
        grant: &Grant,
        identity: &impl LiveIdentity,
        gate: &impl Gate,
        control: &impl ControlPlane,
    ) -> Result<Ticket, Error> {
        self.owner(&grant.binding)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let snapshot = healthy(control)?;
        check(&tx, &grant.binding, &snapshot)?;
        let principal = identity.verify(&grant.binding)?;
        principal_matches(&grant.binding, &principal, snapshot.now)?;
        let stored: Option<(String, i64)> = tx
            .query_row(
                "SELECT body,expires FROM issuance WHERE id=?1",
                [&grant.id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (body, expires) = stored.ok_or(Error::Denied)?;
        if serde_json::from_str::<Binding>(&body).map_err(|_| Error::Unavailable)? != grant.binding
            || expires != grant.expires
        {
            return Err(Error::Denied);
        }
        let consumed = gate.consumption(grant)?;
        let event = consumed.acknowledged_event.ok_or(Error::Denied)?;
        if consumed.binding != grant.binding
            || consumed.grant_id != grant.id
            || consumed.fence < 1
            || !identifier(&consumed.worker)
            || !valid_digest(&event)
        {
            return Err(Error::Denied);
        }
        let deadline = snapshot
            .now
            .checked_add(5)
            .ok_or(Error::Unavailable)?
            .min(expires)
            .min(consumed.lease_expires)
            .min(principal.expires());
        if !current(0, deadline, snapshot.now) {
            return Err(Error::Expired);
        }
        tx.commit()?;
        Ok(Ticket {
            grant: grant.clone(),
            worker: consumed.worker,
            fence: consumed.fence,
            expires: deadline,
            event,
        })
    }

    /// Persist a suspension before acknowledgement; no restoration or expiry shortcut.
    pub fn suspend(
        &mut self,
        request: &str,
        scope: &Scope,
        control: &impl ControlPlane,
    ) -> Result<i64, Error> {
        let (kind, subject) = scope.parts();
        if !identifier(request) || (subject != "*" && !identifier(subject)) {
            return Err(Error::InvalidInput);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        control.suspension(request, scope)?;
        let now = control.snapshot()?.now;
        tx.execute(
            "INSERT OR IGNORE INTO suspension VALUES(?1,?2,?3,?4)",
            params![kind, subject, request, now],
        )?;
        let accepted = tx.query_row(
            "SELECT accepted FROM suspension WHERE kind=?1 AND subject=?2",
            params![kind, subject],
            |r| r.get(0),
        )?;
        tx.commit()?;
        Ok(accepted)
    }

    fn owner(&self, binding: &Binding) -> Result<(), Error> {
        if !binding.valid()
            || binding.tenant != self.tenant
            || binding.deployment != self.deployment
            || binding.cell != self.cell
        {
            return Err(Error::Denied);
        }
        Ok(())
    }
}

fn healthy(control: &impl ControlPlane) -> Result<Snapshot, Error> {
    let s = control.snapshot()?;
    if !s.healthy || s.recovery_epoch <= 0 {
        return Err(Error::Quarantined);
    }
    Ok(s)
}

fn principal_matches(binding: &Binding, p: &Principal, now: i64) -> Result<(), Error> {
    if p.tenant() != binding.tenant
        || p.deployment() != binding.deployment
        || p.fingerprint() != binding.principal_digest
        || p.policy_digest() != binding.policy_digest
        || p.task_digest() != binding.task_digest
        || !p.permits(&binding.scope, &binding.resource)
        || !current(0, p.expires(), now)
    {
        return Err(Error::Identity);
    }
    Ok(())
}

fn check(db: &Connection, b: &Binding, s: &Snapshot) -> Result<(), Error> {
    let body: Option<String> = db
        .query_row(
            "SELECT body FROM activation ORDER BY epoch DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    let a: Activation =
        serde_json::from_str(&body.ok_or(Error::Denied)?).map_err(|_| Error::Unavailable)?;
    if a.epoch != b.activation_epoch
        || a.mode != b.mode
        || a.policy_digest != b.policy_digest
        || a.recovery_epoch != b.recovery_epoch
        || b.recovery_epoch != s.recovery_epoch
    {
        return Err(Error::Denied);
    }
    let blocked: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM suspension WHERE kind IN ('tenant','deployment') OR (kind='instance' AND subject=?1) OR (kind='version' AND subject=?2))", params![b.instance,b.agent_version], |r| r.get(0))?;
    if blocked {
        return Err(Error::Denied);
    }
    Ok(())
}
