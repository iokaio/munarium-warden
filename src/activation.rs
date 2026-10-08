// SPDX-License-Identifier: Apache-2.0
//! Warden's Stage 2 participant store, separate from the older grant experiment.
use crate::activation_wire::{self as wire, Authority, Error, Result};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde_json::{Value, json};
mod delivery;
use std::path::Path;
impl From<rusqlite::Error> for Error {
    fn from(_: rusqlite::Error) -> Self {
        Self::Unavailable
    }
}
/// Authenticated dependency evidence; no request can deserialize it as authority.
pub struct Evidence {
    /// Exact Gate pause.
    pub pause: Value,
    /// Current Gate barrier, independently read alongside its historical pause receipt.
    pub gate_head: Value,
    /// Registry's exact applied receipt.
    pub registry_receipt: Value,
    /// Registry's current installed head.
    pub registry_head: Value,
}
/// Owner-local durable participant and retained outbox.
pub struct Store {
    db: Connection,
}
impl Store {
    /// Open additive participant tables with WAL and full synchronous durability.
    pub fn open(path: &Path) -> Result<Self> {
        let db = Connection::open(path)?;
        db.busy_timeout(std::time::Duration::from_secs(3))?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
          CREATE TABLE IF NOT EXISTS stage2_cells(scope TEXT PRIMARY KEY,initial_epoch INTEGER NOT NULL,initial_digest TEXT NOT NULL,epoch INTEGER NOT NULL,digest TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS stage2_transitions(scope TEXT NOT NULL,id TEXT NOT NULL,record TEXT NOT NULL,receipt TEXT NOT NULL,PRIMARY KEY(scope,id));
          CREATE TABLE IF NOT EXISTS stage2_outbox(sequence INTEGER PRIMARY KEY,scope TEXT NOT NULL,id TEXT NOT NULL,record TEXT NOT NULL,receipt TEXT NOT NULL,UNIQUE(scope,id));")?;
        db.execute_batch("CREATE TABLE IF NOT EXISTS activation_delivery(scope TEXT NOT NULL,id TEXT NOT NULL,sequence INTEGER NOT NULL,event TEXT NOT NULL,acknowledgement TEXT,PRIMARY KEY(scope,id),UNIQUE(scope,sequence));")?;
        Ok(Self { db })
    }
    /// Enroll once; later configuration cannot reset an evolved or differently enrolled head.
    pub fn initialize(&mut self, scope: &Value, epoch: u64, digest: &str) -> Result<()> {
        wire::initial(scope, epoch, digest)?;
        let key = wire::raw(scope)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT OR IGNORE INTO stage2_cells VALUES(?1,?2,?3,?2,?3)",
            params![key, epoch, digest],
        )?;
        let old: (u64, String) = tx.query_row(
            "SELECT initial_epoch,initial_digest FROM stage2_cells WHERE scope=?1",
            [&key],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if old != (epoch, digest.into()) {
            return Err(Error::Conflict);
        }
        tx.commit()?;
        Ok(())
    }
    /// Apply only the exact ratified, paused and Registry-admitted set; retry retains bytes.
    pub fn apply(&mut self, auth: &Authority, t: &Value, evidence: &Evidence) -> Result<Value> {
        wire::validate(auth, t)?;
        wire::check_receipt(t, &evidence.pause, "gate", "paused")?;
        let h = &evidence.gate_head;
        if h["scope"] != auth.scope
            || h["participant"] != "gate"
            || h["paused"] != true
            || h["transition_id"] != t["transition"]["id"]
            || !((h["epoch"] == t["prior_epoch"]
                && h["artifact_set_digest"] == t["prior_artifact_set_digest"])
                || (h["epoch"] == t["successor_epoch"]
                    && h["artifact_set_digest"] == t["artifact_set_digest"]))
        {
            return Err(Error::Refused);
        }
        wire::check_receipt(t, &evidence.registry_receipt, "registry", "applied")?;
        wire::check_head(t, &evidence.registry_head, "registry")?;
        let key = wire::raw(&auth.scope)?;
        let raw = wire::raw(t)?;
        let id = t["transition"]["id"].as_str().ok_or(Error::Invalid)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old: Option<(String, String)> = tx
            .query_row(
                "SELECT record,receipt FROM stage2_transitions WHERE scope=?1 AND id=?2",
                params![key, id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((prior, receipt)) = old {
            if prior != raw {
                return Err(Error::Conflict);
            }
            return wire::parse(&receipt);
        }
        let (epoch, digest): (u64, String) = tx
            .query_row(
                "SELECT epoch,digest FROM stage2_cells WHERE scope=?1",
                [&key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .ok_or(Error::Refused)?;
        if t["prior_epoch"] != epoch || t["prior_artifact_set_digest"] != digest {
            return Err(Error::Conflict);
        }
        let receipt = wire::receipt(t, "warden", "applied")?;
        let encoded = wire::raw(&receipt)?;
        tx.execute(
            "UPDATE stage2_cells SET epoch=?2,digest=?3 WHERE scope=?1",
            params![
                key,
                t["successor_epoch"].as_u64().ok_or(Error::Invalid)?,
                t["artifact_set_digest"].as_str().ok_or(Error::Invalid)?
            ],
        )?;
        tx.execute(
            "INSERT INTO stage2_transitions VALUES(?1,?2,?3,?4)",
            params![key, id, raw, encoded],
        )?;
        tx.execute(
            "INSERT INTO stage2_outbox(scope,id,record,receipt) VALUES(?1,?2,?3,?4)",
            params![key, id, raw, encoded],
        )?;
        tx.commit()?;
        Ok(receipt)
    }
    /// Historical exact receipt lookup is never global activation.
    pub fn lookup(&self, scope: &Value, id: &str) -> Result<Value> {
        let raw: String = self
            .db
            .query_row(
                "SELECT receipt FROM stage2_transitions WHERE scope=?1 AND id=?2",
                params![wire::raw(scope)?, id],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(Error::Refused)?;
        wire::parse(&raw)
    }
    /// Current Warden epoch, explicitly separate from resumed cell authority.
    pub fn head(&self, scope: &Value) -> Result<Value> {
        let (epoch, digest): (u64, String) = self
            .db
            .query_row(
                "SELECT epoch,digest FROM stage2_cells WHERE scope=?1",
                [wire::raw(scope)?],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .ok_or(Error::Refused)?;
        Ok(
            json!({"scope":scope,"participant":"warden","epoch":epoch,"artifact_set_digest":digest,"cell_resumed":false,"execution_enabled":false}),
        )
    }
    /// Retained local outbox; no Server delivery is claimed by this accessor.
    pub fn pending(&self, scope: &Value) -> Result<Vec<Value>> {
        let mut stmt = self
            .db
            .prepare("SELECT record,receipt FROM stage2_outbox WHERE scope=?1 ORDER BY sequence")?;
        stmt.query_map([wire::raw(scope)?], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?
        .map(|row| {
            let (t, r) = row?;
            Ok(json!({"transition":wire::parse(&t)?,"receipt":wire::parse(&r)?}))
        })
        .collect()
    }
}
