// SPDX-License-Identifier: Apache-2.0
//! Stage 2 grant custody; service adapters supply independently verified current evidence.
use crate::{
    activation::Store,
    activation_wire::{self as wire, Error, Result},
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde_json::{Value, json};
/// Independently fetched and authorized issuance inputs, never caller-deserialized authority.
pub struct Issuance {
    /// Complete Gate lookup with original request, approval and claim custody.
    pub lookup: Value,
    /// Current Council approval lookup.
    pub approval: Value,
    /// Current bounded UTC observation.
    pub now: u64,
    /// Enrolled dedicated Warden action stream.
    pub stream: String,
    /// Current source generation.
    pub generation: u64,
    /// Externally governed recovery generation.
    pub recovery: u64,
}
impl Store {
    /// Oldest retained issuance awaiting delivery, including expired or revoked grants.
    /// Audit delivery cannot renew issuance or confer current-use permission.
    pub fn grant_pending(&self, scope: &Value) -> Result<Option<Value>> {
        let raw:Option<String>=self.db.query_row("SELECT event FROM execution_grants WHERE scope=?1 AND acknowledgement IS NULL ORDER BY rowid LIMIT 1",[wire::raw(scope)?],|r|r.get(0)).optional()?;
        raw.map(|v| wire::parse(&v)).transpose()
    }
    /// Issue a stable thirty-second grant and canonical outbox event in one transaction.
    pub fn grant_issue(&mut self, input: &Issuance) -> Result<Value> {
        let lookup = &input.lookup;
        let r = &lookup["binding"]["request"];
        let claim = &lookup["claim"];
        let scope = &r["operation"]["scope"];
        let key = wire::raw(scope)?;
        let approval = &input.approval["approval"];
        for (v, kind) in [
            (r, "action-request"),
            (claim, "accountability-event"),
            (approval, "action-approval"),
        ] {
            wire::shape(v, kind)?;
            wire::scoped(v, scope)?;
        }
        crate::activation_delivery::acknowledge(claim, &lookup["claim_audit"]["acknowledgement"])?;
        if claim["kind"] != "claim-created"
            || claim["producer"] != "gate"
            || claim["payload_digest"] != wire::digest("event-payload", &claim["payload"])?
            || approval != &lookup["binding"]["approval"]
            || input.approval["currently_usable"] != true
            || input.approval["status"] != "approved"
            || input.approval["revision"] != 1
            || claim["payload"]["request_digest"] != wire::digest("action-request", r)?
            || claim["payload"]["context_digest"] != r["context_digest"]
            || claim["payload"]["operation"] != r["operation"]
            || claim["payload"]["attempt"] != r["attempt"]
            || claim["payload"]["recovery_epoch"] != input.recovery
            || input.recovery == 0
            || input.generation == 0
            || input.stream.is_empty()
            || input.stream.len() > 96
        {
            return Err(Error::Refused);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (epoch, digest): (u64, String) = tx.query_row(
            "SELECT epoch,digest FROM stage2_cells WHERE scope=?1",
            [&key],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let set = wire::digest(
            "artifact-set",
            &json!({"artifacts":[{"kind":"manifest","digest":r["context"]["manifest_digest"]},{"kind":"policy","digest":r["context"]["policy_digest"]}]}),
        )?;
        if claim["payload"]["activation_epoch"] != epoch || set != digest {
            return Err(Error::Refused);
        }
        let registration = wire::raw(
            &json!({"stream":input.stream,"generation":input.generation,"recovery":input.recovery}),
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO execution_streams VALUES(?1,?2)",
            params![key, registration],
        )?;
        let old: String = tx.query_row(
            "SELECT registration FROM execution_streams WHERE scope=?1",
            [&key],
            |r| r.get(0),
        )?;
        if old != registration {
            return Err(Error::Refused);
        }
        let operation = r["operation"]["id"].as_str().ok_or(Error::Invalid)?;
        let binding = wire::raw(&lookup["binding"])?;
        let old:Option<(String,String,Option<String>)>=tx.query_row("SELECT binding,event,acknowledgement FROM execution_grants WHERE scope=?1 AND operation=?2",params![key,operation],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
        if let Some((b, event, ack)) = old {
            if b != binding {
                return Err(Error::Conflict);
            }
            let event = wire::parse(&event)?;
            if event["payload"]["expires_at"]
                .as_u64()
                .ok_or(Error::Invalid)?
                <= input.now.saturating_add(2)
            {
                return Err(Error::Refused);
            }
            return Ok(
                json!({"event":event,"acknowledgement":ack.map(|v|wire::parse(&v)).transpose()?}),
            );
        }
        let expires = input
            .now
            .saturating_add(30)
            .min(approval["expires_at"].as_u64().ok_or(Error::Invalid)?)
            .min(r["context"]["expires_at"].as_u64().ok_or(Error::Invalid)?);
        if expires <= input.now.saturating_add(2) {
            return Err(Error::Refused);
        }
        let mut p = claim["payload"].clone();
        p.as_object_mut()
            .ok_or(Error::Invalid)?
            .remove("grant_binding_digest");
        p["kind"] = json!("grant-issued");
        p["expires_at"] = json!(expires);
        p["grant"] = json!({"scope":scope,"kind":"grant","id":format!("grant-{}",&wire::digest("grant-binding",&lookup["binding"])?[7..])});
        let mut stmt = tx.prepare("SELECT event FROM execution_grants WHERE scope=?1")?;
        let mut prior: Option<Value> = None;
        for row in stmt.query_map([&key], |r| r.get::<_, String>(0))? {
            let e = wire::parse(&row?)?;
            if prior
                .as_ref()
                .is_none_or(|old| old["sequence"].as_u64() < e["sequence"].as_u64())
            {
                prior = Some(e);
            }
        }
        drop(stmt);
        let sequence = prior
            .as_ref()
            .map(|p| p["sequence"].as_u64().unwrap_or(0) + 1)
            .unwrap_or(1);
        let event = json!({"schema_version":1,"type":"accountability-event","profile":"stage2-single-cell-v1","scope":scope,"event_id":format!("grant-{}-{sequence}",input.stream),"producer":"warden","stream":{"kind":"stream","scope":scope,"id":input.stream},"source_generation":input.generation,"sequence":sequence,"predecessor":prior.as_ref().map(|p|wire::digest("accountability-event",p)).transpose()?,"occurred_at":input.now,"clock":"bounded-utc-2s","family":"action","kind":"grant-issued","payload_digest":wire::digest("event-payload",&p)?,"payload":p,"causal_parents":[wire::digest("accountability-event",claim)?]});
        wire::shape(&event, "accountability-event")?;
        tx.execute(
            "INSERT INTO execution_grants(scope,operation,binding,event) VALUES(?1,?2,?3,?4)",
            params![key, operation, binding, wire::raw(&event)?],
        )?;
        tx.commit()?;
        Ok(json!({"event":event,"acknowledgement":null}))
    }
    /// Original grant and acknowledgement; lookup is not current-use permission.
    pub fn grant_lookup(&self, scope: &Value, operation: &str) -> Result<Value> {
        let (event,ack,custody):(String,Option<String>,Option<String>)=self.db.query_row("SELECT event,acknowledgement,custody FROM execution_grants WHERE scope=?1 AND operation=?2",params![wire::raw(scope)?,operation],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
        Ok(
            json!({"event":wire::parse(&event)?,"acknowledgement":ack.map(|v|wire::parse(&v)).transpose()?,"custody":custody.map(|v|wire::parse(&v)).transpose()?}),
        )
    }
    /// Retain exact Server custody. A changed acknowledgement cannot overwrite history.
    pub fn grant_ack(&mut self, scope: &Value, operation: &str, ack: &Value) -> Result<()> {
        let original = self.grant_lookup(scope, operation)?;
        crate::activation_delivery::acknowledge(&original["event"], ack)?;
        if !original["acknowledgement"].is_null() && original["acknowledgement"] != *ack {
            return Err(Error::Conflict);
        }
        let changed=self.db.execute("UPDATE execution_grants SET acknowledgement=?3 WHERE scope=?1 AND operation=?2 AND (acknowledgement IS NULL OR acknowledgement=?3)",params![wire::raw(scope)?,operation,wire::raw(ack)?])?;
        if changed != 1 {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    /// Bind custody once; a lost delivery never renews its invocation or expiry.
    pub fn grant_custody(
        &mut self,
        scope: &Value,
        operation: &str,
        ticket: &Value,
    ) -> Result<Value> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let key = wire::raw(scope)?;
        let old: Option<String> = tx.query_row(
            "SELECT custody FROM execution_grants WHERE scope=?1 AND operation=?2",
            params![key, operation],
            |r| r.get(0),
        )?;
        if let Some(old) = old {
            let old = wire::parse(&old)?;
            if old["invocation"] != ticket["invocation"] || old["connector"] != ticket["connector"]
            {
                return Err(Error::Conflict);
            }
            return Ok(old);
        }
        tx.execute(
            "UPDATE execution_grants SET custody=?3 WHERE scope=?1 AND operation=?2",
            params![key, operation, wire::raw(ticket)?],
        )?;
        tx.commit()?;
        Ok(ticket.clone())
    }
}
