// SPDX-License-Identifier: Apache-2.0
#![allow(dead_code)]
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::{Signer, SigningKey};
use munarium_warden::{
    authority::*,
    encoding::digest,
    error::Error,
    principal::{self, Principal, Trust, TrustedKey},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI64, Ordering},
    },
};

pub fn payload() -> Value {
    json!({"schema_version":1,"deployment":"fixture","tenant":"alpha","issuer":"fixture-issuer",
        "audience":"svc-gate","origin":"agent-a","actor":"agent-a","origin_kind":"agent",
        "service":"svc-harness","purpose":"decision","scopes":["evaluate"],"resources":["item-a"],
        "iat":980,"nbf":980,"exp":1040,"parent_digest":null,"bootstrap":null})
}
pub fn key() -> SigningKey {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).unwrap();
    SigningKey::from_bytes(&seed)
}
pub fn sign_bytes(key: &SigningKey, header: &[u8], body: &[u8]) -> String {
    let input = format!("{}.{}", B64.encode(header), B64.encode(body));
    format!(
        "{input}.{}",
        B64.encode(key.sign(input.as_bytes()).to_bytes())
    )
}
pub fn sign(key: &SigningKey, body: &Value) -> String {
    sign_bytes(
        key,
        br#"{"alg":"Ed25519","kid":"test-key","typ":"munarium-principal+jws"}"#,
        &serde_json::to_vec(body).unwrap(),
    )
}
pub fn trust(key: &SigningKey, now: i64) -> Trust {
    Trust {
        deployment: "fixture".into(),
        tenant: "alpha".into(),
        audience: "svc-gate".into(),
        peer_service: "svc-harness".into(),
        now,
        available: true,
        keys: BTreeMap::from([(
            "test-key".into(),
            TrustedKey {
                decision: true,
                public_key: key.verifying_key().to_bytes(),
                issuer: "fixture-issuer".into(),
            },
        )]),
        delegations: vec![],
        task_digest: digest(b"task"),
        policy_digest: digest(b"policy"),
        not_before: 900,
        expires: 1100,
        scopes: vec!["read".into(), "evaluate".into(), "propose".into()],
        resources: vec!["item-a".into(), "item-b".into()],
        maximum_depth: 4,
    }
}
pub struct Identity {
    pub key: SigningKey,
    pub chain: Vec<String>,
    pub clock: Arc<AtomicI64>,
    pub retired: AtomicBool,
}
impl Identity {
    pub fn new(clock: Arc<AtomicI64>) -> Self {
        let key = key();
        let chain = vec![sign(&key, &payload())];
        Self {
            key,
            chain,
            clock,
            retired: AtomicBool::new(false),
        }
    }
    pub fn binding(&self) -> Binding {
        Binding {
            tenant: "alpha".into(),
            deployment: "fixture".into(),
            cell: "cell-a".into(),
            recovery_epoch: 1,
            claim: "claim-a".into(),
            request_digest: digest(b"request"),
            principal_digest: digest(self.chain[0].as_bytes()),
            instance: "instance-a".into(),
            agent_version: "version-a".into(),
            resource: "item-a".into(),
            scope: "evaluate".into(),
            audience: "connector-a".into(),
            policy_digest: digest(b"policy"),
            task_digest: digest(b"task"),
            activation_epoch: 1,
            mode: "enforce".into(),
        }
    }
}
impl LiveIdentity for Identity {
    fn verify(&self, _: &Binding) -> Result<Principal, Error> {
        let mut t = trust(&self.key, self.clock.load(Ordering::SeqCst));
        if self.retired.load(Ordering::SeqCst) {
            t.keys.clear();
        }
        principal::verify(&self.chain, &t)
    }
}
pub struct Control {
    pub clock: Arc<AtomicI64>,
    pub healthy: AtomicBool,
    pub recovery: AtomicI64,
    pub activation: Activation,
    pub authorized: bool,
}
impl Control {
    pub fn new(clock: Arc<AtomicI64>) -> Self {
        Self {
            clock,
            healthy: AtomicBool::new(true),
            recovery: AtomicI64::new(1),
            authorized: true,
            activation: Activation {
                tenant: "alpha".into(),
                deployment: "fixture".into(),
                cell: "cell-a".into(),
                transition: "activation-1".into(),
                previous_epoch: 0,
                epoch: 1,
                policy_digest: digest(b"policy"),
                mode: "enforce".into(),
                recovery_epoch: 1,
            },
        }
    }
}
impl ControlPlane for Control {
    fn snapshot(&self) -> Result<Snapshot, Error> {
        Ok(Snapshot {
            now: self.clock.load(Ordering::SeqCst),
            recovery_epoch: self.recovery.load(Ordering::SeqCst),
            healthy: self.healthy.load(Ordering::SeqCst),
        })
    }
    fn activation(&self, _: &str) -> Result<Activation, Error> {
        if !self.authorized {
            return Err(Error::Denied);
        }
        Ok(self.activation.clone())
    }
    fn suspension(&self, _: &str, _: &Scope) -> Result<(), Error> {
        if self.authorized {
            Ok(())
        } else {
            Err(Error::Denied)
        }
    }
}
pub struct Journal {
    pub binding: Binding,
    pub available: bool,
    pub consumed: bool,
    pub acknowledged: bool,
    pub lease: i64,
    pub fence: i64,
}
impl Journal {
    pub fn new(binding: Binding) -> Self {
        Self {
            binding,
            available: true,
            consumed: true,
            acknowledged: true,
            lease: 1010,
            fence: 1,
        }
    }
}
impl Gate for Journal {
    fn claim(&self, _: &Binding) -> Result<Binding, Error> {
        if !self.available {
            return Err(Error::Unavailable);
        }
        Ok(self.binding.clone())
    }
    fn consumption(&self, grant: &Grant) -> Result<Consumption, Error> {
        if !self.available {
            return Err(Error::Unavailable);
        }
        if !self.consumed {
            return Err(Error::Denied);
        }
        Ok(Consumption {
            binding: self.binding.clone(),
            grant_id: grant.id.clone(),
            worker: "worker-a".into(),
            fence: self.fence,
            lease_expires: self.lease,
            acknowledged_event: self.acknowledged.then(|| digest(b"predispatch-event")),
        })
    }
}
