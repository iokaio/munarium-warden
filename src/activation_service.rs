// SPDX-License-Identifier: Apache-2.0
//! Stage 2 participant admission through current mTLS authority and independent dependencies.
use super::*;
use munarium_warden::{
    activation::{Evidence, Store},
    activation_wire::{self as wire, Authority, Error},
};
use std::collections::BTreeSet;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    pub database: PathBuf,
    pub service: String,
    pub council_endpoint: String,
    pub gate_endpoint: String,
    pub registry_endpoint: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    scope: Value,
    coordinator: String,
    readers: BTreeSet<String>,
    initial_epoch: u64,
    initial_artifact_set_digest: String,
}
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
enum Operation {
    Flush,
    Apply { transition: String },
    Lookup { transition_id: String },
    Head,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    tenant: String,
    action: Operation,
}
pub(super) fn open(config: &Option<Config>) -> Result<Option<tokio::sync::Mutex<Store>>, Failure> {
    let Some(c) = config else { return Ok(None) };
    if !c.database.is_absolute()
        || [&c.council_endpoint, &c.gate_endpoint, &c.registry_endpoint]
            .iter()
            .any(|e| !e.starts_with("https://"))
    {
        return Err(Failure::Configuration);
    }
    Store::open(&c.database)
        .map(|s| Some(tokio::sync::Mutex::new(s)))
        .map_err(|_| Failure::Unavailable)
}
async fn post(runtime: &Runtime, endpoint: &str, body: Value) -> Result<Value, Error> {
    let response = runtime
        .client
        .post(endpoint)
        .json(&body)
        .send()
        .await
        .map_err(|_| Error::Unavailable)?;
    service_transport::json_response(response, 262144)
        .await
        .map_err(|_| Error::Unavailable)
}
async fn admitted(runtime: &Runtime, peer: &Peer, body: &[u8]) -> Result<Value, Error> {
    let _permit = runtime
        .permits
        .try_acquire()
        .map_err(|_| Error::Unavailable)?;
    let r: Request = serde_json::from_slice(body).map_err(|_| Error::Invalid)?;
    if !peer.tenants.contains(&r.tenant) {
        return Err(Error::Refused);
    }
    let cfg = runtime
        .config
        .activation
        .as_ref()
        .ok_or(Error::Unavailable)?;
    let store = runtime.activation.as_ref().ok_or(Error::Unavailable)?;
    let state = service_transport::authority(
        &runtime.client,
        &runtime.config.server_endpoint,
        &runtime.config.deployment,
        &r.tenant,
    )
    .await
    .map_err(|_| Error::Unavailable)?;
    let policy: Policy = serde_json::from_value(
        state["artifact"]["bindings"][format!("stage2:{}", cfg.service)].clone(),
    )
    .map_err(|_| Error::Refused)?;
    if policy.scope["tenant"] != r.tenant
        || policy.scope["deployment"] != runtime.config.deployment
        || peer.service != policy.coordinator && !policy.readers.contains(&peer.service)
    {
        return Err(Error::Refused);
    }
    {
        let mut db = store.lock().await;
        db.initialize(
            &policy.scope,
            policy.initial_epoch,
            &policy.initial_artifact_set_digest,
        )?;
        match &r.action {
            Operation::Lookup { transition_id } => return db.lookup(&policy.scope, transition_id),
            Operation::Head => return db.head(&policy.scope),
            _ => {}
        }
    }
    if peer.service != policy.coordinator {
        return Err(Error::Refused);
    }
    if matches!(r.action, Operation::Flush) {
        let delivery = runtime.config.delivery.as_ref().ok_or(Error::Unavailable)?;
        let registration = munarium_warden::activation_delivery::registration(
            &state,
            &policy.scope,
            &delivery.server_service,
            &cfg.service,
            "warden",
        )?;
        let now = service_transport::now()
            .map_err(|_| Error::Unavailable)?
            .try_into()
            .map_err(|_| Error::Unavailable)?;
        let event = store
            .lock()
            .await
            .delivery_next(&policy.scope, &registration, now)?;
        let Some(event) = event else {
            return Ok(json!({"delivered":0}));
        };
        let ack = delivery_service::deliver(runtime, &r.tenant, &event)
            .await
            .map_err(|_| Error::Unavailable)?;
        store
            .lock()
            .await
            .delivery_ack(&policy.scope, &event, &ack)?;
        return Ok(json!({"delivered":1,"acknowledgement":ack}));
    }
    let Operation::Apply { transition } = r.action else {
        return Err(Error::Invalid);
    };
    let t = wire::parse(&transition)?;
    wire::shape(&t, "activation")?;
    wire::scoped(&t, &policy.scope)?;
    let id = t["transition"]["id"].as_str().ok_or(Error::Invalid)?;
    let lookup = json!({"tenant":r.tenant,"action":{"operation":"lookup","transition_id":id}});
    let ratified = post(
        runtime,
        &format!(
            "{}/v1/transitions",
            cfg.council_endpoint.trim_end_matches('/')
        ),
        lookup.clone(),
    )
    .await?;
    let gate = format!("{}/v1/actions", cfg.gate_endpoint.trim_end_matches('/'));
    let pause = post(
        runtime,
        &gate,
        json!({"tenant":r.tenant,"action":{"operation":"pause-lookup","transition_id":id}}),
    )
    .await?;
    let gate_head = post(
        runtime,
        &gate,
        json!({"tenant":r.tenant,"action":{"operation":"activation-head"}}),
    )
    .await?;
    let registry = format!(
        "{}/v1/activation",
        cfg.registry_endpoint.trim_end_matches('/')
    );
    let registry_receipt = post(runtime, &registry, lookup).await?;
    let registry_head = post(
        runtime,
        &registry,
        json!({"tenant":r.tenant,"action":{"operation":"head"}}),
    )
    .await?;
    let current = service_transport::authority(
        &runtime.client,
        &runtime.config.server_endpoint,
        &runtime.config.deployment,
        &r.tenant,
    )
    .await
    .map_err(|_| Error::Unavailable)?;
    if state != current {
        return Err(Error::Refused);
    }
    let auth = Authority {
        scope: policy.scope,
        ratified,
        now: service_transport::now()
            .map_err(|_| Error::Unavailable)?
            .try_into()
            .map_err(|_| Error::Unavailable)?,
    };
    store.lock().await.apply(
        &auth,
        &t,
        &Evidence {
            pause,
            gate_head,
            registry_receipt,
            registry_head,
        },
    )
}
pub(super) async fn operate(
    State(runtime): State<Arc<Runtime>>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    body: Bytes,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    admitted(&runtime, &peer, &body)
        .await
        .map(Json)
        .map_err(|e| {
            (
                match e {
                    Error::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
                    Error::Conflict => StatusCode::CONFLICT,
                    Error::Invalid => StatusCode::BAD_REQUEST,
                    _ => StatusCode::FORBIDDEN,
                },
                Json(json!({"error":e.to_string()})),
            )
        })
}
