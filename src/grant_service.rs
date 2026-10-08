// SPDX-License-Identifier: Apache-2.0
//! Authenticated grant and connector-only OpenBao custody adapters.
use super::*;
use munarium_warden::{
    activation_wire::{self as wire, Error as E},
    live_grants::Issuance,
};
use std::collections::BTreeSet;
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BrokerConfig {
    endpoint: String,
    token_file: PathBuf,
    resource: String,
    #[serde(default)]
    loopback_test: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    scope: Value,
    gate: String,
    connector: String,
    stream: String,
    generation: u64,
    recovery: u64,
    blocked: BTreeSet<String>,
    target: Value,
}
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
enum Action {
    Flush,
    Issue {
        operation_id: String,
    },
    Validate {
        operation_id: String,
        invocation: Value,
    },
    Custody {
        operation_id: String,
        invocation: Value,
    },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    tenant: String,
    action: Action,
}
async fn post(rt: &Runtime, url: String, body: Value) -> Result<Value, E> {
    if !url.starts_with("https://") {
        return Err(E::Refused);
    }
    let response = rt
        .client
        .post(url)
        .json(&body)
        .send()
        .await
        .map_err(|_| E::Unavailable)?;
    service_transport::json_response(response, 262144)
        .await
        .map_err(|_| E::Unavailable)
}
fn now() -> Result<u64, E> {
    service_transport::now()
        .map_err(|_| E::Unavailable)?
        .try_into()
        .map_err(|_| E::Unavailable)
}
async fn admitted(rt: &Runtime, peer: &Peer, body: &[u8], broker: bool) -> Result<Value, E> {
    let input: Input = serde_json::from_slice(body).map_err(|_| E::Invalid)?;
    if !peer.tenants.contains(&input.tenant) {
        return Err(E::Refused);
    }
    let cfg = rt.config.activation.as_ref().ok_or(E::Unavailable)?;
    let store = rt.activation.as_ref().ok_or(E::Unavailable)?;
    let state = service_transport::authority(
        &rt.client,
        &rt.config.server_endpoint,
        &rt.config.deployment,
        &input.tenant,
    )
    .await
    .map_err(|_| E::Unavailable)?;
    let p: Policy = serde_json::from_value(
        state["artifact"]["bindings"][format!("execution:{}", cfg.service)].clone(),
    )
    .map_err(|_| E::Refused)?;
    if p.scope["tenant"] != input.tenant || p.scope["deployment"] != rt.config.deployment {
        return Err(E::Refused);
    }
    if matches!(input.action, Action::Flush) {
        if broker || peer.service != p.gate {
            return Err(E::Refused);
        }
        let Some(event) = store.lock().await.grant_pending(&p.scope)? else {
            return Ok(json!({"delivered":0}));
        };
        let ack = delivery_service::deliver(rt, &input.tenant, &event)
            .await
            .map_err(|_| E::Unavailable)?;
        store.lock().await.grant_ack(
            &p.scope,
            event["payload"]["operation"]["id"]
                .as_str()
                .ok_or(E::Invalid)?,
            &ack,
        )?;
        return Ok(json!({"delivered":1}));
    }
    let (operation, invocation) = match &input.action {
        Action::Flush => return Err(E::Invalid),
        Action::Issue { operation_id } => (operation_id, None),
        Action::Validate {
            operation_id,
            invocation,
        }
        | Action::Custody {
            operation_id,
            invocation,
        } => (operation_id, Some(invocation)),
    };
    if p.blocked.contains(operation)
        || (broker
            && (!matches!(input.action, Action::Custody { .. }) || peer.service != p.connector))
        || (!broker
            && (!matches!(input.action, Action::Issue { .. } | Action::Validate { .. })
                || peer.service != p.gate))
    {
        return Err(E::Refused);
    }
    let lookup=post(rt,format!("{}/v1/actions",cfg.gate_endpoint.trim_end_matches('/')),json!({"tenant":input.tenant,"action":{"operation":"claim-lookup","operation_id":operation}})).await?;
    let r = &lookup["binding"]["request"];
    if r["operation"]["scope"] != p.scope
        || r["operation"]["id"] != *operation
        || r["intent"]["target"] != p.target
        || r["context"]["recovery"]["revision"] != p.recovery
    {
        return Err(E::Refused);
    }
    let approval=post(rt,format!("{}/v1/approvals",cfg.council_endpoint.trim_end_matches('/')),json!({"tenant":input.tenant,"action":{"operation":"lookup","id":lookup["binding"]["approval"]["approval"]["id"]}})).await?;
    if approval["currently_usable"] != true
        || approval["status"] != "approved"
        || approval["revision"] != 1
        || approval["approval"] != lookup["binding"]["approval"]
    {
        return Err(E::Refused);
    }
    let next = service_transport::authority(
        &rt.client,
        &rt.config.server_endpoint,
        &rt.config.deployment,
        &input.tenant,
    )
    .await
    .map_err(|_| E::Unavailable)?;
    if state != next {
        return Err(E::Refused);
    }
    if matches!(input.action, Action::Issue { .. }) {
        let g = store.lock().await.grant_issue(&Issuance {
            lookup,
            approval,
            now: now()?,
            stream: p.stream,
            generation: p.generation,
            recovery: p.recovery,
        })?;
        if g["acknowledgement"].is_null() {
            let ack = delivery_service::deliver(rt, &input.tenant, &g["event"])
                .await
                .map_err(|_| E::Unavailable)?;
            store.lock().await.grant_ack(&p.scope, operation, &ack)?;
        }
        return store.lock().await.grant_lookup(&p.scope, operation);
    }
    let grant = store.lock().await.grant_lookup(&p.scope, operation)?;
    let c = &lookup["consumption"];
    let current = now()?;
    if c["binding"]["grant_event"] != grant["event"]
        || c["binding"]["grant_ack"] != grant["acknowledgement"]
        || c["binding"]["worker"] != p.connector
        || !lookup["dispatch"]["send_intent"].is_null()
        || grant["event"]["payload"]["expires_at"]
            .as_u64()
            .ok_or(E::Invalid)?
            <= current.saturating_add(2)
    {
        return Err(E::Refused);
    }
    munarium_warden::activation_delivery::acknowledge(
        &c["predispatch"],
        &lookup["predispatch_audit"]["acknowledgement"],
    )?;
    let invocation = invocation.ok_or(E::Invalid)?;
    wire::scoped(invocation, &p.scope)?;
    if invocation["scope"] != p.scope
        || invocation["kind"] != "invocation"
        || invocation["id"].as_str().is_none_or(str::is_empty)
    {
        return Err(E::Invalid);
    }
    let ticket = if broker {
        store.lock().await.grant_custody(&p.scope,operation,&json!({"grant":grant["event"]["payload"]["grant"],"connector":p.connector,"invocation":invocation,"fence":c["consumption"]["payload"]["worker_fence"],"expires_at":current.saturating_add(5).min(grant["event"]["payload"]["expires_at"].as_u64().ok_or(E::Invalid)?),"recovery":p.recovery}))?
    } else {
        grant["custody"].clone()
    };
    if ticket["invocation"] != *invocation
        || ticket["connector"] != p.connector
        || ticket["recovery"] != p.recovery
        || ticket["expires_at"].as_u64().ok_or(E::Refused)? <= now()?.saturating_add(2)
    {
        return Err(E::Refused);
    }
    Ok(ticket)
}
fn failure(e: E) -> (StatusCode, Json<Value>) {
    (
        match e {
            E::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            E::Conflict => StatusCode::CONFLICT,
            _ => StatusCode::FORBIDDEN,
        },
        Json(json!({"error":e.to_string()})),
    )
}
pub(super) async fn operate(
    State(rt): State<Arc<Runtime>>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    body: Bytes,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _permit = rt
        .permits
        .try_acquire()
        .map_err(|_| failure(E::Unavailable))?;
    admitted(&rt, &peer, &body, false)
        .await
        .map(Json)
        .map_err(failure)
}
pub(super) async fn custody(
    State(rt): State<Arc<Runtime>>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    body: Bytes,
) -> Result<axum::response::Response, (StatusCode, Json<Value>)> {
    use axum::response::IntoResponse;
    use munarium_warden::credential::{OpenBao, SecretProvider};
    let _permit = rt
        .permits
        .try_acquire()
        .map_err(|_| failure(E::Unavailable))?;
    admitted(&rt, &peer, &body, true).await.map_err(failure)?;
    let cfg = rt
        .config
        .broker
        .clone()
        .ok_or_else(|| failure(E::Unavailable))?;
    let credential = tokio::task::spawn_blocking(move || {
        if !cfg.token_file.is_absolute() {
            return Err(E::Refused);
        }
        let token =
            Zeroizing::new(std::fs::read_to_string(&cfg.token_file).map_err(|_| E::Unavailable)?);
        let provider = if cfg.loopback_test {
            OpenBao::loopback_test(&cfg.endpoint, token.trim().into(), &cfg.resource)
        } else {
            OpenBao::https(&cfg.endpoint, token.trim().into(), &cfg.resource, None)
        }
        .map_err(|_| E::Unavailable)?;
        provider.fetch(&cfg.resource).map_err(|_| E::Unavailable)
    })
    .await
    .map_err(|_| failure(E::Unavailable))?
    .map_err(failure)?;
    // Slow provider I/O cannot extend custody or bypass a concurrent revocation.
    admitted(&rt, &peer, &body, true).await.map_err(failure)?;
    Ok((
        [
            ("content-type", "application/octet-stream"),
            ("cache-control", "no-store"),
        ],
        credential.expose_to_connector().to_vec(),
    )
        .into_response())
}
