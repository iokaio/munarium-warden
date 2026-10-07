// SPDX-License-Identifier: Apache-2.0
//! Warden's decision-only service. No grant, broker or connector route is mounted.
mod service_transport;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{ConnectInfo, DefaultBodyLimit, State},
    http::StatusCode,
    routing::post,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use munarium_warden::{
    admission::{self, Delegate, ProviderBinding, ProviderKey},
    policy,
};
use serde::Deserialize;
use serde_json::{Value, json};
use service_transport::{Failure, Peer, TlsConfig};
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    tls: TlsConfig,
    server_endpoint: String,
    deployment: String,
    signing_key_file: PathBuf,
    key_id: String,
}
struct Runtime {
    config: Config,
    client: reqwest::Client,
    signer: SigningKey,
    permits: tokio::sync::Semaphore,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Provider {
    issuer: String,
    audience: String,
    key_id: String,
    public_key: String,
    subjects: BTreeMap<String, String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderPolicy {
    providers: BTreeMap<String, Provider>,
    bindings: Vec<ProviderBinding>,
}
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
enum Operation {
    Root {
        provider_id: String,
        token: String,
        scopes: Vec<String>,
        resources: Vec<String>,
    },
    Delegate {
        chain: Vec<String>,
        actor: String,
        service: String,
        scopes: Vec<String>,
        resources: Vec<String>,
    },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    tenant: String,
    audience: String,
    action: Operation,
}

async fn issue(
    State(runtime): State<Arc<Runtime>>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    body: Bytes,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    async fn admitted(runtime: &Runtime, peer: &Peer, body: &[u8]) -> Result<Value, Failure> {
        let _permit = runtime
            .permits
            .try_acquire()
            .map_err(|_| Failure::Unavailable)?;
        let request: Request = serde_json::from_slice(body).map_err(|_| Failure::Refused)?;
        if !peer.tenants.contains(&request.tenant) {
            return Err(Failure::Refused);
        }
        let state = service_transport::authority(
            &runtime.client,
            &runtime.config.server_endpoint,
            &runtime.config.deployment,
            &request.tenant,
        )
        .await?;
        let bindings = &state["artifact"]["bindings"];
        let now = service_transport::now()?;
        let trust = policy::current(
            &bindings[format!("identity:{}", request.audience)],
            &runtime.config.deployment,
            &request.tenant,
            &request.audience,
            &peer.service,
            now,
        )
        .map_err(|_| Failure::Refused)?;
        let chain = match request.action {
            Operation::Root {
                provider_id,
                token,
                scopes,
                resources,
            } => {
                let policy: ProviderPolicy = serde_json::from_value(bindings["warden"].clone())
                    .map_err(|_| Failure::Refused)?;
                if policy.providers.len() > 32 {
                    return Err(Failure::Refused);
                }
                let provider = policy.providers.get(&provider_id).ok_or(Failure::Refused)?;
                let key = URL_SAFE_NO_PAD
                    .decode(&provider.public_key)
                    .map_err(|_| Failure::Refused)?;
                if URL_SAFE_NO_PAD.encode(&key) != provider.public_key {
                    return Err(Failure::Refused);
                }
                let provider = ProviderKey {
                    issuer: provider.issuer.clone(),
                    audience: provider.audience.clone(),
                    key_id: provider.key_id.clone(),
                    public_key: key.try_into().map_err(|_| Failure::Refused)?,
                    subjects: provider.subjects.clone(),
                };
                let identity = admission::verify_provider(&token, &provider, now)
                    .map_err(|_| Failure::Refused)?;
                vec![
                    admission::issue_root(
                        &identity,
                        &policy.bindings,
                        &trust,
                        &scopes,
                        &resources,
                        &runtime.signer,
                        &runtime.config.key_id,
                    )
                    .map_err(|_| Failure::Refused)?,
                ]
            }
            Operation::Delegate {
                chain,
                actor,
                service,
                scopes,
                resources,
            } => admission::issue_delegate(
                &chain,
                &trust,
                Delegate {
                    actor: &actor,
                    service: &service,
                    scopes: &scopes,
                    resources: &resources,
                },
                &runtime.signer,
                &runtime.config.key_id,
            )
            .map_err(|_| Failure::Refused)?,
        };
        Ok(
            json!({"chain":chain,"usable_at":now.checked_add(2).ok_or(Failure::Unavailable)?,"authority_revision":state["revision"]}),
        )
    }
    admitted(&runtime,&peer,&body).await.map(Json).map_err(|failure| {
        let unavailable=matches!(failure,Failure::Unavailable);
        (if unavailable {StatusCode::SERVICE_UNAVAILABLE} else {StatusCode::FORBIDDEN},Json(json!({"error":if unavailable {"authority-unavailable"} else {"identity-refused"}})))
    })
}
async fn run() -> Result<(), Failure> {
    let path = std::env::args_os().nth(1).ok_or(Failure::Configuration)?;
    let bytes = std::fs::read(path).map_err(|_| Failure::Configuration)?;
    if bytes.len() > 1048576 {
        return Err(Failure::Configuration);
    }
    let config: Config = serde_json::from_slice(&bytes).map_err(|_| Failure::Configuration)?;
    let key = Zeroizing::new(
        std::fs::read(&config.signing_key_file).map_err(|_| Failure::Configuration)?,
    );
    let bytes: &[u8; 32] = key
        .as_slice()
        .try_into()
        .map_err(|_| Failure::Configuration)?;
    let signer = SigningKey::from_bytes(bytes);
    let client = service_transport::client(&config.tls)?;
    let listener = service_transport::Mtls::bind(&config.tls).await?;
    let runtime = Arc::new(Runtime {
        config,
        client,
        signer,
        permits: tokio::sync::Semaphore::new(32),
    });
    let router = Router::new()
        .route("/v1/identity", post(issue))
        .layer(DefaultBodyLimit::max(65536))
        .with_state(runtime);
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<Peer>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
    .map_err(|_| Failure::Unavailable)
}
#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("Warden service unavailable: {error:?}");
        std::process::exit(1);
    }
}
