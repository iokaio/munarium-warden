// SPDX-License-Identifier: Apache-2.0
mod support;
use munarium_warden::{admission::*, principal};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use support::*;

fn provider() -> Value {
    json!({"iss":"https://issuer.invalid","sub":"workload-123","aud":"warden-api","iat":980,"nbf":980,"exp":1060})
}
fn binding() -> ProviderBinding {
    serde_json::from_value(json!({"schema_version":1,"binding_id":"provider-a","deployment":"fixture","tenant":"alpha",
        "provider_issuer":"https://issuer.invalid","provider_subject":"workload-123","origin_kind":"agent",
        "origin":"agent-a","peer_service":"svc-harness","audiences":["svc-gate"],"scopes":["evaluate"],
        "resources":["item-a"],"nbf":900,"exp":1100})).unwrap()
}
#[test]
fn provider_mapping_uses_actual_signature_enrollment_peer_and_current_authority() {
    let upstream = key();
    let platform = key();
    let provider_key = ProviderKey {
        issuer: "https://issuer.invalid".into(),
        audience: "warden-api".into(),
        key_id: "upstream".into(),
        public_key: upstream.verifying_key().to_bytes(),
        subjects: BTreeMap::from([("workload-123".into(), "agent".into())]),
    };
    let header = br#"{"alg":"EdDSA","kid":"upstream","typ":"at+jwt"}"#;
    let sign_provider =
        |body: &Value| sign_bytes(&upstream, header, &serde_json::to_vec(body).unwrap());
    let signed = sign_provider(&provider());
    let identity = verify_provider(&signed, &provider_key, 1000).unwrap();
    let mut current = trust(&platform, 1000);
    let scope = vec!["evaluate".into()];
    let resource = vec!["item-a".into()];
    let root = issue_root(
        &identity,
        &[binding()],
        &current,
        &scope,
        &resource,
        &platform,
        "test-key",
    )
    .unwrap();
    assert!(principal::verify(std::slice::from_ref(&root), &current).is_err()); // no backdating
    current.now = 1002;
    let verified = principal::verify(std::slice::from_ref(&root), &current).unwrap();
    assert_eq!(verified.origin_kind(), "agent");
    assert_eq!(verified.origin(), "agent-a");
    assert_eq!(verified.service(), "svc-harness");
    assert_eq!(verified.expires(), 1060);
    assert!(
        verify_provider(
            &sign_bytes(&platform, header, &serde_json::to_vec(&provider()).unwrap()),
            &provider_key,
            1000
        )
        .is_err()
    );
    for (field, value) in [
        ("iss", json!("untrusted")),
        ("sub", json!("invented")),
        ("aud", json!("gate-api")),
        ("exp", json!(1002)),
        ("nbf", json!(999)),
        ("role", json!("human")),
    ] {
        let mut changed = provider();
        changed[field] = value;
        assert!(
            verify_provider(&sign_provider(&changed), &provider_key, 1000).is_err(),
            "{field}"
        );
    }
    assert!(
        issue_root(
            &identity,
            &[binding(), binding()],
            &current,
            &scope,
            &resource,
            &platform,
            "test-key"
        )
        .is_err()
    );
    for field in ["tenant", "provider_subject", "origin_kind", "peer_service"] {
        let mut changed = serde_json::to_value(json!({"schema_version":1,"binding_id":"provider-a","deployment":"fixture","tenant":"alpha",
            "provider_issuer":"https://issuer.invalid","provider_subject":"workload-123","origin_kind":"agent",
            "origin":"agent-a","peer_service":"svc-harness","audiences":["svc-gate"],"scopes":["evaluate"],
            "resources":["item-a"],"nbf":900,"exp":1100})).unwrap();
        changed[field] = json!("different");
        assert!(
            issue_root(
                &identity,
                &[serde_json::from_value(changed).unwrap()],
                &current,
                &scope,
                &resource,
                &platform,
                "test-key"
            )
            .is_err()
        );
    }
    assert!(
        issue_root(
            &identity,
            &[binding()],
            &current,
            &["govern".into()],
            &resource,
            &platform,
            "test-key"
        )
        .is_err()
    );
    assert!(
        issue_root(
            &identity,
            &[binding()],
            &current,
            &scope,
            &["item-b".into()],
            &platform,
            "test-key"
        )
        .is_err()
    );
    current.available = false;
    assert!(
        issue_root(
            &identity,
            &[binding()],
            &current,
            &scope,
            &resource,
            &platform,
            "test-key"
        )
        .is_err()
    );
    current.available = true;
    current.keys.clear();
    assert!(
        issue_root(
            &identity,
            &[binding()],
            &current,
            &scope,
            &resource,
            &platform,
            "test-key"
        )
        .is_err()
    );
}

#[test]
fn delegation_issuance_preserves_origin_and_requires_registered_edge() {
    let signer = key();
    let root = vec![sign(&signer, &payload())];
    let mut current = trust(&signer, 1000);
    let scope = vec!["evaluate".into()];
    let resource = vec!["item-a".into()];
    assert!(
        issue_delegate(
            &root,
            &current,
            Delegate {
                actor: "agent-b",
                service: "svc-child",
                scopes: &scope,
                resources: &resource
            },
            &signer,
            "test-key"
        )
        .is_err()
    );
    current.delegations.push(principal::Delegation {
        registration_id: "edge-a".into(),
        deployment: current.deployment.clone(),
        tenant: current.tenant.clone(),
        origin_kind: "agent".into(),
        audience: current.audience.clone(),
        task_digest: current.task_digest.clone(),
        policy_digest: current.policy_digest.clone(),
        origin: "agent-a".into(),
        from: "agent-a".into(),
        to: "agent-b".into(),
        service: "svc-child".into(),
        scopes: scope.clone(),
        resources: resource.clone(),
        not_before: 900,
        expires: 1030,
        maximum_depth: 1,
    });
    let child = issue_delegate(
        &root,
        &current,
        Delegate {
            actor: "agent-b",
            service: "svc-child",
            scopes: &scope,
            resources: &resource,
        },
        &signer,
        "test-key",
    )
    .unwrap();
    current.now = 1002;
    current.peer_service = "svc-child".into();
    let p = principal::verify(&child, &current).unwrap();
    assert_eq!(p.origin(), "agent-a");
    assert_eq!(p.actor(), "agent-b");
    assert_eq!(p.expires(), 1030);
    assert!(
        issue_delegate(
            &root,
            &current,
            Delegate {
                actor: "agent-b",
                service: "svc-child",
                scopes: &scope,
                resources: &resource
            },
            &signer,
            "test-key"
        )
        .is_err()
    ); // actual parent peer differs
    current.peer_service = "svc-harness".into();
    assert!(
        issue_delegate(
            &root,
            &current,
            Delegate {
                actor: "agent-b",
                service: "svc-child",
                scopes: &["read".into()],
                resources: &resource
            },
            &signer,
            "test-key"
        )
        .is_err()
    );
    current.delegations[0].maximum_depth = 0;
    assert!(
        issue_delegate(
            &root,
            &current,
            Delegate {
                actor: "agent-b",
                service: "svc-child",
                scopes: &scope,
                resources: &resource
            },
            &signer,
            "test-key"
        )
        .is_err()
    );
}
