// SPDX-License-Identifier: Apache-2.0
mod support;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use munarium_warden::{
    encoding::digest,
    principal::{Delegation, TrustedKey, verify},
};
use serde_json::{Value, json};
use support::*;

#[test]
fn signed_identity_checks_every_authority_binding() {
    let k = key();
    let p = payload();
    let t = trust(&k, 1000);
    assert!(verify(&[sign(&k, &p)], &t).is_ok());
    for (field, value) in [
        ("tenant", json!("beta")),
        ("issuer", json!("other")),
        ("deployment", json!("other")),
        ("audience", json!("other")),
        ("service", json!("other")),
        ("actor", json!("other")),
        ("origin_kind", json!("human")),
        ("purpose", json!("bootstrap")),
        ("schema_version", json!(2)),
        ("scopes", json!(["ratify"])),
        ("resources", json!(["other"])),
        ("nbf", json!(999)),
        ("exp", json!(1002)),
        ("iat", json!(900)),
    ] {
        let mut changed = p.clone();
        changed[field] = value;
        assert!(verify(&[sign(&k, &changed)], &t).is_err(), "{field}");
    }
    let mut changed = p.clone();
    changed.as_object_mut().unwrap().remove("bootstrap");
    assert!(verify(&[sign(&k, &changed)], &t).is_err());
    changed = p.clone();
    changed["scopes"] = json!(["evaluate", "evaluate"]);
    assert!(verify(&[sign(&k, &changed)], &t).is_err());
    changed = p;
    changed["unexpected"] = json!(true);
    assert!(verify(&[sign(&k, &changed)], &t).is_err());
}

#[test]
fn rejects_noncanonical_forged_and_oversized_envelopes() {
    let k = key();
    let t = trust(&k, 1000);
    let p = payload();
    let valid = sign(&k, &p);
    let header = br#"{"alg":"Ed25519","kid":"test-key","typ":"munarium-principal+jws"}"#;
    let canonical = serde_json::to_string(&p).unwrap();
    for body in [
        format!(" {canonical}"),
        canonical.replace("\"actor\":", "\"actor\":\"agent-a\",\"actor\":"),
        canonical.replace("\"agent-a\"", "\"agent-\\u0061\""),
    ] {
        assert!(verify(&[sign_bytes(&k, header, body.as_bytes())], &t).is_err());
    }
    for header in [br#"{"alg":"none","kid":"test-key","typ":"munarium-principal+jws"}"#.as_slice(), br#"{"alg":"Ed25519","jku":"https://example.test/keys","kid":"test-key","typ":"munarium-principal+jws"}"#] {
        assert!(verify(&[sign_bytes(&k,header,canonical.as_bytes())],&t).is_err());
    }
    let mut parts: Vec<_> = valid.split('.').map(str::to_owned).collect();
    parts[2] = B64.encode([0u8; 64]);
    assert!(verify(&[parts.join(".")], &t).is_err());
    assert!(verify(&["a".repeat(65537)], &t).is_err());
    assert!(verify(&[], &t).is_err());
}

#[test]
fn delegation_requires_unique_current_registration_and_narrowing() {
    let k = key();
    let mut t = trust(&k, 1000);
    let root = sign(&k, &payload());
    let mut p = payload();
    p["actor"] = json!("agent-b");
    p["parent_digest"] = json!(digest(root.as_bytes()));
    p["exp"] = json!(1030);
    let chain = vec![root, sign(&k, &p)];
    assert!(verify(&chain, &t).is_err());
    let edge = || Delegation {
        registration_id: "edge-1".into(),
        deployment: "fixture".into(),
        tenant: "alpha".into(),
        origin_kind: "agent".into(),
        audience: "svc-gate".into(),
        task_digest: digest(b"task"),
        policy_digest: digest(b"policy"),
        origin: "agent-a".into(),
        from: "agent-a".into(),
        to: "agent-b".into(),
        service: "svc-harness".into(),
        scopes: vec!["evaluate".into()],
        resources: vec!["item-a".into()],
        not_before: 900,
        expires: 1100,
        maximum_depth: 4,
    };
    t.delegations.push(edge());
    assert!(verify(&chain, &t).is_ok());
    t.delegations.push(edge());
    assert!(verify(&chain, &t).is_err());
    t.delegations.pop();
    t.delegations[0].maximum_depth = 0;
    assert!(verify(&chain, &t).is_err());
    t.delegations[0] = edge();
    t.delegations[0].task_digest = digest(b"other-task");
    assert!(verify(&chain, &t).is_err());
    t.delegations[0] = edge();
    t.delegations[0].policy_digest = digest(b"other-policy");
    assert!(verify(&chain, &t).is_err());
    t.delegations[0] = edge();
    t.delegations[0].tenant = "other".into();
    assert!(verify(&chain, &t).is_err());
    t.delegations[0] = edge();
    t.delegations[0].expires = 1029;
    assert!(verify(&chain, &t).is_err());
    t.delegations[0] = edge();
    p["resources"] = json!(["item-a", "item-b"]);
    assert!(verify(&[chain[0].clone(), sign(&k, &p)], &t).is_err());
}

#[test]
fn pinned_hub_vectors_preserve_oracle_with_explicit_profile_narrowing() {
    let raw = include_str!("fixtures/identity-vectors.json").replace("\r\n", "\n");
    assert_eq!(
        digest(raw.as_bytes()),
        "sha256:a60f52749ad657fea82abdddc79955b235946391bb1a7a76373a705bba111c2d"
    );
    let fixture: Value = serde_json::from_str(&raw).unwrap();
    let mut count = 0;
    for case in fixture["cases"].as_array().unwrap() {
        let k = key();
        let c = &case["context"];
        let mut t = trust(&k, c["now"].as_i64().unwrap());
        t.deployment = c["deployment"].as_str().unwrap().into();
        t.tenant = c["tenant"].as_str().unwrap().into();
        t.audience = c["audience"].as_str().unwrap().into();
        t.peer_service = c["peer_service"].as_str().unwrap().into();
        t.available = c["authority_available"].as_bool().unwrap()
            && !c["restore_quarantined"].as_bool().unwrap();
        t.keys.clear();
        if !c["retired_keys"]
            .as_array()
            .unwrap()
            .contains(&json!("fixture-key"))
        {
            t.keys.insert(
                "fixture-key".into(),
                TrustedKey {
                    decision: true,
                    issuer: "fixture-issuer".into(),
                    public_key: B64
                        .decode(
                            fixture["keys"]["fixture-key"]["public_key"]
                                .as_str()
                                .unwrap(),
                        )
                        .unwrap()
                        .try_into()
                        .unwrap(),
                },
            );
        }
        let chain: Vec<String> = case["tokens"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| {
                format!(
                    "{}.{}.{}",
                    p["protected"].as_str().unwrap(),
                    p["payload"].as_str().unwrap(),
                    p["signature"].as_str().unwrap()
                )
            })
            .collect();
        // Registrations are independently prescribed fictional test policy, never inferred from the submitted chain.
        for (from, to) in [
            ("agent-a", "agent-b"),
            ("agent-a", "agent-1"),
            ("agent-1", "agent-2"),
            ("agent-2", "agent-3"),
            ("agent-3", "agent-4"),
        ] {
            t.delegations.push(Delegation {
                registration_id: format!("edge-{from}-{to}"),
                deployment: "fixture".into(),
                tenant: "alpha".into(),
                origin_kind: "agent".into(),
                audience: "svc-server".into(),
                task_digest: digest(b"task"),
                policy_digest: digest(b"policy"),
                origin: "agent-a".into(),
                from: from.into(),
                to: to.into(),
                service: "svc-harness".into(),
                scopes: vec!["read".into(), "evaluate".into()],
                resources: vec!["item-a".into(), "item-b".into()],
                not_before: 900,
                expires: 1100,
                maximum_depth: 4,
            });
        }
        let expected = case["expected"] == "accept" && case["id"] != "valid-bootstrap";
        assert_eq!(verify(&chain, &t).is_ok(), expected, "{}", case["id"]);
        count += 1;
    }
    assert_eq!(count, 32);
}

#[test]
fn current_policy_key_purpose_and_service_origin_are_preserved() {
    let k = key();
    let mut t = trust(&k, 1000);
    let mut p = payload();
    p["origin_kind"] = json!("service");
    let chain = vec![sign(&k, &p)];
    let verified = verify(&chain, &t).unwrap();
    assert_eq!(verified.origin_kind(), "service");
    assert_eq!(verified.origin(), "agent-a");
    assert_eq!(verified.actor(), "agent-a");
    assert_eq!(verified.fingerprint(), digest(chain[0].as_bytes()));
    assert_eq!(verified.scopes(), ["evaluate"]);
    assert_eq!(verified.resources(), ["item-a"]);
    t.keys.get_mut("test-key").unwrap().decision = false;
    assert!(verify(&chain, &t).is_err());
    t.keys.get_mut("test-key").unwrap().decision = true;
    t.expires = 1039;
    assert!(verify(&chain, &t).is_err());
    t.expires = 1100;
    t.not_before = 999;
    assert!(verify(&chain, &t).is_err());
}

#[test]
fn intermediate_presenter_and_every_ancestor_interval_are_bound() {
    let k = key();
    let mut t = trust(&k, 1000);
    let root = sign(&k, &payload());
    let mut middle = payload();
    middle["actor"] = json!("agent-b");
    middle["service"] = json!("svc-middle");
    middle["parent_digest"] = json!(digest(root.as_bytes()));
    middle["exp"] = json!(1035);
    let mid = sign(&k, &middle);
    let mut leaf = middle.clone();
    leaf["actor"] = json!("agent-c");
    leaf["service"] = json!("svc-harness");
    leaf["parent_digest"] = json!(digest(mid.as_bytes()));
    leaf["exp"] = json!(1030);
    let chain = vec![root, mid, sign(&k, &leaf)];
    for (from, to, service) in [
        ("agent-a", "agent-b", "svc-middle"),
        ("agent-b", "agent-c", "svc-harness"),
    ] {
        t.delegations.push(Delegation {
            registration_id: format!("edge-{from}-{to}"),
            deployment: "fixture".into(),
            tenant: "alpha".into(),
            origin_kind: "agent".into(),
            audience: "svc-gate".into(),
            task_digest: digest(b"task"),
            policy_digest: digest(b"policy"),
            origin: "agent-a".into(),
            from: from.into(),
            to: to.into(),
            service: service.into(),
            scopes: vec!["evaluate".into()],
            resources: vec!["item-a".into()],
            not_before: 900,
            expires: 1100,
            maximum_depth: 4,
        });
    }
    assert!(verify(&chain, &t).is_ok());
    t.delegations[0].service = "svc-harness".into();
    assert!(verify(&chain, &t).is_err());
    t.delegations[0].service = "svc-middle".into();
    t.expires = 1037;
    assert!(verify(&chain, &t).is_err(), "root outlives policy");
    t.expires = 1100;
    middle["nbf"] = json!(985);
    let mid = sign(&k, &middle);
    leaf["nbf"] = json!(990);
    leaf["parent_digest"] = json!(digest(mid.as_bytes()));
    t.not_before = 983;
    assert!(
        verify(&[chain[0].clone(), mid, sign(&k, &leaf)], &t).is_err(),
        "root predates task"
    );
}
