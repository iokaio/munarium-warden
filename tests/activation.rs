// SPDX-License-Identifier: Apache-2.0
use serde_json::{Value, json};
fn fixture() -> Value {
    serde_json::from_str(include_str!("../contracts/stage2-v1/vectors.json")).unwrap()
}
fn authority(t: &Value) -> wire::Authority {
    wire::Authority {
        scope: t["scope"].clone(),
        ratified: json!({"ratified":true,"transition":t,"transition_digest":wire::digest("activation",t).unwrap()}),
        now: 1000,
    }
}
fn receipt(t: &Value, owner: &str, phase: &str) -> Value {
    let mut r = fixture()["records"]["pause"].clone();
    for k in [
        "transition",
        "prior_epoch",
        "successor_epoch",
        "artifact_set_digest",
        "participant_set_digest",
    ] {
        r[k] = t[k].clone();
    }
    r["transition_digest"] = json!(wire::digest("activation", t).unwrap());
    r["participant"] = json!(owner);
    r["phase"] = json!(phase);
    r
}
fn head(t: &Value, owner: &str) -> Value {
    json!({"participant":owner,"scope":t["scope"],"epoch":t["successor_epoch"],"artifact_set_digest":t["artifact_set_digest"]})
}
#[test]
fn exact_activation_vector_and_negative_bindings() {
    let v = fixture();
    let t = &v["records"]["activation"];
    assert_eq!(
        wire::raw(t).unwrap(),
        v["canonical"]["activation"].as_str().unwrap()
    );
    assert_eq!(
        wire::digest("activation", t).unwrap(),
        v["records"]["pause"]["transition_digest"]
    );
    wire::validate(&authority(t), t).unwrap();
    for owner in ["registry", "server", "warden", "gate"] {
        wire::check_receipt(
            t,
            &v["records"][format!("{owner}-receipt")],
            owner,
            "applied",
        )
        .unwrap();
    }
    assert!(wire::parse("{\"x\":1,\"x\":1}").is_err());
    let mut a = authority(t);
    a.now = 1298;
    assert!(wire::validate(&a, t).is_err());
    a.now = 991;
    assert!(wire::validate(&a, t).is_err());
    a.now = 1000;
    a.ratified["ratified"] = json!(false);
    assert!(wire::validate(&a, t).is_err());
    let mut changed = t.clone();
    changed["participants"] = json!(["gate", "registry"]);
    assert!(wire::validate(&authority(&changed), &changed).is_err());
    let mut foreign = t.clone();
    foreign["ratification"]["scope"]["tenant"] = json!("foreign");
    assert!(wire::validate(&authority(&foreign), &foreign).is_err());
}

use munarium_warden::{
    activation::{Evidence, Store},
    activation_wire as wire,
};
fn evidence(t: &Value) -> Evidence {
    let mut gate = head(t, "gate");
    gate["paused"] = json!(true);
    gate["transition_id"] = t["transition"]["id"].clone();
    Evidence {
        pause: receipt(t, "gate", "paused"),
        gate_head: gate,
        registry_receipt: receipt(t, "registry", "applied"),
        registry_head: head(t, "registry"),
    }
}
#[test]
fn committed_receipt_outbox_and_enrollment_survive_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("participant.sqlite");
    let t = fixture()["records"]["activation"].clone();
    let a = authority(&t);
    let mut db = Store::open(&path).unwrap();
    db.initialize(
        &a.scope,
        1,
        t["prior_artifact_set_digest"].as_str().unwrap(),
    )
    .unwrap();
    let r = db.apply(&a, &t, &evidence(&t)).unwrap();
    assert_eq!(r, receipt(&t, "warden", "applied"));
    drop(db);
    let mut db = Store::open(&path).unwrap();
    db.initialize(
        &a.scope,
        1,
        t["prior_artifact_set_digest"].as_str().unwrap(),
    )
    .unwrap();
    assert!(
        db.initialize(&a.scope, 2, t["artifact_set_digest"].as_str().unwrap())
            .is_err()
    );
    assert_eq!(db.apply(&a, &t, &evidence(&t)).unwrap(), r);
    assert_eq!(db.pending(&a.scope).unwrap().len(), 1);
    assert_eq!(db.head(&a.scope).unwrap()["cell_resumed"], false);
    assert_eq!(db.head(&a.scope).unwrap()["epoch"], 2);
    let mut changed = t.clone();
    changed["expires_at"] = json!(1299);
    assert_eq!(
        db.apply(&authority(&changed), &changed, &evidence(&changed)),
        Err(wire::Error::Conflict)
    );
    let mut foreign = a.scope.clone();
    foreign["cell"] = json!("elsewhere");
    assert!(db.lookup(&foreign, "transition-a").is_err());
}
#[test]
fn missing_stale_or_substituted_dependencies_never_apply() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = Store::open(&dir.path().join("participant.sqlite")).unwrap();
    let t = fixture()["records"]["activation"].clone();
    let a = authority(&t);
    db.initialize(
        &a.scope,
        1,
        t["prior_artifact_set_digest"].as_str().unwrap(),
    )
    .unwrap();
    for changed in 0..5 {
        let mut e = evidence(&t);
        match changed {
            0 => e.pause["phase"] = json!("applied"),
            1 => e.gate_head["paused"] = json!(false),
            2 => e.gate_head["transition_id"] = json!("other"),
            3 => e.registry_head["epoch"] = json!(1),
            _ => e.registry_receipt["participant"] = json!("server"),
        }
        assert!(db.apply(&a, &t, &e).is_err());
    }
    assert_eq!(db.head(&a.scope).unwrap()["epoch"], 1);
    assert!(db.pending(&a.scope).unwrap().is_empty());
}
#[test]
fn competing_connections_cannot_both_consume_prior_head() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("participant.sqlite");
    let t = fixture()["records"]["activation"].clone();
    let a = authority(&t);
    Store::open(&path)
        .unwrap()
        .initialize(
            &a.scope,
            1,
            t["prior_artifact_set_digest"].as_str().unwrap(),
        )
        .unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let workers: Vec<_> = (0..2)
        .map(|i| {
            let path = path.clone();
            let mut t = t.clone();
            let barrier = barrier.clone();
            t["transition"]["id"] = json!(format!("race-{i}"));
            std::thread::spawn(move || {
                let mut db = Store::open(&path).unwrap();
                barrier.wait();
                db.apply(&authority(&t), &t, &evidence(&t))
            })
        })
        .collect();
    assert_eq!(
        workers
            .into_iter()
            .map(|w| usize::from(w.join().unwrap().is_ok()))
            .sum::<usize>(),
        1
    );
    assert_eq!(
        Store::open(&path).unwrap().pending(&a.scope).unwrap().len(),
        1
    );
}

#[test]
fn delivery_retries_exact_event_and_rejects_wrong_custody() {
    let t = fixture()["records"]["activation"].clone();
    let a = authority(&t);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("delivery.sqlite");
    let mut db = Store::open(&path).unwrap();
    db.initialize(
        &a.scope,
        1,
        t["prior_artifact_set_digest"].as_str().unwrap(),
    )
    .unwrap();
    db.apply(&a, &t, &evidence(&t)).unwrap();
    let registration = json!({"stream":"activation-delivery","generation":1});
    let event = db
        .delivery_next(&a.scope, &registration, 1001)
        .unwrap()
        .unwrap();
    drop(db);
    let mut db = Store::open(&path).unwrap();
    assert_eq!(
        db.delivery_next(&a.scope, &registration, 1099).unwrap(),
        Some(event.clone())
    );
    assert!(
        db.delivery_next(
            &a.scope,
            &json!({"stream":"activation-delivery","generation":2}),
            1099
        )
        .is_err()
    );
    let mut ack = fixture()["records"]["ack"].clone();
    ack["scope"] = a.scope.clone();
    ack["ledger"]["scope"] = a.scope.clone();
    ack["event_id"] = event["event_id"].clone();
    ack["payload_digest"] = event["payload_digest"].clone();
    ack["event_digest"] = json!(wire::digest("accountability-event", &event).unwrap());
    let mut wrong = ack.clone();
    wrong["position"] = json!(0);
    assert!(db.delivery_ack(&a.scope, &event, &wrong).is_err());
    wrong = ack.clone();
    wrong["event_id"] = json!("wrong");
    assert!(db.delivery_ack(&a.scope, &event, &wrong).is_err());
    wrong = ack.clone();
    wrong["ledger"]["scope"]["tenant"] = json!("foreign");
    assert!(db.delivery_ack(&a.scope, &event, &wrong).is_err());
    assert_eq!(
        db.delivery_next(&a.scope, &registration, 1100).unwrap(),
        Some(event.clone())
    );
    db.delivery_ack(&a.scope, &event, &ack).unwrap();
    db.delivery_ack(&a.scope, &event, &ack).unwrap();
    assert!(
        db.delivery_next(&a.scope, &registration, 1101)
            .unwrap()
            .is_none()
    );
    assert!(!db.pending(&a.scope).unwrap().is_empty());
}

#[test]
fn live_grant_immutable_issuance_custody_expiry_and_recovery() {
    use munarium_warden::live_grants::Issuance;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("grants.sqlite");
    let v = fixture();
    let t = &v["records"]["activation"];
    let a = authority(t);
    let scope = &a.scope;
    let mut db = Store::open(&path).unwrap();
    db.initialize(scope, 1, t["prior_artifact_set_digest"].as_str().unwrap())
        .unwrap();
    db.apply(&a, t, &evidence(t)).unwrap();
    let claim = &v["records"]["claim-created"];
    let mut ack = v["records"]["ack"].clone();
    ack["event_id"] = claim["event_id"].clone();
    ack["event_digest"] = json!(wire::digest("accountability-event", claim).unwrap());
    ack["payload_digest"] = claim["payload_digest"].clone();
    let mut input = Issuance {
        lookup: json!({"binding":{"request":v["records"]["request"],"approval":v["records"]["approval"]},"claim":claim,"claim_audit":{"acknowledgement":ack}}),
        approval: json!({"approval":v["records"]["approval"],"currently_usable":true,"status":"approved","revision":1}),
        now: 1000,
        stream: "live-grants".into(),
        generation: 1,
        recovery: 1,
    };
    let original = db.grant_issue(&input).unwrap();
    wire::shape(&original["event"], "accountability-event").unwrap();
    drop(db);
    let mut db = Store::open(&path).unwrap();
    input.now = 1001;
    assert_eq!(db.grant_issue(&input).unwrap(), original);
    input.approval["currently_usable"] = json!(false);
    assert!(db.grant_issue(&input).is_err());
    input.approval["currently_usable"] = json!(true);
    input.recovery = 2;
    assert!(db.grant_issue(&input).is_err());
    input.recovery = 1;
    let ticket = json!({"connector":"connector","invocation":{"scope":scope,"kind":"invocation","id":"one"},"expires_at":1005});
    assert_eq!(
        db.grant_custody(scope, "publish-artifact", &ticket)
            .unwrap(),
        ticket
    );
    let mut changed = ticket.clone();
    changed["expires_at"] = json!(1009);
    assert_eq!(
        db.grant_custody(scope, "publish-artifact", &changed)
            .unwrap(),
        ticket,
        "lost custody cannot renew expiry"
    );
    changed["invocation"]["id"] = json!("two");
    assert!(
        db.grant_custody(scope, "publish-artifact", &changed)
            .is_err()
    );
    input.now = 1028;
    assert!(
        db.grant_issue(&input).is_err(),
        "expired original cannot mint successor"
    );
    assert_eq!(
        db.grant_pending(scope).unwrap(),
        Some(original["event"].clone()),
        "expired issuance still has deliverable audit intent"
    );
    let mut ack = v["records"]["ack"].clone();
    assert!(db.grant_ack(scope, "publish-artifact", &ack).is_err());
    ack["event_id"] = original["event"]["event_id"].clone();
    ack["event_digest"] = json!(wire::digest("accountability-event", &original["event"]).unwrap());
    ack["payload_digest"] = original["event"]["payload_digest"].clone();
    db.grant_ack(scope, "publish-artifact", &ack).unwrap();
    assert_eq!(db.grant_pending(scope).unwrap(), None);
    ack["position"] = json!(999);
    assert!(
        db.grant_ack(scope, "publish-artifact", &ack).is_err(),
        "original custody cannot be overwritten"
    );
}
