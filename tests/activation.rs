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
