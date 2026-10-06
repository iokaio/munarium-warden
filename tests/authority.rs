// SPDX-License-Identifier: Apache-2.0
mod support;
use munarium_warden::{authority::*, encoding::digest, error::Error};
use std::{
    sync::{
        Arc, Barrier,
        atomic::{AtomicI64, Ordering},
    },
    thread,
};
use support::*;

fn store(path: &std::path::Path) -> Store {
    Store::open(path, "alpha", "fixture", "cell-a").unwrap()
}

#[test]
fn durable_issuance_retries_conflicts_and_expiry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("warden.db");
    let clock = Arc::new(AtomicI64::new(1000));
    let c = Control::new(clock.clone());
    let i = Identity::new(clock.clone());
    let b = i.binding();
    let mut g = Journal::new(b.clone());
    let mut s = store(&path);
    assert!(s.issue(&b, &i, &g, &c).is_err());
    s.activate("activation-1", &c).unwrap();
    let grant = s.issue(&b, &i, &g, &c).unwrap();
    assert_eq!(grant.expires, 1030);
    drop(s);
    let mut s = store(&path);
    clock.store(1005, Ordering::SeqCst);
    assert_eq!(grant, s.issue(&b, &i, &g, &c).unwrap());
    let mut changed = b.clone();
    changed.request_digest = digest(b"changed");
    g.binding = changed.clone();
    assert_eq!(s.issue(&changed, &i, &g, &c), Err(Error::Conflict));
    g.binding = b.clone();
    clock.store(1028, Ordering::SeqCst);
    assert_eq!(s.issue(&b, &i, &g, &c), Err(Error::Expired));
    assert!(Store::open(&path, "other", "fixture", "cell-a").is_err());
}

#[test]
fn concurrent_connections_issue_one_stable_grant() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("warden.db");
    let clock = Arc::new(AtomicI64::new(1000));
    let c = Arc::new(Control::new(clock.clone()));
    let i = Arc::new(Identity::new(clock));
    let b = i.binding();
    let g = Arc::new(Journal::new(b.clone()));
    store(&path).activate("activation-1", c.as_ref()).unwrap();
    let barrier = Arc::new(Barrier::new(4));
    let mut threads = vec![];
    for _ in 0..4 {
        let (path, c, i, b, g, barrier) = (
            path.clone(),
            c.clone(),
            i.clone(),
            b.clone(),
            g.clone(),
            barrier.clone(),
        );
        threads.push(thread::spawn(move || {
            let mut s = store(&path);
            barrier.wait();
            s.issue(&b, i.as_ref(), g.as_ref(), c.as_ref()).unwrap()
        }));
    }
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert!(results.iter().all(|g| g == &results[0]));
    let db = rusqlite::Connection::open(path).unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM issuance", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[test]
fn missing_mismatched_or_unavailable_claim_never_issues() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = store(&dir.path().join("warden.db"));
    let clock = Arc::new(AtomicI64::new(1000));
    let c = Control::new(clock.clone());
    let i = Identity::new(clock);
    let b = i.binding();
    let mut g = Journal::new(b.clone());
    s.activate("activation-1", &c).unwrap();
    g.available = false;
    assert_eq!(s.issue(&b, &i, &g, &c), Err(Error::Unavailable));
    g.available = true;
    for field in [
        "request_digest",
        "audience",
        "instance",
        "agent_version",
        "cell",
        "tenant",
        "resource",
        "policy_digest",
    ] {
        let mut v = serde_json::to_value(&b).unwrap();
        v[field] = serde_json::json!("substitution");
        g.binding = serde_json::from_value(v).unwrap();
        assert_eq!(s.issue(&b, &i, &g, &c), Err(Error::Denied), "{field}");
    }
    g.binding = b.clone();
    assert!(s.issue(&b, &i, &g, &c).is_ok());
}

#[test]
fn validation_requires_live_identity_consumption_ack_and_lease() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = store(&dir.path().join("warden.db"));
    let clock = Arc::new(AtomicI64::new(1000));
    let c = Control::new(clock.clone());
    let i = Identity::new(clock);
    let b = i.binding();
    let mut g = Journal::new(b.clone());
    s.activate("activation-1", &c).unwrap();
    let grant = s.issue(&b, &i, &g, &c).unwrap();
    let ticket = s.validate(&grant, &i, &g, &c).unwrap();
    assert_eq!(ticket.expires(), 1005);
    g.consumed = false;
    assert!(s.validate(&grant, &i, &g, &c).is_err());
    g.consumed = true;
    g.acknowledged = false;
    assert!(s.validate(&grant, &i, &g, &c).is_err());
    g.acknowledged = true;
    g.fence = 0;
    assert!(s.validate(&grant, &i, &g, &c).is_err());
    g.fence = 1;
    g.lease = 1002;
    assert!(s.validate(&grant, &i, &g, &c).is_err());
    g.lease = 1010;
    i.retired.store(true, Ordering::SeqCst);
    assert!(s.validate(&grant, &i, &g, &c).is_err());
    assert!(s.issue(&b, &i, &g, &c).is_err());
    i.retired.store(false, Ordering::SeqCst);
    let mut forged = grant.clone();
    forged.expires += 1;
    assert!(s.validate(&forged, &i, &g, &c).is_err());
    c.healthy.store(false, Ordering::SeqCst);
    assert!(s.validate(&grant, &i, &g, &c).is_err());
}

#[test]
fn activation_is_authorized_scoped_idempotent_and_invalidates_old_grants() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = store(&dir.path().join("warden.db"));
    let clock = Arc::new(AtomicI64::new(1000));
    let mut c = Control::new(clock.clone());
    let i = Identity::new(clock);
    let b = i.binding();
    let g = Journal::new(b.clone());
    c.authorized = false;
    assert!(s.activate("activation-1", &c).is_err());
    c.authorized = true;
    c.activation.tenant = "other".into();
    assert!(s.activate("activation-1", &c).is_err());
    c.activation.tenant = "alpha".into();
    let ack = s.activate("activation-1", &c).unwrap();
    assert_eq!(ack, s.activate("activation-1", &c).unwrap());
    let grant = s.issue(&b, &i, &g, &c).unwrap();
    c.activation.mode = "guard".into();
    assert_eq!(s.activate("activation-1", &c), Err(Error::Conflict));
    c.activation.transition = "activation-2".into();
    c.activation.epoch = 2;
    assert_eq!(s.activate("activation-2", &c), Err(Error::Conflict));
    c.activation.previous_epoch = 1;
    c.activation.mode = "observe".into();
    s.activate("activation-2", &c).unwrap();
    assert!(s.validate(&grant, &i, &g, &c).is_err());
    assert!(s.issue(&b, &i, &g, &c).is_err());
    let mut changed = b.clone();
    changed.activation_epoch = 2;
    changed.mode = "observe".into();
    let journal = Journal::new(changed.clone());
    assert!(s.issue(&changed, &i, &journal, &c).is_err());
    c.activation = ack;
    assert_eq!(s.activate("activation-1", &c), Err(Error::Conflict));
}

#[test]
fn every_suspension_scope_survives_reopen_and_blocks_outstanding_grants() {
    for scope in [
        Scope::Tenant,
        Scope::Deployment,
        Scope::Instance("instance-a".into()),
        Scope::AgentVersion("version-a".into()),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("warden.db");
        let mut s = store(&path);
        let clock = Arc::new(AtomicI64::new(1000));
        let mut c = Control::new(clock.clone());
        let i = Identity::new(clock);
        let b = i.binding();
        let g = Journal::new(b.clone());
        s.activate("activation-1", &c).unwrap();
        let grant = s.issue(&b, &i, &g, &c).unwrap();
        c.authorized = false;
        assert!(s.suspend("stop-a", &scope, &c).is_err());
        c.authorized = true;
        assert!(s.validate(&grant, &i, &g, &c).is_ok());
        let started = std::time::Instant::now();
        assert_eq!(s.suspend("stop-a", &scope, &c).unwrap(), 1000);
        assert!(s.validate(&grant, &i, &g, &c).is_err());
        assert!(s.issue(&b, &i, &g, &c).is_err());
        eprintln!("local suspension to rejection: {:?}", started.elapsed());
        drop(s);
        let mut s = store(&path);
        assert!(s.issue(&b, &i, &g, &c).is_err());
        assert!(s.validate(&grant, &i, &g, &c).is_err());
    }
}

#[test]
fn unrelated_suspension_preserves_admission() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = store(&dir.path().join("warden.db"));
    let clock = Arc::new(AtomicI64::new(1000));
    let c = Control::new(clock.clone());
    let i = Identity::new(clock);
    let b = i.binding();
    let g = Journal::new(b.clone());
    s.activate("activation-1", &c).unwrap();
    s.suspend("stop-other", &Scope::Instance("other".into()), &c)
        .unwrap();
    assert!(s.issue(&b, &i, &g, &c).is_ok());
}

#[test]
fn restored_database_cannot_supply_its_own_recovery_authority() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("warden.db");
    let restored = dir.path().join("restored.db");
    let clock = Arc::new(AtomicI64::new(1000));
    let c = Control::new(clock.clone());
    let i = Identity::new(clock);
    let b = i.binding();
    let g = Journal::new(b.clone());
    let mut s = store(&path);
    s.activate("activation-1", &c).unwrap();
    let grant = s.issue(&b, &i, &g, &c).unwrap();
    drop(s);
    std::fs::copy(&path, &restored).unwrap();
    let mut s = store(&path);
    s.suspend("stop", &Scope::Tenant, &c).unwrap();
    let mut old = store(&restored);
    c.healthy.store(false, Ordering::SeqCst);
    assert!(old.issue(&b, &i, &g, &c).is_err());
    c.recovery.store(2, Ordering::SeqCst);
    c.healthy.store(true, Ordering::SeqCst);
    assert!(old.issue(&b, &i, &g, &c).is_err());
    assert!(old.validate(&grant, &i, &g, &c).is_err());
}

#[test]
fn crash_after_commit_retains_activation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("warden.db");
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "crash_child", "--ignored"])
        .env("WARDEN_TEST_DB", &path)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(43));
    let clock = Arc::new(AtomicI64::new(1000));
    let c = Control::new(clock.clone());
    let i = Identity::new(clock);
    let b = i.binding();
    let g = Journal::new(b.clone());
    assert!(store(&path).issue(&b, &i, &g, &c).is_ok());
}

#[test]
#[ignore = "subprocess-only crash injection, exercised by crash_after_commit_retains_activation"]
fn crash_child() {
    let path = std::env::var_os("WARDEN_TEST_DB").expect("subprocess path");
    let c = Control::new(Arc::new(AtomicI64::new(1000)));
    store(std::path::Path::new(&path))
        .activate("activation-1", &c)
        .unwrap();
    std::process::exit(43);
}
