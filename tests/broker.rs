// SPDX-License-Identifier: Apache-2.0
mod support;
use munarium_warden::{authority::*, credential::*, encoding::digest, error::Error};
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{
        Arc,
        atomic::{AtomicI64, AtomicUsize, Ordering},
    },
    thread,
};
use support::*;

struct Provider {
    calls: AtomicUsize,
}
impl SecretProvider for Provider {
    fn fetch(&self, _: &str) -> Result<Credential, Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Credential::from_bytes(b"disposable-target-value".to_vec())
    }
}
struct Target {
    audience: String,
    sends: usize,
    admitted: bool,
}
impl Connector for Target {
    fn audience(&self) -> &str {
        &self.audience
    }
    fn deliver(&mut self, ticket: &Ticket, credential: &Credential) -> Result<(), Error> {
        // Test double for the connector's live Gate CAS, not a Warden consumption implementation.
        if self.admitted || ticket.fence() != 1 || ticket.expires() != 1005 {
            return Err(Error::Denied);
        }
        self.admitted = true;
        assert_eq!(credential.expose_to_connector(), b"disposable-target-value");
        self.sends += 1;
        Ok(())
    }
}

#[test]
fn delivery_checks_audience_consumption_and_replay_before_any_effect() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = Store::open(dir.path().join("warden.db"), "alpha", "fixture", "cell-a").unwrap();
    let clock = Arc::new(AtomicI64::new(1000));
    let c = Control::new(clock.clone());
    let i = Identity::new(clock);
    let b = i.binding();
    let mut g = Journal::new(b.clone());
    s.activate("activation-1", &c).unwrap();
    let grant = s.issue(&b, &i, &g, &c).unwrap();
    let p = Provider {
        calls: AtomicUsize::new(0),
    };
    let mut target = Target {
        audience: "other".into(),
        sends: 0,
        admitted: false,
    };
    assert!(deliver(&mut s, &grant, &i, &g, &c, &p, &mut target).is_err());
    assert_eq!(p.calls.load(Ordering::SeqCst), 0);
    target.audience = "connector-a".into();
    g.consumed = false;
    assert!(deliver(&mut s, &grant, &i, &g, &c, &p, &mut target).is_err());
    assert_eq!(p.calls.load(Ordering::SeqCst), 0);
    g.consumed = true;
    let receipt = deliver(&mut s, &grant, &i, &g, &c, &p, &mut target).unwrap();
    assert!(!format!("{receipt:?}").contains("disposable-target-value"));
    assert!(deliver(&mut s, &grant, &i, &g, &c, &p, &mut target).is_err());
    assert_eq!(target.sends, 1);
}

#[test]
fn suspension_during_vault_lookup_blocks_delivery() {
    struct Revoking<'a> {
        path: &'a std::path::Path,
        control: &'a Control,
    }
    impl SecretProvider for Revoking<'_> {
        fn fetch(&self, _: &str) -> Result<Credential, Error> {
            let mut s = Store::open(self.path, "alpha", "fixture", "cell-a")?;
            s.suspend("stop", &Scope::Tenant, self.control)?;
            Credential::from_bytes(b"disposable-target-value".to_vec())
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("warden.db");
    let mut s = Store::open(&path, "alpha", "fixture", "cell-a").unwrap();
    let clock = Arc::new(AtomicI64::new(1000));
    let c = Control::new(clock.clone());
    let i = Identity::new(clock);
    let b = i.binding();
    let g = Journal::new(b.clone());
    s.activate("activation-1", &c).unwrap();
    let grant = s.issue(&b, &i, &g, &c).unwrap();
    let mut target = Target {
        audience: "connector-a".into(),
        sends: 0,
        admitted: false,
    };
    let p = Revoking {
        path: &path,
        control: &c,
    };
    assert!(deliver(&mut s, &grant, &i, &g, &c, &p, &mut target).is_err());
    assert_eq!(target.sends, 0);
}

#[test]
fn lost_connector_acknowledgement_is_unresolved_and_never_retried() {
    struct LostReply(usize);
    impl Connector for LostReply {
        fn audience(&self) -> &str {
            "connector-a"
        }
        fn deliver(&mut self, _: &Ticket, _: &Credential) -> Result<(), Error> {
            self.0 += 1;
            Err(Error::Unavailable)
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let mut s = Store::open(dir.path().join("warden.db"), "alpha", "fixture", "cell-a").unwrap();
    let clock = Arc::new(AtomicI64::new(1000));
    let c = Control::new(clock.clone());
    let i = Identity::new(clock);
    let b = i.binding();
    let g = Journal::new(b.clone());
    s.activate("activation-1", &c).unwrap();
    let grant = s.issue(&b, &i, &g, &c).unwrap();
    let p = Provider {
        calls: AtomicUsize::new(0),
    };
    let mut connector = LostReply(0);
    assert_eq!(
        deliver(&mut s, &grant, &i, &g, &c, &p, &mut connector),
        Err(Error::Unresolved)
    );
    assert_eq!(connector.0, 1);
    assert_eq!(p.calls.load(Ordering::SeqCst), 1);
}

fn serve(status: &str, body: String, extra: &str) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "http://{}/v1/test/data/target",
        listener.local_addr().unwrap()
    );
    let status = status.to_owned();
    let extra = extra.to_owned();
    let child = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut request = [0u8; 8192];
        let size = stream.read(&mut request).unwrap();
        assert!(size > 0);
        write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{body}",
            body.len()
        )
        .unwrap();
    });
    (url, child)
}

#[test]
fn openbao_transport_bounds_errors_redirects_and_resource_selection() {
    assert!(
        OpenBao::https(
            "http://127.0.0.1:8200/v1/test/data/x",
            "test-token".into(),
            "item-a",
            None
        )
        .is_err()
    );
    assert!(
        OpenBao::loopback_test(
            "http://example.test/v1/test/data/x",
            "test-token".into(),
            "item-a"
        )
        .is_err()
    );
    for (status, body, extra) in [
        ("403 Forbidden", "disposable-target-value".to_owned(), ""),
        ("302 Found", "".into(), "Location: http://127.0.0.1:1/\r\n"),
        ("200 OK", "x".repeat(65537), ""),
        ("200 OK", "not-json-disposable-target-value".into(), ""),
    ] {
        let (url, server) = serve(status, body, extra);
        let p = OpenBao::loopback_test(&url, "test-token".into(), "item-a").unwrap();
        let result = p.fetch("item-a");
        assert!(result.is_err());
        assert_eq!(result.err().unwrap().to_string(), "Unavailable");
        server.join().unwrap();
    }
    let (url, server) = serve(
        "200 OK",
        r#"{"data":{"data":{"credential":"disposable-target-value"}}}"#.into(),
        "",
    );
    let p = OpenBao::loopback_test(&url, "test-token".into(), "item-a").unwrap();
    assert!(p.fetch("other").is_err());
    let value = p.fetch("item-a").unwrap();
    assert_eq!(value.expose_to_connector(), b"disposable-target-value");
    server.join().unwrap();
}

#[test]
fn connector_child_receives_secret_only_over_owned_stdin() {
    use std::process::{Command, Stdio};
    let mut secret = vec![0u8; 32];
    getrandom::fill(&mut secret).unwrap();
    let expected = digest(&secret);
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "connector_child", "--ignored", "--nocapture"])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&secret).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains(&expected));
    assert!(!output.stdout.windows(secret.len()).any(|w| w == secret));
    assert!(!output.stderr.windows(secret.len()).any(|w| w == secret));
}

#[test]
#[ignore = "subprocess-only credential channel probe, exercised by connector_child_receives_secret_only_over_owned_stdin"]
fn connector_child() {
    let mut secret = vec![];
    std::io::stdin()
        .take(16385)
        .read_to_end(&mut secret)
        .unwrap();
    assert!(!secret.is_empty() && secret.len() <= 16384);
    for (_, value) in std::env::vars_os() {
        assert!(
            !value
                .to_string_lossy()
                .as_bytes()
                .windows(secret.len())
                .any(|w| w == secret)
        );
    }
    println!("{}", digest(&secret));
}

#[test]
#[ignore = "requires Docker and the pinned public OpenBao image; run explicitly"]
fn openbao_live_broker_flow() {
    use std::process::{Command, Stdio};
    const IMAGE: &str = "ghcr.io/openbao/openbao:2.4.4@sha256:01bdba095690b1fe7cc1ec956ca422cfe01fd9a994ea28d9a6a2f84886dc9569";
    struct Container(String);
    impl Drop for Container {
        fn drop(&mut self) {
            let _ = Command::new("docker")
                .args(["rm", "--force", "--volumes", &self.0])
                .output();
        }
    }
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce).unwrap();
    let name = format!(
        "warden-test-{}-{}",
        std::process::id(),
        &digest(&nonce)[7..19]
    );
    let started = Command::new("docker")
        .args([
            "run",
            "--detach",
            "--rm",
            "--name",
            &name,
            "--publish",
            "127.0.0.1::8200",
            "--env",
            "SKIP_SETCAP=true",
            "--env",
            "SKIP_CHOWN=true",
            IMAGE,
            "server",
            "-dev",
            "-dev-no-store-token",
            "-dev-root-token-id=warden-disposable-root",
            "-dev-listen-address=0.0.0.0:8200",
        ])
        .output()
        .unwrap();
    assert!(
        started.status.success(),
        "disposable OpenBao start failed (diagnostics suppressed)"
    );
    let container = Container(name);
    let port = Command::new("docker")
        .args(["port", &container.0, "8200/tcp"])
        .output()
        .unwrap();
    assert!(port.status.success());
    let address = String::from_utf8(port.stdout).unwrap();
    let base = format!("http://{}", address.trim());
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .unwrap();
    let mut ready = false;
    for _ in 0..50 {
        if client
            .get(format!("{base}/v1/sys/health"))
            .send()
            .is_ok_and(|r| r.status().is_success())
        {
            ready = true;
            break;
        }
        thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(ready, "disposable vault did not become ready");
    let mut random = [0u8; 32];
    getrandom::fill(&mut random).unwrap();
    let secret = digest(&random);
    let endpoint = format!("{base}/v1/secret/data/warden-target");
    assert!(
        client
            .post(&endpoint)
            .header("X-Vault-Token", "warden-disposable-root")
            .json(&serde_json::json!({"data":{"credential":secret}}))
            .send()
            .unwrap()
            .status()
            .is_success()
    );
    struct Child {
        expected: String,
        sends: usize,
    }
    impl Connector for Child {
        fn audience(&self) -> &str {
            "connector-a"
        }
        fn deliver(&mut self, ticket: &Ticket, credential: &Credential) -> Result<(), Error> {
            // Disposable connector probe. Real Gate final admission remains a
            // composition requirement, not a claim made by this child process.
            if self.sends != 0 || ticket.worker() != "worker-a" {
                return Err(Error::Denied);
            }
            self.sends += 1;
            let mut child = Command::new(std::env::current_exe().map_err(|_| Error::Unavailable)?)
                .args(["--exact", "connector_child", "--ignored", "--nocapture"])
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|_| Error::Unavailable)?;
            child
                .stdin
                .take()
                .ok_or(Error::Unavailable)?
                .write_all(credential.expose_to_connector())
                .map_err(|_| Error::Unavailable)?;
            let output = child.wait_with_output().map_err(|_| Error::Unavailable)?;
            let secret = credential.expose_to_connector();
            if !output.status.success()
                || !String::from_utf8_lossy(&output.stdout).contains(&self.expected)
                || output.stdout.windows(secret.len()).any(|w| w == secret)
                || output.stderr.windows(secret.len()).any(|w| w == secret)
            {
                return Err(Error::Denied);
            }
            Ok(())
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let mut s = Store::open(dir.path().join("warden.db"), "alpha", "fixture", "cell-a").unwrap();
    let clock = Arc::new(AtomicI64::new(1000));
    let c = Control::new(clock.clone());
    let i = Identity::new(clock);
    let b = i.binding();
    let g = Journal::new(b.clone());
    s.activate("activation-1", &c).unwrap();
    let grant = s.issue(&b, &i, &g, &c).unwrap();
    let provider =
        OpenBao::loopback_test(&endpoint, "warden-disposable-root".into(), "item-a").unwrap();
    let mut connector = Child {
        expected: digest(secret.as_bytes()),
        sends: 0,
    };
    let receipt = deliver(&mut s, &grant, &i, &g, &c, &provider, &mut connector).unwrap();
    assert!(!format!("{receipt:?}").contains(&secret));
    assert_eq!(connector.sends, 1);
    s.suspend("stop", &Scope::Tenant, &c).unwrap();
    assert!(deliver(&mut s, &grant, &i, &g, &c, &provider, &mut connector).is_err());
    assert_eq!(connector.sends, 1);
    println!(
        "OpenBao retrieval, child delivery and post-suspension refusal passed; no target value emitted."
    );
}
