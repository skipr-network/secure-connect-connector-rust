//! PR #278 review (Tasneem): the daemon must warn loudly when it generates a fresh identity at
//! normal startup (as opposed to via `--generate-identity`), since that almost always means the
//! key Portal registered isn't the one about to be used. Runs the real compiled binary on the
//! normal (no-flag) startup path with a CONNECTOR_IDENTITY_KEY_PATH that doesn't exist yet,
//! captures its stdout (tracing_subscriber::fmt's default writer) for a moment, then kills it -
//! it never exits on its own (it retries the heartbeat loop forever against a deliberately-
//! unreachable Agent), so the log line has to be observed while it's still running.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::Duration;

#[test]
fn warns_when_generating_a_fresh_identity_at_normal_startup() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("identity.key");

    let mut child = Command::new(env!("CARGO_BIN_EXE_secure_connect_connector"))
        .env_clear()
        .env("CONNECTOR_ID", "c-test")
        .env("AGENT_BASE_URL", "http://127.0.0.1:1")
        .env("AGENT_IP_ADDRESS", "127.0.0.1")
        .env("REGISTRY_BASE_URL", "http://127.0.0.1:1")
        .env("CONNECTOR_IDENTITY_KEY_PATH", &key_path)
        .env("RUST_LOG", "warn")
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to spawn the connector binary");

    std::thread::sleep(Duration::from_millis(1500));
    child.kill().ok();

    let mut stdout = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    let _ = child.wait();

    assert!(
        key_path.exists(),
        "a fresh identity should have been generated"
    );
    assert!(
        stdout.contains("generated a brand new identity"),
        "expected the fresh-identity warning, got: {stdout:?}"
    );
}

#[test]
fn does_not_warn_when_an_identity_already_existed() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("identity.key");

    // Pre-create the identity via --generate-identity, exactly like a real admin would.
    let generate = Command::new(env!("CARGO_BIN_EXE_secure_connect_connector"))
        .arg("--generate-identity")
        .env_clear()
        .env("CONNECTOR_IDENTITY_KEY_PATH", &key_path)
        .output()
        .unwrap();
    assert!(generate.status.success());

    let mut child = Command::new(env!("CARGO_BIN_EXE_secure_connect_connector"))
        .env_clear()
        .env("CONNECTOR_ID", "c-test")
        .env("AGENT_BASE_URL", "http://127.0.0.1:1")
        .env("AGENT_IP_ADDRESS", "127.0.0.1")
        .env("REGISTRY_BASE_URL", "http://127.0.0.1:1")
        .env("CONNECTOR_IDENTITY_KEY_PATH", &key_path)
        .env("RUST_LOG", "warn")
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to spawn the connector binary");

    std::thread::sleep(Duration::from_millis(1500));
    child.kill().ok();

    let mut stdout = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    let _ = child.wait();

    assert!(
        !stdout.contains("generated a brand new identity"),
        "must not warn when the identity already existed, got: {stdout:?}"
    );
}
