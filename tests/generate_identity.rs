//! TT-1886: end-to-end proof that `--generate-identity` really is a standalone mode - runs the
//! actual compiled binary (not just the internal function) with none of Config::from_env's
//! required env vars set, so a regression that re-introduces a Config::from_env call on this
//! path would fail here even if a narrower unit test missed it.

use std::process::Command;

fn run_generate_identity(key_path: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_secure_connect_connector"))
        .arg("--generate-identity")
        .env_clear()
        .env("CONNECTOR_IDENTITY_KEY_PATH", key_path)
        .output()
        .expect("failed to run the connector binary")
}

#[test]
fn prints_a_public_key_and_persists_it_without_any_config_env_vars_set() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("identity.key");

    let output = run_generate_identity(&key_path);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let printed_key = stdout.trim();
    // 32 raw bytes, base64-encoded with padding - matches identity.rs's own test expectation.
    assert_eq!(printed_key.len(), 44);
    assert!(key_path.exists());
}

#[test]
fn prints_the_same_key_again_on_a_second_run_against_the_same_path() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("identity.key");

    let first = run_generate_identity(&key_path);
    let second = run_generate_identity(&key_path);

    assert!(first.status.success());
    assert!(second.status.success());
    assert_eq!(
        String::from_utf8(first.stdout).unwrap(),
        String::from_utf8(second.stdout).unwrap()
    );
}
