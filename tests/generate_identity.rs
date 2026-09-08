//! TT-1886: end-to-end proof that `--generate-identity` really is a standalone mode - runs the
//! actual compiled binary (not just the internal function) with none of Config::from_env's
//! required env vars set, so a regression that re-introduces a Config::from_env call on this
//! path would fail here even if a narrower unit test missed it.

use std::process::Command;

fn run(args: &[&str], key_path: Option<&std::path::Path>) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_secure_connect_connector"));
    cmd.args(args).env_clear();
    if let Some(path) = key_path {
        cmd.env("CONNECTOR_IDENTITY_KEY_PATH", path);
    }
    cmd.output().expect("failed to run the connector binary")
}

#[test]
fn prints_exactly_the_persisted_public_key_line_and_nothing_else_on_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("identity.key");

    let output = run(&["--generate-identity"], Some(&key_path));

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    // Exactly one line, not just "trim() looks like 44 base64 chars" - the persisted file's two
    // lines (private key, public key) are both 32 raw bytes and so both base64-encode to the same
    // 44-char length. A bug that printed the private key instead would pass a length-only check
    // (PR #5 review, Tasneem).
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "stdout should be exactly one line, got: {stdout:?}"
    );
    let printed = lines[0];

    let persisted = std::fs::read_to_string(&key_path).unwrap();
    let persisted_lines: Vec<&str> = persisted.lines().collect();
    assert_eq!(
        persisted_lines.len(),
        2,
        "identity file should have exactly 2 lines"
    );
    let (persisted_private, persisted_public) = (persisted_lines[0], persisted_lines[1]);

    assert_eq!(printed, persisted_public, "must print the public key line");
    assert_ne!(
        printed, persisted_private,
        "must not print the private key line"
    );
}

#[test]
fn reports_the_resolved_key_path_on_stderr_not_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("identity.key");

    let output = run(&["--generate-identity"], Some(&key_path));

    assert!(output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains(&key_path.display().to_string()),
        "stderr should report the resolved key path, got: {stderr:?}"
    );
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    assert!(
        !stdout.contains(&key_path.display().to_string()),
        "the key path must not leak into stdout, got: {stdout:?}"
    );
}

#[test]
fn prints_the_same_key_again_on_a_second_run_against_the_same_path() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("identity.key");

    let first = run(&["--generate-identity"], Some(&key_path));
    let second = run(&["--generate-identity"], Some(&key_path));

    assert!(first.status.success());
    assert!(second.status.success());
    assert_eq!(first.stdout, second.stdout);
}

#[test]
fn help_flag_prints_usage_and_does_not_require_any_config() {
    for flag in ["--help", "-h"] {
        let output = run(&[flag], None);
        assert!(
            output.status.success(),
            "flag {flag}: stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(
            stdout.contains("--generate-identity"),
            "flag {flag}: usage text missing, got: {stdout:?}"
        );
    }
}

#[test]
fn a_typo_in_the_flag_is_rejected_with_a_usage_error_not_the_config_id_dead_end() {
    let output = run(&["--generate-identiy"], None);

    assert!(!output.status.success(), "a typo'd flag must not succeed");
    let stderr = String::from_utf8(output.stderr).unwrap();
    // The bug this test guards against: before PR #5's fixes, an unrecognized flag silently fell
    // through to the normal startup path and failed with this exact message instead - the precise
    // dead-end TT-1886 exists to remove.
    assert!(
        !stderr.contains("CONNECTOR_ID"),
        "must not fall through to the daemon's CONNECTOR_ID check, got: {stderr:?}"
    );
    assert!(stderr.contains("unrecognized argument"), "got: {stderr:?}");
}

#[test]
fn extra_arguments_after_the_flag_are_rejected() {
    let output = run(&["--generate-identity", "extra"], None);

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!stderr.contains("CONNECTOR_ID"), "got: {stderr:?}");
}
