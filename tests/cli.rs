use serde_json::Value;
use std::fs;
use std::process::Command;

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_inlet-guard"))
}

#[test]
fn check_allows_valid_fixture() {
    let output = binary()
        .args([
            "check",
            "--policy",
            "examples/policy.json",
            "--request",
            "examples/allowed-request.json",
            "--output",
            "json",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["decision"], "allow");
}

#[test]
fn check_denies_mutated_arguments_with_exit_two() {
    let output = binary()
        .args([
            "check",
            "--policy",
            "examples/policy.json",
            "--request",
            "examples/denied-request.json",
            "--output",
            "json",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["decision"], "deny");
    let codes = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|finding| finding["code"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(codes.contains(&"approval_arguments_mismatch"));
    assert!(codes.contains(&"host_not_allowed"));
    assert!(codes.contains(&"origin_not_allowed"));
    assert!(codes.contains(&"payload_too_large"));
}

#[test]
fn batch_reports_every_input_and_denies_mixed_batch() {
    let directory = tempfile::tempdir().unwrap();
    let batch_path = directory.path().join("requests.jsonl");
    let allowed: Value =
        serde_json::from_str(&fs::read_to_string("examples/allowed-request.json").unwrap())
            .unwrap();
    let denied: Value =
        serde_json::from_str(&fs::read_to_string("examples/denied-request.json").unwrap()).unwrap();
    fs::write(
        &batch_path,
        format!(
            "{}\n{}\n",
            serde_json::to_string(&allowed).unwrap(),
            serde_json::to_string(&denied).unwrap()
        ),
    )
    .unwrap();
    let output = binary()
        .args([
            "batch",
            "--policy",
            "examples/policy.json",
            "--input",
            batch_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout.split(|byte| *byte == b'\n').count() - 1, 2);
}

#[test]
fn digest_command_matches_fixture_approval() {
    let directory = tempfile::tempdir().unwrap();
    let arguments_path = directory.path().join("arguments.json");
    fs::write(&arguments_path, r#"{"replicas":2,"environment":"staging"}"#).unwrap();
    let output = binary()
        .args([
            "digest-args",
            "--arguments",
            arguments_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let request: Value =
        serde_json::from_str(&fs::read_to_string("examples/allowed-request.json").unwrap())
            .unwrap();
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        request["tool_call"]["approval"]["arguments_sha256"]
            .as_str()
            .unwrap()
    );
}

#[test]
fn unknown_request_field_is_an_input_error() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("request.json");
    fs::write(
        &path,
        r#"{"request_id":"x","transport":"http","host":"localhost:8080","origin":"https://console.example.test","observed_bytes":0,"received_at_unix":1000,"run_id":"r","tool_call":null,"surprise":true}"#,
    )
    .unwrap();
    let output = binary()
        .args([
            "check",
            "--policy",
            "examples/policy.json",
            "--request",
            path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("unknown field")
    );
}
