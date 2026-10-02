#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use thiserror::Error;
use url::{Host, Url};

#[derive(Debug, Error)]
pub enum GuardError {
    #[error("invalid policy: {0}")]
    InvalidPolicy(String),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub policy_id: String,
    pub allowed_hosts: Vec<String>,
    pub allowed_origins: Vec<String>,
    pub require_origin: bool,
    pub max_http_body_bytes: u64,
    pub max_websocket_message_bytes: u64,
    pub require_bound_approval_for_side_effects: bool,
    pub max_approval_ttl_seconds: u64,
    pub clock_skew_seconds: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Http,
    Websocket,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestEnvelope {
    pub request_id: String,
    pub transport: Transport,
    pub host: String,
    pub origin: Option<String>,
    pub observed_bytes: u64,
    pub received_at_unix: u64,
    pub run_id: String,
    pub tool_call: Option<ToolCall>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolCall {
    pub tool: String,
    pub arguments: Value,
    pub side_effecting: bool,
    pub approval: Option<Approval>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub request_id: String,
    pub run_id: String,
    pub tool: String,
    pub arguments_sha256: String,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FindingCode {
    ApprovalArgumentsMismatch,
    ApprovalExpired,
    ApprovalIssuedInFuture,
    ApprovalRequestMismatch,
    ApprovalRunMismatch,
    ApprovalToolMismatch,
    ApprovalWindowTooLong,
    HostNotAllowed,
    InvalidHost,
    InvalidOrigin,
    MissingApproval,
    MissingOrigin,
    OriginNotAllowed,
    PayloadTooLarge,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub code: FindingCode,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub policy_id: String,
    pub request_id: String,
    pub decision: Decision,
    pub normalized_host: Option<String>,
    pub normalized_origin: Option<String>,
    pub arguments_sha256: Option<String>,
    pub findings: Vec<Finding>,
}

impl Policy {
    /// Validate policy invariants and canonicalize every configured boundary value.
    ///
    /// # Errors
    ///
    /// Returns [`GuardError::InvalidPolicy`] when an identifier, allowlist entry,
    /// payload limit, or approval window is unusable.
    pub fn validate(&self) -> Result<(), GuardError> {
        if self.policy_id.trim().is_empty() {
            return Err(GuardError::InvalidPolicy(
                "policy_id must not be empty".to_owned(),
            ));
        }
        if self.allowed_hosts.is_empty() {
            return Err(GuardError::InvalidPolicy(
                "allowed_hosts must not be empty".to_owned(),
            ));
        }
        for host in &self.allowed_hosts {
            normalize_authority(host).map_err(GuardError::InvalidPolicy)?;
        }
        for origin in &self.allowed_origins {
            normalize_origin(origin).map_err(GuardError::InvalidPolicy)?;
        }
        if self.require_origin && self.allowed_origins.is_empty() {
            return Err(GuardError::InvalidPolicy(
                "require_origin needs at least one allowed origin".to_owned(),
            ));
        }
        if self.max_http_body_bytes == 0 || self.max_websocket_message_bytes == 0 {
            return Err(GuardError::InvalidPolicy(
                "payload limits must be greater than zero".to_owned(),
            ));
        }
        if self.require_bound_approval_for_side_effects && self.max_approval_ttl_seconds == 0 {
            return Err(GuardError::InvalidPolicy(
                "approval TTL must be greater than zero".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Evaluate one inbound envelope. Invalid or mismatched security attributes deny the request.
///
/// # Errors
///
/// Returns an error when the policy or envelope is structurally invalid. Security
/// mismatches in an otherwise valid envelope are represented as a denial report.
pub fn evaluate(policy: &Policy, request: &RequestEnvelope) -> Result<Report, GuardError> {
    policy.validate()?;
    validate_request(request)?;

    let allowed_hosts = policy
        .allowed_hosts
        .iter()
        .map(|host| normalize_authority(host).map_err(GuardError::InvalidPolicy))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let allowed_origins = policy
        .allowed_origins
        .iter()
        .map(|origin| normalize_origin(origin).map_err(GuardError::InvalidPolicy))
        .collect::<Result<BTreeSet<_>, _>>()?;

    let mut findings = Vec::new();
    let normalized_host = check_host(&request.host, &allowed_hosts, &mut findings);
    let normalized_origin = check_origin(policy, request, &allowed_origins, &mut findings);
    check_payload(policy, request, &mut findings);
    let arguments_sha256 = check_tool_call(policy, request, &mut findings);

    findings.sort_by(|left, right| {
        left.code
            .cmp(&right.code)
            .then_with(|| left.message.cmp(&right.message))
    });

    Ok(Report {
        policy_id: policy.policy_id.clone(),
        request_id: request.request_id.clone(),
        decision: if findings.is_empty() {
            Decision::Allow
        } else {
            Decision::Deny
        },
        normalized_host,
        normalized_origin,
        arguments_sha256,
        findings,
    })
}

fn check_host(
    raw: &str,
    allowed: &BTreeSet<String>,
    findings: &mut Vec<Finding>,
) -> Option<String> {
    match normalize_authority(raw) {
        Ok(host) => {
            if !allowed.contains(&host) {
                push_finding(
                    findings,
                    FindingCode::HostNotAllowed,
                    format!("host `{host}` is not on the exact allowlist"),
                );
            }
            Some(host)
        }
        Err(message) => {
            push_finding(findings, FindingCode::InvalidHost, message);
            None
        }
    }
}

fn check_origin(
    policy: &Policy,
    request: &RequestEnvelope,
    allowed: &BTreeSet<String>,
    findings: &mut Vec<Finding>,
) -> Option<String> {
    let Some(raw) = request.origin.as_deref() else {
        if policy.require_origin {
            push_finding(
                findings,
                FindingCode::MissingOrigin,
                "an Origin header is required".to_owned(),
            );
        }
        return None;
    };
    match normalize_origin(raw) {
        Ok(origin) => {
            if !allowed.contains(&origin) {
                push_finding(
                    findings,
                    FindingCode::OriginNotAllowed,
                    format!("origin `{origin}` is not on the exact allowlist"),
                );
            }
            Some(origin)
        }
        Err(message) => {
            push_finding(findings, FindingCode::InvalidOrigin, message);
            None
        }
    }
}

fn check_payload(policy: &Policy, request: &RequestEnvelope, findings: &mut Vec<Finding>) {
    let limit = match request.transport {
        Transport::Http => policy.max_http_body_bytes,
        Transport::Websocket => policy.max_websocket_message_bytes,
    };
    if request.observed_bytes > limit {
        push_finding(
            findings,
            FindingCode::PayloadTooLarge,
            format!(
                "observed {} bytes exceeds the {:?} limit of {limit}",
                request.observed_bytes, request.transport
            ),
        );
    }
}

fn check_tool_call(
    policy: &Policy,
    request: &RequestEnvelope,
    findings: &mut Vec<Finding>,
) -> Option<String> {
    request.tool_call.as_ref().map(|call| {
        let digest = canonical_json_sha256(&call.arguments);
        if call.side_effecting && policy.require_bound_approval_for_side_effects {
            match &call.approval {
                Some(approval) => {
                    check_approval(policy, request, call, approval, &digest, findings);
                }
                None => push_finding(
                    findings,
                    FindingCode::MissingApproval,
                    "side-effecting tool call has no bound approval".to_owned(),
                ),
            }
        }
        digest
    })
}

/// SHA-256 over canonical JSON with recursively sorted object keys and no whitespace.
#[must_use]
pub fn canonical_json_sha256(value: &Value) -> String {
    let mut canonical = String::new();
    write_canonical(value, &mut canonical);
    sha256_hex(canonical.as_bytes())
}

fn validate_request(request: &RequestEnvelope) -> Result<(), GuardError> {
    for (name, value) in [
        ("request_id", request.request_id.as_str()),
        ("run_id", request.run_id.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(GuardError::InvalidRequest(format!(
                "{name} must not be empty"
            )));
        }
    }
    if let Some(call) = &request.tool_call
        && call.tool.trim().is_empty()
    {
        return Err(GuardError::InvalidRequest(
            "tool must not be empty".to_owned(),
        ));
    }
    Ok(())
}

fn check_approval(
    policy: &Policy,
    request: &RequestEnvelope,
    call: &ToolCall,
    approval: &Approval,
    digest: &str,
    findings: &mut Vec<Finding>,
) {
    if approval.request_id != request.request_id {
        push_finding(
            findings,
            FindingCode::ApprovalRequestMismatch,
            "approval is bound to a different request".to_owned(),
        );
    }
    if approval.run_id != request.run_id {
        push_finding(
            findings,
            FindingCode::ApprovalRunMismatch,
            "approval is bound to a different run".to_owned(),
        );
    }
    if approval.tool != call.tool {
        push_finding(
            findings,
            FindingCode::ApprovalToolMismatch,
            "approval is bound to a different tool".to_owned(),
        );
    }
    if approval.arguments_sha256 != digest {
        push_finding(
            findings,
            FindingCode::ApprovalArgumentsMismatch,
            "approval arguments digest does not match the tool call".to_owned(),
        );
    }

    let skew = policy.clock_skew_seconds;
    if approval.issued_at_unix > request.received_at_unix.saturating_add(skew) {
        push_finding(
            findings,
            FindingCode::ApprovalIssuedInFuture,
            "approval issue time is later than the accepted clock skew".to_owned(),
        );
    }
    if request.received_at_unix > approval.expires_at_unix.saturating_add(skew) {
        push_finding(
            findings,
            FindingCode::ApprovalExpired,
            "approval expired before the request was received".to_owned(),
        );
    }
    let ttl = approval
        .expires_at_unix
        .saturating_sub(approval.issued_at_unix);
    if approval.expires_at_unix < approval.issued_at_unix || ttl > policy.max_approval_ttl_seconds {
        push_finding(
            findings,
            FindingCode::ApprovalWindowTooLong,
            format!(
                "approval window is invalid or exceeds {} seconds",
                policy.max_approval_ttl_seconds
            ),
        );
    }
}

fn normalize_authority(raw: &str) -> Result<String, String> {
    if raw.trim() != raw || raw.is_empty() {
        return Err("host must be nonempty and contain no surrounding whitespace".to_owned());
    }
    if raw.contains(['/', '@', '?', '#']) || raw.contains("://") {
        return Err("host must be an authority only, without scheme, path, or userinfo".to_owned());
    }

    let parsed = Url::parse(&format!("http://{raw}/"))
        .map_err(|error| format!("host is not a valid authority: {error}"))?;
    let host = parsed
        .host()
        .ok_or_else(|| "host authority has no hostname or IP".to_owned())?;
    let host_text = match host {
        Host::Domain(domain) => domain.to_ascii_lowercase(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => format!("[{address}]"),
    };
    Ok(match parsed.port() {
        Some(port) => format!("{host_text}:{port}"),
        None => host_text,
    })
}

fn normalize_origin(raw: &str) -> Result<String, String> {
    if raw.trim() != raw || raw.is_empty() {
        return Err("origin must be nonempty and contain no surrounding whitespace".to_owned());
    }
    if raw == "null" {
        return Err("opaque `null` origins are not accepted".to_owned());
    }
    let parsed = Url::parse(raw).map_err(|error| format!("origin is invalid: {error}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err("origin scheme must be http or https".to_owned());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("origin must not contain userinfo".to_owned());
    }
    if parsed.path() != "/" || parsed.query().is_some() || parsed.fragment().is_some() {
        return Err("origin must not contain a path, query, or fragment".to_owned());
    }
    let host = parsed
        .host()
        .ok_or_else(|| "origin has no hostname or IP".to_owned())?;
    let host_text = match host {
        Host::Domain(domain) => domain.to_ascii_lowercase(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => format!("[{address}]"),
    };
    let default_port = match parsed.scheme() {
        "http" => 80,
        "https" => 443,
        _ => unreachable!("scheme was checked"),
    };
    let port = parsed.port().filter(|port| *port != default_port);
    Ok(match port {
        Some(port) => format!("{}://{host_text}:{port}", parsed.scheme()),
        None => format!("{}://{host_text}", parsed.scheme()),
    })
}

fn write_canonical(value: &Value, output: &mut String) {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::Number(value) => output.push_str(&value.to_string()),
        Value::String(value) => {
            output
                .push_str(&serde_json::to_string(value).expect("serializing a string cannot fail"));
        }
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_canonical(value, output);
            }
            output.push(']');
        }
        Value::Object(values) => {
            output.push('{');
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_by_key(|(key, _)| key.as_str());
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                output.push_str(
                    &serde_json::to_string(key).expect("serializing an object key cannot fail"),
                );
                output.push(':');
                write_canonical(value, output);
            }
            output.push('}');
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

fn push_finding(findings: &mut Vec<Finding>, code: FindingCode, message: String) {
    findings.push(Finding { code, message });
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn policy() -> Policy {
        Policy {
            policy_id: "test-policy".to_owned(),
            allowed_hosts: vec!["localhost:8080".to_owned(), "[::1]:8080".to_owned()],
            allowed_origins: vec!["https://console.example.test".to_owned()],
            require_origin: true,
            max_http_body_bytes: 100,
            max_websocket_message_bytes: 200,
            require_bound_approval_for_side_effects: true,
            max_approval_ttl_seconds: 300,
            clock_skew_seconds: 5,
        }
    }

    fn request() -> RequestEnvelope {
        let arguments = json!({"environment": "staging", "replicas": 2});
        RequestEnvelope {
            request_id: "request-1".to_owned(),
            transport: Transport::Http,
            host: "LOCALHOST:8080".to_owned(),
            origin: Some("https://console.example.test:443".to_owned()),
            observed_bytes: 80,
            received_at_unix: 1_000,
            run_id: "run-1".to_owned(),
            tool_call: Some(ToolCall {
                tool: "deploy_preview".to_owned(),
                arguments: arguments.clone(),
                side_effecting: true,
                approval: Some(Approval {
                    request_id: "request-1".to_owned(),
                    run_id: "run-1".to_owned(),
                    tool: "deploy_preview".to_owned(),
                    arguments_sha256: canonical_json_sha256(&arguments),
                    issued_at_unix: 950,
                    expires_at_unix: 1_050,
                }),
            }),
        }
    }

    fn codes(report: &Report) -> BTreeSet<FindingCode> {
        report
            .findings
            .iter()
            .map(|finding| finding.code.clone())
            .collect()
    }

    #[test]
    fn allows_exact_bound_request() {
        let report = evaluate(&policy(), &request()).unwrap();
        assert_eq!(report.decision, Decision::Allow);
        assert_eq!(report.normalized_host.as_deref(), Some("localhost:8080"));
        assert_eq!(
            report.normalized_origin.as_deref(),
            Some("https://console.example.test")
        );
        assert!(report.findings.is_empty());
    }

    #[test]
    fn rejects_dns_rebinding_host() {
        let mut request = request();
        request.host = "attacker.example:8080".to_owned();
        let report = evaluate(&policy(), &request).unwrap();
        assert!(codes(&report).contains(&FindingCode::HostNotAllowed));
    }

    #[test]
    fn rejects_host_userinfo_confusion() {
        let mut request = request();
        request.host = "localhost:8080@attacker.example".to_owned();
        let report = evaluate(&policy(), &request).unwrap();
        assert!(codes(&report).contains(&FindingCode::InvalidHost));
    }

    #[test]
    fn rejects_cross_origin_request() {
        let mut request = request();
        request.origin = Some("https://evil.example".to_owned());
        let report = evaluate(&policy(), &request).unwrap();
        assert!(codes(&report).contains(&FindingCode::OriginNotAllowed));
    }

    #[test]
    fn rejects_missing_required_origin() {
        let mut request = request();
        request.origin = None;
        let report = evaluate(&policy(), &request).unwrap();
        assert!(codes(&report).contains(&FindingCode::MissingOrigin));
    }

    #[test]
    fn rejects_opaque_origin() {
        let mut request = request();
        request.origin = Some("null".to_owned());
        let report = evaluate(&policy(), &request).unwrap();
        assert!(codes(&report).contains(&FindingCode::InvalidOrigin));
    }

    #[test]
    fn rejects_http_body_over_limit() {
        let mut request = request();
        request.observed_bytes = 101;
        let report = evaluate(&policy(), &request).unwrap();
        assert!(codes(&report).contains(&FindingCode::PayloadTooLarge));
    }

    #[test]
    fn applies_distinct_websocket_limit() {
        let mut request = request();
        request.transport = Transport::Websocket;
        request.observed_bytes = 150;
        assert_eq!(
            evaluate(&policy(), &request).unwrap().decision,
            Decision::Allow
        );
        request.observed_bytes = 201;
        assert!(
            codes(&evaluate(&policy(), &request).unwrap()).contains(&FindingCode::PayloadTooLarge)
        );
    }

    #[test]
    fn rejects_missing_side_effect_approval() {
        let mut request = request();
        request.tool_call.as_mut().unwrap().approval = None;
        let report = evaluate(&policy(), &request).unwrap();
        assert!(codes(&report).contains(&FindingCode::MissingApproval));
    }

    #[test]
    fn permits_read_only_call_without_approval() {
        let mut request = request();
        let call = request.tool_call.as_mut().unwrap();
        call.side_effecting = false;
        call.approval = None;
        assert_eq!(
            evaluate(&policy(), &request).unwrap().decision,
            Decision::Allow
        );
    }

    #[test]
    fn rejects_cross_run_approval() {
        let mut request = request();
        request
            .tool_call
            .as_mut()
            .unwrap()
            .approval
            .as_mut()
            .unwrap()
            .run_id = "run-other".to_owned();
        let report = evaluate(&policy(), &request).unwrap();
        assert!(codes(&report).contains(&FindingCode::ApprovalRunMismatch));
    }

    #[test]
    fn rejects_cross_request_approval() {
        let mut request = request();
        request
            .tool_call
            .as_mut()
            .unwrap()
            .approval
            .as_mut()
            .unwrap()
            .request_id = "request-other".to_owned();
        let report = evaluate(&policy(), &request).unwrap();
        assert!(codes(&report).contains(&FindingCode::ApprovalRequestMismatch));
    }

    #[test]
    fn rejects_cross_tool_approval() {
        let mut request = request();
        request
            .tool_call
            .as_mut()
            .unwrap()
            .approval
            .as_mut()
            .unwrap()
            .tool = "delete_database".to_owned();
        let report = evaluate(&policy(), &request).unwrap();
        assert!(codes(&report).contains(&FindingCode::ApprovalToolMismatch));
    }

    #[test]
    fn rejects_argument_substitution() {
        let mut request = request();
        request.tool_call.as_mut().unwrap().arguments = json!({"environment": "production"});
        let report = evaluate(&policy(), &request).unwrap();
        assert!(codes(&report).contains(&FindingCode::ApprovalArgumentsMismatch));
    }

    #[test]
    fn rejects_expired_approval() {
        let mut request = request();
        request.received_at_unix = 1_100;
        let report = evaluate(&policy(), &request).unwrap();
        assert!(codes(&report).contains(&FindingCode::ApprovalExpired));
    }

    #[test]
    fn accepts_expiry_within_clock_skew() {
        let mut request = request();
        request.received_at_unix = 1_055;
        assert_eq!(
            evaluate(&policy(), &request).unwrap().decision,
            Decision::Allow
        );
    }

    #[test]
    fn rejects_future_issued_approval() {
        let mut request = request();
        request
            .tool_call
            .as_mut()
            .unwrap()
            .approval
            .as_mut()
            .unwrap()
            .issued_at_unix = 1_006;
        let report = evaluate(&policy(), &request).unwrap();
        assert!(codes(&report).contains(&FindingCode::ApprovalIssuedInFuture));
    }

    #[test]
    fn rejects_overbroad_approval_window() {
        let mut request = request();
        request
            .tool_call
            .as_mut()
            .unwrap()
            .approval
            .as_mut()
            .unwrap()
            .expires_at_unix = 1_300;
        let report = evaluate(&policy(), &request).unwrap();
        assert!(codes(&report).contains(&FindingCode::ApprovalWindowTooLong));
    }

    #[test]
    fn canonical_digest_ignores_object_key_order() {
        let left = json!({"b": 2, "a": {"z": true, "x": null}});
        let right = json!({"a": {"x": null, "z": true}, "b": 2});
        assert_eq!(canonical_json_sha256(&left), canonical_json_sha256(&right));
    }

    #[test]
    fn canonical_digest_preserves_array_order() {
        assert_ne!(
            canonical_json_sha256(&json!([1, 2])),
            canonical_json_sha256(&json!([2, 1]))
        );
    }

    #[test]
    fn policy_rejects_invalid_origin_allowlist() {
        let mut policy = policy();
        policy.allowed_origins = vec!["https://example.test/path".to_owned()];
        assert!(policy.validate().is_err());
    }

    #[test]
    fn policy_requires_host_allowlist() {
        let mut policy = policy();
        policy.allowed_hosts.clear();
        assert!(policy.validate().is_err());
    }
}
