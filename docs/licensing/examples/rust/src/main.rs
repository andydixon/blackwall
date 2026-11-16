// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025-2026 Andy Dixon

use chrono::{DateTime, Utc};
use reqwest::blocking::Client;
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Read;
use std::net::IpAddr;
use std::process;
use std::str::FromStr;
use std::time::Duration;

const VERIFY_URL: &str = "https://blackwall.cx/licences/v1/verify";
const EXPECTED_ISSUER: &str = "https://blackwall.cx";
const MAX_LICENCE_BYTES: usize = 16 * 1024;
const MAX_RESPONSE_BYTES: u64 = 64 * 1024;

#[derive(Serialize)]
struct VerificationRequest<'a> {
    licence: &'a str,
    expected_hostname: &'a str,
    project_uuid: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerificationResponse {
    valid: bool,
    code: String,
    checked_at: String,
    claims: Option<Claims>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Claims {
    v: u8,
    licence_id: String,
    iss: String,
    aud: String,
    project_uuid: String,
    entity: Entity,
    hostnames: Vec<String>,
    features: Vec<String>,
    max_instances: u64,
    iat: i64,
    nbf: i64,
    exp: i64,
    kid: String,
    status_url: String,
    online_check_seconds: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entity {
    #[serde(rename = "type")]
    entity_type: String,
    name: String,
    #[serde(default)]
    reference: String,
}

fn main() {
    if let Err(message) = run() {
        eprintln!("invalid: {message}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let arguments: Vec<String> = std::env::args().collect();
    if arguments.len() != 4 {
        return Err("usage: cargo run -- <licence-file> <hostname> <project-uuid>".into());
    }
    let licence = fs::read_to_string(&arguments[1])
        .map_err(|error| format!("read licence: {error}"))?
        .trim()
        .to_owned();
    if licence.is_empty() || licence.len() > MAX_LICENCE_BYTES {
        return Err("licence file is empty or too large".into());
    }
    let hostname = normalise_hostname(&arguments[2])?;
    let project_uuid = arguments[3].to_ascii_lowercase();

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(5))
        .redirect(Policy::none())
        .https_only(true)
        .build()
        .map_err(|error| format!("create HTTP client: {error}"))?;
    let response = client
        .post(VERIFY_URL)
        .header("Accept", "application/json")
        .json(&VerificationRequest {
            licence: &licence,
            expected_hostname: &hostname,
            project_uuid: &project_uuid,
        })
        .send()
        .map_err(|error| format!("verification request failed: {error}"))?;
    if response.status().as_u16() != 200 {
        return Err(format!(
            "verification service returned HTTP {}",
            response.status()
        ));
    }
    let mut body = Vec::new();
    response
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|error| format!("read verification response: {error}"))?;
    if body.len() as u64 > MAX_RESPONSE_BYTES {
        return Err("verification response was too large".into());
    }
    let result: VerificationResponse =
        serde_json::from_slice(&body).map_err(|error| format!("invalid response JSON: {error}"))?;
    if !result.valid || result.code != "valid" {
        return Err(format!("licence rejected: {}", result.code));
    }
    let claims = result.claims.ok_or("valid response omitted claims")?;
    let checked_at = DateTime::parse_from_rfc3339(&result.checked_at)
        .map_err(|_| "invalid checked_at timestamp")?
        .with_timezone(&Utc);
    let now = Utc::now();
    if (now - checked_at).num_seconds().abs() > 300
        || claims.v != 1
        || claims.iss != EXPECTED_ISSUER
        || claims.aud != "blackwall-licence"
        || claims.project_uuid != project_uuid
        || !claims.hostnames.iter().any(|value| value == &hostname)
        || now.timestamp() + 120 < claims.nbf
        || now.timestamp() - 120 > claims.exp
    {
        return Err("verified response did not match the local policy".into());
    }
    // The remaining fields are intentionally deserialised under
    // deny_unknown_fields so a protocol change fails closed.
    let _policy_fields = (
        &claims.entity.entity_type,
        &claims.entity.name,
        &claims.entity.reference,
        &claims.features,
        claims.max_instances,
        claims.iat,
        &claims.kid,
        &claims.status_url,
        claims.online_check_seconds,
    );
    println!("valid licence {}", claims.licence_id);
    Ok(())
}

fn normalise_hostname(raw: &str) -> Result<String, String> {
    let host = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host.len() > 253 || !host.is_ascii() {
        return Err("invalid hostname".into());
    }
    if let Ok(address) = IpAddr::from_str(&host) {
        return Ok(address.to_string());
    }
    if host.contains([':', '*', '/', '\\', '@', '?', '#', '%']) {
        return Err("ports, URLs, and wildcards are not allowed".into());
    }
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        {
            return Err("invalid DNS hostname".into());
        }
    }
    Ok(host)
}
