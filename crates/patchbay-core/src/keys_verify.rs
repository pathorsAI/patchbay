//! Provider-aware verification for the key vault.
//!
//! `pb key list` can only tell you what you told it. This module asks the
//! issuer: is this token still alive, what can it do, when does it die? For the
//! providers it knows, the answer comes back authoritative, and the registry
//! updates itself from it.
//!
//! **Secret handling.** The value is pulled from the keystore, put in exactly
//! one place — the `Authorization` header of the outbound request, or of the
//! second one where a provider needs asking twice — and dropped. It is never
//! in a URL, a query string, a log line, an error, or the returned outcome. [`KeyVerifyOutcome`] carries a verdict and nothing else,
//! which is why the MCP `verify_key` tool is *not* gated behind
//! `PATCHBAY_ALLOW_SECRET_READ`: there is nothing in it to leak.
//!
//! **Tests never reach the network.** Everything goes through [`HttpClient`];
//! the tests hand [`verify_key_with`] a [`StubHttp`] and assert on the mapping
//! from real captured response shapes to outcomes.

use std::collections::BTreeMap;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::keys::KeyEntry;

/// How long to wait for a provider before giving up. Verification is something
/// a human is watching, so this is short on purpose.
const TIMEOUT: Duration = Duration::from_secs(5);

/// Sent on every request. GitHub rejects requests without a User-Agent, and it
/// is the polite thing to do everywhere else.
const USER_AGENT: &str = concat!("patchbay/", env!("CARGO_PKG_VERSION"));

// ---------------------------------------------------------------------------
// outcome
// ---------------------------------------------------------------------------

/// The verdict. Deliberately more than a boolean: "we could not ask" and "the
/// provider says it is dead" are different facts, and conflating them is how a
/// flaky wifi connection gets someone to rotate a perfectly good token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyVerifyStatus {
    /// The issuer confirms the key works right now.
    Valid,
    /// The issuer rejected it: revoked, deleted, disabled, or never real.
    Invalid,
    /// The issuer knows the key but its lifetime is over.
    Expired,
    /// The provider answered, and its answer does not separate a dead key from
    /// a live one whose permissions are too narrow to prove it. Every check
    /// patchbay could make came back the same for both.
    Inconclusive,
    /// patchbay has no verification path for this provider.
    Unsupported,
    /// The provider could not be reached. Says nothing about the key.
    Unreachable,
}

impl KeyVerifyStatus {
    /// Whether this verdict is bad news about the key itself. `Unsupported`,
    /// `Inconclusive` and `Unreachable` are not: they are patchbay failing to
    /// answer, not the key failing to work.
    pub fn is_bad_news(&self) -> bool {
        matches!(self, Self::Invalid | Self::Expired)
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Invalid => "invalid",
            Self::Expired => "expired",
            Self::Inconclusive => "inconclusive",
            Self::Unsupported => "unsupported",
            Self::Unreachable => "unreachable",
        }
    }
}

/// What the issuer said. Never contains the secret.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyVerifyOutcome {
    pub status: KeyVerifyStatus,
    /// One line, safe to print: the provider's own message where there is one.
    pub detail: String,
    /// Expiry as the *issuer* reports it, which beats whatever the user typed
    /// at registration time. `None` when the provider did not say.
    pub expires_at: Option<DateTime<Utc>>,
    /// Scopes as the issuer reports them. Empty when the provider's verify
    /// endpoint does not enumerate them.
    pub scopes: Vec<String>,
}

impl KeyVerifyOutcome {
    fn new(status: KeyVerifyStatus, detail: impl Into<String>) -> Self {
        Self {
            status,
            detail: detail.into(),
            expires_at: None,
            scopes: Vec::new(),
        }
    }

    fn expires_at(mut self, at: Option<DateTime<Utc>>) -> Self {
        self.expires_at = at;
        self
    }

    fn scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }
}

// ---------------------------------------------------------------------------
// http seam
// ---------------------------------------------------------------------------

/// One HTTP response, reduced to what a verifier needs.
#[derive(Debug, Clone, Default)]
pub struct HttpResponse {
    pub status: u16,
    /// Header names are lower-cased on the way in, so lookups are case-safe.
    headers: BTreeMap<String, String>,
    pub body: String,
}

impl HttpResponse {
    pub fn new(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            headers: BTreeMap::new(),
            body: body.into(),
        }
    }

    pub fn with_header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.insert(name.to_ascii_lowercase(), value.into());
        self
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(|s| s.as_str())
    }
}

/// The seam that keeps the network out of the test suite.
pub trait HttpClient: Send + Sync {
    /// GET `url` with `headers`. `Err` is a transport failure (DNS, TLS,
    /// timeout, refused) — an HTTP error *status* is a normal `Ok`, because to
    /// a verifier a 401 is an answer, not a failure.
    ///
    /// Implementations must never log the headers: one of them is the secret.
    fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<HttpResponse, String>;
}

/// The real client: `ureq` over rustls. Blocking, because patchbay-core is.
pub struct UreqClient {
    agent: ureq::Agent,
}

impl UreqClient {
    pub fn new() -> Self {
        Self {
            agent: ureq::Agent::config_builder()
                .timeout_global(Some(TIMEOUT))
                // A 401 is the answer to "is this token good", not an error.
                .http_status_as_error(false)
                .user_agent(USER_AGENT)
                .build()
                .new_agent(),
        }
    }
}

impl Default for UreqClient {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpClient for UreqClient {
    fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<HttpResponse, String> {
        let mut request = self.agent.get(url);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        // The error is stringified WITHOUT the request: ureq's Display for an
        // error does not include headers, and we do not add them.
        let mut response = request.call().map_err(|e| e.to_string())?;

        let status = response.status().as_u16();
        let mut out = HttpResponse::new(status, String::new());
        for (name, value) in response.headers().iter() {
            if let Ok(value) = value.to_str() {
                out = out.with_header(name.as_str(), value);
            }
        }
        out.body = response
            .body_mut()
            .read_to_string()
            .map_err(|e| format!("could not read the response body: {e}"))?;
        Ok(out)
    }
}

/// One recorded request: the URL, and the headers it was sent with.
type SeenRequest = (String, Vec<(String, String)>);

/// Test double. Returns a canned response (or a canned transport failure) and
/// records what it was asked for, so a test can assert the secret went into the
/// header and never into the URL.
#[derive(Debug, Default)]
pub struct StubHttp {
    response: Option<HttpResponse>,
    queue: std::sync::Mutex<std::collections::VecDeque<HttpResponse>>,
    failure: Option<String>,
    seen: std::sync::Mutex<Vec<SeenRequest>>,
}

impl StubHttp {
    pub fn responding(response: HttpResponse) -> Self {
        Self {
            response: Some(response),
            ..Self::default()
        }
    }

    /// Answer each call from a queue, in order. For the verifiers that ask a
    /// second question when the first answer is not a verdict: the responses
    /// have to differ per call, and by URL is not enough — the same URL can be
    /// asked twice.
    pub fn responding_in_turn(responses: Vec<HttpResponse>) -> Self {
        Self {
            queue: std::sync::Mutex::new(responses.into()),
            ..Self::default()
        }
    }

    pub fn failing(detail: impl Into<String>) -> Self {
        Self {
            failure: Some(detail.into()),
            ..Self::default()
        }
    }

    /// The last URL requested.
    pub fn last_url(&self) -> Option<String> {
        self.seen.lock().unwrap().last().map(|(u, _)| u.clone())
    }

    /// Every URL requested, in order.
    pub fn urls(&self) -> Vec<String> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .map(|(u, _)| u.clone())
            .collect()
    }

    /// The last request's headers.
    pub fn last_headers(&self) -> Vec<(String, String)> {
        self.seen
            .lock()
            .unwrap()
            .last()
            .map(|(_, h)| h.clone())
            .unwrap_or_default()
    }

    pub fn call_count(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

impl HttpClient for StubHttp {
    fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<HttpResponse, String> {
        self.seen.lock().unwrap().push((
            url.to_string(),
            headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        ));
        if let Some(response) = self.queue.lock().unwrap().pop_front() {
            return Ok(response);
        }
        match (&self.failure, &self.response) {
            (Some(detail), _) => Err(detail.clone()),
            (None, Some(response)) => Ok(response.clone()),
            (None, None) => Err("stub has nothing to return".to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// entry points
// ---------------------------------------------------------------------------

/// Ask the issuer about a key, over the real network.
pub fn verify_key(entry: &KeyEntry, secret: &str) -> KeyVerifyOutcome {
    verify_key_with(entry, secret, &UreqClient::new())
}

/// [`verify_key`] against an injected client. This is what the tests call.
pub fn verify_key_with(entry: &KeyEntry, secret: &str, http: &dyn HttpClient) -> KeyVerifyOutcome {
    match normalize_provider(&entry.provider) {
        Some(Provider::Cloudflare) => cloudflare(secret, http),
        Some(Provider::Github) => github(secret, http),
        Some(Provider::Grafana) => grafana(entry, secret, http),
        None => KeyVerifyOutcome::new(
            KeyVerifyStatus::Unsupported,
            format!(
                "patchbay cannot verify `{}` keys yet — it knows how to ask Cloudflare, GitHub \
                 and Grafana, and nothing else. Check this one in the provider's dashboard.",
                entry.provider
            ),
        ),
    }
}

/// Providers patchbay can interrogate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Provider {
    Cloudflare,
    Github,
    Grafana,
}

/// Accept the spellings people actually type.
fn normalize_provider(provider: &str) -> Option<Provider> {
    match provider.trim().to_ascii_lowercase().as_str() {
        "cloudflare" | "cf" => Some(Provider::Cloudflare),
        "github" | "gh" => Some(Provider::Github),
        "grafana" => Some(Provider::Grafana),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// cloudflare
// ---------------------------------------------------------------------------

const CLOUDFLARE_VERIFY: &str = "https://api.cloudflare.com/client/v4/user/tokens/verify";

/// The second question, asked when the first one refuses to answer. One page of
/// one account is the smallest authenticated read on the API, and the point is
/// the HTTP status, not the list.
const CLOUDFLARE_ACCOUNTS: &str = "https://api.cloudflare.com/client/v4/accounts?per_page=1";

#[derive(Debug, Deserialize)]
struct CfEnvelope {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    result: Option<CfResult>,
    #[serde(default)]
    errors: Vec<CfMessage>,
    #[serde(default)]
    messages: Vec<CfMessage>,
}

#[derive(Debug, Deserialize)]
struct CfResult {
    #[serde(default)]
    status: String,
    #[serde(default)]
    expires_on: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
struct CfMessage {
    #[serde(default)]
    message: String,
}

/// The envelope reduced to its verdict flag, for the calls where the payload
/// shape is beside the point.
#[derive(Debug, Deserialize)]
struct CfSuccess {
    #[serde(default)]
    success: bool,
}

fn cloudflare(secret: &str, http: &dyn HttpClient) -> KeyVerifyOutcome {
    let bearer = format!("Bearer {secret}");
    let response = match http.get(
        CLOUDFLARE_VERIFY,
        &[("Authorization", &bearer), ("Accept", "application/json")],
    ) {
        Ok(response) => response,
        Err(detail) => return unreachable_outcome("Cloudflare", &detail),
    };

    let envelope: CfEnvelope = match serde_json::from_str(&response.body) {
        Ok(envelope) => envelope,
        Err(e) => {
            return KeyVerifyOutcome::new(
                KeyVerifyStatus::Unreachable,
                format!(
                "Cloudflare answered HTTP {} with something that is not the expected JSON ({e})",
                response.status
            ),
            )
        }
    };

    let first = |list: &[CfMessage]| {
        list.iter()
            .map(|m| m.message.trim())
            .find(|m| !m.is_empty())
            .map(|m| m.to_string())
    };

    // The token's own status is the authority when Cloudflare reports one;
    // otherwise the HTTP status and the errors array carry the verdict.
    if let Some(result) = envelope.result.filter(|_| envelope.success) {
        let detail = first(&envelope.messages)
            .unwrap_or_else(|| format!("Cloudflare reports the token as {}", result.status));
        let status = match result.status.as_str() {
            "active" => KeyVerifyStatus::Valid,
            "expired" => KeyVerifyStatus::Expired,
            // "disabled", and anything Cloudflare adds later: present but not
            // usable, which is the user's problem to fix, not a patchbay gap.
            _ => KeyVerifyStatus::Invalid,
        };
        // Cloudflare's verify endpoint reports liveness, not policies, so
        // scopes stay empty here by design rather than by omission.
        return KeyVerifyOutcome::new(status, detail).expires_at(result.expires_on);
    }

    let detail = first(&envelope.errors)
        .unwrap_or_else(|| format!("Cloudflare rejected the token (HTTP {})", response.status));
    match response.status {
        // 400 and 401 are both how Cloudflare says "no" — a bad token is a
        // malformed request to it — but "no" here is not the same as "dead":
        // the endpoint only speaks for user-owned tokens, so ask again.
        400 | 401 | 403 => cloudflare_scoped(secret, http, &detail),
        429 => KeyVerifyOutcome::new(
            KeyVerifyStatus::Unreachable,
            format!("Cloudflare rate-limited the check ({detail}); try again shortly"),
        ),
        500..=599 => KeyVerifyOutcome::new(
            KeyVerifyStatus::Unreachable,
            format!("Cloudflare returned HTTP {} ({detail})", response.status),
        ),
        _ => KeyVerifyOutcome::new(KeyVerifyStatus::Invalid, detail),
    }
}

/// Re-ask the question a token-verify rejection cannot answer.
///
/// `/user/tokens/verify` only speaks for tokens owned by a *user*. Hand it an
/// account-owned or scoped token — which is what the Cloudflare dashboard
/// mostly issues now, and what an R2 or Workers token is — and it returns
/// `success: false` with error 1000 "Invalid API Token" while the token is
/// happily deploying in production. Byte for byte the same body a revoked token
/// gets, so the first answer has to be re-asked as something a scoped token can
/// answer: can it read anything at all?
///
/// A 200 is proof of life. Anything else leaves the two cases genuinely
/// indistinguishable — a token scoped to, say, R2 alone cannot list accounts
/// either — and `Inconclusive` says that instead of picking the answer that
/// gets a working key rotated.
fn cloudflare_scoped(secret: &str, http: &dyn HttpClient, rejection: &str) -> KeyVerifyOutcome {
    let bearer = format!("Bearer {secret}");
    let response = match http.get(
        CLOUDFLARE_ACCOUNTS,
        &[("Authorization", &bearer), ("Accept", "application/json")],
    ) {
        Ok(response) => response,
        Err(detail) => return unreachable_outcome("Cloudflare", &detail),
    };

    match response.status {
        // Cloudflare wraps every answer of its own; a 200 carrying anything
        // else came from something in the path, not from the API, and proves
        // nothing about the token.
        200 if cloudflare_succeeded(&response.body) => KeyVerifyOutcome::new(
            KeyVerifyStatus::Valid,
            "confirmed by listing accounts with it — Cloudflare's token-verify endpoint \
             only answers for user-owned tokens, and this one is account-owned or scoped"
                .to_string(),
        ),
        200 => KeyVerifyOutcome::new(
            KeyVerifyStatus::Unreachable,
            "Cloudflare answered HTTP 200 with something that is not its own JSON envelope"
                .to_string(),
        ),
        429 => KeyVerifyOutcome::new(
            KeyVerifyStatus::Unreachable,
            format!("Cloudflare rate-limited the check ({rejection}); try again shortly"),
        ),
        500..=599 => KeyVerifyOutcome::new(
            KeyVerifyStatus::Unreachable,
            format!("Cloudflare returned HTTP {} ({rejection})", response.status),
        ),
        _ => KeyVerifyOutcome::new(
            KeyVerifyStatus::Inconclusive,
            format!(
                "Cloudflare said `{rejection}` to both checks patchbay can make, and a token \
                 scoped to one product answers exactly like a revoked one. Open the token in \
                 the dashboard, or run the command that uses it — patchbay cannot tell these \
                 two apart from here"
            ),
        ),
    }
}

/// Whether a body is Cloudflare's own envelope reporting success. Read through
/// its own struct because `result` is a list here and an object on the verify
/// endpoint, and only the flag matters.
fn cloudflare_succeeded(body: &str) -> bool {
    serde_json::from_str::<CfSuccess>(body).is_ok_and(|envelope| envelope.success)
}

// ---------------------------------------------------------------------------
// github
// ---------------------------------------------------------------------------

const GITHUB_USER: &str = "https://api.github.com/user";

#[derive(Debug, Deserialize)]
struct GhUser {
    #[serde(default)]
    login: String,
}

#[derive(Debug, Deserialize)]
struct GhError {
    #[serde(default)]
    message: String,
}

fn github(secret: &str, http: &dyn HttpClient) -> KeyVerifyOutcome {
    // A GitHub App's private key is a PEM, not a bearer token: `/user` can only
    // ever answer "Bad credentials" to it, which reads as a dead key when the
    // key is fine. There is no request worth spending here — verifying an App
    // means signing a JWT with this PEM and presenting it as the app, and the
    // registry has no app id to sign for.
    if is_pem(secret) {
        return KeyVerifyOutcome::new(
            KeyVerifyStatus::Unsupported,
            "this is a PEM private key, not a token GitHub's API will authenticate. A GitHub \
             App key is verified by minting a JWT with it, which needs the app id patchbay \
             does not have — so patchbay has no way to ask. Check it under the App's settings."
                .to_string(),
        );
    }

    let bearer = format!("Bearer {secret}");
    let response = match http.get(
        GITHUB_USER,
        &[
            ("Authorization", &bearer),
            ("Accept", "application/vnd.github+json"),
            ("X-GitHub-Api-Version", "2022-11-28"),
        ],
    ) {
        Ok(response) => response,
        Err(detail) => return unreachable_outcome("GitHub", &detail),
    };

    match response.status {
        200 => {
            // Classic PATs list their grants in a header; fine-grained tokens
            // send the header empty, which is a real answer (their permissions
            // are per-repository and not enumerable here), not a missing one.
            let scopes = response
                .header("x-oauth-scopes")
                .map(parse_scopes)
                .unwrap_or_default();
            // Only PATs with an expiry send this, in GitHub's own format.
            let expires_at = response
                .header("github-authentication-token-expiration")
                .and_then(parse_github_expiry);

            let login = serde_json::from_str::<GhUser>(&response.body)
                .map(|u| u.login)
                .unwrap_or_default();
            let detail = if login.is_empty() {
                "GitHub accepted the token".to_string()
            } else {
                format!("GitHub accepts it as {login}")
            };
            KeyVerifyOutcome::new(KeyVerifyStatus::Valid, detail)
                .expires_at(expires_at)
                .scopes(scopes)
        }
        401 => {
            let detail = serde_json::from_str::<GhError>(&response.body)
                .map(|e| e.message)
                .ok()
                .filter(|m| !m.trim().is_empty())
                .unwrap_or_else(|| "GitHub rejected the token".to_string());
            KeyVerifyOutcome::new(KeyVerifyStatus::Invalid, detail)
        }
        403 => KeyVerifyOutcome::new(
            KeyVerifyStatus::Invalid,
            "GitHub returned 403: the token is real but blocked (SSO not authorised, \
             or the token has no access here)"
                .to_string(),
        ),
        429 => KeyVerifyOutcome::new(
            KeyVerifyStatus::Unreachable,
            "GitHub rate-limited the check; try again shortly".to_string(),
        ),
        status => KeyVerifyOutcome::new(
            KeyVerifyStatus::Unreachable,
            format!("GitHub returned an unexpected HTTP {status}"),
        ),
    }
}

/// Whether a value is PEM armour rather than a token.
///
/// Shape only — the value is read, never reported. RFC 7468 armour always opens
/// with `-----BEGIN`, and no issuer hands out a token that starts that way, so
/// there is nothing to be clever about here.
fn is_pem(secret: &str) -> bool {
    secret.trim_start().starts_with("-----BEGIN")
}

/// `"repo, workflow, read:org"` -> three scopes. An empty header is an empty
/// list, not a failure.
fn parse_scopes(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// GitHub sends `2026-08-01 00:00:00 UTC`, which is nobody's standard.
fn parse_github_expiry(raw: &str) -> Option<DateTime<Utc>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    crate::util::parse_timestamp(trimmed.trim_end_matches(" UTC"))
}

// ---------------------------------------------------------------------------
// grafana
// ---------------------------------------------------------------------------

/// Cheapest authenticated endpoint that proves a token belongs to an org.
/// `/api/org` needs no permissions beyond being a valid token for the instance,
/// and its response names the org, which is what a human needs to tell two
/// instances apart.
const GRAFANA_ORG_PATH: &str = "/api/org";

#[derive(Debug, Deserialize)]
struct GrafanaOrg {
    #[serde(default)]
    name: String,
}

#[derive(Debug, Deserialize)]
struct GrafanaError {
    #[serde(default)]
    message: String,
}

/// Unlike Cloudflare and GitHub, there is no one address to ask: a Grafana
/// token is only meaningful against the instance that issued it, which is why
/// [`KeyEntry::endpoint`] exists.
fn grafana(entry: &KeyEntry, secret: &str, http: &dyn HttpClient) -> KeyVerifyOutcome {
    let Some(endpoint) = entry
        .endpoint
        .as_deref()
        .map(str::trim)
        .filter(|e| !e.is_empty())
    else {
        return KeyVerifyOutcome::new(
            KeyVerifyStatus::Unsupported,
            "grafana verification needs --endpoint: a token is only valid against the instance \
             that issued it, and patchbay has no address to ask. Re-register this key with \
             `pb key add <id> --provider grafana --endpoint https://<your>.grafana.net \
             --overwrite`, or set it on the existing entry."
                .to_string(),
        );
    };
    // A bare hostname would be sent as a relative URL; refuse rather than
    // guess a scheme, and never echo a secret in the message.
    if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
        return KeyVerifyOutcome::new(
            KeyVerifyStatus::Unsupported,
            format!(
                "`{endpoint}` is not a URL patchbay can call; the endpoint needs a scheme, \
                 e.g. https://{endpoint}"
            ),
        );
    }

    let url = format!("{}{GRAFANA_ORG_PATH}", endpoint.trim_end_matches('/'));
    let bearer = format!("Bearer {secret}");
    let response = match http.get(
        &url,
        &[("Authorization", &bearer), ("Accept", "application/json")],
    ) {
        Ok(response) => response,
        Err(detail) => return unreachable_outcome("Grafana", &detail),
    };

    match response.status {
        200 => {
            // A 200 is NOT enough on its own. Point the endpoint at a dashboard
            // URL instead of the instance root and Grafana Cloud serves its
            // single-page app — HTML, HTTP 200 — for `/api/org` too. Treating
            // that as success reports a dead token as live, which is the single
            // worst answer this function can give. Verified against a real
            // instance; the body has to parse as the object we asked for.
            let Ok(org) = serde_json::from_str::<GrafanaOrg>(&response.body) else {
                return KeyVerifyOutcome::new(
                    KeyVerifyStatus::Unreachable,
                    format!(
                        "{url} returned HTTP 200 but not the JSON a Grafana API returns — \
                         the endpoint is probably not the instance root. It should be the \
                         bare origin, e.g. https://<you>.grafana.net, with no path."
                    ),
                );
            };
            let detail = if org.name.trim().is_empty() {
                format!("{endpoint} accepted the token")
            } else {
                format!("{endpoint} accepts it for org `{}`", org.name.trim())
            };
            // Grafana's service-account tokens carry a role, not a scope list,
            // and /api/org does not report it; leaving scopes empty is honest.
            KeyVerifyOutcome::new(KeyVerifyStatus::Valid, detail)
        }
        401 | 403 => {
            let detail = serde_json::from_str::<GrafanaError>(&response.body)
                .map(|e| e.message)
                .ok()
                .filter(|m| !m.trim().is_empty())
                .unwrap_or_else(|| format!("{endpoint} rejected the token"));
            KeyVerifyOutcome::new(KeyVerifyStatus::Invalid, detail)
        }
        404 => KeyVerifyOutcome::new(
            KeyVerifyStatus::Unreachable,
            format!(
                "{url} returned 404 — that address does not look like a Grafana API. \
                 Check the endpoint is the instance root, not a dashboard URL."
            ),
        ),
        429 => KeyVerifyOutcome::new(
            KeyVerifyStatus::Unreachable,
            format!("{endpoint} rate-limited the check; try again shortly"),
        ),
        status => KeyVerifyOutcome::new(
            KeyVerifyStatus::Unreachable,
            format!("{endpoint} returned an unexpected HTTP {status}"),
        ),
    }
}

/// A transport failure. Phrased so nobody reads it as "your key is dead".
fn unreachable_outcome(provider: &str, detail: &str) -> KeyVerifyOutcome {
    KeyVerifyOutcome::new(
        KeyVerifyStatus::Unreachable,
        format!(
            "could not reach {provider} ({detail}) — this says nothing about the key, \
             only about the connection"
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(provider: &str) -> KeyEntry {
        KeyEntry {
            id: "k".into(),
            provider: provider.into(),
            label: "k".into(),
            purpose: None,
            scopes: vec![],
            created_at: Utc::now(),
            expires_at: None,
            last4: "1234".into(),
            source: "cli".into(),
            endpoint: None,
            env: None,
        }
    }

    fn entry_at(provider: &str, endpoint: &str) -> KeyEntry {
        KeyEntry {
            endpoint: Some(endpoint.to_string()),
            ..entry(provider)
        }
    }

    // --- cloudflare ---------------------------------------------------------

    /// The real shape of a good answer, from Cloudflare's docs.
    const CF_ACTIVE: &str = r#"{
      "result": { "id": "ed17574386854bf78a67040be0a770b0", "status": "active",
                  "expires_on": "2027-01-01T00:00:00Z" },
      "success": true, "errors": [],
      "messages": [{ "code": 10000, "message": "This API Token is valid and active" }]
    }"#;

    /// What a wrong token really gets back: HTTP 400, success false. Also,
    /// exactly, what a live account-owned token gets back from `/user/tokens/
    /// verify` — which is the whole reason the fallback exists.
    const CF_BAD: &str = r#"{
      "result": null, "success": false,
      "errors": [{ "code": 1000, "message": "Invalid API Token" }], "messages": []
    }"#;

    /// One page of one account, trimmed. Only `success` is read.
    const CF_ACCOUNTS: &str = r#"{
      "result": [{ "id": "01a7362d577a6c3019a474fd6f485823", "name": "Pathors" }],
      "success": true, "errors": [], "messages": [],
      "result_info": { "page": 1, "per_page": 1, "count": 1, "total_count": 1 }
    }"#;

    #[test]
    fn test_cloudflare_active_token_is_valid_and_carries_its_expiry() {
        let http = StubHttp::responding(HttpResponse::new(200, CF_ACTIVE));
        let out = verify_key_with(&entry("cloudflare"), "cf-secret", &http);

        assert_eq!(out.status, KeyVerifyStatus::Valid);
        assert_eq!(out.detail, "This API Token is valid and active");
        assert_eq!(
            out.expires_at,
            Some("2027-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap())
        );
        assert!(
            out.scopes.is_empty(),
            "the verify endpoint lists no policies"
        );
        assert_eq!(
            http.call_count(),
            1,
            "a definitive answer must not be second-guessed"
        );
    }

    #[test]
    fn test_cloudflare_sends_the_secret_only_as_a_bearer_header() {
        let http = StubHttp::responding(HttpResponse::new(200, CF_ACTIVE));
        verify_key_with(&entry("cf"), "cf-secret", &http);

        let url = http.last_url().unwrap();
        assert_eq!(url, CLOUDFLARE_VERIFY);
        assert!(
            !url.contains("cf-secret"),
            "the secret must never reach the URL"
        );
        let headers = http.last_headers();
        let auth = headers.iter().find(|(k, _)| k == "Authorization").unwrap();
        assert_eq!(auth.1, "Bearer cf-secret");
    }

    #[test]
    fn test_cloudflare_account_scoped_token_rejected_by_verify_is_valid_if_it_can_list_accounts() {
        // Observed on real keys: an R2 token and an account API token, both in
        // daily use, both told "Invalid API Token" by /user/tokens/verify.
        let http = StubHttp::responding_in_turn(vec![
            HttpResponse::new(400, CF_BAD),
            HttpResponse::new(200, CF_ACCOUNTS),
        ]);
        let out = verify_key_with(&entry("cloudflare"), "cf-secret", &http);

        assert_eq!(out.status, KeyVerifyStatus::Valid);
        assert!(!out.status.is_bad_news());
        assert!(
            out.detail.contains("user-owned"),
            "the detail has to explain why the first check said otherwise: {}",
            out.detail
        );
        assert_eq!(http.urls(), vec![CLOUDFLARE_VERIFY, CLOUDFLARE_ACCOUNTS]);
        // Same secret, same one place, on the second request too.
        let headers = http.last_headers();
        let auth = headers.iter().find(|(k, _)| k == "Authorization").unwrap();
        assert_eq!(auth.1, "Bearer cf-secret");
        assert!(!http.last_url().unwrap().contains("cf-secret"));
    }

    #[test]
    fn test_cloudflare_rejected_by_both_checks_is_inconclusive_because_a_revoked_token_and_a_narrowly_scoped_one_are_the_same_response(
    ) {
        // Deliberately undecidable: this is the response a revoked token gets
        // AND the response a live R2-only token gets. Calling it `invalid`
        // would tell someone to rotate a key that is working.
        let http = StubHttp::responding_in_turn(vec![
            HttpResponse::new(400, CF_BAD),
            HttpResponse::new(403, CF_BAD),
        ]);
        let out = verify_key_with(&entry("cloudflare"), "nope", &http);

        assert_eq!(out.status, KeyVerifyStatus::Inconclusive);
        assert!(!out.status.is_bad_news());
        assert_eq!(out.status.label(), "inconclusive");
        assert!(
            out.detail.contains("cannot tell these two apart"),
            "{}",
            out.detail
        );
        assert_eq!(http.call_count(), 2);
    }

    #[test]
    fn test_cloudflare_a_rate_limited_fallback_is_unreachable_not_a_verdict() {
        let http = StubHttp::responding_in_turn(vec![
            HttpResponse::new(401, CF_BAD),
            HttpResponse::new(429, "{}"),
        ]);
        let out = verify_key_with(&entry("cloudflare"), "s", &http);
        assert_eq!(out.status, KeyVerifyStatus::Unreachable);
        assert!(!out.status.is_bad_news());
    }

    #[test]
    fn test_cloudflare_a_200_from_the_fallback_still_has_to_be_cloudflares_own_json() {
        // A captive portal or a proxy answering 200 with HTML proves nothing;
        // reading it as success would report a dead token as live.
        let http = StubHttp::responding_in_turn(vec![
            HttpResponse::new(400, CF_BAD),
            HttpResponse::new(200, "<html>proxy says hello</html>"),
        ]);
        let out = verify_key_with(&entry("cloudflare"), "s", &http);
        assert_eq!(out.status, KeyVerifyStatus::Unreachable);
        assert!(!out.status.is_bad_news());
    }

    #[test]
    fn test_cloudflare_reports_a_user_owned_tokens_own_status_without_a_fallback() {
        // The token's own reported status is definitive in both directions;
        // only a rejection is ambiguous.
        for (body, expected) in [
            (CF_ACTIVE, KeyVerifyStatus::Valid),
            (
                r#"{"result":{"status":"disabled"},"success":true,"errors":[],"messages":[]}"#,
                KeyVerifyStatus::Invalid,
            ),
        ] {
            let http = StubHttp::responding(HttpResponse::new(200, body));
            let out = verify_key_with(&entry("cloudflare"), "s", &http);
            assert_eq!(out.status, expected);
            assert_eq!(http.call_count(), 1);
        }
    }

    #[test]
    fn test_cloudflare_expired_and_disabled_are_told_apart() {
        let expired = r#"{"result":{"status":"expired","expires_on":"2020-01-01T00:00:00Z"},
                          "success":true,"errors":[],"messages":[]}"#;
        let out = verify_key_with(
            &entry("cloudflare"),
            "s",
            &StubHttp::responding(HttpResponse::new(200, expired)),
        );
        assert_eq!(out.status, KeyVerifyStatus::Expired);
        assert!(out.expires_at.is_some());
        assert!(out.detail.contains("expired"), "{}", out.detail);

        let disabled = r#"{"result":{"status":"disabled"},"success":true,
                           "errors":[],"messages":[]}"#;
        let out = verify_key_with(
            &entry("cloudflare"),
            "s",
            &StubHttp::responding(HttpResponse::new(200, disabled)),
        );
        assert_eq!(out.status, KeyVerifyStatus::Invalid);
    }

    #[test]
    fn test_cloudflare_server_error_and_rate_limit_are_not_the_keys_fault() {
        for (status, body) in [(500, "{}"), (429, "{}")] {
            let out = verify_key_with(
                &entry("cloudflare"),
                "s",
                &StubHttp::responding(HttpResponse::new(status, body)),
            );
            assert_eq!(
                out.status,
                KeyVerifyStatus::Unreachable,
                "HTTP {status} should not condemn the key"
            );
            assert!(!out.status.is_bad_news());
        }
    }

    #[test]
    fn test_cloudflare_garbage_body_is_unreachable_not_invalid() {
        let http = StubHttp::responding(HttpResponse::new(200, "<html>proxy error</html>"));
        let out = verify_key_with(&entry("cloudflare"), "s", &http);
        assert_eq!(out.status, KeyVerifyStatus::Unreachable);
    }

    // --- github -------------------------------------------------------------

    #[test]
    fn test_github_valid_token_reports_login_scopes_and_expiry() {
        let http = StubHttp::responding(
            HttpResponse::new(200, r#"{"login":"YJack0000","id":1}"#)
                .with_header("X-OAuth-Scopes", "repo, workflow, read:org")
                .with_header(
                    "github-authentication-token-expiration",
                    "2027-03-01 00:00:00 UTC",
                ),
        );
        let out = verify_key_with(&entry("github"), "ghp_xxx", &http);

        assert_eq!(out.status, KeyVerifyStatus::Valid);
        assert_eq!(out.detail, "GitHub accepts it as YJack0000");
        assert_eq!(out.scopes, vec!["repo", "workflow", "read:org"]);
        assert_eq!(
            out.expires_at,
            Some("2027-03-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap())
        );
    }

    #[test]
    fn test_github_header_lookup_is_case_insensitive() {
        // GitHub's real casing is `X-OAuth-Scopes`; hyper lower-cases it.
        let http = StubHttp::responding(
            HttpResponse::new(200, r#"{"login":"o"}"#).with_header("x-oauth-scopes", "gist"),
        );
        let out = verify_key_with(&entry("gh"), "t", &http);
        assert_eq!(out.scopes, vec!["gist"]);
    }

    #[test]
    fn test_github_fine_grained_token_has_no_scopes_but_is_still_valid() {
        let http = StubHttp::responding(
            HttpResponse::new(200, r#"{"login":"octocat"}"#).with_header("X-OAuth-Scopes", ""),
        );
        let out = verify_key_with(&entry("github"), "github_pat_x", &http);
        assert_eq!(out.status, KeyVerifyStatus::Valid);
        assert!(out.scopes.is_empty());
        assert_eq!(out.expires_at, None);
    }

    #[test]
    fn test_github_app_private_key_is_unsupported_and_never_asks() {
        // Observed on a real key: a GitHub App's PEM registered under
        // `github`, reported `invalid` — "Bad credentials" — while the App was
        // signing CI tokens all day. `/user` has no answer for a PEM, so the
        // request is not worth making.
        let http = StubHttp::failing("should not be called");
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow…\n-----END RSA PRIVATE KEY-----\n";
        let out = verify_key_with(&entry("github"), pem, &http);

        assert_eq!(out.status, KeyVerifyStatus::Unsupported);
        assert!(!out.status.is_bad_news());
        assert!(out.detail.contains("JWT"), "{}", out.detail);
        assert_eq!(http.call_count(), 0, "a PEM must not reach the network");
        assert!(!serde_json::to_string(&out).unwrap().contains("MIIEow"));

        // Leading whitespace from a heredoc or a copy-paste does not disguise
        // it, and an ordinary token still takes the request path.
        let out = verify_key_with(&entry("gh"), &format!("\n  {pem}"), &http);
        assert_eq!(out.status, KeyVerifyStatus::Unsupported);
        assert_eq!(http.call_count(), 0);

        let http = StubHttp::responding(HttpResponse::new(200, r#"{"login":"octocat"}"#));
        let out = verify_key_with(&entry("github"), "ghp_ordinary_token", &http);
        assert_eq!(out.status, KeyVerifyStatus::Valid);
        assert_eq!(http.call_count(), 1);
    }

    #[test]
    fn test_github_401_is_invalid_with_githubs_message() {
        let http = StubHttp::responding(HttpResponse::new(
            401,
            r#"{"message":"Bad credentials","status":"401"}"#,
        ));
        let out = verify_key_with(&entry("github"), "bad", &http);
        assert_eq!(out.status, KeyVerifyStatus::Invalid);
        assert_eq!(out.detail, "Bad credentials");
    }

    #[test]
    fn test_github_403_is_invalid_and_explains_sso() {
        let out = verify_key_with(
            &entry("github"),
            "t",
            &StubHttp::responding(HttpResponse::new(403, "{}")),
        );
        assert_eq!(out.status, KeyVerifyStatus::Invalid);
        assert!(out.detail.contains("SSO"), "{}", out.detail);
    }

    // --- shared -------------------------------------------------------------

    #[test]
    fn test_a_transport_failure_is_unreachable_and_says_so_plainly() {
        let http = StubHttp::failing("dns error: no record found");
        let out = verify_key_with(&entry("cloudflare"), "s", &http);

        assert_eq!(out.status, KeyVerifyStatus::Unreachable);
        assert!(!out.status.is_bad_news());
        assert!(
            out.detail.contains("could not reach Cloudflare"),
            "{}",
            out.detail
        );
        assert!(
            out.detail.contains("says nothing about the key"),
            "{}",
            out.detail
        );
    }

    #[test]
    fn test_an_unknown_provider_is_unsupported_and_never_calls_out() {
        let http = StubHttp::failing("should not be called");
        let out = verify_key_with(&entry("stripe"), "sk_test", &http);

        assert_eq!(out.status, KeyVerifyStatus::Unsupported);
        assert!(out.detail.contains("stripe"), "{}", out.detail);
        assert_eq!(http.call_count(), 0, "unsupported must not make a request");
    }

    // --- grafana ------------------------------------------------------------

    #[test]
    fn test_grafana_valid_token_names_the_org_and_asks_the_right_url() {
        let http = StubHttp::responding(HttpResponse::new(
            200,
            r#"{"id":1,"name":"Pathors","address":{}}"#,
        ));
        let out = verify_key_with(
            &entry_at("grafana", "https://pathors.grafana.net"),
            "glsa_xxx",
            &http,
        );

        assert_eq!(out.status, KeyVerifyStatus::Valid);
        assert_eq!(
            out.detail,
            "https://pathors.grafana.net accepts it for org `Pathors`"
        );
        assert_eq!(
            http.last_url().unwrap(),
            "https://pathors.grafana.net/api/org"
        );
        let headers = http.last_headers();
        let auth = headers.iter().find(|(k, _)| k == "Authorization").unwrap();
        assert_eq!(auth.1, "Bearer glsa_xxx");
        assert!(!http.last_url().unwrap().contains("glsa_xxx"));
    }

    #[test]
    fn test_grafana_endpoint_slashes_do_not_double_up() {
        let http = StubHttp::responding(HttpResponse::new(200, r#"{"name":"Main Org."}"#));
        verify_key_with(
            &entry_at("grafana", "https://self.hosted.example/grafana/"),
            "t",
            &http,
        );
        assert_eq!(
            http.last_url().unwrap(),
            "https://self.hosted.example/grafana/api/org"
        );
    }

    #[test]
    fn test_grafana_without_an_endpoint_is_unsupported_and_says_what_to_do() {
        let http = StubHttp::failing("should not be called");
        let out = verify_key_with(&entry("grafana"), "glsa_xxx", &http);

        assert_eq!(out.status, KeyVerifyStatus::Unsupported);
        assert!(out.detail.contains("--endpoint"), "{}", out.detail);
        assert_eq!(http.call_count(), 0, "no endpoint means no request");

        // An endpoint that is only whitespace is no endpoint at all.
        let out = verify_key_with(&entry_at("grafana", "   "), "t", &http);
        assert_eq!(out.status, KeyVerifyStatus::Unsupported);
        assert_eq!(http.call_count(), 0);
    }

    #[test]
    fn test_grafana_endpoint_without_a_scheme_is_refused_not_guessed() {
        let http = StubHttp::failing("should not be called");
        let out = verify_key_with(&entry_at("grafana", "pathors.grafana.net"), "t", &http);
        assert_eq!(out.status, KeyVerifyStatus::Unsupported);
        assert!(
            out.detail.contains("https://pathors.grafana.net"),
            "{}",
            out.detail
        );
        assert_eq!(http.call_count(), 0);
    }

    #[test]
    fn test_grafana_401_and_403_are_invalid_with_grafanas_message() {
        for status in [401, 403] {
            let out = verify_key_with(
                &entry_at("grafana", "https://x.grafana.net"),
                "bad",
                &StubHttp::responding(HttpResponse::new(
                    status,
                    r#"{"message":"invalid API key"}"#,
                )),
            );
            assert_eq!(out.status, KeyVerifyStatus::Invalid, "HTTP {status}");
            assert_eq!(out.detail, "invalid API key");
        }
    }

    #[test]
    fn test_grafana_404_points_at_the_endpoint_not_the_key() {
        let out = verify_key_with(
            &entry_at("grafana", "https://x.example/dashboards/foo"),
            "t",
            &StubHttp::responding(HttpResponse::new(404, "<html>")),
        );
        assert_eq!(out.status, KeyVerifyStatus::Unreachable);
        assert!(!out.status.is_bad_news());
        assert!(
            out.detail.contains("does not look like a Grafana API"),
            "{}",
            out.detail
        );
    }

    #[test]
    fn test_grafana_html_on_a_200_is_not_a_valid_token() {
        // Found on a real instance: point the endpoint at a dashboard URL and
        // Grafana Cloud serves its SPA for /api/org — HTML, HTTP 200. Reading
        // that as success reports a dead token as live.
        let out = verify_key_with(
            &entry_at("grafana", "https://x.grafana.net/d/some-dashboard"),
            "definitely-not-a-real-token",
            &StubHttp::responding(HttpResponse::new(
                200,
                "<!DOCTYPE html><html><head><title>Grafana</title></head></html>",
            )),
        );
        assert_eq!(out.status, KeyVerifyStatus::Unreachable);
        assert!(!out.status.is_bad_news());
        assert!(out.detail.contains("instance root"), "{}", out.detail);
    }

    #[test]
    fn test_grafana_transport_failure_is_unreachable() {
        let out = verify_key_with(
            &entry_at("grafana", "https://x.grafana.net"),
            "t",
            &StubHttp::failing("connection refused"),
        );
        assert_eq!(out.status, KeyVerifyStatus::Unreachable);
        assert!(
            out.detail.contains("could not reach Grafana"),
            "{}",
            out.detail
        );
    }

    #[test]
    fn test_grafana_outcomes_never_carry_the_secret() {
        let secret = "glsa_super_secret_value";
        let cases = [
            verify_key_with(
                &entry_at("grafana", "https://x.grafana.net"),
                secret,
                &StubHttp::responding(HttpResponse::new(200, r#"{"name":"Org"}"#)),
            ),
            verify_key_with(
                &entry_at("grafana", "https://x.grafana.net"),
                secret,
                &StubHttp::responding(HttpResponse::new(401, r#"{"message":"nope"}"#)),
            ),
            verify_key_with(&entry("grafana"), secret, &StubHttp::failing("boom")),
            verify_key_with(
                &entry_at("grafana", "no-scheme"),
                secret,
                &StubHttp::failing("x"),
            ),
        ];
        for out in cases {
            let json = serde_json::to_string(&out).unwrap();
            assert!(!json.contains(secret), "secret leaked into {json}");
        }
    }

    #[test]
    fn test_provider_spellings_are_normalized() {
        assert_eq!(normalize_provider("Cloudflare"), Some(Provider::Cloudflare));
        assert_eq!(normalize_provider(" CF "), Some(Provider::Cloudflare));
        assert_eq!(normalize_provider("GitHub"), Some(Provider::Github));
        assert_eq!(normalize_provider("gh"), Some(Provider::Github));
        assert_eq!(normalize_provider("Grafana"), Some(Provider::Grafana));
        assert_eq!(normalize_provider(" grafana "), Some(Provider::Grafana));
        assert_eq!(normalize_provider("openai"), None);
    }

    #[test]
    fn test_no_outcome_ever_carries_the_secret() {
        let secret = "super-secret-value";
        let cases = [
            verify_key_with(
                &entry("cloudflare"),
                secret,
                &StubHttp::responding(HttpResponse::new(200, CF_ACTIVE)),
            ),
            verify_key_with(
                &entry("cloudflare"),
                secret,
                &StubHttp::responding(HttpResponse::new(400, CF_BAD)),
            ),
            verify_key_with(&entry("github"), secret, &StubHttp::failing("boom")),
            verify_key_with(&entry("stripe"), secret, &StubHttp::failing("boom")),
        ];
        for out in cases {
            let json = serde_json::to_string(&out).unwrap();
            assert!(!json.contains(secret), "secret leaked into {json}");
        }
    }

    #[test]
    fn test_scope_and_expiry_parsers() {
        assert_eq!(parse_scopes("a, b ,c"), vec!["a", "b", "c"]);
        assert!(parse_scopes("").is_empty());
        assert!(parse_scopes("  ,  ").is_empty());

        assert!(parse_github_expiry("2027-03-01 00:00:00 UTC").is_some());
        assert!(parse_github_expiry("").is_none());
        assert!(parse_github_expiry("never").is_none());
    }

    #[test]
    fn test_status_labels_and_bad_news_split() {
        assert!(KeyVerifyStatus::Invalid.is_bad_news());
        assert!(KeyVerifyStatus::Expired.is_bad_news());
        assert!(!KeyVerifyStatus::Valid.is_bad_news());
        assert!(!KeyVerifyStatus::Unsupported.is_bad_news());
        assert!(!KeyVerifyStatus::Unreachable.is_bad_news());
        assert!(!KeyVerifyStatus::Inconclusive.is_bad_news());
        assert_eq!(KeyVerifyStatus::Unreachable.label(), "unreachable");
        assert_eq!(KeyVerifyStatus::Inconclusive.label(), "inconclusive");
    }
}
