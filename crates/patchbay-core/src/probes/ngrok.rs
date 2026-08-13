//! `ngrok` — the agent's authentication, from `ngrok.yml`.
//!
//! Verified **empirically** against ngrok 3.25.1 on macOS. The v3 agent keeps
//! its config in the platform config directory —
//! `~/Library/Application Support/ngrok/ngrok.yml` here — and `NGROK_CONFIG`
//! overrides it. The v2 location `~/.ngrok2/ngrok.yml` is still read when it is
//! the only one present, because upgrading ngrok does not move the old file.
//!
//! **What counts as a profile.** One: the authenticated agent. Named `tunnels:`
//! (and, in newer builds, `endpoints:`) look like a profile list and are not —
//! they are forwarding rules, all of them belonging to the same account, and
//! showing four tunnels as four logins would be four times wrong. They are
//! reported as names and a count in `meta`.
//!
//! ```yaml
//! version: "3"
//! agent:
//!     authtoken: 2x...           # v3.5+ nests it under `agent`
//! authtoken: 2x...               # earlier v3 kept it at the top level
//! api_key: ak_...                # only needed for the ngrok API
//! tunnels:
//!   web: { proto: http, addr: 8080 }
//! ```
//!
//! **Secret handling.** The `authtoken` and `api_key` are read only to answer
//! *is one set* and, in [`Probe::verify`], to authenticate one request. Neither
//! value reaches a [`ToolStatus`], and there is no last4 hint for them: unlike a
//! vault key, which the user matches against a provider dashboard, an ngrok
//! token has nothing to be matched against, so the last four characters would be
//! leakage that buys nothing.

use serde::Deserialize;

use crate::keys_verify::{HttpClient, UreqClient};
use crate::paths::Paths;
use crate::probe::{unsupported_switch, unsupported_verify, Probe};
use crate::types::{PermissionsReport, Profile, SwitchOutcome, ToolStatus, VerifyOutcome};
use crate::util::{read_text};

/// The ngrok API. Used only when an `api_key` is configured — an `authtoken`
/// authenticates the *agent*, not the API, and cannot be checked this way.
const NGROK_API_INGRESSES: &str = "https://api.ngrok.com/agent_ingresses";
/// ngrok pins its API behind a version header; without it the API 400s.
const NGROK_API_VERSION: &str = "2";

pub struct NgrokProbe {
    paths: Paths,
}

/// Only the fields patchbay needs. No `Deserialize` for anything holding a
/// secret beyond the two token fields, which are read as presence flags.
#[derive(Debug, Default, Deserialize)]
struct Config {
    #[serde(default)]
    version: Option<String>,
    /// v3.5+ nests agent settings; earlier v3 put them at the top level.
    #[serde(default)]
    agent: Option<Agent>,
    #[serde(default)]
    authtoken: Option<String>,
    #[serde(default)]
    api_key: Option<String>,
    /// Forwarding rules, not identities.
    #[serde(default)]
    tunnels: std::collections::BTreeMap<String, serde_yaml_ng::Value>,
    /// The newer spelling of the same idea.
    #[serde(default)]
    endpoints: Vec<serde_yaml_ng::Value>,
}

#[derive(Debug, Default, Deserialize)]
struct Agent {
    #[serde(default)]
    authtoken: Option<String>,
    #[serde(default)]
    api_key: Option<String>,
}

impl Config {
    /// The authtoken, from wherever this version keeps it.
    fn authtoken(&self) -> Option<&str> {
        self.agent
            .as_ref()
            .and_then(|a| a.authtoken.as_deref())
            .or(self.authtoken.as_deref())
            .map(str::trim)
            .filter(|t| !t.is_empty())
    }

    fn api_key(&self) -> Option<&str> {
        self.agent
            .as_ref()
            .and_then(|a| a.api_key.as_deref())
            .or(self.api_key.as_deref())
            .map(str::trim)
            .filter(|k| !k.is_empty())
    }

    /// Named forwarding rules, for `meta`.
    fn tunnel_names(&self) -> Vec<String> {
        self.tunnels.keys().cloned().collect()
    }
}

impl NgrokProbe {
    pub const TOOL: &'static str = "ngrok";
    /// The single profile's id. ngrok has no notion of switching accounts —
    /// one config, one authtoken — so this is an identifier, not a selector.
    const AGENT: &'static str = "agent";

    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }

    /// The config, plus the path it came from.
    fn load(&self) -> (Option<std::path::PathBuf>, Result<Config, String>) {
        let Some(path) = self
            .paths
            .ngrok_candidates()
            .into_iter()
            .find(|p| p.is_file())
        else {
            return (None, Ok(Config::default()));
        };
        let parsed = match read_text(&path) {
            Ok(Some(text)) => serde_yaml_ng::from_str::<Config>(&text)
                .map_err(|e| format!("{} is not valid YAML ({e})", path.display())),
            Ok(None) => Ok(Config::default()),
            Err(e) => Err(e),
        };
        (Some(path), parsed)
    }
}

impl Probe for NgrokProbe {
    fn tool(&self) -> &'static str {
        Self::TOOL
    }

    fn status(&self) -> anyhow::Result<ToolStatus> {
        let (path, parsed) = self.load();
        let installed = self.paths.has_binary("ngrok") || path.is_some();
        let mut status = ToolStatus::empty(Self::TOOL, installed);
        for note in self.paths.path_notes("ngrok") {
            status.note(note);
        }

        let config = match parsed {
            Ok(config) => config,
            Err(e) => {
                status.note(e);
                return Ok(status);
            }
        };
        let Some(path) = path else {
            return Ok(status);
        };

        let authtoken = config.authtoken().is_some();
        let api_key = config.api_key().is_some();
        if !authtoken && !api_key {
            status.note(format!(
                "{} has no authtoken; run `ngrok config add-authtoken <token>`",
                path.display()
            ));
            return Ok(status);
        }

        // One account, however many tunnels are defined.
        let label = match (authtoken, api_key) {
            (true, true) => "ngrok agent (authtoken + api key)",
            (true, false) => "ngrok agent (authtoken)",
            (false, true) => "ngrok api key only",
            (false, false) => unreachable!("checked above"),
        };
        let tunnels = config.tunnel_names();
        status.profiles.push(
            Profile::new(Self::AGENT)
                .label(label)
                .with_meta("authtoken", authtoken)
                .with_meta("api_key", api_key)
                .with_meta("config_version", config.version.clone())
                .with_meta("tunnels", tunnels.len())
                .with_meta("tunnel_names", tunnels.clone())
                .with_meta("endpoints", config.endpoints.len())
                .with_meta("source", path.display().to_string()),
        );
        // An authtoken is what the agent authenticates with; an API key alone
        // cannot start a tunnel, so it is not an active login.
        if authtoken {
            status.active = Some(Self::AGENT.to_string());
        } else {
            status.note(
                "an api_key is set but no authtoken: the ngrok API is reachable, but \
                 `ngrok http …` will refuse to start a tunnel",
            );
        }

        status.note(
            "ngrok authtokens do not expire on a schedule; patchbay cannot tell a live one \
             from a revoked one without `pb verify ngrok`",
        );
        if !tunnels.is_empty() {
            status.note(format!(
                "{} named tunnel{} defined ({}) — forwarding rules on this one account, not \
                 separate logins",
                tunnels.len(),
                if tunnels.len() == 1 { "" } else { "s" },
                tunnels.join(", ")
            ));
        }
        Ok(status)
    }

    fn switch(&self, _profile_id: &str) -> anyhow::Result<SwitchOutcome> {
        Ok(unsupported_switch(
            Self::TOOL,
            "ngrok has one agent config with one authtoken; there is nothing to switch between. \
             Replacing the token is a different operation from selecting a profile",
            Some("ngrok config add-authtoken <token>"),
        ))
    }

    fn verify(&self) -> anyhow::Result<VerifyOutcome> {
        if !self.paths.may_exec() {
            return Ok(unsupported_verify(
                Self::TOOL,
                "verification is disabled in this context",
                Some("ngrok config check"),
            ));
        }
        let (path, parsed) = self.load();
        if path.is_none() {
            return Ok(VerifyOutcome::Invalid {
                tool: Self::TOOL.to_string(),
                detail: "no ngrok config found; run `ngrok config add-authtoken <token>`"
                    .to_string(),
            });
        }
        let config = parsed.map_err(anyhow::Error::msg)?;

        // Tier 2a: the CLI's own validator. No network, and it is the only
        // thing that can judge the whole file rather than the fields patchbay
        // happens to parse.
        let mut details = Vec::new();
        if self.paths.has_binary("ngrok") {
            let out = self.paths.run("ngrok", &["config", "check"])?;
            if !out.ok {
                return Ok(VerifyOutcome::Invalid {
                    tool: Self::TOOL.to_string(),
                    detail: out.message(),
                });
            }
            details.push(out.message());
        } else {
            details.push("the ngrok CLI is not on PATH; config not validated".to_string());
        }

        // Tier 2b: an API key can be checked against the API. An authtoken
        // cannot — it authenticates the agent's tunnel session, and there is no
        // endpoint that will simply confirm one.
        match config.api_key() {
            Some(api_key) => {
                let outcome = check_api_key(api_key, &UreqClient::new());
                details.push(outcome.detail);
                Ok(if outcome.live {
                    VerifyOutcome::Valid {
                        tool: Self::TOOL.to_string(),
                        detail: details.join("; "),
                    }
                } else {
                    VerifyOutcome::Invalid {
                        tool: Self::TOOL.to_string(),
                        detail: details.join("; "),
                    }
                })
            }
            None => {
                details.push(
                    "no api_key is configured, so the authtoken itself was not checked against \
                     ngrok — only the config file was validated"
                        .to_string(),
                );
                Ok(VerifyOutcome::Valid {
                    tool: Self::TOOL.to_string(),
                    detail: details.join("; "),
                })
            }
        }
    }

    fn permissions(&self) -> anyhow::Result<PermissionsReport> {
        Ok(PermissionsReport::unsupported(
            Self::TOOL,
            "ngrok scopes live on the API key in the ngrok dashboard; the agent config records \
             no permissions",
            Some("https://dashboard.ngrok.com/api-keys"),
        ))
    }
}

/// Whether an API key is live, and one line saying how we know.
struct ApiKeyCheck {
    live: bool,
    detail: String,
}

/// Ask the ngrok API whether a key works. Split out and taking an
/// [`HttpClient`] so it can be tested without the network — the same seam the
/// key vault's verification uses, rather than a second HTTP path.
fn check_api_key(api_key: &str, http: &dyn HttpClient) -> ApiKeyCheck {
    let bearer = format!("Bearer {api_key}");
    match http.get(
        NGROK_API_INGRESSES,
        &[
            ("Authorization", &bearer),
            ("Ngrok-Version", NGROK_API_VERSION),
        ],
    ) {
        Ok(response) => match response.status {
            200 => ApiKeyCheck {
                live: true,
                detail: "the api_key is live".to_string(),
            },
            401 | 403 => ApiKeyCheck {
                live: false,
                detail: "ngrok rejected the api_key".to_string(),
            },
            status => ApiKeyCheck {
                live: true,
                // Not a verdict on the key: say so rather than condemn it.
                detail: format!("the ngrok API answered HTTP {status}; the api_key was not judged"),
            },
        },
        Err(e) => ApiKeyCheck {
            live: true,
            detail: format!("could not reach the ngrok API ({e}); the api_key was not judged"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys_verify::{HttpResponse, StubHttp};
    use std::fs;
    use std::path::PathBuf;

    /// A fixture home with an ngrok config at the macOS v3 location.
    fn fixture(body: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let config = home.join("Library/Application Support/ngrok");
        fs::create_dir_all(&config).unwrap();
        fs::write(config.join("ngrok.yml"), body).unwrap();
        (dir, home)
    }

    /// The exact file on the machine this probe was written against
    /// (ngrok 3.25.1), token length preserved, value not.
    const REAL_V3: &str =
        "version: \"3\"\nagent:\n    authtoken: 2abcdefghijklmnopqrstuvwxyz_0123456789ABCDEFGHIJ\n";

    #[test]
    fn test_v3_agent_authtoken_is_one_profile_and_never_a_value() {
        let (_dir, home) = fixture(REAL_V3);
        let status = NgrokProbe::new(Paths::for_test(&home)).status().unwrap();

        assert!(status.installed);
        assert_eq!(status.profiles.len(), 1);
        assert_eq!(status.profiles[0].id, "agent");
        assert_eq!(status.profiles[0].label, "ngrok agent (authtoken)");
        assert_eq!(status.active.as_deref(), Some("agent"));
        assert_eq!(status.profiles[0].meta["authtoken"], true);
        assert_eq!(status.profiles[0].meta["api_key"], false);
        assert_eq!(status.profiles[0].meta["config_version"], "3");
        assert_eq!(status.profiles[0].meta["tunnels"], 0);

        // The token is a presence flag and nothing else — no value, and no
        // last4 either.
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("2abcdefghij"), "{json}");
        assert!(!json.contains("GHIJ"), "{json}");
    }

    #[test]
    fn test_top_level_authtoken_still_works() {
        // Pre-3.5 layout: no `agent:` block at all.
        let (_dir, home) = fixture("version: \"3\"\nauthtoken: 2older_style_token\n");
        let status = NgrokProbe::new(Paths::for_test(&home)).status().unwrap();
        assert_eq!(status.active.as_deref(), Some("agent"));
        assert!(!serde_json::to_string(&status)
            .unwrap()
            .contains("2older_style_token"));
    }

    #[test]
    fn test_named_tunnels_are_metadata_not_profiles() {
        let (_dir, home) = fixture(
            "version: \"3\"\nagent:\n    authtoken: 2tok\ntunnels:\n  web:\n    proto: http\n    addr: 8080\n  api:\n    proto: http\n    addr: 9000\n",
        );
        let status = NgrokProbe::new(Paths::for_test(&home)).status().unwrap();

        // Two tunnels, still one login.
        assert_eq!(status.profiles.len(), 1);
        assert_eq!(status.profiles[0].meta["tunnels"], 2);
        assert_eq!(
            status.profiles[0].meta["tunnel_names"],
            serde_json::json!(["api", "web"])
        );
        assert!(
            status
                .notes
                .iter()
                .any(|n| n.contains("not separate logins")),
            "{:?}",
            status.notes
        );
    }

    #[test]
    fn test_an_api_key_without_an_authtoken_is_not_an_active_login() {
        let (_dir, home) = fixture("version: \"3\"\napi_key: ak_secret_value\n");
        let status = NgrokProbe::new(Paths::for_test(&home)).status().unwrap();

        assert_eq!(status.profiles.len(), 1);
        assert_eq!(status.profiles[0].label, "ngrok api key only");
        // An API key cannot start a tunnel, so nothing is active.
        assert_eq!(status.active, None);
        assert!(
            status.notes.iter().any(|n| n.contains("refuse to start")),
            "{:?}",
            status.notes
        );
        assert!(!serde_json::to_string(&status)
            .unwrap()
            .contains("ak_secret_value"));
    }

    #[test]
    fn test_the_legacy_v2_location_is_read_when_it_is_the_only_one() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        fs::create_dir_all(home.join(".ngrok2")).unwrap();
        fs::write(home.join(".ngrok2/ngrok.yml"), "authtoken: 2legacy\n").unwrap();

        let status = NgrokProbe::new(Paths::for_test(&home)).status().unwrap();
        assert_eq!(status.active.as_deref(), Some("agent"));
        assert!(status.profiles[0].meta["source"]
            .as_str()
            .unwrap()
            .ends_with(".ngrok2/ngrok.yml"));
    }

    #[test]
    fn test_the_v3_location_wins_over_the_legacy_one() {
        let (_dir, home) = fixture(REAL_V3);
        fs::create_dir_all(home.join(".ngrok2")).unwrap();
        fs::write(home.join(".ngrok2/ngrok.yml"), "authtoken: 2legacy\n").unwrap();

        let status = NgrokProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status.profiles[0].meta["source"]
            .as_str()
            .unwrap()
            .contains("Application Support"));
    }

    #[test]
    fn test_ngrok_config_env_var_wins_over_both() {
        let dir = tempfile::tempdir().unwrap();
        let custom = dir.path().join("elsewhere.yml");
        fs::write(&custom, "authtoken: 2custom\n").unwrap();

        let paths = Paths::for_test(dir.path()).with_env("NGROK_CONFIG", custom.to_str().unwrap());
        let status = NgrokProbe::new(paths).status().unwrap();
        assert_eq!(status.active.as_deref(), Some("agent"));
        assert!(status.notes.iter().any(|n| n.contains("NGROK_CONFIG")));
    }

    #[test]
    fn test_missing_and_malformed() {
        let dir = tempfile::tempdir().unwrap();
        let status = NgrokProbe::new(Paths::for_test(dir.path()))
            .status()
            .unwrap();
        assert!(!status.installed);
        assert!(status.profiles.is_empty());

        let (_dir, home) = fixture("version: \"3\"\n  bad: [indent\n");
        let status = NgrokProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status.installed);
        assert!(status.profiles.is_empty());
        assert!(
            status.notes.iter().any(|n| n.contains("not valid YAML")),
            "{:?}",
            status.notes
        );
    }

    #[test]
    fn test_a_config_with_no_credentials_at_all_says_what_to_run() {
        let (_dir, home) = fixture("version: \"3\"\n");
        let status = NgrokProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status.profiles.is_empty());
        assert_eq!(status.active, None);
        assert!(
            status.notes.iter().any(|n| n.contains("add-authtoken")),
            "{:?}",
            status.notes
        );
    }

    #[test]
    fn test_switch_is_unsupported_because_there_is_nothing_to_switch_to() {
        let (_dir, home) = fixture(REAL_V3);
        match NgrokProbe::new(Paths::for_test(&home))
            .switch("agent")
            .unwrap()
        {
            SwitchOutcome::Unsupported { hint, .. } => {
                assert_eq!(hint.as_deref(), Some("ngrok config add-authtoken <token>"));
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn test_verify_never_runs_in_a_test_context() {
        // `Paths::for_test` disables exec, which is what keeps this suite off
        // both the ngrok binary and the network.
        let (_dir, home) = fixture(REAL_V3);
        assert!(matches!(
            NgrokProbe::new(Paths::for_test(&home)).verify().unwrap(),
            VerifyOutcome::Unsupported { .. }
        ));
    }

    // --- the API key check, through the shared HTTP seam --------------------

    #[test]
    fn test_a_live_api_key_is_reported_live_and_sent_as_a_bearer_header() {
        let http = StubHttp::responding(HttpResponse::new(200, r#"{"ingresses":[]}"#));
        let check = check_api_key("ak_live", &http);

        assert!(check.live);
        assert_eq!(check.detail, "the api_key is live");
        assert_eq!(http.last_url().unwrap(), NGROK_API_INGRESSES);
        let headers = http.last_headers();
        assert_eq!(
            headers
                .iter()
                .find(|(k, _)| k == "Authorization")
                .unwrap()
                .1,
            "Bearer ak_live"
        );
        // ngrok 400s without its version header.
        assert_eq!(
            headers
                .iter()
                .find(|(k, _)| k == "Ngrok-Version")
                .unwrap()
                .1,
            "2"
        );
        assert!(!http.last_url().unwrap().contains("ak_live"));
    }

    #[test]
    fn test_a_rejected_api_key_is_the_only_thing_that_reads_as_dead() {
        for status in [401, 403] {
            let check = check_api_key(
                "ak_bad",
                &StubHttp::responding(HttpResponse::new(status, "")),
            );
            assert!(!check.live, "HTTP {status}");
            assert_eq!(check.detail, "ngrok rejected the api_key");
        }

        // A server error or an unreachable API says nothing about the key.
        let check = check_api_key("ak", &StubHttp::responding(HttpResponse::new(500, "")));
        assert!(check.live);
        assert!(check.detail.contains("was not judged"), "{}", check.detail);

        let check = check_api_key("ak", &StubHttp::failing("dns error"));
        assert!(check.live);
        assert!(check.detail.contains("could not reach"), "{}", check.detail);
    }

    #[test]
    fn test_the_api_key_never_appears_in_a_check_detail() {
        let key = "ak_super_secret";
        for http in [
            StubHttp::responding(HttpResponse::new(200, "")),
            StubHttp::responding(HttpResponse::new(401, "")),
            StubHttp::responding(HttpResponse::new(500, "")),
            StubHttp::failing("boom"),
        ] {
            assert!(!check_api_key(key, &http).detail.contains(key));
        }
    }
}
