//! Shared shape for the tier-2 `verify` paths that shell out to a vendor CLI.
//!
//! Every probe that runs somebody else's binary faces the same three problems,
//! and solving them nine different ways is how nine subtly different answers
//! get shipped:
//!
//! 1. **Which failure is this?** "logged out", "the server said no" and "there
//!    is no network" want three different sentences, and calling the third one
//!    an invalid login is a lie that sends the user off to re-authenticate a
//!    credential that was fine. [`classify`] separates them.
//! 2. **What do we quote?** A CLI answers a failure with a paragraph. The
//!    [`crate::types::VerifyOutcome`] detail is one sentence, and
//!    [`crate::util::CmdOutput::message`] is the wrong tool for it — it joins
//!    *every* line with `; `, so "take the headline" written on top of it
//!    silently takes the whole paragraph. [`headline`] takes the first line and
//!    strips the prefix that only names the command patchbay just ran.
//! 3. **Where is the message?** stderr, unless it is empty. [`failure_text`].
//!
//! Nothing here executes anything: this is pure text handling, so it is tested
//! directly rather than through nine `FakeExec` fixtures.

use crate::types::VerifyOutcome;
use crate::util::CmdOutput;

/// Why a vendor CLI refused, at the granularity a user can act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Failure {
    /// No credential at all — the tool has never been logged in, or was logged
    /// out. The fix is to log in.
    LoggedOut,
    /// A credential exists and the server rejected it: 401, expired, revoked.
    /// The fix is also to log in, but the sentence is a different one, because
    /// the user's mental model ("I *am* logged in") is what needs correcting.
    Rejected,
    /// Nothing was proved either way: DNS, TLS, timeouts, refused connections.
    /// **Never** report this as a bad credential.
    Unreachable,
    /// The CLI failed for a reason patchbay has no opinion about.
    Other,
}

/// DNS / TLS / connection markers. Checked first and deliberately generous:
/// mistaking an outage for a rejected token is the expensive error, and
/// mistaking a rejected token for an outage only costs the user a retry.
const UNREACHABLE: &[&str] = &[
    "dial tcp",
    // supabase dials through its own DoH resolver and says so.
    "failed to dial",
    "no such host",
    "network is unreachable",
    "connection refused",
    "connection reset",
    "connection timed out",
    "i/o timeout",
    "timed out",
    "temporary failure in name resolution",
    "could not resolve host",
    "name resolution",
    "getaddrinfo",
    "enotfound",
    "econnrefused",
    "econnreset",
    "etimedout",
    "eai_again",
    "max retries exceeded",
    "failed to establish a new connection",
    "tls handshake",
    "x509",
    "certificate verify failed",
    "unable to get local issuer",
    "self signed certificate",
    "proxyconnect",
];

/// "The server looked at your credential and said no."
const REJECTED: &[&str] = &[
    "401",
    "403",
    "unauthorized",
    "unauthenticated",
    "invalid token",
    "invalid access token",
    "invalid api key",
    "invalid_grant",
    "invalid credentials",
    "token is invalid",
    "expired",
    "revoked",
    "forbidden",
    "permission denied",
    "unable to authenticate",
    "authentication failed",
];

/// "There is no credential here."
const LOGGED_OUT: &[&str] = &[
    "not logged in",
    "not authenticated",
    "no existing credentials",
    "no credentials",
    "credentials not found",
    "access token not provided",
    "access token is required",
    "no access token",
    "no api token",
    "you need to be logged",
    "please log in",
    "please login",
    "must be logged in",
    "run `login`",
    "login first",
    // stripe: "You have not configured API keys yet."
    "not configured",
];

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| haystack.contains(n))
}

/// "invalid" and "token" in the same breath, however the CLI words it.
///
/// A literal-phrase list cannot keep up here: `hf` says "Invalid user token.",
/// stripe says "The API key for the default profile has expired", others say
/// "the token stored is invalid". What they share is a negation next to the
/// noun, so that pairing is matched instead of the sentence around it.
fn says_invalid_credential(text: &str) -> bool {
    let negated = text.contains("invalid") || text.contains("not valid");
    let subject = text.contains("token") || text.contains("key") || text.contains("credential");
    negated && subject
}

/// stderr when it has anything to say, else stdout. Several of these CLIs put
/// their whole diagnostic on stdout and exit non-zero, so neither stream can be
/// the only one read.
pub(super) fn failure_text(out: &CmdOutput) -> &str {
    if out.stderr.trim().is_empty() {
        out.stdout.trim()
    } else {
        out.stderr.trim()
    }
}

/// Sort a CLI's complaint into something a sentence can be built from.
///
/// Order matters, and it is transport first: if the text carries evidence that
/// the request never completed, nothing the payload says about credentials was
/// ever established. Rejection beats logged-out next, because a 401 is a fact
/// about a credential that exists, while "run login" is advice both states
/// print.
pub(super) fn classify(out: &CmdOutput) -> Failure {
    let text = failure_text(out).to_lowercase();
    if contains_any(&text, UNREACHABLE) {
        return Failure::Unreachable;
    }
    if contains_any(&text, REJECTED) || says_invalid_credential(&text) {
        return Failure::Rejected;
    }
    if contains_any(&text, LOGGED_OUT) {
        return Failure::LoggedOut;
    }
    Failure::Other
}

/// Some CLIs report "you are logged out" on a **successful** exit — `hf auth
/// whoami` prints `Not logged in` and exits 0, `wrangler whoami` prints "You
/// are not authenticated." and exits 0. Reading only the exit code files those
/// as working logins.
pub(super) fn says_logged_out(text: &str) -> bool {
    contains_any(&text.to_lowercase(), LOGGED_OUT)
}

/// The first line worth reading, without the prefix that repeats the command.
///
/// The bug this exists to avoid: [`crate::util::CmdOutput::message`] joins
/// every non-empty line with `; `, so a "headline" built on it is the CLI's
/// entire error paragraph on one line. This takes the *first* line, which is
/// what "headline" has to mean.
pub(super) fn headline(text: &str) -> String {
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.chars().all(|c| c == '-' || c == '=' || c == '─'))
        .unwrap_or("the command failed without saying why");
    // `Error: `, `ERROR: `, `error: ` — every Go and Node CLI here uses one.
    let line = line
        .strip_prefix("Error: ")
        .or_else(|| line.strip_prefix("ERROR: "))
        .or_else(|| line.strip_prefix("error: "))
        .unwrap_or(line);
    // gcloud-style `(gcloud.auth.print-access-token) real message`.
    match line
        .strip_prefix('(')
        .and_then(|rest| rest.split_once(") "))
    {
        Some((_command, rest)) => rest.trim().to_string(),
        None => line.to_string(),
    }
}

/// The whole failure branch, in the one shape all nine probes want.
///
/// `login_command` is what ends a logged-out or rejected state; `service` names
/// what could not be reached, so the network sentence says which host mattered.
pub(super) fn failure_outcome(
    tool: &'static str,
    out: &CmdOutput,
    service: &str,
    login_command: &str,
) -> VerifyOutcome {
    let text = failure_text(out);
    match classify(out) {
        Failure::LoggedOut => VerifyOutcome::Invalid {
            tool: tool.to_string(),
            detail: format!("not logged in — run `{login_command}`"),
        },
        Failure::Rejected => VerifyOutcome::Invalid {
            tool: tool.to_string(),
            detail: format!("{service} rejected the stored credential — run `{login_command}`"),
        },
        // Not Invalid: nothing about the credential was established.
        Failure::Unreachable => VerifyOutcome::Unsupported {
            tool: tool.to_string(),
            reason: format!(
                "could not reach {service}, so the credential was not tested ({})",
                headline(text)
            ),
            hint: Some(login_command.to_string()),
        },
        Failure::Other => VerifyOutcome::Invalid {
            tool: tool.to_string(),
            detail: headline(text),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn out(ok: bool, stdout: &str, stderr: &str) -> CmdOutput {
        CmdOutput {
            ok,
            stdout: stdout.to_string(),
            stderr: stderr.to_string(),
        }
    }

    #[test]
    fn test_a_network_failure_is_never_a_bad_credential() {
        let dns = out(
            false,
            "",
            "Get \"https://api.digitalocean.com/v2/account\": dial tcp: lookup api.digitalocean.com: no such host",
        );
        assert_eq!(classify(&dns), Failure::Unreachable);
        match failure_outcome("doctl", &dns, "DigitalOcean", "doctl auth init") {
            VerifyOutcome::Unsupported { reason, .. } => {
                assert!(reason.contains("could not reach DigitalOcean"), "{reason}");
                assert!(reason.contains("not tested"), "{reason}");
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn test_rejected_and_logged_out_get_different_sentences() {
        let rejected = out(false, "", "Error: 401 Unauthorized");
        let logged_out = out(false, "", "Error: No existing credentials found.");
        assert_eq!(classify(&rejected), Failure::Rejected);
        assert_eq!(classify(&logged_out), Failure::LoggedOut);

        let a = failure_outcome("vercel", &rejected, "Vercel", "vercel login");
        let b = failure_outcome("vercel", &logged_out, "Vercel", "vercel login");
        assert_ne!(a, b);
        for outcome in [a, b] {
            match outcome {
                VerifyOutcome::Invalid { detail, .. } => {
                    assert!(detail.contains("vercel login"), "{detail}");
                    assert_eq!(detail.lines().count(), 1, "{detail}");
                }
                other => panic!("expected Invalid, got {other:?}"),
            }
        }
    }

    #[test]
    fn test_headline_takes_the_first_line_not_all_of_them() {
        // The bug: `CmdOutput::message` joins every line with "; ", so a
        // headline built on it is the whole paragraph.
        let paragraph = "ERROR: (gcloud.auth) There was a problem.\nPlease run:\n\n  $ gcloud auth login\n\nto obtain new credentials.\n";
        let line = headline(paragraph);
        assert_eq!(line, "There was a problem.");
        assert!(!line.contains("Please run"), "{line}");
        assert_eq!(line.lines().count(), 1);
    }

    #[test]
    fn test_headline_never_panics_on_empty_or_decorative_output() {
        assert_eq!(headline(""), "the command failed without saying why");
        assert_eq!(
            headline("\n\n────────────\n"),
            "the command failed without saying why"
        );
        assert_eq!(headline("error: nope"), "nope");
    }

    #[test]
    fn test_stdout_is_read_when_stderr_is_silent() {
        let stdout_only = out(false, "Error: not logged in\n", "");
        assert_eq!(failure_text(&stdout_only), "Error: not logged in");
        assert_eq!(classify(&stdout_only), Failure::LoggedOut);
    }

    #[test]
    fn test_a_zero_exit_can_still_say_logged_out() {
        assert!(says_logged_out("Not logged in"));
        assert!(says_logged_out(
            "You are not authenticated. Please run `wrangler login`."
        ));
        assert!(!says_logged_out("dev@example.com"));
    }

    #[test]
    fn test_an_unclassifiable_failure_keeps_the_cli_s_own_first_line() {
        let weird = out(false, "", "Error: unable to parse config at line 3\nstack…");
        assert_eq!(classify(&weird), Failure::Other);
        match failure_outcome("stripe", &weird, "Stripe", "stripe login") {
            VerifyOutcome::Invalid { detail, .. } => {
                assert_eq!(detail, "unable to parse config at line 3");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }
}
