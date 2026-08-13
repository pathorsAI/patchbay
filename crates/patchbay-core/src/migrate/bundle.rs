//! The `.pbx` container: one file, encrypted with a passphrase.
//!
//! # On disk
//!
//! ```text
//! patchbay-bundle/1\n        <- cleartext header, 19 bytes
//! <age ciphertext>           <- everything else
//! ```
//!
//! The header is the only cleartext, and it names nothing but the format and
//! its version. It exists so a bundle written by a newer patchbay can be
//! refused *before* the user is asked for a passphrase — being told "wrong
//! passphrase" when the real problem is a version skew is the kind of error
//! message people spend an hour on. The version is repeated inside the
//! encrypted payload and checked again there, so a doctored header buys
//! nothing.
//!
//! # Encryption
//!
//! `age` with an scrypt (passphrase) recipient. No key files, nothing to lose,
//! nothing to leave on the old machine — the user types a passphrase twice on
//! export and once on import. The scrypt work factor is tuned by the `age`
//! crate to about a second on the machine doing the encrypting; tests override
//! it, because a test suite that spends a second per case is a test suite
//! people stop running.
//!
//! # Payload
//!
//! One JSON document. Files are base64 — configs are small (the largest real
//! case is gcloud's `credentials.db` at a few hundred KB) and a single
//! self-describing document is worth far more than the ~33% than an archive
//! format would save. Everything a bundle can hold is a field on [`Payload`],
//! so "what is in this file" is answerable by reading one struct.

use std::io::Read;
use std::path::Path;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};

use super::manifest::{Manifest, BUNDLE_VERSION};
use super::policy::Location;
use crate::envs::ProjectEntry;

/// Cleartext header, terminated by a newline.
const HEADER_PREFIX: &str = "patchbay-bundle/";

/// The extension `pb export` gives a bundle.
pub const BUNDLE_EXTENSION: &str = "pbx";

/// One credential file, in flight.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BundleFile {
    /// The tool it belongs to, for reporting.
    pub tool: String,
    pub location: Location,
    /// Path under the location's root on the destination.
    pub rel: String,
    /// Unix mode from the source, so a `0600` credentials file stays `0600`.
    pub mode: u32,
    /// Contents, base64. Bytes, not text: `credentials.db` is SQLite.
    pub bytes: String,
}

impl BundleFile {
    pub fn decode(&self) -> anyhow::Result<Vec<u8>> {
        BASE64.decode(self.bytes.as_bytes()).map_err(|e| {
            anyhow::anyhow!(
                "the bundle's copy of {}/{} is corrupt: {e}",
                self.location.key(),
                self.rel
            )
        })
    }

    pub fn encode(tool: &str, location: Location, rel: String, mode: u32, bytes: &[u8]) -> Self {
        Self {
            tool: tool.to_string(),
            location,
            rel,
            mode,
            bytes: BASE64.encode(bytes),
        }
    }
}

/// A vault secret in flight. Only present when the user passed `--keys`.
///
/// Not `Debug`: the whole point of this type is that its field is a secret, and
/// a stray `{:?}` in an error path is exactly how one escapes.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct BundleSecret {
    pub id: String,
    pub secret: String,
}

/// An MCP registration in flight, values included — the same trade
/// `pb mcp copy` makes, for the same reason: a server nobody can authenticate
/// to is not a server. The manifest lists only the variable *names*, so what
/// travelled is visible without the bundle being opened.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct BundleMcpServer {
    pub client: String,
    pub name: String,
    /// `stdio`, `http` or `sse`.
    pub transport: String,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub env: Vec<(String, String)>,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
}

/// Everything inside the encrypted half of a bundle.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Payload {
    pub version: u32,
    /// The readable manifest, verbatim — the same bytes that get written out as
    /// `manifest.json` on import.
    pub manifest: Manifest,
    /// Generated at export time, so a machine with no patchbay still gets
    /// instructions.
    pub setup_md: String,
    #[serde(default)]
    pub files: Vec<BundleFile>,
    #[serde(default)]
    pub secrets: Vec<BundleSecret>,
    #[serde(default)]
    pub mcp: Vec<BundleMcpServer>,
    /// The env vault's portable project manifest: ids, environments and sync
    /// pins. [`ProjectEntry`] is portable by construction — no absolute path,
    /// no value — and the entries carried here have had every `local_names`
    /// list cleared as well, because the local layer's *values* cannot travel
    /// and names without values would make `pb env list` lie on arrival.
    ///
    /// `#[serde(default)]` rather than a [`BUNDLE_VERSION`] bump: a bundle
    /// written before this field existed imports with an empty section, and a
    /// bundle written *after* it, opened by an older patchbay, loses the
    /// section silently — serde ignores unknown fields. That asymmetry is
    /// acceptable here and would not be for a credential file: nothing else in
    /// the payload depends on this list, and everything it points at is
    /// rebuildable by `pb env pull`. Bumping the version instead would make an
    /// older build refuse the whole bundle, which trades a recoverable omission
    /// for an unrecoverable one.
    #[serde(default)]
    pub env_projects: Vec<ProjectEntry>,
}

impl Payload {
    /// Total decoded size of the carried files, for the export report.
    pub fn bytes_carried(&self) -> usize {
        self.files.iter().map(|f| f.bytes.len() * 3 / 4).sum()
    }
}

// The three types that hold credential material get a hand-written `Debug` that
// counts rather than prints. `#[derive(Debug)]` on any of them would put an AWS
// secret key into the first `{:?}` somebody reaches for while debugging — and
// deriving nothing at all is not the answer either, because then a test or a
// caller that needs `assert_eq!` reaches for a workaround instead.

impl std::fmt::Debug for BundleSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BundleSecret")
            .field("id", &self.id)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl std::fmt::Debug for BundleMcpServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BundleMcpServer")
            .field("client", &self.client)
            .field("name", &self.name)
            .field("transport", &self.transport)
            // Names, never values — the same contract `mcp_clients` reports on.
            .field(
                "env_keys",
                &self.env.iter().map(|(k, _)| k).collect::<Vec<_>>(),
            )
            .field(
                "header_keys",
                &self.headers.iter().map(|(k, _)| k).collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Payload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Payload")
            .field("version", &self.version)
            .field("tools", &self.manifest.tools.len())
            .field("files", &self.files.len())
            .field("bytes_carried", &self.bytes_carried())
            .field("secrets", &self.secrets.len())
            .field("mcp", &self.mcp.len())
            .field("env_projects", &self.env_projects.len())
            .finish_non_exhaustive()
    }
}

/// The version in a bundle's cleartext header, without decrypting anything.
pub fn peek_version(path: &Path) -> anyhow::Result<u32> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| anyhow::anyhow!("could not open {}: {e}", path.display()))?;
    // Long enough for the header of any plausible version, short enough that a
    // wrong file is not slurped into memory.
    let mut head = [0u8; 64];
    let read = file
        .read(&mut head)
        .map_err(|e| anyhow::anyhow!("could not read {}: {e}", path.display()))?;
    parse_header(&head[..read])
        .map(|(version, _)| version)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "{} is not a patchbay bundle (no `{HEADER_PREFIX}<version>` header)",
                path.display()
            )
        })
}

/// `(version, offset of the ciphertext)`.
fn parse_header(bytes: &[u8]) -> Option<(u32, usize)> {
    let text = std::str::from_utf8(bytes.get(..HEADER_PREFIX.len())?).ok()?;
    if text != HEADER_PREFIX {
        return None;
    }
    let rest = &bytes[HEADER_PREFIX.len()..];
    let end = rest.iter().position(|b| *b == b'\n')?;
    let version: u32 = std::str::from_utf8(&rest[..end]).ok()?.parse().ok()?;
    Some((version, HEADER_PREFIX.len() + end + 1))
}

fn refuse_future(version: u32, what: &str) -> anyhow::Result<()> {
    if version > BUNDLE_VERSION {
        anyhow::bail!(
            "{what} is a version {version} bundle; this patchbay understands version \
             {BUNDLE_VERSION}. Upgrade patchbay on this machine and try again — importing it \
             with an older build could restore a credential file into the wrong place."
        );
    }
    Ok(())
}

/// Encrypt a payload to `path`.
///
/// `work_factor` is the scrypt log2 cost. `None` means "let age pick", which
/// targets about a second of work; tests pass a small value.
pub fn write(
    path: &Path,
    payload: &Payload,
    passphrase: &str,
    work_factor: Option<u8>,
) -> anyhow::Result<()> {
    let json = serde_json::to_vec(payload)
        .map_err(|e| anyhow::anyhow!("could not serialize the bundle: {e}"))?;

    let mut recipient =
        age::scrypt::Recipient::new(age::secrecy::SecretString::from(passphrase.to_owned()));
    if let Some(log_n) = work_factor {
        recipient.set_work_factor(log_n);
    }
    let ciphertext = age::encrypt(&recipient, &json)
        .map_err(|e| anyhow::anyhow!("could not encrypt the bundle: {e}"))?;

    let mut body = format!("{HEADER_PREFIX}{BUNDLE_VERSION}\n").into_bytes();
    body.extend_from_slice(&ciphertext);

    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir)
                .map_err(|e| anyhow::anyhow!("could not create {}: {e}", dir.display()))?;
        }
    }
    std::fs::write(path, &body)
        .map_err(|e| anyhow::anyhow!("could not write {}: {e}", path.display()))?;
    // A bundle is every credential on the machine in one file. Nobody else on
    // this box gets to read it.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| anyhow::anyhow!("could not chmod {}: {e}", path.display()))?;
    }
    Ok(())
}

/// Decrypt a bundle. The plaintext exists only in this process's memory: no
/// temporary file is written anywhere, and the caller writes each file straight
/// to its destination.
pub fn read(path: &Path, passphrase: &str) -> anyhow::Result<Payload> {
    let raw = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("could not read {}: {e}", path.display()))?;
    let (version, offset) = parse_header(&raw).ok_or_else(|| {
        anyhow::anyhow!(
            "{} is not a patchbay bundle (no `{HEADER_PREFIX}<version>` header)",
            path.display()
        )
    })?;
    refuse_future(version, &path.display().to_string())?;

    let identity =
        age::scrypt::Identity::new(age::secrecy::SecretString::from(passphrase.to_owned()));
    let plaintext = age::decrypt(&identity, &raw[offset..]).map_err(|e| match e {
        age::DecryptError::NoMatchingKeys | age::DecryptError::DecryptionFailed => anyhow::anyhow!(
            "could not decrypt {} — wrong passphrase, or the file was modified in transit",
            path.display()
        ),
        other => anyhow::anyhow!("could not decrypt {}: {other}", path.display()),
    })?;

    let payload: Payload = serde_json::from_slice(&plaintext).map_err(|e| {
        anyhow::anyhow!(
            "{} decrypted, but its contents are not a readable patchbay bundle: {e}",
            path.display()
        )
    })?;
    // Belt and braces: the header could have been edited, the payload could not.
    refuse_future(payload.version, "the decrypted payload")?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrate::manifest::Source;
    use chrono::{DateTime, Utc};

    /// Low enough that the suite stays fast; scrypt at 2^10 is still scrypt.
    const TEST_WORK_FACTOR: u8 = 10;

    fn payload() -> Payload {
        Payload {
            version: BUNDLE_VERSION,
            manifest: Manifest {
                version: BUNDLE_VERSION,
                created_at: DateTime::parse_from_rfc3339("2026-08-13T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
                source: Source {
                    patchbay_version: "0.1.0".into(),
                    os: "macos".into(),
                },
                tools: vec![],
                keys: vec![],
                mcp: vec![],
                env_projects: vec![],
                gaps: vec![],
            },
            setup_md: "# Setting up\n".into(),
            files: vec![BundleFile::encode(
                "aws",
                Location::AwsCredentials,
                "credentials".into(),
                0o600,
                b"[default]\naws_secret_access_key = wJalrXUtnFEMI/EXAMPLEKEY\n",
            )],
            secrets: vec![BundleSecret {
                id: "cf-api".into(),
                secret: "cf-token-value-9876".into(),
            }],
            mcp: vec![],
            env_projects: vec![],
        }
    }

    #[test]
    fn test_round_trip_through_a_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("b.pbx");
        write(&path, &payload(), "correct horse", Some(TEST_WORK_FACTOR)).unwrap();

        let back = read(&path, "correct horse").unwrap();
        assert_eq!(back, payload());
        assert_eq!(back.files.len(), 1);
        assert_eq!(
            String::from_utf8(back.files[0].decode().unwrap()).unwrap(),
            "[default]\naws_secret_access_key = wJalrXUtnFEMI/EXAMPLEKEY\n"
        );
        assert_eq!(back.secrets[0].secret, "cf-token-value-9876");
        assert_eq!(back.files[0].mode, 0o600);
    }

    #[test]
    fn test_the_file_on_disk_is_opaque() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("b.pbx");
        write(&path, &payload(), "pass", Some(TEST_WORK_FACTOR)).unwrap();
        let raw = std::fs::read(&path).unwrap();
        let text = String::from_utf8_lossy(&raw);

        // The header, and nothing else.
        assert!(text.starts_with("patchbay-bundle/1\n"), "{:?}", &text[..20]);
        for secret in [
            "wJalrXUtnFEMI",
            "cf-token-value",
            "aws_secret_access_key",
            "cf-api",
            "credentials",
            "manifest",
        ] {
            assert!(
                !text.contains(secret),
                "`{secret}` is readable in the encrypted bundle"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_the_bundle_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("b.pbx");
        write(&path, &payload(), "pass", Some(TEST_WORK_FACTOR)).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "mode was {:o}", mode & 0o777);
    }

    #[test]
    fn test_the_wrong_passphrase_says_so_without_guessing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("b.pbx");
        write(&path, &payload(), "right", Some(TEST_WORK_FACTOR)).unwrap();
        let err = read(&path, "wrong").unwrap_err().to_string();
        assert!(err.contains("wrong passphrase"), "{err}");
    }

    #[test]
    fn test_a_bundle_from_the_future_is_refused_before_the_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("b.pbx");
        write(&path, &payload(), "pass", Some(TEST_WORK_FACTOR)).unwrap();

        // Rewrite the header as a later version, leaving the ciphertext alone.
        let raw = std::fs::read(&path).unwrap();
        let (_, offset) = parse_header(&raw).unwrap();
        let mut doctored = b"patchbay-bundle/99\n".to_vec();
        doctored.extend_from_slice(&raw[offset..]);
        std::fs::write(&path, &doctored).unwrap();

        assert_eq!(peek_version(&path).unwrap(), 99);
        // Refused with the passphrase that WOULD have worked, so the message
        // cannot be mistaken for a passphrase problem.
        let err = read(&path, "pass").unwrap_err().to_string();
        assert!(err.contains("version 99"), "{err}");
        assert!(err.contains("Upgrade patchbay"), "{err}");
    }

    #[test]
    fn test_a_payload_from_the_future_inside_a_current_header_is_still_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("b.pbx");
        let mut p = payload();
        p.version = BUNDLE_VERSION + 1;
        write(&path, &p, "pass", Some(TEST_WORK_FACTOR)).unwrap();
        let err = read(&path, "pass").unwrap_err().to_string();
        assert!(err.contains("decrypted payload"), "{err}");
    }

    #[test]
    fn test_a_file_that_is_not_a_bundle_is_named_as_such() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notes.txt");
        std::fs::write(&path, "hello").unwrap();
        assert!(peek_version(&path)
            .unwrap_err()
            .to_string()
            .contains("not a patchbay bundle"));
        assert!(read(&path, "pass")
            .unwrap_err()
            .to_string()
            .contains("not a patchbay bundle"));
    }

    #[test]
    fn test_corrupt_base64_names_the_file_it_belongs_to() {
        let file = BundleFile {
            tool: "aws".into(),
            location: Location::AwsConfig,
            rel: "config".into(),
            mode: 0o600,
            bytes: "!!!not base64!!!".into(),
        };
        let err = file.decode().unwrap_err().to_string();
        assert!(err.contains("aws_config/config"), "{err}");
    }
}
