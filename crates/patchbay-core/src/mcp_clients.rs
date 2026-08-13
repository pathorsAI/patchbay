//! MCP client management: which AI clients on this machine have which MCP
//! servers registered, and moving servers between them.
//!
//! The problem this solves is duplication by hand. Claude Code keeps its MCP
//! servers in `~/.claude.json`, Claude Desktop in an Application Support JSON,
//! Cursor in `~/.cursor/mcp.json`, Codex in `~/.codex/config.toml` as TOML
//! tables — same servers, six spellings. Registering one server everywhere means
//! editing four files in two formats and getting the field names right.
//!
//! **Secret handling.** The same rule as the rest of patchbay: this module
//! reports *names*, never values. An `env` block comes back as `env_keys`, a
//! `headers` block as `header_keys`, a command's arguments as a count — because
//! on a real machine those are exactly where the API keys are (a `--figma-api-key=…`
//! argument, an `Authorization: Bearer …` header). Values are read only when a
//! copy has to carry them from one file to another, and even then the report
//! names them so the caller can say what travelled.
//!
//! **Write safety**, in order, for every mutation:
//!
//! 1. a rolling backup — the file is copied to `<path>.patchbay-bak` first;
//! 2. parse–modify–serialize, never a rewrite from a template, so unknown keys,
//!    other servers and (in TOML) comments and layout survive;
//! 3. an atomic write: temp file in the same directory, then rename.
//!
//! Claude Code has two scopes: the top-level `mcpServers` (user) and one map per
//! project under `projects.<path>.mcpServers`. Both are *read* and labelled.
//! Only the user scope is ever *written* — a project's servers are that
//! project's business, and patchbay has no way to know which of 500 project
//! entries a caller meant.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use toml_edit::{DocumentMut, Item, Table};

use crate::paths::Paths;

/// Appended to a config path to make its rolling backup. One generation only:
/// the point is an undo for the write patchbay just did, not an archive.
const BACKUP_SUFFIX: &str = ".patchbay-bak";

// ---------------------------------------------------------------------------
// model
// ---------------------------------------------------------------------------

/// How a client reaches a server. Deliberately lossy on the stdio side:
/// `args_len` rather than the arguments themselves, because arguments are where
/// `--api-key=…` lives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "transport", rename_all = "snake_case")]
pub enum McpTransport {
    Stdio { command: String, args_len: usize },
    Http { url: String },
    Sse { url: String },
}

impl McpTransport {
    /// One-line summary for a table cell.
    pub fn summary(&self) -> String {
        match self {
            Self::Stdio { command, args_len } => {
                let base = short_command(command);
                match args_len {
                    0 => format!("stdio {base}"),
                    1 => format!("stdio {base} (1 arg)"),
                    n => format!("stdio {base} ({n} args)"),
                }
            }
            Self::Http { url } => format!("http {url}"),
            Self::Sse { url } => format!("sse {url}"),
        }
    }
}

/// One server as one client has it registered. Metadata only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpServerEntry {
    pub name: String,
    #[serde(flatten)]
    pub transport: McpTransport,
    /// Claude Code only: `"user"` or `"project:<path>"`. `None` elsewhere —
    /// those clients have a single scope.
    pub scope: Option<String>,
    /// Names of the environment variables the entry sets. **Never values.**
    pub env_keys: Vec<String>,
    /// Names of the HTTP headers the entry sets. **Never values** — this is
    /// where bearer tokens live.
    pub header_keys: Vec<String>,
}

impl McpServerEntry {
    /// Whether this entry is in a scope patchbay is willing to write.
    pub fn is_writable_scope(&self) -> bool {
        !matches!(self.scope.as_deref(), Some(s) if s.starts_with("project:"))
    }
}

/// One AI client and everything it has registered.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpClient {
    /// Stable key used on the command line: `claude-code`, `codex`, …
    pub client: String,
    /// Display name: "Claude Code", "Codex CLI", …
    pub label: String,
    pub config_path: PathBuf,
    /// Whether that config file exists. A client that is not installed, and one
    /// that is installed but has never been configured, both read as `false`.
    pub present: bool,
    pub servers: Vec<McpServerEntry>,
    /// Caveats: unreadable file, malformed config, entries patchbay skipped.
    pub notes: Vec<String>,
}

/// What to register. Unlike [`McpServerEntry`] this *does* carry values — it is
/// the input to a write, and a server nobody can authenticate to is not a
/// server. It is never serialized into a status report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSpec {
    pub transport: TransportSpec,
    /// Environment variables, in file order.
    pub env: Vec<(String, String)>,
    /// HTTP headers, in file order.
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportSpec {
    Stdio { command: String, args: Vec<String> },
    Http { url: String },
    Sse { url: String },
}

impl ServerSpec {
    pub fn stdio(command: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            transport: TransportSpec::Stdio {
                command: command.into(),
                args,
            },
            env: Vec::new(),
            headers: Vec::new(),
        }
    }

    pub fn http(url: impl Into<String>) -> Self {
        Self {
            transport: TransportSpec::Http { url: url.into() },
            env: Vec::new(),
            headers: Vec::new(),
        }
    }

    pub fn sse(url: impl Into<String>) -> Self {
        Self {
            transport: TransportSpec::Sse { url: url.into() },
            env: Vec::new(),
            headers: Vec::new(),
        }
    }

    pub fn env(mut self, env: Vec<(String, String)>) -> Self {
        self.env = env;
        self
    }

    pub fn headers(mut self, headers: Vec<(String, String)>) -> Self {
        self.headers = headers;
        self
    }

    /// The names of every value this spec carries. What a copy reports so the
    /// user knows what travelled between files.
    pub fn env_keys(&self) -> Vec<String> {
        self.env.iter().map(|(k, _)| k.clone()).collect()
    }

    pub fn header_keys(&self) -> Vec<String> {
        self.headers.iter().map(|(k, _)| k.clone()).collect()
    }

    /// Value-free summary, safe to print.
    pub fn summary(&self) -> String {
        match &self.transport {
            TransportSpec::Stdio { command, args } => McpTransport::Stdio {
                command: command.clone(),
                args_len: args.len(),
            }
            .summary(),
            TransportSpec::Http { url } => McpTransport::Http { url: url.clone() }.summary(),
            TransportSpec::Sse { url } => McpTransport::Sse { url: url.clone() }.summary(),
        }
    }
}

/// The outcome of one mutation, including where the undo lives.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WriteReport {
    pub client: String,
    pub label: String,
    pub name: String,
    pub config_path: PathBuf,
    /// The rolling backup written before the change. `None` only when the
    /// config file did not exist yet.
    pub backup_path: Option<PathBuf>,
    /// Whether patchbay had to create the config file.
    pub created_file: bool,
    /// Things the caller must pass on: format limitations, restart hints.
    pub notes: Vec<String>,
}

/// The outcome of a copy: one source, several targets, and the names of the
/// values that travelled with it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CopyReport {
    pub name: String,
    pub from: String,
    pub summary: String,
    /// Names of environment variables copied. Their VALUES were copied too —
    /// this list is what the caller must surface.
    pub env_carried: Vec<String>,
    /// Names of headers copied, values included. Same warning.
    pub header_carried: Vec<String>,
    pub written: Vec<WriteReport>,
}

// ---------------------------------------------------------------------------
// the client table
// ---------------------------------------------------------------------------

/// A JSON client's dialect. Four fields is all it takes to cover every JSON
/// client patchbay knows: they differ only in the top-level key, the name of
/// the URL field, whether they understand a `type` discriminator, and whether
/// they have per-project scopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct JsonDialect {
    /// Top-level key holding the server map (`mcpServers`, or `servers` in
    /// VS Code).
    root_key: &'static str,
    /// Field naming a remote server's endpoint (`url`, or `serverUrl` in
    /// Windsurf).
    url_field: &'static str,
    /// Whether the client records `"type": "stdio" | "http" | "sse"`. When it
    /// does not, an SSE server is written as a plain URL and the client works
    /// the transport out for itself.
    typed: bool,
    /// Claude Code keeps a second set of maps under `projects.<path>`.
    project_scopes: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Json(JsonDialect),
    /// Codex's `[mcp_servers.<name>]` tables.
    CodexToml,
}

/// One supported client.
#[derive(Debug, Clone, Copy)]
pub struct ClientDef {
    pub key: &'static str,
    pub label: &'static str,
    format: Format,
}

/// Every client patchbay knows about, present or not. Order is the order the
/// board shows them in.
const CLIENTS: &[ClientDef] = &[
    ClientDef {
        key: "claude-code",
        label: "Claude Code",
        format: Format::Json(JsonDialect {
            root_key: "mcpServers",
            url_field: "url",
            typed: true,
            project_scopes: true,
        }),
    },
    ClientDef {
        key: "claude-desktop",
        label: "Claude Desktop",
        format: Format::Json(JsonDialect {
            root_key: "mcpServers",
            url_field: "url",
            typed: false,
            project_scopes: false,
        }),
    },
    ClientDef {
        key: "cursor",
        label: "Cursor",
        format: Format::Json(JsonDialect {
            root_key: "mcpServers",
            url_field: "url",
            typed: false,
            project_scopes: false,
        }),
    },
    ClientDef {
        key: "codex",
        label: "Codex CLI",
        format: Format::CodexToml,
    },
    ClientDef {
        key: "windsurf",
        label: "Windsurf",
        format: Format::Json(JsonDialect {
            root_key: "mcpServers",
            // Windsurf's own docs name the remote field `serverUrl`; it also
            // accepts `url`, which is why reads look for both.
            url_field: "serverUrl",
            typed: false,
            project_scopes: false,
        }),
    },
    ClientDef {
        key: "vscode",
        label: "VS Code",
        format: Format::Json(JsonDialect {
            // VS Code is the odd one out: `servers`, not `mcpServers`.
            root_key: "servers",
            url_field: "url",
            typed: true,
            project_scopes: false,
        }),
    },
];

/// Every client key, for error messages and shell completion.
pub fn client_keys() -> Vec<&'static str> {
    CLIENTS.iter().map(|c| c.key).collect()
}

fn def_for(key: &str) -> anyhow::Result<&'static ClientDef> {
    CLIENTS.iter().find(|c| c.key == key).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown MCP client `{key}`; patchbay knows: {}",
            client_keys().join(", ")
        )
    })
}

/// Where a client keeps its config on this machine.
fn config_path(def: &ClientDef, paths: &Paths) -> PathBuf {
    let home = paths.home();
    match def.key {
        "claude-code" => home.join(".claude.json"),
        "claude-desktop" => {
            home.join("Library/Application Support/Claude/claude_desktop_config.json")
        }
        "cursor" => home.join(".cursor/mcp.json"),
        "codex" => match paths.env("CODEX_HOME") {
            Some(dir) => PathBuf::from(dir).join("config.toml"),
            None => home.join(".codex/config.toml"),
        },
        "windsurf" => home.join(".codeium/windsurf/mcp_config.json"),
        "vscode" => home.join("Library/Application Support/Code/User/mcp.json"),
        // Unreachable while CLIENTS and this match stay in step; a new client
        // with no path lands in its own home directory rather than panicking.
        other => home.join(format!(".{other}/mcp.json")),
    }
}

// ---------------------------------------------------------------------------
// registry
// ---------------------------------------------------------------------------

/// The board: every known client, read through a [`Paths`].
///
/// Stateless between calls — files are re-read on every operation, so a server
/// added by the CLI is immediately visible to a running MCP server.
#[derive(Debug, Clone)]
pub struct McpClientRegistry {
    paths: Paths,
}

impl McpClientRegistry {
    /// Bind to an explicit [`Paths`]. Tests use this with a tempdir home, which
    /// is what keeps them off the real config files.
    pub fn with_paths(paths: Paths) -> Self {
        Self { paths }
    }

    /// The real clients on this machine.
    pub fn detect() -> anyhow::Result<Self> {
        Ok(Self::with_paths(Paths::detect()?))
    }

    /// Every known client, present or not, in board order.
    pub fn clients(&self) -> Vec<McpClient> {
        CLIENTS.iter().map(|def| self.read(def)).collect()
    }

    /// One client. An unknown key is an error listing the valid ones.
    pub fn client(&self, key: &str) -> anyhow::Result<McpClient> {
        Ok(self.read(def_for(key)?))
    }

    /// Where a client's config lives, whether or not it exists.
    pub fn config_path_of(&self, key: &str) -> anyhow::Result<PathBuf> {
        Ok(config_path(def_for(key)?, &self.paths))
    }

    // --- reads --------------------------------------------------------------

    fn read(&self, def: &ClientDef) -> McpClient {
        let path = config_path(def, &self.paths);
        let mut client = McpClient {
            client: def.key.to_string(),
            label: def.label.to_string(),
            present: path.is_file(),
            config_path: path.clone(),
            servers: Vec::new(),
            notes: Vec::new(),
        };

        let text = match crate::util::read_text(&path) {
            Ok(Some(text)) => text,
            Ok(None) => return client,
            Err(e) => {
                // Same rule as the probes: one broken client never blanks the
                // board, it just explains itself.
                client.notes.push(e);
                return client;
            }
        };

        let parsed = match def.format {
            Format::Json(dialect) => read_json(&text, dialect),
            Format::CodexToml => read_codex(&text),
        };
        match parsed {
            Ok((servers, notes)) => {
                client.servers = servers;
                client.notes.extend(notes);
            }
            Err(e) => client.notes.push(format!("{}: {e}", path.display())),
        }
        client
    }

    /// The full definition of one registered server, values included, ready to
    /// be written into another client. The only read path that touches values.
    pub fn read_spec(&self, client: &str, name: &str) -> anyhow::Result<ServerSpec> {
        let def = def_for(client)?;
        let path = config_path(def, &self.paths);
        let text = crate::util::read_text(&path)
            .map_err(anyhow::Error::msg)?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "{} has no MCP config yet ({} does not exist)",
                    def.label,
                    path.display()
                )
            })?;

        let spec = match def.format {
            Format::Json(dialect) => json_spec(&text, dialect, name)?,
            Format::CodexToml => codex_spec(&text, name)?,
        };
        spec.ok_or_else(|| {
            anyhow::anyhow!(
                "{} has no MCP server called `{name}` in its user scope ({})",
                def.label,
                path.display()
            )
        })
    }

    // --- writes -------------------------------------------------------------

    /// Register a server with one client.
    ///
    /// Refuses an existing name unless `overwrite` is set: silently replacing a
    /// working server is how a machine loses a config nobody remembers writing.
    pub fn add_server(
        &self,
        client: &str,
        name: &str,
        spec: &ServerSpec,
        overwrite: bool,
    ) -> anyhow::Result<WriteReport> {
        let def = def_for(client)?;
        validate_name(name)?;
        let path = config_path(def, &self.paths);
        let existed = path.is_file();
        let text = crate::util::read_text(&path).map_err(anyhow::Error::msg)?;

        let mut notes = Vec::new();
        let body = match def.format {
            Format::Json(dialect) => {
                json_upsert(text.as_deref(), dialect, name, spec, overwrite, &mut notes)?
            }
            Format::CodexToml => codex_upsert(text.as_deref(), name, spec, overwrite, &mut notes)?,
        };

        let backup_path = backup(&path)?;
        write_atomic(&path, &body)?;
        notes.push(restart_note(def));
        Ok(WriteReport {
            client: def.key.to_string(),
            label: def.label.to_string(),
            name: name.to_string(),
            config_path: path,
            backup_path,
            created_file: !existed,
            notes,
        })
    }

    /// Unregister a server from one client. Removing it here does not stop the
    /// server itself from existing — it just stops this client launching it.
    pub fn remove_server(&self, client: &str, name: &str) -> anyhow::Result<WriteReport> {
        let def = def_for(client)?;
        let path = config_path(def, &self.paths);
        let text = crate::util::read_text(&path)
            .map_err(anyhow::Error::msg)?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "{} has no MCP config to remove from ({} does not exist)",
                    def.label,
                    path.display()
                )
            })?;

        let mut notes = Vec::new();
        let body = match def.format {
            Format::Json(dialect) => json_remove(&text, dialect, name, def.label)?,
            Format::CodexToml => codex_remove(&text, name, def.label)?,
        };

        let backup_path = backup(&path)?;
        write_atomic(&path, &body)?;
        notes.push(restart_note(def));
        Ok(WriteReport {
            client: def.key.to_string(),
            label: def.label.to_string(),
            name: name.to_string(),
            config_path: path,
            backup_path,
            created_file: false,
            notes,
        })
    }

    /// Copy one server from one client to several, translating formats on the
    /// way (a JSON `mcpServers` entry becomes a `[mcp_servers.<name>]` table,
    /// and back).
    ///
    /// Every target is validated before anything is written, so a typo in the
    /// third target does not leave the first two changed.
    pub fn copy_server(
        &self,
        name: &str,
        from: &str,
        to: &[String],
        overwrite: bool,
    ) -> anyhow::Result<CopyReport> {
        if to.is_empty() {
            anyhow::bail!("no target client given; pass at least one --to");
        }
        let source = def_for(from)?;
        let spec = self.read_spec(from, name)?;

        // Validate the whole target list first.
        let mut targets = Vec::new();
        for key in to {
            let def = def_for(key)?;
            if def.key == source.key {
                anyhow::bail!("`{key}` is both the source and a target of this copy");
            }
            if targets.iter().any(|d: &&ClientDef| d.key == def.key) {
                anyhow::bail!("`{key}` is listed twice as a target");
            }
            if !overwrite {
                let existing = self.read(def);
                if existing
                    .servers
                    .iter()
                    .any(|s| s.name == name && s.is_writable_scope())
                {
                    anyhow::bail!(
                        "{} already has an MCP server called `{name}`; \
                         pass --force to replace it, or pick another name",
                        def.label
                    );
                }
            }
            targets.push(def);
        }

        let mut written = Vec::new();
        for def in targets {
            match self.add_server(def.key, name, &spec, true) {
                Ok(report) => written.push(report),
                Err(e) => {
                    let done: Vec<&str> = written.iter().map(|w| w.client.as_str()).collect();
                    return Err(e.context(format!(
                        "copying `{name}` into {} failed; already written to: {}",
                        def.label,
                        if done.is_empty() {
                            "nothing".to_string()
                        } else {
                            done.join(", ")
                        }
                    )));
                }
            }
        }

        Ok(CopyReport {
            name: name.to_string(),
            from: source.key.to_string(),
            summary: spec.summary(),
            env_carried: spec.env_keys(),
            header_carried: spec.header_keys(),
            written,
        })
    }
}

/// The one caveat every write shares: a client already running reads its config
/// at startup, and some rewrite it on exit.
fn restart_note(def: &ClientDef) -> String {
    match def.key {
        "claude-code" => "Claude Code reads ~/.claude.json at startup and rewrites it on exit; \
             restart it, and avoid editing while a session is open."
            .to_string(),
        _ => format!("{} picks this up on its next start.", def.label),
    }
}

/// Server names end up as JSON object keys and TOML table keys, both of which
/// quote and escape whatever they are given — so this is deliberately loose.
/// Real machines have servers called `Framelink Figma MCP`, and refusing to
/// copy one because patchbay dislikes the spaces would be patchbay's problem
/// presented as the user's. What is rejected is what no config can round-trip:
/// nothing, only whitespace, control characters, or a name so long it is a
/// mistake.
const MAX_NAME_LEN: usize = 128;

fn validate_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty() {
        anyhow::bail!("a server name cannot be empty");
    }
    if name.trim().is_empty() {
        anyhow::bail!("a server name cannot be only whitespace");
    }
    if name != name.trim() {
        anyhow::bail!(
            "server name `{name}` has leading or trailing whitespace; \
             clients will not match it back"
        );
    }
    if name.chars().any(|c| c.is_control()) {
        anyhow::bail!("server name `{name:?}` contains a control character");
    }
    if name.chars().count() > MAX_NAME_LEN {
        anyhow::bail!("server name is longer than {MAX_NAME_LEN} characters");
    }
    Ok(())
}

/// The last path component of a command, so a 90-character absolute path does
/// not take over the table.
fn short_command(command: &str) -> String {
    Path::new(command)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| command.to_string())
}

// ---------------------------------------------------------------------------
// JSON clients
// ---------------------------------------------------------------------------

fn parse_json(text: &str) -> anyhow::Result<Value> {
    if text.trim().is_empty() {
        return Ok(Value::Object(Map::new()));
    }
    serde_json::from_str(text).map_err(|e| anyhow::anyhow!("not readable JSON: {e}"))
}

fn as_object<'a>(value: &'a Value, what: &str) -> anyhow::Result<&'a Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("`{what}` is not a JSON object"))
}

fn string_keys(entry: &Map<String, Value>, field: &str) -> Vec<String> {
    entry
        .get(field)
        .and_then(Value::as_object)
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}

fn string_pairs(entry: &Map<String, Value>, field: &str) -> Vec<(String, String)> {
    entry
        .get(field)
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .map(|(k, v)| {
                    let value = match v {
                        Value::String(s) => s.clone(),
                        other => other.to_string(),
                    };
                    (k.clone(), value)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The endpoint of a remote entry, under either spelling.
fn entry_url(entry: &Map<String, Value>) -> Option<&str> {
    entry
        .get("url")
        .or_else(|| entry.get("serverUrl"))
        .and_then(Value::as_str)
}

fn json_transport(entry: &Map<String, Value>) -> McpTransport {
    let declared = entry.get("type").and_then(Value::as_str).unwrap_or("");
    match entry_url(entry) {
        Some(url) if declared.eq_ignore_ascii_case("sse") => McpTransport::Sse {
            url: url.to_string(),
        },
        Some(url) => McpTransport::Http {
            url: url.to_string(),
        },
        None => McpTransport::Stdio {
            command: entry
                .get("command")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            args_len: entry
                .get("args")
                .and_then(Value::as_array)
                .map(|a| a.len())
                .unwrap_or(0),
        },
    }
}

fn json_entry(name: &str, entry: &Map<String, Value>, scope: Option<String>) -> McpServerEntry {
    McpServerEntry {
        name: name.to_string(),
        transport: json_transport(entry),
        scope,
        env_keys: string_keys(entry, "env"),
        header_keys: string_keys(entry, "headers"),
    }
}

/// Read every server a JSON client has registered, user scope first.
fn read_json(
    text: &str,
    dialect: JsonDialect,
) -> anyhow::Result<(Vec<McpServerEntry>, Vec<String>)> {
    let root = parse_json(text)?;
    let root = as_object(&root, "the config file")?;
    let mut servers = Vec::new();
    let mut notes = Vec::new();

    let user_scope = dialect.project_scopes.then(|| "user".to_string());
    if let Some(map) = root.get(dialect.root_key) {
        match map.as_object() {
            Some(map) => {
                for (name, entry) in map {
                    match entry.as_object() {
                        Some(entry) => servers.push(json_entry(name, entry, user_scope.clone())),
                        None => notes.push(format!("skipped `{name}`: not a JSON object")),
                    }
                }
            }
            None => notes.push(format!("`{}` is not a JSON object", dialect.root_key)),
        }
    }

    if dialect.project_scopes {
        if let Some(projects) = root.get("projects").and_then(Value::as_object) {
            for (project, config) in projects {
                let Some(map) = config
                    .as_object()
                    .and_then(|c| c.get(dialect.root_key))
                    .and_then(Value::as_object)
                else {
                    continue;
                };
                for (name, entry) in map {
                    if let Some(entry) = entry.as_object() {
                        servers.push(json_entry(name, entry, Some(format!("project:{project}"))));
                    }
                }
            }
        }
    }

    Ok((servers, notes))
}

/// The user-scope definition of one server, values included.
fn json_spec(text: &str, dialect: JsonDialect, name: &str) -> anyhow::Result<Option<ServerSpec>> {
    let root = parse_json(text)?;
    let root = as_object(&root, "the config file")?;
    let Some(entry) = root
        .get(dialect.root_key)
        .and_then(Value::as_object)
        .and_then(|m| m.get(name))
        .and_then(Value::as_object)
    else {
        return Ok(None);
    };

    let transport = match json_transport(entry) {
        McpTransport::Sse { url } => TransportSpec::Sse { url },
        McpTransport::Http { url } => TransportSpec::Http { url },
        McpTransport::Stdio { command, .. } => {
            if command.is_empty() {
                anyhow::bail!("`{name}` has neither a command nor a url; nothing to copy");
            }
            TransportSpec::Stdio {
                command,
                args: entry
                    .get("args")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .map(|v| match v {
                                Value::String(s) => s.clone(),
                                other => other.to_string(),
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
            }
        }
    };

    Ok(Some(ServerSpec {
        transport,
        env: string_pairs(entry, "env"),
        headers: string_pairs(entry, "headers"),
    }))
}

/// Render a spec into one client's JSON dialect.
fn spec_to_json(spec: &ServerSpec, dialect: JsonDialect, notes: &mut Vec<String>) -> Value {
    let mut entry = Map::new();
    match &spec.transport {
        TransportSpec::Stdio { command, args } => {
            if dialect.typed {
                entry.insert("type".into(), Value::String("stdio".into()));
            }
            entry.insert("command".into(), Value::String(command.clone()));
            entry.insert(
                "args".into(),
                Value::Array(args.iter().cloned().map(Value::String).collect()),
            );
        }
        TransportSpec::Http { url } | TransportSpec::Sse { url } => {
            let sse = matches!(spec.transport, TransportSpec::Sse { .. });
            if dialect.typed {
                entry.insert(
                    "type".into(),
                    Value::String(if sse { "sse" } else { "http" }.into()),
                );
            } else if sse {
                notes.push(
                    "this client does not record a transport type; the server was written as a \
                     plain URL and the client will decide how to connect"
                        .to_string(),
                );
            }
            entry.insert(dialect.url_field.into(), Value::String(url.clone()));
        }
    }

    if !spec.env.is_empty() {
        entry.insert("env".into(), pairs_to_json(&spec.env));
    }
    if !spec.headers.is_empty() {
        entry.insert("headers".into(), pairs_to_json(&spec.headers));
    }
    Value::Object(entry)
}

fn pairs_to_json(pairs: &[(String, String)]) -> Value {
    let mut map = Map::new();
    for (k, v) in pairs {
        map.insert(k.clone(), Value::String(v.clone()));
    }
    Value::Object(map)
}

/// Insert or replace one server, leaving every other key in the file exactly
/// where it was.
fn json_upsert(
    text: Option<&str>,
    dialect: JsonDialect,
    name: &str,
    spec: &ServerSpec,
    overwrite: bool,
    notes: &mut Vec<String>,
) -> anyhow::Result<String> {
    let mut root = parse_json(text.unwrap_or(""))?;
    if !root.is_object() {
        anyhow::bail!("the config file is not a JSON object; patchbay will not rewrite it");
    }
    let entry = spec_to_json(spec, dialect, notes);

    let map = root
        .as_object_mut()
        .expect("checked above")
        .entry(dialect.root_key)
        .or_insert_with(|| Value::Object(Map::new()));
    let map = map.as_object_mut().ok_or_else(|| {
        anyhow::anyhow!(
            "`{}` in this config is not a JSON object; patchbay will not overwrite it",
            dialect.root_key
        )
    })?;

    if map.contains_key(name) && !overwrite {
        anyhow::bail!(
            "an MCP server called `{name}` is already registered here; \
             pass --force to replace it"
        );
    }
    // With serde_json's `preserve_order`, replacing an existing key keeps its
    // position, so an overwrite does not reshuffle the file.
    map.insert(name.to_string(), entry);

    Ok(serialize_json(&root, text))
}

fn json_remove(
    text: &str,
    dialect: JsonDialect,
    name: &str,
    label: &str,
) -> anyhow::Result<String> {
    let mut root = parse_json(text)?;
    let map = root
        .as_object_mut()
        .and_then(|m| m.get_mut(dialect.root_key))
        .and_then(Value::as_object_mut)
        .ok_or_else(|| anyhow::anyhow!("{label} has no `{}` block", dialect.root_key))?;

    if map.remove(name).is_none() {
        // A project-scope hit is the interesting near-miss: say so rather than
        // claiming the server does not exist.
        if dialect.project_scopes && in_project_scope(&root, dialect, name) {
            anyhow::bail!(
                "`{name}` is registered in {label}'s PROJECT scope, not the user scope. \
                 patchbay only writes the user scope; remove the project entry with \
                 `claude mcp remove {name}` from that project, or edit it by hand"
            );
        }
        anyhow::bail!("{label} has no MCP server called `{name}`");
    }
    Ok(serialize_json(&root, Some(text)))
}

fn in_project_scope(root: &Value, dialect: JsonDialect, name: &str) -> bool {
    root.get("projects")
        .and_then(Value::as_object)
        .map(|projects| {
            projects.values().any(|config| {
                config
                    .get(dialect.root_key)
                    .and_then(Value::as_object)
                    .is_some_and(|m| m.contains_key(name))
            })
        })
        .unwrap_or(false)
}

/// Serialize back out, matching the indentation the file already used. Clients
/// write these files themselves; handing one back a two-space file as four-space
/// makes a diff nobody asked for.
fn serialize_json(root: &Value, original: Option<&str>) -> String {
    let compact = original.is_some_and(|text| !text.contains('\n') && text.len() > 2);
    let mut body = if compact {
        serde_json::to_string(root).unwrap_or_default()
    } else {
        serde_json::to_string_pretty(root).unwrap_or_default()
    };
    if !compact {
        body.push('\n');
    }
    body
}

// ---------------------------------------------------------------------------
// Codex TOML
// ---------------------------------------------------------------------------

/// Codex keeps servers as `[mcp_servers.<name>]` tables alongside unrelated
/// settings and hundreds of `[projects."…"]` tables, so every write goes
/// through `toml_edit`: comments, ordering and formatting survive untouched.
const CODEX_ROOT: &str = "mcp_servers";

fn parse_toml(text: &str) -> anyhow::Result<DocumentMut> {
    text.parse::<DocumentMut>()
        .map_err(|e| anyhow::anyhow!("not readable TOML: {e}"))
}

fn toml_str(table: &Table, key: &str) -> Option<String> {
    table.get(key)?.as_str().map(|s| s.to_string())
}

/// Keys of a sub-table, whether it is a real table or an inline one.
fn toml_sub_keys(table: &Table, key: &str) -> Vec<String> {
    match table.get(key) {
        Some(Item::Table(t)) => t.iter().map(|(k, _)| k.to_string()).collect(),
        Some(Item::Value(v)) => v
            .as_inline_table()
            .map(|t| t.iter().map(|(k, _)| k.to_string()).collect())
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

fn toml_sub_pairs(table: &Table, key: &str) -> Vec<(String, String)> {
    let render = |v: &toml_edit::Value| match v.as_str() {
        Some(s) => s.to_string(),
        None => v.to_string().trim().to_string(),
    };
    match table.get(key) {
        Some(Item::Table(t)) => t
            .iter()
            .filter_map(|(k, item)| item.as_value().map(|v| (k.to_string(), render(v))))
            .collect(),
        Some(Item::Value(v)) => v
            .as_inline_table()
            .map(|t| {
                t.iter()
                    .map(|(k, v)| (k.to_string(), render(v)))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

fn codex_servers(doc: &DocumentMut) -> Vec<(String, &Table)> {
    match doc.get(CODEX_ROOT) {
        Some(Item::Table(root)) => root
            .iter()
            .filter_map(|(name, item)| match item {
                Item::Table(t) => Some((name.to_string(), t)),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn read_codex(text: &str) -> anyhow::Result<(Vec<McpServerEntry>, Vec<String>)> {
    let doc = parse_toml(text)?;
    let mut servers = Vec::new();
    for (name, table) in codex_servers(&doc) {
        let transport = match toml_str(table, "url") {
            Some(url) => McpTransport::Http { url },
            None => McpTransport::Stdio {
                command: toml_str(table, "command").unwrap_or_default(),
                args_len: table
                    .get("args")
                    .and_then(|i| i.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0),
            },
        };
        servers.push(McpServerEntry {
            name,
            transport,
            scope: None,
            env_keys: toml_sub_keys(table, "env"),
            header_keys: toml_sub_keys(table, "http_headers"),
        });
    }
    Ok((servers, Vec::new()))
}

fn codex_spec(text: &str, name: &str) -> anyhow::Result<Option<ServerSpec>> {
    let doc = parse_toml(text)?;
    let Some((_, table)) = codex_servers(&doc).into_iter().find(|(n, _)| n == name) else {
        return Ok(None);
    };

    let transport = match toml_str(table, "url") {
        Some(url) => TransportSpec::Http { url },
        None => {
            let command = toml_str(table, "command")
                .ok_or_else(|| anyhow::anyhow!("`{name}` has no command; nothing to copy"))?;
            let args = table
                .get("args")
                .and_then(|i| i.as_array())
                .map(|a| {
                    a.iter()
                        .map(|v| match v.as_str() {
                            Some(s) => s.to_string(),
                            None => v.to_string().trim().to_string(),
                        })
                        .collect()
                })
                .unwrap_or_default();
            TransportSpec::Stdio { command, args }
        }
    };

    Ok(Some(ServerSpec {
        transport,
        env: toml_sub_pairs(table, "env"),
        headers: toml_sub_pairs(table, "http_headers"),
    }))
}

fn pairs_to_toml(pairs: &[(String, String)]) -> Table {
    let mut table = Table::new();
    for (k, v) in pairs {
        table.insert(k, toml_edit::value(v.as_str()));
    }
    table
}

fn spec_to_codex(spec: &ServerSpec, notes: &mut Vec<String>) -> Table {
    let mut table = Table::new();
    match &spec.transport {
        TransportSpec::Stdio { command, args } => {
            table.insert("command", toml_edit::value(command.as_str()));
            let mut array = toml_edit::Array::new();
            for arg in args {
                array.push(arg.as_str());
            }
            table.insert("args", toml_edit::value(array));
        }
        TransportSpec::Http { url } => {
            table.insert("url", toml_edit::value(url.as_str()));
        }
        TransportSpec::Sse { url } => {
            table.insert("url", toml_edit::value(url.as_str()));
            notes.push(
                "Codex has no separate SSE transport; the endpoint was written as `url`. \
                 Check that the server speaks streamable HTTP there."
                    .to_string(),
            );
        }
    }
    if !spec.env.is_empty() {
        table.insert("env", Item::Table(pairs_to_toml(&spec.env)));
    }
    if !spec.headers.is_empty() {
        table.insert("http_headers", Item::Table(pairs_to_toml(&spec.headers)));
    }
    table
}

fn codex_upsert(
    text: Option<&str>,
    name: &str,
    spec: &ServerSpec,
    overwrite: bool,
    notes: &mut Vec<String>,
) -> anyhow::Result<String> {
    let mut doc = parse_toml(text.unwrap_or(""))?;
    let table = spec_to_codex(spec, notes);

    let root = doc
        .entry(CODEX_ROOT)
        .or_insert_with(|| Item::Table(Table::new()));
    let root = root.as_table_mut().ok_or_else(|| {
        anyhow::anyhow!(
            "`{CODEX_ROOT}` in this config is not a table; patchbay will not rewrite it"
        )
    })?;
    // Implicit, so a fresh file renders `[mcp_servers.<name>]` rather than an
    // empty `[mcp_servers]` header followed by the child.
    root.set_implicit(true);

    if root.contains_key(name) && !overwrite {
        anyhow::bail!(
            "an MCP server called `{name}` is already registered here; \
             pass --force to replace it"
        );
    }
    root.insert(name, Item::Table(table));
    Ok(doc.to_string())
}

fn codex_remove(text: &str, name: &str, label: &str) -> anyhow::Result<String> {
    let mut doc = parse_toml(text)?;
    let root = doc
        .get_mut(CODEX_ROOT)
        .and_then(|i| i.as_table_mut())
        .ok_or_else(|| anyhow::anyhow!("{label} has no `[{CODEX_ROOT}]` block"))?;
    if root.remove(name).is_none() {
        anyhow::bail!("{label} has no MCP server called `{name}`");
    }
    Ok(doc.to_string())
}

// ---------------------------------------------------------------------------
// file plumbing
// ---------------------------------------------------------------------------

/// `<path>.patchbay-bak`. Suffix, not extension: `mcp.json.patchbay-bak` keeps
/// the original name visible, and `with_extension` would eat the `.json`.
pub fn backup_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(BACKUP_SUFFIX);
    PathBuf::from(name)
}

/// Copy the file aside before it is modified. A single rolling generation: the
/// undo for the write about to happen.
fn backup(path: &Path) -> anyhow::Result<Option<PathBuf>> {
    if !path.is_file() {
        return Ok(None);
    }
    let dest = backup_path(path);
    std::fs::copy(path, &dest).map_err(|e| {
        anyhow::anyhow!(
            "could not back {} up to {}: {e}; nothing was modified",
            path.display(),
            dest.display()
        )
    })?;
    Ok(Some(dest))
}

/// Temp file in the same directory, then rename. A crash mid-write leaves the
/// original untouched rather than a truncated config no client can parse.
fn write_atomic(path: &Path, body: &str) -> anyhow::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{} has no parent directory", path.display()))?;
    std::fs::create_dir_all(dir)
        .map_err(|e| anyhow::anyhow!("could not create {}: {e}", dir.display()))?;

    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("{} has no file name", path.display()))?
        .to_string_lossy()
        .into_owned();
    let tmp = dir.join(format!(".{file_name}.patchbay-tmp"));

    std::fs::write(&tmp, body)
        .map_err(|e| anyhow::anyhow!("could not write {}: {e}", tmp.display()))?;

    // Keep the file's own permissions; these configs hold API keys, and a new
    // one should not be born world-readable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .map(|m| m.permissions().mode() & 0o777)
            .unwrap_or(0o600);
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))
            .map_err(|e| anyhow::anyhow!("could not chmod {}: {e}", tmp.display()))?;
    }

    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        anyhow::anyhow!("could not replace {}: {e}", path.display())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixture home with whichever client files a test needs. Nothing here
    /// ever touches the real `$HOME`.
    struct Machine {
        _dir: tempfile::TempDir,
        home: PathBuf,
        registry: McpClientRegistry,
    }

    impl Machine {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let home = dir.path().to_path_buf();
            let registry = McpClientRegistry::with_paths(Paths::for_test(&home));
            Self {
                _dir: dir,
                home,
                registry,
            }
        }

        fn write(&self, rel: &str, body: &str) -> PathBuf {
            let path = self.home.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, body).unwrap();
            path
        }

        fn read(&self, rel: &str) -> String {
            std::fs::read_to_string(self.home.join(rel)).unwrap()
        }

        fn client(&self, key: &str) -> McpClient {
            self.registry.client(key).unwrap()
        }
    }

    const CLAUDE_CODE: &str = r#"{
  "numStartups": 42,
  "mcpServers": {
    "grafana": {
      "type": "stdio",
      "command": "uvx",
      "args": ["mcp-grafana"],
      "env": { "GRAFANA_URL": "https://example.grafana.net", "GRAFANA_TOKEN": "glsa_secret" }
    },
    "resend": {
      "type": "http",
      "url": "https://mcp.resend.com/mcp",
      "headers": { "Authorization": "Bearer re_secret" }
    }
  },
  "projects": {
    "/Users/x/repo": {
      "allowedTools": [],
      "mcpServers": { "figma": { "command": "npx", "args": ["-y", "figma-mcp"] } }
    }
  }
}
"#;

    const CODEX: &str = r#"# Codex settings
model = "gpt-5.6-sol"

[mcp_servers.node_repl]
command = "/opt/node_repl"
args = []
startup_timeout_sec = 120

[mcp_servers.node_repl.env]
NODE_OPTIONS = "--max-old-space-size=4096"

[projects."/Users/x/repo"]
trust_level = "trusted"
"#;

    const CURSOR: &str = r#"{
  "mcpServers": {
    "Framelink": { "command": "npx", "args": ["-y", "figma-developer-mcp", "--figma-api-key=figd_secret", "--stdio"] }
  }
}
"#;

    const VSCODE: &str = r#"{
  "inputs": [{ "id": "token", "type": "promptString" }],
  "servers": {
    "github": { "type": "http", "url": "https://api.githubcopilot.com/mcp" }
  }
}
"#;

    const WINDSURF: &str = r#"{
  "mcpServers": {
    "remote": { "serverUrl": "https://example.com/mcp", "headers": { "API_KEY": "secret" } }
  }
}
"#;

    // --- detection ----------------------------------------------------------

    #[test]
    fn test_every_known_client_is_reported_even_when_absent() {
        let m = Machine::new();
        let clients = m.registry.clients();
        let keys: Vec<&str> = clients.iter().map(|c| c.client.as_str()).collect();
        assert_eq!(
            keys,
            vec![
                "claude-code",
                "claude-desktop",
                "cursor",
                "codex",
                "windsurf",
                "vscode"
            ]
        );
        assert!(clients.iter().all(|c| !c.present));
        assert!(clients.iter().all(|c| c.servers.is_empty()));
        // The path is still reported, so a caller can say where to put one.
        assert!(clients[0].config_path.ends_with(".claude.json"));
    }

    #[test]
    fn test_config_paths_are_the_documented_ones() {
        let m = Machine::new();
        let path = |k: &str| m.registry.config_path_of(k).unwrap();
        assert_eq!(path("claude-code"), m.home.join(".claude.json"));
        assert_eq!(
            path("claude-desktop"),
            m.home
                .join("Library/Application Support/Claude/claude_desktop_config.json")
        );
        assert_eq!(path("cursor"), m.home.join(".cursor/mcp.json"));
        assert_eq!(path("codex"), m.home.join(".codex/config.toml"));
        assert_eq!(
            path("windsurf"),
            m.home.join(".codeium/windsurf/mcp_config.json")
        );
        assert_eq!(
            path("vscode"),
            m.home
                .join("Library/Application Support/Code/User/mcp.json")
        );
    }

    #[test]
    fn test_codex_home_env_wins() {
        let paths = Paths::for_test("/nowhere").with_env("CODEX_HOME", "/custom/codex");
        let registry = McpClientRegistry::with_paths(paths);
        assert_eq!(
            registry.config_path_of("codex").unwrap(),
            PathBuf::from("/custom/codex/config.toml")
        );
    }

    #[test]
    fn test_unknown_client_error_lists_the_valid_keys() {
        let m = Machine::new();
        let err = m.registry.client("emacs").unwrap_err().to_string();
        assert!(err.contains("unknown MCP client `emacs`"), "{err}");
        assert!(err.contains("claude-code"), "{err}");
        assert!(err.contains("codex"), "{err}");
    }

    // --- parsing, per format ------------------------------------------------

    #[test]
    fn test_claude_code_reads_both_scopes_and_hides_every_value() {
        let m = Machine::new();
        m.write(".claude.json", CLAUDE_CODE);
        let client = m.client("claude-code");

        assert!(client.present);
        assert_eq!(client.servers.len(), 3);

        let grafana = &client.servers[0];
        assert_eq!(grafana.name, "grafana");
        assert_eq!(
            grafana.transport,
            McpTransport::Stdio {
                command: "uvx".into(),
                args_len: 1
            }
        );
        assert_eq!(grafana.scope.as_deref(), Some("user"));
        assert_eq!(grafana.env_keys, vec!["GRAFANA_URL", "GRAFANA_TOKEN"]);

        let resend = &client.servers[1];
        assert_eq!(
            resend.transport,
            McpTransport::Http {
                url: "https://mcp.resend.com/mcp".into()
            }
        );
        assert_eq!(resend.header_keys, vec!["Authorization"]);

        let figma = &client.servers[2];
        assert_eq!(figma.scope.as_deref(), Some("project:/Users/x/repo"));
        assert!(!figma.is_writable_scope());

        // The hard rule: no value from the file may appear in the report.
        let json = serde_json::to_string(&client).unwrap();
        for secret in ["glsa_secret", "re_secret", "https://example.grafana.net"] {
            assert!(!json.contains(secret), "`{secret}` leaked into {json}");
        }
    }

    #[test]
    fn test_codex_toml_is_parsed_into_the_same_shape() {
        let m = Machine::new();
        m.write(".codex/config.toml", CODEX);
        let client = m.client("codex");

        assert!(client.present);
        assert_eq!(client.servers.len(), 1);
        let entry = &client.servers[0];
        assert_eq!(entry.name, "node_repl");
        assert_eq!(
            entry.transport,
            McpTransport::Stdio {
                command: "/opt/node_repl".into(),
                args_len: 0
            }
        );
        assert_eq!(entry.env_keys, vec!["NODE_OPTIONS"]);
        assert!(entry.scope.is_none());
        // `[projects."…"]` tables are not MCP servers.
        assert!(!client.servers.iter().any(|s| s.name.contains("repo")));
    }

    #[test]
    fn test_cursor_args_are_counted_not_shown() {
        let m = Machine::new();
        m.write(".cursor/mcp.json", CURSOR);
        let client = m.client("cursor");
        assert_eq!(
            client.servers[0].transport,
            McpTransport::Stdio {
                command: "npx".into(),
                args_len: 4
            }
        );
        let json = serde_json::to_string(&client).unwrap();
        assert!(!json.contains("figd_secret"), "{json}");
    }

    #[test]
    fn test_vscode_uses_servers_not_mcpservers() {
        let m = Machine::new();
        m.write("Library/Application Support/Code/User/mcp.json", VSCODE);
        let client = m.client("vscode");
        assert_eq!(client.servers.len(), 1);
        assert_eq!(client.servers[0].name, "github");
        assert!(matches!(
            client.servers[0].transport,
            McpTransport::Http { .. }
        ));
    }

    #[test]
    fn test_windsurf_server_url_field_is_understood() {
        let m = Machine::new();
        m.write(".codeium/windsurf/mcp_config.json", WINDSURF);
        let client = m.client("windsurf");
        assert_eq!(
            client.servers[0].transport,
            McpTransport::Http {
                url: "https://example.com/mcp".into()
            }
        );
        assert_eq!(client.servers[0].header_keys, vec!["API_KEY"]);
    }

    #[test]
    fn test_sse_type_is_kept_apart_from_http() {
        let m = Machine::new();
        m.write(
            ".cursor/mcp.json",
            r#"{"mcpServers":{"s":{"type":"sse","url":"https://e/sse"}}}"#,
        );
        assert_eq!(
            m.client("cursor").servers[0].transport,
            McpTransport::Sse {
                url: "https://e/sse".into()
            }
        );
    }

    #[test]
    fn test_a_broken_config_is_a_note_not_a_blank_board() {
        let m = Machine::new();
        m.write(".cursor/mcp.json", "{ not json");
        let client = m.client("cursor");
        assert!(client.present);
        assert!(client.servers.is_empty());
        assert!(client.notes[0].contains("not readable JSON"), "{client:?}");

        // And one broken client does not take the others with it.
        m.write(".claude.json", CLAUDE_CODE);
        let all = m.registry.clients();
        assert_eq!(
            all.iter()
                .find(|c| c.client == "claude-code")
                .unwrap()
                .servers
                .len(),
            3
        );
    }

    #[test]
    fn test_a_non_object_entry_is_skipped_with_a_note() {
        let m = Machine::new();
        m.write(".cursor/mcp.json", r#"{"mcpServers":{"bad":"nope"}}"#);
        let client = m.client("cursor");
        assert!(client.servers.is_empty());
        assert!(client.notes[0].contains("skipped `bad`"), "{client:?}");
    }

    #[test]
    fn test_an_empty_config_file_is_not_an_error() {
        let m = Machine::new();
        m.write(".cursor/mcp.json", "");
        let client = m.client("cursor");
        assert!(client.present);
        assert!(client.notes.is_empty());
        assert!(client.servers.is_empty());
    }

    // --- add ----------------------------------------------------------------

    #[test]
    fn test_add_preserves_unknown_keys_and_the_other_servers() {
        let m = Machine::new();
        m.write(".claude.json", CLAUDE_CODE);
        let report = m
            .registry
            .add_server(
                "claude-code",
                "patchbay",
                &ServerSpec::stdio("/usr/local/bin/patchbay-mcp", vec![]),
                false,
            )
            .unwrap();

        let raw = m.read(".claude.json");
        let root: Value = serde_json::from_str(&raw).unwrap();
        // Untouched: the unrelated top-level key, and the project scope.
        assert_eq!(root["numStartups"], 42);
        assert!(root["projects"]["/Users/x/repo"]["mcpServers"]["figma"].is_object());
        assert_eq!(root["mcpServers"]["grafana"]["command"], "uvx");
        assert_eq!(
            root["mcpServers"]["patchbay"]["command"],
            "/usr/local/bin/patchbay-mcp"
        );
        // Claude Code understands the discriminator, so it is written.
        assert_eq!(root["mcpServers"]["patchbay"]["type"], "stdio");

        // Key order survived: `preserve_order` keeps the file diffable.
        let keys: Vec<&str> = root
            .as_object()
            .unwrap()
            .keys()
            .map(|k| k.as_str())
            .collect();
        assert_eq!(keys, vec!["numStartups", "mcpServers", "projects"]);

        assert!(!report.created_file);
        assert_eq!(report.backup_path, Some(backup_path(&report.config_path)));
        assert!(report.notes.iter().any(|n| n.contains("restart")));
    }

    #[test]
    fn test_add_creates_a_missing_config_with_a_backup_free_report() {
        let m = Machine::new();
        let report = m
            .registry
            .add_server(
                "windsurf",
                "patchbay",
                &ServerSpec::stdio("patchbay-mcp", vec!["--stdio".into()]),
                false,
            )
            .unwrap();

        assert!(report.created_file);
        assert_eq!(report.backup_path, None);
        let raw = m.read(".codeium/windsurf/mcp_config.json");
        let root: Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(root["mcpServers"]["patchbay"]["command"], "patchbay-mcp");
        // Windsurf does not use the type discriminator.
        assert!(root["mcpServers"]["patchbay"].get("type").is_none());
    }

    #[test]
    fn test_add_refuses_a_duplicate_unless_forced() {
        let m = Machine::new();
        m.write(".cursor/mcp.json", CURSOR);
        let spec = ServerSpec::stdio("other", vec![]);
        let err = m
            .registry
            .add_server("cursor", "Framelink", &spec, false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("already registered"), "{err}");
        assert!(err.contains("--force"), "{err}");
        // Nothing changed.
        assert_eq!(m.read(".cursor/mcp.json"), CURSOR);

        m.registry
            .add_server("cursor", "Framelink", &spec, true)
            .unwrap();
        let client = m.client("cursor");
        assert_eq!(client.servers.len(), 1);
        assert_eq!(
            client.servers[0].transport,
            McpTransport::Stdio {
                command: "other".into(),
                args_len: 0
            }
        );
    }

    #[test]
    fn test_add_rejects_only_names_no_config_could_round_trip() {
        let m = Machine::new();
        let spec = ServerSpec::stdio("x", vec![]);
        for bad in ["", "   ", " leading", "trailing ", "new\nline"] {
            assert!(
                m.registry.add_server("cursor", bad, &spec, false).is_err(),
                "`{bad}` should be rejected"
            );
        }
        assert!(!m.home.join(".cursor/mcp.json").exists());
    }

    #[test]
    fn test_a_name_with_spaces_survives_both_formats() {
        // Cursor really does ship servers called "Framelink Figma MCP"; a copy
        // has to be able to carry that name into a TOML table key.
        let m = Machine::new();
        m.write(".cursor/mcp.json", CURSOR);
        m.registry
            .copy_server(
                "Framelink",
                "cursor",
                &["codex".to_string(), "vscode".to_string()],
                false,
            )
            .unwrap();

        let name = "Framelink Figma MCP";
        m.registry
            .add_server("cursor", name, &ServerSpec::stdio("npx", vec![]), false)
            .unwrap();
        m.registry
            .copy_server(name, "cursor", &["codex".to_string()], false)
            .unwrap();

        let raw = m.read(".codex/config.toml");
        assert!(
            raw.contains(r#"[mcp_servers."Framelink Figma MCP"]"#),
            "{raw}"
        );
        assert!(raw.parse::<DocumentMut>().is_ok(), "{raw}");
        assert!(m.client("codex").servers.iter().any(|s| s.name == name));
    }

    #[test]
    fn test_add_to_codex_keeps_comments_and_layout() {
        let m = Machine::new();
        m.write(".codex/config.toml", CODEX);
        m.registry
            .add_server(
                "codex",
                "patchbay",
                &ServerSpec::stdio("patchbay-mcp", vec!["--stdio".into()])
                    .env(vec![("PATCHBAY_MODE".into(), "read".into())]),
                false,
            )
            .unwrap();

        let raw = m.read(".codex/config.toml");
        assert!(raw.starts_with("# Codex settings"), "{raw}");
        assert!(raw.contains("model = \"gpt-5.6-sol\""), "{raw}");
        assert!(raw.contains("startup_timeout_sec = 120"), "{raw}");
        assert!(raw.contains("[projects.\"/Users/x/repo\"]"), "{raw}");
        assert!(raw.contains("[mcp_servers.patchbay]"), "{raw}");
        assert!(raw.contains("[mcp_servers.patchbay.env]"), "{raw}");
        assert!(raw.contains("PATCHBAY_MODE = \"read\""), "{raw}");
        // The parent table stays implicit: no bare `[mcp_servers]` header.
        assert!(!raw.contains("\n[mcp_servers]\n"), "{raw}");

        let client = m.client("codex");
        assert_eq!(client.servers.len(), 2);
    }

    #[test]
    fn test_add_to_a_fresh_codex_file_renders_a_valid_table() {
        let m = Machine::new();
        m.registry
            .add_server(
                "codex",
                "patchbay",
                &ServerSpec::stdio("patchbay-mcp", vec![]),
                false,
            )
            .unwrap();
        let raw = m.read(".codex/config.toml");
        assert!(raw.contains("[mcp_servers.patchbay]"), "{raw}");
        assert!(raw.parse::<DocumentMut>().is_ok(), "{raw}");
        assert_eq!(m.client("codex").servers.len(), 1);
    }

    #[test]
    fn test_add_writes_an_http_server_per_dialect() {
        let m = Machine::new();
        let spec = ServerSpec::http("https://mcp.example.com/mcp")
            .headers(vec![("Authorization".into(), "Bearer t".into())]);

        m.registry
            .add_server("vscode", "remote", &spec, false)
            .unwrap();
        let vscode: Value =
            serde_json::from_str(&m.read("Library/Application Support/Code/User/mcp.json"))
                .unwrap();
        assert_eq!(vscode["servers"]["remote"]["type"], "http");
        assert_eq!(
            vscode["servers"]["remote"]["url"],
            "https://mcp.example.com/mcp"
        );

        m.registry
            .add_server("windsurf", "remote", &spec, false)
            .unwrap();
        let windsurf: Value =
            serde_json::from_str(&m.read(".codeium/windsurf/mcp_config.json")).unwrap();
        // Windsurf's own spelling.
        assert_eq!(
            windsurf["mcpServers"]["remote"]["serverUrl"],
            "https://mcp.example.com/mcp"
        );
        assert_eq!(
            windsurf["mcpServers"]["remote"]["headers"]["Authorization"],
            "Bearer t"
        );
    }

    // --- remove -------------------------------------------------------------

    #[test]
    fn test_remove_takes_only_the_named_server() {
        let m = Machine::new();
        m.write(".claude.json", CLAUDE_CODE);
        let report = m.registry.remove_server("claude-code", "grafana").unwrap();

        let client = m.client("claude-code");
        let names: Vec<&str> = client.servers.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["resend", "figma"]);
        assert_eq!(report.backup_path, Some(backup_path(&report.config_path)));
        // The backup still has it: that is the undo.
        let backup: Value =
            serde_json::from_str(&std::fs::read_to_string(report.backup_path.unwrap()).unwrap())
                .unwrap();
        assert!(backup["mcpServers"]["grafana"].is_object());
    }

    #[test]
    fn test_remove_refuses_to_touch_a_project_scope_and_says_why() {
        let m = Machine::new();
        m.write(".claude.json", CLAUDE_CODE);
        let err = m
            .registry
            .remove_server("claude-code", "figma")
            .unwrap_err()
            .to_string();
        assert!(err.contains("PROJECT scope"), "{err}");
        assert!(err.contains("user scope"), "{err}");
        // Untouched.
        assert_eq!(m.client("claude-code").servers.len(), 3);
    }

    #[test]
    fn test_remove_unknown_server_is_a_clear_error() {
        let m = Machine::new();
        m.write(".cursor/mcp.json", CURSOR);
        let err = m
            .registry
            .remove_server("cursor", "ghost")
            .unwrap_err()
            .to_string();
        assert!(err.contains("no MCP server called `ghost`"), "{err}");

        let err = m
            .registry
            .remove_server("vscode", "ghost")
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not exist"), "{err}");
    }

    #[test]
    fn test_remove_from_codex_keeps_the_rest_of_the_file() {
        let m = Machine::new();
        m.write(".codex/config.toml", CODEX);
        m.registry.remove_server("codex", "node_repl").unwrap();
        let raw = m.read(".codex/config.toml");
        assert!(!raw.contains("mcp_servers"), "{raw}");
        assert!(raw.starts_with("# Codex settings"), "{raw}");
        assert!(raw.contains("[projects.\"/Users/x/repo\"]"), "{raw}");
    }

    // --- copy ---------------------------------------------------------------

    #[test]
    fn test_copy_json_to_toml_translates_the_whole_definition() {
        let m = Machine::new();
        m.write(".claude.json", CLAUDE_CODE);
        m.write(".codex/config.toml", CODEX);

        let report = m
            .registry
            .copy_server("grafana", "claude-code", &["codex".to_string()], false)
            .unwrap();

        let raw = m.read(".codex/config.toml");
        assert!(raw.contains("[mcp_servers.grafana]"), "{raw}");
        assert!(raw.contains("command = \"uvx\""), "{raw}");
        assert!(raw.contains("args = [\"mcp-grafana\"]"), "{raw}");
        assert!(raw.contains("[mcp_servers.grafana.env]"), "{raw}");
        assert!(raw.contains("GRAFANA_TOKEN = \"glsa_secret\""), "{raw}");
        // Pre-existing content survived the translation.
        assert!(raw.contains("[mcp_servers.node_repl]"), "{raw}");
        assert!(raw.starts_with("# Codex settings"), "{raw}");

        // The report names what travelled, without repeating any value.
        assert_eq!(report.env_carried, vec!["GRAFANA_URL", "GRAFANA_TOKEN"]);
        assert_eq!(report.written.len(), 1);
        assert_eq!(report.written[0].client, "codex");
        assert!(!serde_json::to_string(&report)
            .unwrap()
            .contains("glsa_secret"));
    }

    #[test]
    fn test_copy_toml_to_json_translates_the_other_way() {
        let m = Machine::new();
        m.write(".codex/config.toml", CODEX);
        let report = m
            .registry
            .copy_server(
                "node_repl",
                "codex",
                &["cursor".to_string(), "claude-desktop".to_string()],
                false,
            )
            .unwrap();

        let cursor: Value = serde_json::from_str(&m.read(".cursor/mcp.json")).unwrap();
        assert_eq!(
            cursor["mcpServers"]["node_repl"]["command"],
            "/opt/node_repl"
        );
        assert_eq!(
            cursor["mcpServers"]["node_repl"]["env"]["NODE_OPTIONS"],
            "--max-old-space-size=4096"
        );
        assert!(m
            .home
            .join("Library/Application Support/Claude/claude_desktop_config.json")
            .exists());
        assert_eq!(report.written.len(), 2);
        assert_eq!(report.env_carried, vec!["NODE_OPTIONS"]);
    }

    #[test]
    fn test_copy_of_a_remote_server_carries_header_names_into_the_report() {
        let m = Machine::new();
        m.write(".claude.json", CLAUDE_CODE);
        let report = m
            .registry
            .copy_server("resend", "claude-code", &["cursor".to_string()], false)
            .unwrap();
        assert_eq!(report.header_carried, vec!["Authorization"]);
        assert!(report.env_carried.is_empty());
        assert!(report.summary.starts_with("http "), "{}", report.summary);

        let cursor: Value = serde_json::from_str(&m.read(".cursor/mcp.json")).unwrap();
        assert_eq!(
            cursor["mcpServers"]["resend"]["url"],
            "https://mcp.resend.com/mcp"
        );
        assert_eq!(
            cursor["mcpServers"]["resend"]["headers"]["Authorization"],
            "Bearer re_secret"
        );
    }

    #[test]
    fn test_copy_validates_every_target_before_writing_anything() {
        let m = Machine::new();
        m.write(".claude.json", CLAUDE_CODE);
        let err = m
            .registry
            .copy_server(
                "grafana",
                "claude-code",
                &["cursor".to_string(), "emacs".to_string()],
                false,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown MCP client `emacs`"), "{err}");
        // The valid target was not written either.
        assert!(!m.home.join(".cursor/mcp.json").exists());
    }

    #[test]
    fn test_copy_refuses_an_existing_target_name_unless_forced() {
        let m = Machine::new();
        m.write(".claude.json", CLAUDE_CODE);
        m.write(
            ".cursor/mcp.json",
            r#"{"mcpServers":{"grafana":{"command":"old"}}}"#,
        );
        let err = m
            .registry
            .copy_server("grafana", "claude-code", &["cursor".to_string()], false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("already has an MCP server"), "{err}");
        assert!(err.contains("--force"), "{err}");

        m.registry
            .copy_server("grafana", "claude-code", &["cursor".to_string()], true)
            .unwrap();
        assert_eq!(
            m.client("cursor").servers[0].transport,
            McpTransport::Stdio {
                command: "uvx".into(),
                args_len: 1
            }
        );
    }

    #[test]
    fn test_copy_rejects_a_self_copy_and_a_repeated_target() {
        let m = Machine::new();
        m.write(".claude.json", CLAUDE_CODE);
        let err = m
            .registry
            .copy_server(
                "grafana",
                "claude-code",
                &["claude-code".to_string()],
                false,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("both the source and a target"), "{err}");

        let err = m
            .registry
            .copy_server(
                "grafana",
                "claude-code",
                &["cursor".to_string(), "cursor".to_string()],
                false,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("listed twice"), "{err}");

        let err = m
            .registry
            .copy_server("grafana", "claude-code", &[], false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("no target client"), "{err}");
    }

    #[test]
    fn test_copy_never_reads_a_project_scoped_server() {
        let m = Machine::new();
        m.write(".claude.json", CLAUDE_CODE);
        let err = m
            .registry
            .copy_server("figma", "claude-code", &["cursor".to_string()], false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("user scope"), "{err}");
    }

    #[test]
    fn test_copy_of_an_sse_server_into_codex_is_flagged() {
        let m = Machine::new();
        m.write(
            ".cursor/mcp.json",
            r#"{"mcpServers":{"s":{"type":"sse","url":"https://e/sse"}}}"#,
        );
        let report = m
            .registry
            .copy_server("s", "cursor", &["codex".to_string()], false)
            .unwrap();
        assert!(
            report.written[0]
                .notes
                .iter()
                .any(|n| n.contains("no separate SSE transport")),
            "{report:?}"
        );
        assert!(m
            .read(".codex/config.toml")
            .contains("url = \"https://e/sse\""));
    }

    // --- write safety -------------------------------------------------------

    #[test]
    fn test_the_backup_is_the_file_as_it_was_and_rolls_over() {
        let m = Machine::new();
        let path = m.write(".cursor/mcp.json", CURSOR);
        let spec = ServerSpec::stdio("a", vec![]);

        m.registry
            .add_server("cursor", "one", &spec, false)
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(backup_path(&path)).unwrap(),
            CURSOR,
            "the first backup is the original file"
        );

        let after_first = std::fs::read_to_string(&path).unwrap();
        m.registry
            .add_server("cursor", "two", &spec, false)
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(backup_path(&path)).unwrap(),
            after_first,
            "the backup rolls: one generation, always the state before this write"
        );
    }

    #[test]
    fn test_a_failed_write_leaves_the_file_untouched() {
        let m = Machine::new();
        // `mcpServers` present but not an object: refused rather than replaced.
        m.write(".cursor/mcp.json", r#"{"mcpServers": "nonsense"}"#);
        let err = m
            .registry
            .add_server("cursor", "x", &ServerSpec::stdio("a", vec![]), false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not a JSON object"), "{err}");
        assert_eq!(m.read(".cursor/mcp.json"), r#"{"mcpServers": "nonsense"}"#);
        // The backup is only taken once the new content is in hand.
        assert!(!m.home.join(".cursor/mcp.json.patchbay-bak").exists());
    }

    #[test]
    fn test_no_temp_file_is_left_behind() {
        let m = Machine::new();
        m.write(".cursor/mcp.json", CURSOR);
        m.registry
            .add_server("cursor", "x", &ServerSpec::stdio("a", vec![]), false)
            .unwrap();
        let leftovers: Vec<String> = std::fs::read_dir(m.home.join(".cursor"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains("patchbay-tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[cfg(unix)]
    #[test]
    fn test_a_created_config_is_owner_only_and_an_existing_mode_survives() {
        use std::os::unix::fs::PermissionsExt;
        let m = Machine::new();
        m.registry
            .add_server("cursor", "x", &ServerSpec::stdio("a", vec![]), false)
            .unwrap();
        let mode = std::fs::metadata(m.home.join(".cursor/mcp.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "mode was {mode:o}");

        let path = m.write(".codeium/windsurf/mcp_config.json", "{}");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        m.registry
            .add_server("windsurf", "x", &ServerSpec::stdio("a", vec![]), false)
            .unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "an existing mode must survive; was {mode:o}");
    }

    #[test]
    fn test_round_trip_add_then_remove_restores_the_file() {
        let m = Machine::new();
        m.write(".claude.json", CLAUDE_CODE);
        let before: Value = serde_json::from_str(&m.read(".claude.json")).unwrap();

        m.registry
            .add_server(
                "claude-code",
                "patchbay",
                &ServerSpec::stdio("patchbay-mcp", vec![]),
                false,
            )
            .unwrap();
        m.registry.remove_server("claude-code", "patchbay").unwrap();

        let after: Value = serde_json::from_str(&m.read(".claude.json")).unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn test_a_single_line_config_stays_single_line() {
        let m = Machine::new();
        let compact = r#"{"mcpServers":{"a":{"command":"a"}}}"#;
        m.write(".cursor/mcp.json", compact);
        m.registry
            .add_server("cursor", "b", &ServerSpec::stdio("b", vec![]), false)
            .unwrap();
        let raw = m.read(".cursor/mcp.json");
        assert_eq!(raw.lines().count(), 1, "{raw}");
    }

    // --- helpers ------------------------------------------------------------

    #[test]
    fn test_transport_summaries_are_value_free_and_short() {
        assert_eq!(
            McpTransport::Stdio {
                command: "/very/long/path/to/patchbay-mcp".into(),
                args_len: 0
            }
            .summary(),
            "stdio patchbay-mcp"
        );
        assert_eq!(
            McpTransport::Stdio {
                command: "npx".into(),
                args_len: 1
            }
            .summary(),
            "stdio npx (1 arg)"
        );
        assert_eq!(
            McpTransport::Stdio {
                command: "npx".into(),
                args_len: 4
            }
            .summary(),
            "stdio npx (4 args)"
        );
        assert_eq!(
            McpTransport::Http {
                url: "https://e/mcp".into()
            }
            .summary(),
            "http https://e/mcp"
        );
    }

    #[test]
    fn test_spec_keys_name_values_without_exposing_them() {
        let spec = ServerSpec::stdio("x", vec![])
            .env(vec![("TOKEN".into(), "secret".into())])
            .headers(vec![("Authorization".into(), "Bearer secret".into())]);
        assert_eq!(spec.env_keys(), vec!["TOKEN"]);
        assert_eq!(spec.header_keys(), vec!["Authorization"]);
        assert!(!spec.summary().contains("secret"));
    }

    #[test]
    fn test_backup_path_keeps_the_original_name_visible() {
        assert_eq!(
            backup_path(Path::new("/a/mcp.json")),
            PathBuf::from("/a/mcp.json.patchbay-bak")
        );
        assert_eq!(
            backup_path(Path::new("/a/config.toml")),
            PathBuf::from("/a/config.toml.patchbay-bak")
        );
    }
}
