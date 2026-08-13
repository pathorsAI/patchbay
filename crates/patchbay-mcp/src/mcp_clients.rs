//! MCP client management's own MCP surface — patchbay editing the config files
//! that decide which MCP servers exist.
//!
//! The recursion is the point: an agent that just helped a user set up a server
//! can register it in every client they use, instead of dictating four JSON
//! snippets and hoping the paste lands in the right file.
//!
//! These tools are **not gated** the way the key vault's are. They touch config
//! files, not secrets, and everything they return is names-only. What they are
//! instead is *consequential*: a change here alters what tools another AI client
//! has on its next start. The descriptions say so, and say to ask before
//! removing anything.
//!
//! Kept in its own `#[tool_router]` impl block, merged into the main router in
//! [`crate::server`], the same way the vault's tools are.

use std::collections::BTreeMap;

use patchbay_core::mcp_clients::{ServerSpec, TransportSpec};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::{tool, tool_router, ErrorData};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::server::{encode, json_ok, offload, tool_error, PatchbayServer};

// ---------------------------------------------------------------------------
// parameters
// ---------------------------------------------------------------------------

/// The transport half of a registration, shared by `add` and validated once.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct AddMcpServerParams {
    /// Which client to write to: "claude-code", "claude-desktop", "cursor",
    /// "codex", "windsurf", "vscode". An unknown key returns an error listing
    /// every valid one.
    pub client: String,
    /// The name the server will appear under in that client. Use the same name
    /// the user's other clients use — `list_mcp_clients` shows what those are.
    pub name: String,
    /// Executable for a stdio server, e.g. "npx" or an absolute path. Give
    /// either this or `url`, never both.
    pub command: Option<String>,
    /// Arguments for `command`.
    pub args: Option<Vec<String>>,
    /// Endpoint for a remote server. Give either this or `command`.
    pub url: Option<String>,
    /// Remote transport: "http" (default) or "sse". Only meaningful with `url`.
    pub transport: Option<String>,
    /// Environment variables for the server process.
    ///
    /// These are written into the client's config file IN PLAIN TEXT. Never put
    /// a real secret here: pass the name of a variable the user's shell already
    /// exports, or register the secret with `store_key` and let the user wire it
    /// up. If a server genuinely needs a key inline, say so and let the user
    /// paste it themselves.
    pub env: Option<BTreeMap<String, String>>,
    /// HTTP headers for a remote server. Same rule as `env`, more so — this is
    /// where bearer tokens live. Do not put one here.
    pub headers: Option<BTreeMap<String, String>>,
    /// Replace an existing server of the same name. Default false. Only set
    /// this when the user asked to replace a specific server they know about.
    pub overwrite: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CopyMcpServerParams {
    /// The server to copy, exactly as `list_mcp_clients` reports it.
    pub name: String,
    /// The client to copy it FROM.
    pub from: String,
    /// The clients to copy it TO. Every target is checked before anything is
    /// written, so one bad name changes nothing.
    pub to: Vec<String>,
    /// Replace servers of the same name in the targets. Default false.
    pub overwrite: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RemoveMcpServerParams {
    /// The client to remove it from.
    pub client: String,
    /// The server to unregister.
    pub name: String,
}

impl AddMcpServerParams {
    fn spec(&self) -> anyhow::Result<ServerSpec> {
        let transport = match (&self.command, &self.url) {
            (Some(command), None) => TransportSpec::Stdio {
                command: command.clone(),
                args: self.args.clone().unwrap_or_default(),
            },
            (None, Some(url)) => match self.transport.as_deref().unwrap_or("http") {
                "http" | "streamable-http" => TransportSpec::Http { url: url.clone() },
                "sse" => TransportSpec::Sse { url: url.clone() },
                other => anyhow::bail!("unknown transport `{other}`; use \"http\" or \"sse\""),
            },
            (Some(_), Some(_)) => {
                anyhow::bail!("give either `command` (stdio) or `url` (remote), not both")
            }
            (None, None) => anyhow::bail!(
                "nothing to register: give `command` for a stdio server, or `url` for a remote one"
            ),
        };
        Ok(ServerSpec {
            transport,
            env: pairs(self.env.as_ref()),
            headers: pairs(self.headers.as_ref()),
        })
    }
}

fn pairs(map: Option<&BTreeMap<String, String>>) -> Vec<(String, String)> {
    map.map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// tools
// ---------------------------------------------------------------------------

#[tool_router(router = mcp_clients_router, vis = "pub(crate)")]
impl PatchbayServer {
    #[tool(description = "\
CHEAP, SAFE. Every MCP client on this machine and the MCP servers each one has registered. Reads \
a handful of local config files: no subprocess, no network, no secret values.

Call this before adding, copying or removing anything, and whenever the user asks what MCP servers \
they have, why a server is missing from one tool, or where a config lives. It is also the answer \
to 'is X set up everywhere?' — the same server is usually registered in some clients and not \
others, which is exactly the state this reports.

Returns a JSON array, one object per known client: { client, label, config_path, present, \
servers: [{ name, transport, command|url, args_len, scope, env_keys, header_keys }], notes }.

- `present: false` means that client has no config file here. The `config_path` is still reported, \
so you can tell the user where one would go.
- `scope` appears for Claude Code only: 'user' (the top-level config) or 'project:<path>'. patchbay \
READS both and WRITES only 'user' — a project's servers belong to that project.
- `env_keys` and `header_keys` are NAMES ONLY. Values are deliberately not returned: on a real \
machine those fields hold API keys. `args_len` is a count for the same reason — a command's \
arguments routinely carry `--api-key=…`.
- `notes` explains anything patchbay could not parse. A malformed config never blanks the board.")]
    async fn list_mcp_clients(&self) -> Result<CallToolResult, ErrorData> {
        let clients = self.clients.clone();
        let found = offload(move || clients.clients()).await?;
        Ok(json_ok(encode(&found)?))
    }

    #[tool(description = "\
MODIFIES ANOTHER AI TOOL'S CONFIG. Register an MCP server with one client on this machine.

The change lands in that client's own config file and takes effect on its NEXT start — the \
session the user has open right now will not see it, and Claude Code rewrites ~/.claude.json when \
it exits, so tell the user to restart it rather than expecting a live update.

Before calling: run `list_mcp_clients` to see the name conventions already in use and whether the \
server is registered elsewhere. If it IS registered with another client, prefer `copy_mcp_server` \
— it carries the whole definition across and translates the format, instead of you retyping a \
command you are half-remembering.

NEVER put a secret in `env` or `headers`. They are written to the config file in plain text, and \
that file is neither encrypted nor mode-restricted by the client that owns it. Reference an \
environment variable the user's shell already exports, or register the secret with `store_key` and \
tell the user which value to paste in themselves. If you find yourself about to inline an API key \
you were given in chat, stop and hand the step back to the user.

Safety: the config file is copied to <path>.patchbay-bak first, the write is atomic, and every \
other key in the file — other servers, unrelated settings, TOML comments — is preserved. An \
existing name is an error unless `overwrite: true`.

Returns { client, label, name, config_path, backup_path, created_file, notes }. Relay `notes` \
verbatim: they carry the restart requirement and any limitation of the target format.")]
    async fn add_mcp_server(
        &self,
        Parameters(params): Parameters<AddMcpServerParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let spec = match params.spec() {
            Ok(spec) => spec,
            Err(e) => return Ok(tool_error(e)),
        };
        let clients = self.clients.clone();
        let overwrite = params.overwrite.unwrap_or(false);
        let (client, name) = (params.client, params.name);
        match offload(move || clients.add_server(&client, &name, &spec, overwrite)).await? {
            Ok(report) => Ok(json_ok(encode(&report)?)),
            Err(err) => Ok(tool_error(err)),
        }
    }

    #[tool(description = "\
MODIFIES OTHER AI TOOLS' CONFIGS. Copy one MCP server from the client that has it into one or more \
clients that do not, translating between config formats on the way (a JSON `mcpServers` entry \
becomes a `[mcp_servers.<name>]` TOML table for Codex, and back).

This is the right tool for 'set this up in Cursor too' and 'why do I have this in Claude Code but \
not in Codex'. Prefer it over `add_mcp_server` whenever the server already exists somewhere: the \
command, arguments, URL, environment and headers come across exactly as they are, so the copy \
cannot drift from the original.

VALUES TRAVEL. Environment variables and headers are copied with their values, because a server \
that cannot authenticate is not a working server. The result names them in `env_carried` and \
`header_carried` — tell the user which ones landed in which file, so they can decide whether a \
token they thought lived in one place now living in three is acceptable. It is not your call to \
make silently.

Each target is validated before anything is written, so a bad client name leaves every file \
untouched. An existing name in a target is an error unless `overwrite: true`. Every file written \
is backed up to <path>.patchbay-bak first.

Returns { name, from, summary, env_carried, header_carried, written: [...] }. Every target picks \
the change up on its next start.")]
    async fn copy_mcp_server(
        &self,
        Parameters(params): Parameters<CopyMcpServerParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let clients = self.clients.clone();
        let overwrite = params.overwrite.unwrap_or(false);
        let CopyMcpServerParams { name, from, to, .. } = params;
        match offload(move || clients.copy_server(&name, &from, &to, overwrite)).await? {
            Ok(report) => Ok(json_ok(encode(&report)?)),
            Err(err) => Ok(tool_error(err)),
        }
    }

    #[tool(description = "\
DESTRUCTIVE, AND IT CHANGES ANOTHER AI TOOL. Unregister an MCP server from one client's config.

ASK THE USER FIRST, by client and server name, and wait for an answer. Do not call this on your \
own initiative, do not bundle it into a larger task, and do not use it to 'clean up' something \
that looks unused — a server you do not recognise is far more likely to be one you have not seen \
before than one nobody wants. The user loses the command, arguments and environment that entry \
held; patchbay keeps a single <path>.patchbay-bak generation, which the next write overwrites.

Removing an entry does NOT uninstall or revoke anything. The server keeps existing, its API keys \
keep working, and other clients keep using it — this only stops THIS client launching it, from \
its next start.

Claude Code's project scopes are refused deliberately: patchbay writes the user scope only, and \
the error will say so. Point the user at their project's own config rather than working around it.

Returns the same shape as add_mcp_server, including where the backup went.")]
    async fn remove_mcp_server(
        &self,
        Parameters(RemoveMcpServerParams { client, name }): Parameters<RemoveMcpServerParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let clients = self.clients.clone();
        match offload(move || clients.remove_server(&client, &name)).await? {
            Ok(report) => Ok(json_ok(encode(&report)?)),
            Err(err) => Ok(tool_error(err)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(
        command: Option<&str>,
        url: Option<&str>,
        transport: Option<&str>,
    ) -> AddMcpServerParams {
        AddMcpServerParams {
            client: "cursor".into(),
            name: "x".into(),
            command: command.map(str::to_string),
            args: None,
            url: url.map(str::to_string),
            transport: transport.map(str::to_string),
            env: None,
            headers: None,
            overwrite: None,
        }
    }

    #[test]
    fn test_a_stdio_spec_needs_only_a_command() {
        let spec = params(Some("npx"), None, None).spec().unwrap();
        assert_eq!(
            spec.transport,
            TransportSpec::Stdio {
                command: "npx".into(),
                args: vec![]
            }
        );
    }

    #[test]
    fn test_remote_transports_default_to_http() {
        let spec = params(None, Some("https://e/mcp"), None).spec().unwrap();
        assert_eq!(
            spec.transport,
            TransportSpec::Http {
                url: "https://e/mcp".into()
            }
        );
        let spec = params(None, Some("https://e/sse"), Some("sse"))
            .spec()
            .unwrap();
        assert_eq!(
            spec.transport,
            TransportSpec::Sse {
                url: "https://e/sse".into()
            }
        );
        // The name the MCP spec uses for the same thing.
        assert!(params(None, Some("https://e"), Some("streamable-http"))
            .spec()
            .is_ok());
    }

    #[test]
    fn test_an_ambiguous_or_empty_spec_is_refused_with_a_usable_message() {
        let err = params(Some("npx"), Some("https://e"), None)
            .spec()
            .unwrap_err()
            .to_string();
        assert!(err.contains("not both"), "{err}");

        let err = params(None, None, None).spec().unwrap_err().to_string();
        assert!(err.contains("nothing to register"), "{err}");

        let err = params(None, Some("https://e"), Some("carrier-pigeon"))
            .spec()
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown transport"), "{err}");
    }

    #[test]
    fn test_env_and_headers_reach_the_spec_and_are_reported_by_name() {
        let mut p = params(Some("npx"), None, None);
        p.env = Some(BTreeMap::from([(
            "TOKEN".to_string(),
            "secret".to_string(),
        )]));
        p.headers = Some(BTreeMap::from([(
            "Authorization".to_string(),
            "Bearer secret".to_string(),
        )]));
        let spec = p.spec().unwrap();
        assert_eq!(spec.env_keys(), vec!["TOKEN"]);
        assert_eq!(spec.header_keys(), vec!["Authorization"]);
        // The summary is what gets echoed back to a user; it must stay clean.
        assert!(!spec.summary().contains("secret"), "{}", spec.summary());
    }
}
