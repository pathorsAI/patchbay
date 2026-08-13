//! `pb mcp …` — MCP client management in the terminal.
//!
//! The headline is `pb mcp list`: one matrix of every MCP server against every
//! AI client that has one, so "is patchbay registered in Cursor too?" is a
//! glance instead of four `cat`s in two formats.
//!
//! Values are never printed. An entry's environment variables and headers show
//! up as names, and a stdio command's arguments as a count — on a real machine
//! those fields hold `--figma-api-key=…` and `Authorization: Bearer …`.

use std::io::Write;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use patchbay_core::mcp_clients::{
    CopyReport, McpClient, McpClientRegistry, McpServerEntry, ServerSpec, TransportSpec,
    WriteReport,
};

use crate::render::{self, Styles};

/// Marks a registration in the matrix.
const TICK: &str = "✓";
/// Marks its absence.
const DASH: &str = "—";
const GAP: usize = 2;
const COL_NAME_MAX: usize = 28;

#[derive(Subcommand, Debug)]
pub enum Command {
    /// The matrix: every MCP server against every client that has one.
    List {
        /// Emit the full client list as JSON instead of a table.
        #[arg(long)]
        json: bool,
    },
    /// Register a server with one client.
    Add {
        /// Client key: `claude-code`, `claude-desktop`, `cursor`, `codex`,
        /// `windsurf`, `vscode`.
        client: String,
        /// Server name, as the client will show it.
        name: String,
        #[command(flatten)]
        spec: SpecArgs,
        /// Replace an existing server with the same name.
        #[arg(long)]
        force: bool,
    },
    /// Copy a server from one client to others, translating formats.
    Copy {
        /// Server name, as `pb mcp list` shows it.
        name: String,
        /// Client to copy it from.
        #[arg(long)]
        from: String,
        /// Clients to copy it to, comma-separated.
        #[arg(long, value_delimiter = ',', value_name = "CLIENT[,CLIENT…]")]
        to: Vec<String>,
        /// Replace servers of the same name in the targets.
        #[arg(long)]
        force: bool,
    },
    /// Unregister a server from one client.
    Rm {
        client: String,
        name: String,
        /// Skip the confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
}

/// How to reach the server. Either a command (stdio) or a URL (http/sse).
#[derive(Args, Debug)]
pub struct SpecArgs {
    /// Executable to launch for a stdio server.
    #[arg(long, value_name = "CMD", conflicts_with = "url")]
    command: Option<String>,
    /// Arguments for `--command`. Everything after it, hyphens included.
    #[arg(long, num_args = 1.., allow_hyphen_values = true, value_name = "ARG")]
    args: Vec<String>,
    /// Endpoint for a remote server.
    #[arg(long, value_name = "URL")]
    url: Option<String>,
    /// Remote transport. Default `http`.
    #[arg(long, value_name = "KIND", requires = "url")]
    transport: Option<String>,
    /// Environment variable, repeatable: `--env KEY=value`.
    ///
    /// Prefer referencing a name the client already has over pasting a secret
    /// here — this lands in your shell history verbatim.
    #[arg(long = "env", value_name = "KEY=VALUE")]
    env: Vec<String>,
    /// HTTP header, repeatable: `--header 'Authorization: Bearer …'`.
    #[arg(long = "header", value_name = "NAME: VALUE")]
    headers: Vec<String>,
}

impl SpecArgs {
    fn build(&self) -> Result<ServerSpec> {
        let transport = match (&self.command, &self.url) {
            (Some(command), None) => TransportSpec::Stdio {
                command: command.clone(),
                args: self.args.clone(),
            },
            (None, Some(url)) => match self.transport.as_deref().unwrap_or("http") {
                "http" => TransportSpec::Http { url: url.clone() },
                "sse" => TransportSpec::Sse { url: url.clone() },
                other => anyhow::bail!("unknown transport `{other}`; use `http` or `sse`"),
            },
            (Some(_), Some(_)) => anyhow::bail!("pass either --command or --url, not both"),
            (None, None) => anyhow::bail!(
                "nothing to register: pass --command <cmd> for a stdio server, \
                 or --url <url> for a remote one"
            ),
        };
        if self.command.is_none() && !self.args.is_empty() {
            anyhow::bail!("--args only means something with --command");
        }

        Ok(ServerSpec {
            transport,
            env: parse_pairs(&self.env, '=', "--env KEY=value")?,
            headers: parse_pairs(&self.headers, ':', "--header 'Name: value'")?,
        })
    }
}

fn parse_pairs(raw: &[String], sep: char, usage: &str) -> Result<Vec<(String, String)>> {
    raw.iter()
        .map(|item| {
            let (k, v) = item
                .split_once(sep)
                .ok_or_else(|| anyhow::anyhow!("`{item}` is not `{usage}`"))?;
            let k = k.trim();
            if k.is_empty() {
                anyhow::bail!("`{item}` has an empty name");
            }
            Ok((k.to_string(), v.trim().to_string()))
        })
        .collect()
}

/// Returns the process exit code.
pub fn run(command: Command, styles: &Styles) -> Result<i32> {
    let registry = McpClientRegistry::detect()?;

    match command {
        Command::List { json } => {
            let clients = registry.clients();
            if json {
                // Machine-readable: JSON only, no ANSI, no extras.
                println!("{}", serde_json::to_string_pretty(&clients)?);
                return Ok(0);
            }
            print!("{}", render_board(&clients, styles));
            Ok(0)
        }

        Command::Add {
            client,
            name,
            spec,
            force,
        } => {
            let spec = spec.build()?;
            let report = registry.add_server(&client, &name, &spec, force)?;
            println!("registered {} with {}", report.name, report.label);
            print_write(&report);
            if !spec.env.is_empty() {
                println!(
                    "  env set:  {} (values are now in that file in plain text)",
                    spec.env_keys().join(", ")
                );
            }
            if !spec.headers.is_empty() {
                println!("  headers:  {}", spec.header_keys().join(", "));
            }
            Ok(0)
        }

        Command::Copy {
            name,
            from,
            to,
            force,
        } => {
            let report = registry.copy_server(&name, &from, &to, force)?;
            print_copy(&report);
            Ok(0)
        }

        Command::Rm { client, name, yes } => {
            // Look first, so the prompt can say what is about to go.
            let found = registry.client(&client)?;
            let entry = found
                .servers
                .iter()
                .find(|s| s.name == name && s.is_writable_scope());
            match entry {
                Some(entry) => {
                    if !yes && !confirm(&found, entry)? {
                        println!("left {name} alone");
                        return Ok(0);
                    }
                }
                None if !yes => {
                    anyhow::bail!("{} has no MCP server called `{name}`", found.label);
                }
                None => {}
            }

            let report = registry.remove_server(&client, &name)?;
            println!("removed {} from {}", report.name, report.label);
            print_write(&report);
            println!("  the server itself still exists — this only unregisters it here");
            Ok(0)
        }
    }
}

/// `y`/`yes` on stdin. Anything else, including EOF, means no.
fn confirm(client: &McpClient, entry: &McpServerEntry) -> Result<bool> {
    print!(
        "remove {} ({}) from {}? [y/N] ",
        entry.name,
        entry.transport.summary(),
        client.label
    );
    std::io::stdout().flush().ok();
    let mut answer = String::new();
    if std::io::stdin()
        .read_line(&mut answer)
        .context("could not read the answer")?
        == 0
    {
        println!();
        return Ok(false);
    }
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

// ---------------------------------------------------------------------------
// output
// ---------------------------------------------------------------------------

fn print_write(report: &WriteReport) {
    println!("  config:   {}", render::tilde(&report.config_path));
    match &report.backup_path {
        Some(path) => println!("  backup:   {}", render::tilde(path)),
        None => println!("  backup:   none — the file did not exist yet"),
    }
    for note in &report.notes {
        println!("  note: {note}");
    }
}

fn print_copy(report: &CopyReport) {
    let targets: Vec<&str> = report.written.iter().map(|w| w.label.as_str()).collect();
    println!(
        "copied {} from {} to {}",
        report.name,
        report.from,
        targets.join(", ")
    );
    println!("  spec:     {}", report.summary);
    // The one thing the user must see: values travelled, not just names.
    if !report.env_carried.is_empty() {
        println!("  env vars copied: {}", report.env_carried.join(", "));
        println!("    their VALUES were copied too, in plain text, into each target file");
    }
    if !report.header_carried.is_empty() {
        println!("  headers copied:  {}", report.header_carried.join(", "));
        println!("    their VALUES were copied too — rotate them if a target is shared");
    }
    for write in &report.written {
        println!("  {}:", write.label);
        println!("    config: {}", render::tilde(&write.config_path));
        if let Some(path) = &write.backup_path {
            println!("    backup: {}", render::tilde(path));
        }
        for note in &write.notes {
            println!("    note: {note}");
        }
    }
}

fn pad(s: &str, width: usize) -> String {
    let len = s.chars().count();
    if len >= width {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(width - len))
    }
}

fn bold() -> anstyle::Style {
    anstyle::Style::new() | anstyle::Effects::BOLD
}

fn dim() -> anstyle::Style {
    anstyle::Style::new() | anstyle::Effects::DIMMED
}

/// Every server name across the configured clients, in a stable order.
fn server_names(clients: &[&McpClient]) -> Vec<String> {
    let mut names: Vec<String> = clients
        .iter()
        .flat_map(|c| c.servers.iter().map(|s| s.name.clone()))
        .collect();
    names.sort_by_key(|n| n.to_lowercase());
    names.dedup();
    names
}

/// The board: matrix on top, per-client detail below.
///
/// Only clients that actually have a config file become columns — six columns
/// of mostly dashes is not a board, it is a list of software the user does not
/// run. The absent ones get one line at the bottom, with the path they would
/// live at.
pub fn render_board(clients: &[McpClient], styles: &Styles) -> String {
    let present: Vec<&McpClient> = clients.iter().filter(|c| c.present).collect();
    let absent: Vec<&McpClient> = clients.iter().filter(|c| !c.present).collect();
    let mut out = String::new();

    if present.is_empty() {
        out.push_str("no MCP client config found on this machine\n");
        for client in &absent {
            out.push_str(&format!(
                "  {} would keep one at {}\n",
                client.label,
                render::tilde(&client.config_path)
            ));
        }
        return out;
    }

    let names = server_names(&present);
    if names.is_empty() {
        out.push_str("no MCP servers registered with any client\n");
    } else {
        let name_w = names
            .iter()
            .map(|n| n.chars().count().min(COL_NAME_MAX))
            .chain(std::iter::once("SERVER".len()))
            .max()
            .unwrap_or(6);
        let widths: Vec<usize> = present.iter().map(|c| c.client.chars().count()).collect();
        let gap = " ".repeat(GAP);

        let mut header = pad("SERVER", name_w);
        for (client, width) in present.iter().zip(&widths) {
            header.push_str(&gap);
            header.push_str(&pad(&client.client, *width));
        }
        out.push_str(&styles.paint(bold(), header.trim_end()));
        out.push('\n');

        for name in &names {
            let mut line = pad(&render::truncate(name, name_w), name_w);
            for (client, width) in present.iter().zip(&widths) {
                let hit = client.servers.iter().find(|s| &s.name == name);
                let cell = match hit {
                    Some(entry) if entry.is_writable_scope() => pad(TICK, *width),
                    // A project-scoped registration is real, but it is not the
                    // same thing as having it everywhere.
                    Some(_) => pad("proj", *width),
                    None => styles.paint(dim(), &pad(DASH, *width)),
                };
                line.push_str(&gap);
                line.push_str(&cell);
            }
            out.push_str(line.trim_end());
            out.push('\n');
        }
    }

    for client in &present {
        out.push('\n');
        out.push_str(&styles.paint(bold(), &format!("{} — {}", client.client, client.label)));
        out.push('\n');
        out.push_str(&format!("  {}\n", render::tilde(&client.config_path)));
        if client.servers.is_empty() {
            out.push_str(&format!("  {}\n", styles.paint(dim(), "no servers")));
        }
        for entry in &client.servers {
            let mut line = format!("  {}  {}", entry.name, entry.transport.summary());
            if let Some(scope) = &entry.scope {
                line.push_str(&format!("  [{scope}]"));
            }
            out.push_str(line.trim_end());
            out.push('\n');
            // Names only, always: this is where the tokens are.
            if !entry.env_keys.is_empty() {
                out.push_str(&format!(
                    "    {}\n",
                    styles.paint(dim(), &format!("env: {}", entry.env_keys.join(", ")))
                ));
            }
            if !entry.header_keys.is_empty() {
                out.push_str(&format!(
                    "    {}\n",
                    styles.paint(dim(), &format!("headers: {}", entry.header_keys.join(", ")))
                ));
            }
        }
        for note in &client.notes {
            out.push_str(&format!("  note: {note}\n"));
        }
    }

    if !absent.is_empty() {
        out.push('\n');
        out.push_str(&styles.paint(bold(), "no config"));
        out.push('\n');
        for client in &absent {
            out.push_str(&format!(
                "  {}: {}\n",
                client.client,
                render::tilde(&client.config_path)
            ));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use patchbay_core::mcp_clients::McpTransport;
    use std::path::PathBuf;

    fn entry(name: &str, scope: Option<&str>) -> McpServerEntry {
        McpServerEntry {
            name: name.to_string(),
            transport: McpTransport::Stdio {
                command: "uvx".into(),
                args_len: 1,
            },
            scope: scope.map(str::to_string),
            env_keys: vec!["GRAFANA_TOKEN".into()],
            header_keys: vec![],
        }
    }

    fn client(key: &str, present: bool, servers: Vec<McpServerEntry>) -> McpClient {
        McpClient {
            client: key.to_string(),
            label: key.to_uppercase(),
            config_path: PathBuf::from(format!("/home/u/.{key}.json")),
            present,
            servers,
            notes: vec![],
        }
    }

    #[test]
    fn test_matrix_marks_where_each_server_is_registered() {
        let clients = vec![
            client("claude-code", true, vec![entry("grafana", Some("user"))]),
            client(
                "cursor",
                true,
                vec![entry("grafana", None), entry("figma", None)],
            ),
            client("codex", false, vec![]),
        ];
        let out = render_board(&clients, &Styles::new(false));
        assert!(!out.contains('\u{1b}'), "plain mode must emit no ANSI");

        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].starts_with("SERVER"), "{out}");
        let figma = lines.iter().find(|l| l.starts_with("figma")).unwrap();
        let grafana = lines.iter().find(|l| l.starts_with("grafana")).unwrap();
        // figma is Cursor-only; grafana is in both.
        assert_eq!(figma.matches(TICK).count(), 1, "{out}");
        assert_eq!(grafana.matches(TICK).count(), 2, "{out}");
        assert!(figma.contains(DASH), "{out}");

        // The client with no config is not a column, it is a footnote.
        assert!(!lines[0].contains("codex"), "{out}");
        assert!(out.contains("no config"), "{out}");
        assert!(out.contains("  codex: /home/u/.codex.json"), "{out}");
    }

    #[test]
    fn test_a_project_scoped_registration_is_not_shown_as_a_plain_tick() {
        let clients = vec![client(
            "claude-code",
            true,
            vec![entry("figma", Some("project:/Users/x/repo"))],
        )];
        let out = render_board(&clients, &Styles::new(false));
        let row = out.lines().find(|l| l.starts_with("figma")).unwrap();
        assert!(row.contains("proj"), "{out}");
        assert!(!row.contains(TICK), "{out}");
        assert!(out.contains("[project:/Users/x/repo]"), "{out}");
    }

    #[test]
    fn test_detail_lines_name_env_vars_and_never_show_values() {
        let clients = vec![client("cursor", true, vec![entry("grafana", None)])];
        let out = render_board(&clients, &Styles::new(false));
        assert!(out.contains("grafana  stdio uvx (1 arg)"), "{out}");
        assert!(out.contains("env: GRAFANA_TOKEN"), "{out}");
    }

    #[test]
    fn test_an_empty_machine_says_where_configs_would_go() {
        let clients = vec![client("cursor", false, vec![])];
        let out = render_board(&clients, &Styles::new(false));
        assert!(out.contains("no MCP client config found"), "{out}");
        assert!(out.contains("/home/u/.cursor.json"), "{out}");
    }

    #[test]
    fn test_a_configured_client_with_no_servers_says_so() {
        let clients = vec![client("claude-desktop", true, vec![])];
        let out = render_board(&clients, &Styles::new(false));
        assert!(out.contains("no MCP servers registered"), "{out}");
        assert!(out.contains("no servers"), "{out}");
    }

    #[test]
    fn test_spec_args_build_stdio_http_and_sse() {
        let stdio = SpecArgs {
            command: Some("npx".into()),
            args: vec!["-y".into(), "server".into()],
            url: None,
            transport: None,
            env: vec!["TOKEN=abc".into()],
            headers: vec![],
        }
        .build()
        .unwrap();
        assert_eq!(
            stdio.transport,
            TransportSpec::Stdio {
                command: "npx".into(),
                args: vec!["-y".into(), "server".into()]
            }
        );
        assert_eq!(stdio.env, vec![("TOKEN".to_string(), "abc".to_string())]);

        let sse = SpecArgs {
            command: None,
            args: vec![],
            url: Some("https://e/sse".into()),
            transport: Some("sse".into()),
            env: vec![],
            headers: vec!["Authorization: Bearer t".into()],
        }
        .build()
        .unwrap();
        assert_eq!(
            sse.transport,
            TransportSpec::Sse {
                url: "https://e/sse".into()
            }
        );
        assert_eq!(
            sse.headers,
            vec![("Authorization".to_string(), "Bearer t".to_string())]
        );
    }

    #[test]
    fn test_spec_args_reject_nonsense() {
        let empty = SpecArgs {
            command: None,
            args: vec![],
            url: None,
            transport: None,
            env: vec![],
            headers: vec![],
        };
        assert!(empty.build().unwrap_err().to_string().contains("--command"));

        let bad_transport = SpecArgs {
            command: None,
            args: vec![],
            url: Some("https://e".into()),
            transport: Some("carrier-pigeon".into()),
            env: vec![],
            headers: vec![],
        };
        assert!(bad_transport
            .build()
            .unwrap_err()
            .to_string()
            .contains("unknown transport"));

        let bad_env = SpecArgs {
            command: Some("x".into()),
            args: vec![],
            url: None,
            transport: None,
            env: vec!["JUST_A_NAME".into()],
            headers: vec![],
        };
        assert!(bad_env
            .build()
            .unwrap_err()
            .to_string()
            .contains("KEY=value"));
    }

    #[test]
    fn test_env_values_may_contain_the_separator() {
        let pairs =
            parse_pairs(&["URL=https://a/b?x=1".to_string()], '=', "--env KEY=value").unwrap();
        assert_eq!(pairs[0].1, "https://a/b?x=1");
    }
}
