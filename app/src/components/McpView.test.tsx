import { render, screen } from "@testing-library/react";
import { invoke } from "@tauri-apps/api/core";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { McpView } from "./McpView";
import type { McpClient, McpServerEntry } from "../types";

/** Same boundary and the same reason as `KeysView.test.tsx` — see the note there. */
vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
const invoked = vi.mocked(invoke);

const timesAsked = (command: string) =>
  invoked.mock.calls.filter(([cmd]) => cmd === command).length;

const server = (name: string): McpServerEntry => ({
  name,
  scope: null,
  env_keys: [],
  header_keys: [],
  transport: "stdio",
  command: "/opt/homebrew/bin/pb",
  args_len: 1,
});

const client = (id: string, label: string, servers: McpServerEntry[]): McpClient => ({
  client: id,
  label,
  config_path: `/Users/dev/.config/${id}/config.json`,
  present: true,
  servers,
  notes: [],
});

beforeEach(() => {
  invoked.mockReset();
});

describe("McpView", () => {
  it("re-reads every client config when reload changes and draws the servers that came back", async () => {
    // Six config files edited by six other programs is the state that goes
    // stale while you look at it, and the header's refresh is the only thing
    // the user has to say so. Before the fix it moved the timestamp and left
    // this matrix exactly as it was on mount.
    invoked
      .mockResolvedValueOnce([client("claude-code", "Claude Code", [server("patchbay")])])
      .mockResolvedValueOnce([
        client("claude-code", "Claude Code", [server("patchbay"), server("grafana")]),
      ]);

    const { rerender } = render(<McpView reload={0} />);
    expect(await screen.findByText("patchbay")).toBeInTheDocument();
    expect(timesAsked("mcp_list")).toBe(1);

    rerender(<McpView reload={1} />);

    expect(await screen.findByText("grafana")).toBeInTheDocument();
    expect(timesAsked("mcp_list")).toBe(2);
    expect(screen.getByText("2 servers across 1 of 1 clients")).toBeInTheDocument();
  });

  it("leaves the matrix it already drew on screen and adds the error banner when a re-read fails", async () => {
    // The cold-start branch renders the banner *instead of* the view, which is
    // right when there is nothing to show and wrong on a refresh: one
    // unreadable config would replace a matrix that was fine a second ago.
    invoked
      .mockResolvedValueOnce([client("claude-code", "Claude Code", [server("patchbay")])])
      .mockRejectedValueOnce("mcp.json: permission denied");

    const { rerender } = render(<McpView reload={0} />);
    expect(await screen.findByText("patchbay")).toBeInTheDocument();

    rerender(<McpView reload={1} />);

    expect(await screen.findByText("mcp.json: permission denied")).toBeInTheDocument();
    expect(screen.getByRole("table")).toBeInTheDocument();
    expect(screen.getByText("patchbay")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "MCP clients" })).toBeInTheDocument();
  });
});
