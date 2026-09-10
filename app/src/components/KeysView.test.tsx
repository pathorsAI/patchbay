import { render, screen } from "@testing-library/react";
import { invoke } from "@tauri-apps/api/core";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { KeysView } from "./KeysView";
import type { KeyRow } from "../types";

/**
 * The mock sits on `invoke`, not on `../api`.
 *
 * `invoke` is the only thing genuinely missing from a test process — there is
 * no Tauri IPC here — so faking it fakes exactly the absent thing and leaves
 * every line of our own code running, `api.ts` included. Mocking `../api`
 * would stub out code we ship, and it would count calls to a wrapper rather
 * than trips to the backend; here a re-read is a second `keys_list`, spelled
 * the same way the Rust shell registers the handler.
 */
vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
const invoked = vi.mocked(invoke);

const timesAsked = (command: string) =>
  invoked.mock.calls.filter(([cmd]) => cmd === command).length;

const keyRow = (id: string, over: Partial<KeyRow> = {}): KeyRow => ({
  id,
  provider: "cloudflare",
  // Deliberately not the id: the id and the label are different columns, and a
  // query for the id should land on one cell rather than two.
  label: `${id} token`,
  purpose: null,
  scopes: [],
  created_at: "2026-01-01T00:00:00Z",
  expires_at: null,
  last4: "9f2c",
  source: "cli",
  env: null,
  expiry_state: "no_expiry",
  ...over,
});

beforeEach(() => {
  invoked.mockReset();
});

describe("KeysView", () => {
  it("re-reads the vault when reload changes and draws the rows that came back", async () => {
    // The bug this suite exists for: the header's refresh only re-fetched the
    // board, so the vault went on showing whatever it read on mount. Bumping
    // `reload` is all that button does to this view, so it has to reach the
    // backend a second time and repaint from the answer.
    invoked
      .mockResolvedValueOnce([keyRow("cf-deploy")])
      .mockResolvedValueOnce([keyRow("cf-deploy"), keyRow("neon-api", { provider: "neon" })]);

    const { rerender } = render(<KeysView reload={0} />);
    expect(await screen.findByText("cf-deploy")).toBeInTheDocument();
    expect(timesAsked("keys_list")).toBe(1);

    rerender(<KeysView reload={1} />);

    expect(await screen.findByText("neon-api")).toBeInTheDocument();
    expect(timesAsked("keys_list")).toBe(2);
    expect(screen.getByText("2 keys · metadata only")).toBeInTheDocument();
  });

  it("keeps the rows it already drew when a re-read fails", async () => {
    // A refresh that lands while `keys.json` is half-rewritten must not cost
    // the user the table they were already reading.
    invoked
      .mockResolvedValueOnce([keyRow("cf-deploy")])
      .mockRejectedValueOnce("keys.json: unexpected end of input");

    const { rerender } = render(<KeysView reload={0} />);
    expect(await screen.findByText("cf-deploy")).toBeInTheDocument();

    rerender(<KeysView reload={1} />);

    expect(await screen.findByText("keys.json: unexpected end of input")).toBeInTheDocument();
    expect(screen.getByText("cf-deploy")).toBeInTheDocument();
  });
});
