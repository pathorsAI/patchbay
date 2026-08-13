import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const host = process.env.TAURI_DEV_HOST;

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],

  // Keep rust errors visible in `tauri dev`.
  clearScreen: false,
  server: {
    // Tauri expects a fixed port and fails loudly if it is taken. 1425/1426 to
    // stay clear of the 1420/1421 pair other Pathors Tauri apps use.
    port: 1425,
    strictPort: true,
    // Bind an explicit IPv4 address rather than `localhost`. Left to resolve,
    // `localhost` can bind ::1 only while the webview dials 127.0.0.1 (or the
    // reverse) — the connection is refused and the window comes up blank with
    // nothing in any log. `devUrl` in tauri.conf.json must match this exactly.
    host: host || "127.0.0.1",
    hmr: host ? { protocol: "ws", host, port: 1426 } : undefined,
    watch: { ignored: ["**/src-tauri/**"] },
  },
});
