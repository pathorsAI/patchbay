import { defineConfig, mergeConfig } from "vitest/config";
import viteConfig from "./vite.config";

// Merged onto the real vite config rather than written standalone: the React
// plugin is declared once, so a test can never compile JSX under different
// settings than the app it is testing.
export default mergeConfig(
  viteConfig,
  defineConfig({
    test: {
      environment: "jsdom",
      // Registers the DOM matchers and tears the tree down between tests. The
      // suite imports `describe`/`it`/`expect` explicitly, so nothing here
      // depends on vitest globals.
      setupFiles: ["./src/test/setup.ts"],
      include: ["src/**/*.test.{ts,tsx}"],
    },
  }),
);
