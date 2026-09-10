import { afterEach } from "vitest";
import { cleanup } from "@testing-library/react";
// Teaches `expect` the DOM matchers (`toBeInTheDocument` and friends).
import "@testing-library/jest-dom/vitest";

// Testing Library only installs its own auto-cleanup when the runner's hooks
// are globals, and this suite imports them instead. Without this every test
// would render into the document the previous one left behind, and a query for
// a row would find the stale copy.
afterEach(cleanup);
