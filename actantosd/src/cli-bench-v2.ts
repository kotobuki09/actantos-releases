import { formatPerformance, runPerformance } from "./v2/performance.ts";

/**
 * `npm run bench:v2` — measures the latency of each enforcement path.
 *
 * These are in-process numbers for the decision layer. They exclude the Unix domain socket
 * round trip a real sidecar adds, which the report says explicitly rather than burying.
 */

const iterationsArgument = process.argv.find((argument) =>
  argument.startsWith("--iterations="),
);

const iterations = iterationsArgument
  ? Number.parseInt(iterationsArgument.split("=")[1] ?? "2000", 10)
  : 2000;

const report = await runPerformance(Number.isFinite(iterations) ? iterations : 2000);

console.log(formatPerformance(report));