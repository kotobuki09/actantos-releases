#!/usr/bin/env node
import { runPreflight } from "./stage3-preflight-lib.mjs";

const modeArgument = process.argv.find((argument) => argument.startsWith("--mode="));
const mode = modeArgument?.slice("--mode=".length) || "offline";
const result = await runPreflight({ mode, env: process.env });
console.log(result.output);
process.exitCode = result.exitCode;
