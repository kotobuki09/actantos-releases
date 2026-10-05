/**
 * `actant emit-tetragon <signed-policy-bundle.json> <deployment.json>`
 *
 * Compiles a verified policy bundle into the Tetragon TracingPolicy YAML that the sidecar's
 * network cell loads. The deployment file supplies only what a bundle cannot express:
 *
 *   {
 *     "policyName": "actant-agent-reviewer",
 *     "deniedBinaries": ["/usr/bin/curl", "/usr/bin/wget"],
 *     "deniedWritePaths": ["/etc/shadow"],
 *     "mode": "observe"
 *   }
 *
 * This command does not verify the bundle signature. It compiles whatever bundle it is
 * given, so it must be fed a bundle that `verifyPolicyBundle` has already accepted; the
 * output is only as trustworthy as its input.
 */

import { readFileSync } from "node:fs"

import {
  runtimeProfileFromBundle,
  toTracingPolicyYaml,
  buildTracingPolicy,
} from "./v2/tetragon-policy.ts"
import { policyBundleBodySchema } from "./v2/signed-policy-bundle.ts"
import type { PolicyBundleBody } from "./v2/signed-policy-bundle.ts"

type Deployment = {
  readonly policyName: string
  readonly deniedBinaries: readonly string[]
  readonly deniedWritePaths: readonly string[]
  readonly mode?: "observe" | "enforce"
}

const fail = (message: string): never => {
  process.stderr.write(`emit-tetragon: ${message}\n`)
  process.exit(1)
}

const [bundlePath, deploymentPath] = process.argv.slice(2)

if (bundlePath === undefined || deploymentPath === undefined) {
  process.stderr.write(
    "usage: actant emit-tetragon <signed-policy-bundle.json> <deployment.json>\n",
  )
  process.exit(2)
}

/**
 * Read the policy bundle. Accepts either a signed bundle or a bare body, so the command can
 * be pointed at either artefact. Throws rather than exiting, so the caller reports every
 * input problem the same way.
 */
const readBundle = (path: string): PolicyBundleBody => {
  const raw: unknown = JSON.parse(readFileSync(path, "utf8"))
  const candidate =
    typeof raw === "object" && raw !== null && "body" in raw
      ? (raw as { body: unknown }).body
      : raw
  const parsed = policyBundleBodySchema.safeParse(candidate)

  if (!parsed.success) {
    throw new Error(`policy bundle body is invalid: ${parsed.error.message}`)
  }

  return parsed.data
}

const readDeployment = (path: string): Deployment =>
  JSON.parse(readFileSync(path, "utf8")) as Deployment

try {
  const body = readBundle(bundlePath)
  const deployment = readDeployment(deploymentPath)

  const profile = runtimeProfileFromBundle(body, {
    policyName: deployment.policyName,
    deniedBinaries: deployment.deniedBinaries ?? [],
    deniedWritePaths: deployment.deniedWritePaths ?? [],
    ...(deployment.mode === undefined ? {} : { mode: deployment.mode }),
  })

  process.stdout.write(toTracingPolicyYaml(buildTracingPolicy(profile)))
} catch (error) {
  fail((error as Error).message)
}