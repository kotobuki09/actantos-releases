import assert from "node:assert/strict"
import { execFileSync } from "node:child_process"
import test from "node:test"

import { EGRESS_CELL_NETWORK } from "./egress-cell.ts"

/**
 * The cell's real-substrate evidence (invariant S2, phase G).
 *
 * Everything else in phase G is the proxy deciding whether to allow a connection. That is half the
 * claim. The other half is that the workload has no way to reach the proxy *except* by going
 * through it — and that is a property of the Docker network, not of any TypeScript in this
 * repository. No amount of testing `egress-proxy.ts` can establish it.
 *
 * So these tests run real containers on a real internal network and observe what the kernel does.
 * They are gated on Docker being usable; when it is not they skip with a reason, and the skip is
 * registered in `SUBSTRATE_REQUIREMENTS` so it cannot be mistaken for coverage.
 */

const PROBE_IMAGE = "alpine:3.20"

const dockerAvailable = (): boolean => {
  try {
    execFileSync("docker", ["version", "--format", "{{.Server.Version}}"], {
      stdio: ["ignore", "ignore", "ignore"],
      timeout: 20_000,
    })
    return true
  } catch {
    return false
  }
}

const SKIP = dockerAvailable() ? false : "docker is unavailable in this environment"

const docker = (args: readonly string[], timeoutMs = 120_000): string =>
  execFileSync("docker", args, {
    encoding: "utf8",
    timeout: timeoutMs,
    maxBuffer: 8 * 1024 * 1024,
  })

/** Run a shell command in a container on the cell network and report what it printed. */
const inCell = (script: string): string =>
  docker(["run", "--rm", "--network", EGRESS_CELL_NETWORK, PROBE_IMAGE, "sh", "-c", script], 180_000).trim()

/** A container that listens, so a peer on the same network has something to reach. */
const PEER_NAME = "actantos-egress-proxy-test-peer"

const cleanup = (): void => {
  try {
    docker(["rm", "-f", PEER_NAME], 60_000)
  } catch {
    // Already gone.
  }

  try {
    docker(["network", "rm", EGRESS_CELL_NETWORK], 60_000)
  } catch {
    // Already gone.
  }
}

test("S2: the cell network exists and Docker reports it internal", { skip: SKIP }, () => {
  cleanup()

  try {
    docker(["network", "create", "--internal", "--driver", "bridge", EGRESS_CELL_NETWORK])

    const inspect = docker(["network", "inspect", EGRESS_CELL_NETWORK])
    const [network] = JSON.parse(inspect) as { Internal?: unknown }[]

    // Everything else in this file is downstream of this being true. If Docker ever stops
    // honouring --internal, the cell is a plain bridge and every other assertion here is theatre.
    assert.equal(network?.Internal, true)
  } finally {
    cleanup()
  }
})

test("S2: a workload on the cell network cannot reach the internet, including by raw socket", { skip: SKIP }, () => {
  cleanup()

  try {
    docker(["network", "create", "--internal", "--driver", "bridge", EGRESS_CELL_NETWORK])

    // The application-layer probe: a normal HTTPS client.
    assert.equal(
      inCell("wget -q -T 8 -O - https://example.com >/dev/null 2>&1 && echo EGRESS_ALLOWED || echo EGRESS_BLOCKED"),
      "EGRESS_BLOCKED",
    )

    // The probe that matters: a raw socket to a public IP, which no proxy setting can influence.
    // This is the answer to "can curl be bypassed", and it is a kernel property.
    assert.equal(
      inCell("nc -z -w 5 93.184.216.34 443 && echo EGRESS_ALLOWED || echo EGRESS_BLOCKED"),
      "EGRESS_BLOCKED",
    )

    // And the metadata endpoint, which is the address worth stealing.
    assert.equal(
      inCell("nc -z -w 5 169.254.169.254 80 && echo EGRESS_ALLOWED || echo EGRESS_BLOCKED"),
      "EGRESS_BLOCKED",
    )
  } finally {
    cleanup()
  }
})

test("S2: a workload on the cell network cannot resolve any name the cell does not host", { skip: SKIP }, () => {
  cleanup()

  try {
    docker(["network", "create", "--internal", "--driver", "bridge", EGRESS_CELL_NETWORK])

    // An internal network has no upstream resolver. DNS exfiltration needs to resolve a name the
    // agent controls, and this is the property that makes that impossible rather than merely hard.
    const output = inCell("nslookup example.com 2>&1 || true")

    assert.doesNotMatch(output, /93\.184\.216\.34/u)
    assert.match(output, /SERVFAIL|NXDOMAIN|can't find/u)
  } finally {
    cleanup()
  }
})

test("S2: a workload on the cell network can still reach the proxy, by name and by IP", { skip: SKIP }, () => {
  cleanup()

  try {
    docker(["network", "create", "--internal", "--driver", "bridge", EGRESS_CELL_NETWORK])
    docker([
      "run", "-d", "--name", PEER_NAME, "--network", EGRESS_CELL_NETWORK, PROBE_IMAGE,
      "sh", "-c", "while true; do printf 'HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\n\\r\\nok' | nc -l -p 8080; done",
    ])

    const peerIp = docker(["inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", PEER_NAME]).trim()

    // If either of these failed the cell would be unusable rather than secure, which is why they
    // are asserted alongside the blocked cases rather than assumed.
    assert.equal(inCell(`wget -q -T 8 -O - http://${PEER_NAME}:8080/ 2>/dev/null || echo CONNECT_FAILED`), "ok")
    assert.equal(inCell(`wget -q -T 8 -O - http://${peerIp}:8080/ 2>/dev/null || echo CONNECT_FAILED`), "ok")
  } finally {
    cleanup()
  }
})