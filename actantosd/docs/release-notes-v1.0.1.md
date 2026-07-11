# v1.0.1 Portable Agent Test

ActantOS v1.0.1 makes the first-run experience portable across Windows,
macOS, and Linux while preserving the frozen `/v1` API.

## New

- `npm run quickstart` installs dependencies, builds source clones (or uses the
  compiled service in a release tarball), starts
  an isolated in-memory server, tests an agent, and shuts the server down.
- The portable test verifies safe workspace reads are allowed, credential
  reads are denied, remote actions require approval, and decisions return
  audit evidence identifiers.
- Docker and Postgres are no longer required for the first product test.
- `ACTANTOS_QUICKSTART_PORT` can select another local port when 4310 is busy.

## Requirements

- Node.js 22 or newer
- Git when cloning the repository

## Quickstart

```bash
git clone https://github.com/kotobuki09/actantos-releases.git
cd actantos-releases/actantosd
npm run quickstart
```

A successful run ends with:

```text
Portable agent test passed: 4 checks, 0 failed
```

## Scope

The quickstart uses in-memory state for portability. Use the Compose-backed
Postgres setup for persistent audit timelines, evidence packages, and normal
self-host operation. This release does not claim external customer validation.
