# Vendored Cedar CLI

- Binary: `cedar-cli` (Linux x86_64, musl-linked Alpine-compatible)
- Version: cedar-policy-cli 4.11.2
- Source: extracted from a local `actantosd` image previously built with
  `cargo install cedar-policy-cli --version 4.11.2`
- Why vendored: compiling Cedar inside Docker Desktop exhausts the local
  engine and aborts public clean-install verification. The public image still
  ships the same CLI version without a Rust toolchain stage.

Refresh procedure (when bumping Cedar):

```bash
docker build --target cedar-builder -t actantosd:cedar-refresh .
docker create --name cedar-refresh actantosd:cedar-refresh
docker cp cedar-refresh:/usr/local/cargo/bin/cedar docker/cedar-cli
docker rm cedar-refresh
docker run --rm -v "$PWD/docker/cedar-cli:/usr/local/bin/cedar:ro" alpine:3.20 cedar --version
```

Keep the Dockerfile comment and this note in sync with the CLI version.
