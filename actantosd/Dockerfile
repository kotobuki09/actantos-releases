# Cedar CLI is vendored (linux musl) to keep clean installs reliable.
# Compiling cedar-policy-cli from crates.io inside Docker Desktop regularly
# OOMs this host; see docker/README.md for refresh instructions.
FROM alpine:3.20 AS cedar-provider
COPY docker/cedar-cli /usr/local/bin/cedar
RUN chmod +x /usr/local/bin/cedar && cedar --version

FROM node:22-alpine AS deps
WORKDIR /app
# package-lock.json is present in git source; npm-shrinkwrap.json is present in the npm pack tarball.
COPY package.json package-lock.json* npm-shrinkwrap.json* ./
RUN npm ci

FROM deps AS builder
WORKDIR /app
COPY src/ ./src/
COPY sql/ ./sql/
COPY policies/ ./policies/
COPY tsconfig.json ./
RUN npm run build

FROM node:22-alpine AS runtime
WORKDIR /app
COPY package.json package-lock.json* npm-shrinkwrap.json* ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/sql ./sql
COPY --from=builder /app/policies ./policies
COPY --from=cedar-provider /usr/local/bin/cedar /usr/local/bin/cedar

ENV NODE_ENV=production
ENV CEDAR_CLI_PATH=/usr/local/bin/cedar
EXPOSE 3100

CMD ["node", "dist/index.js"]
