FROM rust:1-alpine AS cedar-builder
RUN cargo install cedar-policy-cli --version 4.11.2

FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
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
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/sql ./sql
COPY --from=builder /app/policies ./policies
COPY --from=cedar-builder /usr/local/cargo/bin/cedar /usr/local/bin/cedar

ENV NODE_ENV=production
ENV CEDAR_CLI_PATH=/usr/local/bin/cedar
EXPOSE 3100

CMD ["node", "dist/index.js"]
