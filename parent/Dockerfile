# syntax=docker/dockerfile:1
#
# Parent Server - routes requests from Fargate to Nitro Enclaves.
#
# NOT run as a Docker container in production. Instead, the EC2 user data
# extracts files from this image (docker cp parent-tmp:/app) and runs them via
# systemd. The Docker image is used only as a packaging/distribution mechanism.
#
# IMPORTANT: Uses glibc base images (rust:1.83-slim + node:20-slim, Debian)
# because the extracted files run on the EC2 host (Amazon Linux 2023, glibc).
# The enclave Dockerfiles use Alpine (musl) because they run inside Docker.
# A musl-compiled .node binary won't dlopen in a glibc Node.js runtime.
#
# The @tytle-enclaves/native + @tytle-enclaves/shared workspace packages are
# vendored exactly like the enclave Dockerfiles (vies/sicae/stripe-payment):
# npm ci from a pre-stripped package.docker.json (no file: deps), then the
# built native addon + shared dist are copied into node_modules, then
# devDependencies are removed directly. npm prune fights with locally-injected
# packages, so we do NOT use it (that is what previously shipped a broken
# bundle that crash-looped on the host). The only difference from the enclaves
# is the glibc base images above. Regenerate the docker lockfiles with
# scripts/generate-docker-lockfiles.sh after changing parent/package.json.

# Stage 1: Rust builder for native addon (glibc target for EC2)
FROM rust:1.83-slim AS rust-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    nodejs npm build-essential python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build/native
COPY native/package.json native/package-lock.json* ./
RUN npm ci

COPY native/Cargo.toml native/Cargo.lock native/build.rs ./
COPY native/src/ ./src/
RUN npm run build

# Stage 2: Build shared library (glibc)
FROM node:20-slim AS shared-builder

WORKDIR /shared

# Install shared deps from the pre-stripped docker lockfile (no file: deps).
COPY shared/package.docker.json ./package.json
COPY shared/package-lock.docker.json ./package-lock.json
RUN npm ci

# Inject the glibc-built native addon so tsc can resolve @tytle-enclaves/native.
COPY --from=rust-builder /build/native/index.js /build/native/index.d.ts /build/native/package.json ./node_modules/@tytle-enclaves/native/
COPY --from=rust-builder /build/native/*.node ./node_modules/@tytle-enclaves/native/

COPY shared/tsconfig.json ./
COPY shared/src/ ./src/
RUN npx tsc

# Stage 3: Build parent server (glibc)
FROM node:20-slim AS builder

WORKDIR /app

# Install parent deps from the pre-stripped docker lockfile (no file: deps).
COPY parent/package.docker.json ./package.json
COPY parent/package-lock.docker.json ./package-lock.json
RUN npm ci

# Inject the glibc-built native addon (index.js loader + .node + package.json).
COPY --from=rust-builder /build/native/index.js /build/native/index.d.ts /build/native/package.json ./node_modules/@tytle-enclaves/native/
COPY --from=rust-builder /build/native/*.node ./node_modules/@tytle-enclaves/native/

# Inject the pre-built shared library (dist + package.json for module resolution).
# cbor is a real dependency in package.docker.json, so npm ci installs it at the
# top level and shared resolves it up the tree - no manual cbor copy needed.
COPY --from=shared-builder /shared/dist ./node_modules/@tytle-enclaves/shared/dist/
COPY --from=shared-builder /shared/package.json ./node_modules/@tytle-enclaves/shared/

COPY parent/tsconfig.json ./
COPY parent/src/ ./src/
RUN npx tsc

# Remove devDependencies directly (npm prune fights with locally-injected packages).
RUN node -e " \
  const fs = require('fs'); \
  const pkg = JSON.parse(fs.readFileSync('package.json','utf8')); \
  for (const d of Object.keys(pkg.devDependencies || {})) { \
    fs.rmSync('node_modules/' + d, { recursive: true, force: true }); \
  }"

# Smoke test: reproduce the exact ESM resolution + glibc dlopen that
# dist/vsockClient.js performs at startup, against the final shipped
# node_modules. This historically shipped broken (ERR_MODULE_NOT_FOUND for
# @tytle-enclaves/native -> systemd crash-loop on the EC2 host). Running it on
# node:20-slim (same glibc family as Amazon Linux 2023) makes a broken bundle
# fail the build here instead of crash-looping in production. Do NOT remove.
RUN cd /app && node --input-type=module -e "import { vsockConnectAsync } from '@tytle-enclaves/native'; import { readMessage, writeMessage } from '@tytle-enclaves/shared'; const ok = [vsockConnectAsync, readMessage, writeMessage].every(f => typeof f === 'function'); if (!ok) { console.error('SMOKE FAIL: missing exports', { vsockConnectAsync: typeof vsockConnectAsync, readMessage: typeof readMessage, writeMessage: typeof writeMessage }); process.exit(1); } console.log('SMOKE OK: native + shared resolve under ESM on glibc');"

# Stage 4: Minimal runtime (glibc)
FROM node:20-slim

WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
# Real package.json for type:module + main. Its file: workspace deps are inert
# at runtime - node_modules is already fully populated, so node never
# re-resolves them. Do NOT "fix" these to the docker.json variant.
COPY parent/package.json ./

USER 1000
EXPOSE 5001
CMD ["node", "dist/server.js"]
