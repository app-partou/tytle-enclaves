# syntax=docker/dockerfile:1@sha256:4a43a54dd1fedceb30ba47e76cfcf2b47304f4161c0caeac2db1c61804ea3c91
#
# Parent Server - routes requests from Fargate to Nitro Enclaves.
#
# NOT run as a Docker container in production. Instead, the EC2 user data
# extracts files from this image (docker cp parent-tmp:/app) and runs them via
# systemd. The Docker image is used only as a packaging/distribution mechanism.
#
# IMPORTANT: Uses glibc base images (rust:1.83-slim + node:22-slim, Debian 12, glibc 2.36)
# because the extracted files run on the EC2 host (Amazon Linux 2023, glibc), with the host's
# own /usr/bin/node: Amazon Linux 2023's nodejs22 package (Node.js 22 LTS; the main repository's
# infra/lib/nitro-enclave-stack.ts installs it). Both bases are pinned by digest (resolved 2026-10-08;
# update via: docker buildx imagetools inspect <image>), as in the enclave Dockerfiles.
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
FROM rust:1.83-slim@sha256:540c902e99c384163b688bbd8b5b8520e94e7731b27f7bd0eaa56ae1960627ab AS rust-builder

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
FROM node:22-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392 AS shared-builder

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
FROM node:22-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392 AS builder

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

# Remove every package the lockfile marks dev-only - the build tools AND their whole trees (vitest brings vite,
# rollup and esbuild with native binaries) - and the .bin links to them, so the image ships only the runtime
# closure plus the two injected local packages. npm prune fights with the injected packages, which the lockfile
# does not list, so they stay. Removing only the top-level devDependencies left 32 dev packages (21.7 MB, two
# native binaries) in every enclave image until 2026-10.
RUN node -e " \
  const fs = require('fs'); \
  const lock = JSON.parse(fs.readFileSync('package-lock.json','utf8')); \
  for (const [path, entry] of Object.entries(lock.packages)) { \
    if (path && entry.dev) fs.rmSync(path, { recursive: true, force: true }); \
  } \
  fs.rmSync('node_modules/.bin', { recursive: true, force: true }); \
  for (const scope of fs.readdirSync('node_modules').filter((d) => d.startsWith('@'))) { \
    if (fs.readdirSync('node_modules/' + scope).length === 0) fs.rmdirSync('node_modules/' + scope); \
  }"

# Smoke test: reproduce the exact ESM resolution + glibc dlopen that
# dist/vsockClient.js performs at startup, against the final shipped
# node_modules. This historically shipped broken (ERR_MODULE_NOT_FOUND for
# @tytle-enclaves/native -> systemd crash-loop on the EC2 host). Running it on
# node:22-slim (Node 22 like the host's nodejs22; glibc like Amazon Linux 2023) makes a broken bundle
# fail the build here instead of crash-looping in production. Do NOT remove.
RUN cd /app && node --input-type=module -e "import { vsockConnectAsync } from '@tytle-enclaves/native'; import { readMessage, writeMessage } from '@tytle-enclaves/shared'; const ok = [vsockConnectAsync, readMessage, writeMessage].every(f => typeof f === 'function'); if (!ok) { console.error('SMOKE FAIL: missing exports', { vsockConnectAsync: typeof vsockConnectAsync, readMessage: typeof readMessage, writeMessage: typeof writeMessage }); process.exit(1); } console.log('SMOKE OK: native + shared resolve under ESM on glibc');"

# Stage 4: Minimal runtime (glibc)
FROM node:22-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392

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
