# syntax=docker/dockerfile:1@sha256:4a43a54dd1fedceb30ba47e76cfcf2b47304f4161c0caeac2db1c61804ea3c91
#
# SICAE Portuguese Business CAE Code Lookup Enclave — Reproducible Build
#
# This Dockerfile is public. PCR0 = hash of the resulting EIF.
# Anyone can reproduce the build and verify PCR0 matches the NSM attestation.
#
# NOTE: SICAE uses plain HTTP (no TLS). The attestation proves code identity,
# but the host can read/modify traffic. Acceptable for public CAE data.
#
# CRITICAL: All base images pinned by digest. All system packages pinned by version.
# npm ci with lockfile. SOURCE_DATE_EPOCH + BuildKit rewrite-timestamp for determinism.

# Stage 1: Rust builder for native addon (vsock + NSM ioctl)
# Pin by digest for reproducibility — update via:
#   docker pull rust:1.83-alpine && docker inspect --format='{{index .RepoDigests 0}}' rust:1.83-alpine
FROM rust:1.83-alpine@sha256:0ac946ed7597a9f053a1be2ce38c09aa88b3d7079a91ea491493615294b1f699 AS rust-builder

# Install build deps from vendored .apk files (offline, fully reproducible).
# rust:1.83-alpine lacks nodejs/npm/musl-dev, and Alpine removes old package
# versions from its mirrors over time, so we vendor the exact .apk closure.
# See deps/rust-builder-apks/README.md for rationale and regenerate.sh to update.
COPY deps/rust-builder-apks/SHASUMS256.txt /tmp/apks/SHASUMS256.txt
COPY deps/rust-builder-apks/*.apk /tmp/apks/
RUN cd /tmp/apks && \
    sha256sum -c SHASUMS256.txt && \
    apk add --no-cache --allow-untrusted ./*.apk && \
    rm -rf /tmp/apks

WORKDIR /build/native
COPY native/package.json native/package-lock.json* ./
RUN npm ci

COPY native/Cargo.toml native/Cargo.lock native/build.rs ./
COPY native/src/ ./src/
RUN npm run build

# Stage 2: Build shared library
# Node.js 22 LTS (Node 20 is end-of-life since 2026-04-30), pinned by digest: node:22-alpine = Node 22.23.3 on
# Alpine 3.24.2, resolved 2026-10-08. The same digest in every stage below and in every enclave Dockerfile.
# Update via: docker buildx imagetools inspect node:22-alpine (the index digest)
FROM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402 AS shared-builder

WORKDIR /shared

# Install shared deps from pre-stripped docker lockfile (deterministic)
COPY shared/package.docker.json ./package.json
COPY shared/package-lock.docker.json ./package-lock.json
RUN npm ci

# Copy native addon into shared's node_modules
COPY --from=rust-builder /build/native/index.js /build/native/index.d.ts /build/native/package.json ./node_modules/@tytle-enclaves/native/
COPY --from=rust-builder /build/native/*.node ./node_modules/@tytle-enclaves/native/
COPY shared/tsconfig.json ./
COPY shared/src/ ./src/
RUN npx tsc

# Stage 3: Build sicae enclave
# No extra apk installs: Node.js needs nothing more for HTTPS. TLS trusts Node's BUNDLED Mozilla root store
# (tls.rootCertificates, compiled into the node binary: 119 roots in Node 22.23.3), never the Alpine
# ca-certificates bundle, so a bump of this digest is a bump of the CA store: re-check every upstream host.
FROM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402 AS node-builder

WORKDIR /app

# Install sicae deps from pre-stripped docker lockfile (deterministic)
COPY sicae/package.docker.json ./package.json
COPY sicae/package-lock.docker.json ./package-lock.json
RUN npm ci

# Copy native addon
COPY --from=rust-builder /build/native/index.js /build/native/index.d.ts /build/native/package.json ./node_modules/@tytle-enclaves/native/
COPY --from=rust-builder /build/native/*.node ./node_modules/@tytle-enclaves/native/

# Copy pre-built shared library (dist + package.json for module resolution)
COPY --from=shared-builder /shared/dist ./node_modules/@tytle-enclaves/shared/dist/
COPY --from=shared-builder /shared/package.json ./node_modules/@tytle-enclaves/shared/

# Build sicae TypeScript
COPY sicae/tsconfig.json ./
COPY sicae/src/ ./src/
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

# Stage 4: Minimal runtime
# The same Node.js 22 image as the build stages; no extra apk installs.
FROM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402

WORKDIR /app
COPY --from=node-builder /app/dist ./dist
COPY --from=node-builder /app/node_modules ./node_modules
COPY sicae/package.json ./

# Fixed UID — avoids /etc/passwd differences across builds
USER 1000

# vsock listener port (inside enclave)
EXPOSE 5000

# Nitro Enclaves init execs the Docker image's CMD directly via execvpe
# without resolving PATH, and without running the base image's ENTRYPOINT
# (docker-entrypoint.sh from node:22-alpine). Clear ENTRYPOINT and use
# absolute paths so the enclave init can locate the binary.
ENTRYPOINT []
CMD ["/usr/local/bin/node", "/app/dist/enclave.js"]
