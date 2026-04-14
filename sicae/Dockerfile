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
FROM node:20-alpine@sha256:f598378b5240225e6beab68fa9f356db1fb8efe55173e6d4d8153113bb8f333c AS shared-builder

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
# node:20-alpine already includes libcrypto3, libssl3, and ca-certificates-bundle,
# which is everything Node.js needs for HTTPS/TLS. No extra apk installs required.
FROM node:20-alpine@sha256:f598378b5240225e6beab68fa9f356db1fb8efe55173e6d4d8153113bb8f333c AS node-builder

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

# Remove devDependencies directly (npm prune fights with local packages).
RUN node -e " \
  const fs = require('fs'); \
  const pkg = JSON.parse(fs.readFileSync('package.json','utf8')); \
  for (const d of Object.keys(pkg.devDependencies || {})) { \
    fs.rmSync('node_modules/' + d, { recursive: true, force: true }); \
  }"

# Stage 4: Minimal runtime
# node:20-alpine already has ca-certificates-bundle; no extra apk installs needed.
FROM node:20-alpine@sha256:f598378b5240225e6beab68fa9f356db1fb8efe55173e6d4d8153113bb8f333c

WORKDIR /app
COPY --from=node-builder /app/dist ./dist
COPY --from=node-builder /app/node_modules ./node_modules
COPY sicae/package.json ./

# Fixed UID — avoids /etc/passwd differences across builds
USER 1000

# vsock listener port (inside enclave)
EXPOSE 5000
CMD ["node", "dist/enclave.js"]
