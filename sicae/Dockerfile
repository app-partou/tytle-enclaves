# syntax=docker/dockerfile:1
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

RUN apk add --no-cache \
    musl-dev=1.2.5-r9 \
    nodejs=22.15.1-r0 \
    npm=10.9.1-r0

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
FROM node:20-alpine@sha256:f598378b5240225e6beab68fa9f356db1fb8efe55173e6d4d8153113bb8f333c AS node-builder

RUN apk add --no-cache \
    openssl=3.5.5-r0 \
    ca-certificates=20251003-r0

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

# Prune devDependencies for minimal runtime image.
# Add workspace packages to deps so npm prune keeps them.
RUN node -e " \
  const pkg = JSON.parse(require('fs').readFileSync('package.json','utf8')); \
  pkg.dependencies = pkg.dependencies || {}; \
  pkg.dependencies['@tytle-enclaves/native'] = '*'; \
  pkg.dependencies['@tytle-enclaves/shared'] = '*'; \
  require('fs').writeFileSync('package.json', JSON.stringify(pkg, null, 2));"
RUN npm prune --production

# Stage 4: Minimal runtime
FROM node:20-alpine@sha256:f598378b5240225e6beab68fa9f356db1fb8efe55173e6d4d8153113bb8f333c

RUN apk add --no-cache ca-certificates=20251003-r0

WORKDIR /app
COPY --from=node-builder /app/dist ./dist
COPY --from=node-builder /app/node_modules ./node_modules
COPY sicae/package.json ./

# Fixed UID — avoids /etc/passwd differences across builds
USER 1000

# vsock listener port (inside enclave)
EXPOSE 5000
CMD ["node", "dist/enclave.js"]
