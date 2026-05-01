# syntax=docker/dockerfile:1
#
# Parent Server - routes requests from Fargate to Nitro Enclaves.
#
# NOT run as a Docker container in production. Instead, the EC2 user data
# extracts files from this image and runs them via systemd. The Docker image
# is used only as a packaging/distribution mechanism.
#
# IMPORTANT: Uses a glibc-based Rust builder (rust:1.83-slim, Debian) because
# the extracted files run on EC2 (Amazon Linux 2023, glibc). The enclave
# Dockerfiles use Alpine (musl) because they run inside Docker. A musl-compiled
# .node binary won't load in a glibc Node.js runtime.

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

# Stage 2: Build shared library
FROM node:20-slim AS shared-builder

WORKDIR /shared
COPY shared/package.json shared/package-lock.json ./
RUN npm ci --ignore-scripts

COPY --from=rust-builder /build/native/index.js ./node_modules/@tytle-enclaves/native/index.js
COPY --from=rust-builder /build/native/index.d.ts ./node_modules/@tytle-enclaves/native/index.d.ts
COPY --from=rust-builder /build/native/*.node ./node_modules/@tytle-enclaves/native/
COPY --from=rust-builder /build/native/package.json ./node_modules/@tytle-enclaves/native/package.json

COPY shared/tsconfig.json ./
COPY shared/src/ ./src/
RUN npx tsc

# Stage 3: Build parent server
FROM node:20-slim AS builder

WORKDIR /app
COPY parent/package.json parent/package-lock.json* ./
RUN npm ci --ignore-scripts

# Wire workspace deps BEFORE tsc so TypeScript can resolve imports.
# npm can't resolve file: paths inside Docker, so inject manually.
COPY --from=rust-builder /build/native/index.js ./node_modules/@tytle-enclaves/native/index.js
COPY --from=rust-builder /build/native/index.d.ts ./node_modules/@tytle-enclaves/native/index.d.ts
COPY --from=rust-builder /build/native/*.node ./node_modules/@tytle-enclaves/native/
COPY --from=rust-builder /build/native/package.json ./node_modules/@tytle-enclaves/native/package.json
COPY --from=shared-builder /shared/dist/ ./node_modules/@tytle-enclaves/shared/dist/
COPY --from=shared-builder /shared/package.json ./node_modules/@tytle-enclaves/shared/package.json
COPY --from=shared-builder /shared/node_modules/cbor/ ./node_modules/cbor/

COPY parent/tsconfig.json ./
COPY parent/src/ ./src/
RUN npx tsc

RUN npm prune --production

# Minimal runtime
FROM node:20-slim

WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./

USER 1000
EXPOSE 5001
CMD ["node", "dist/server.js"]
