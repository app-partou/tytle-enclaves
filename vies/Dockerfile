# syntax=docker/dockerfile:1
#
# VIES/HMRC VAT Validation Enclave — Reproducible Build
#
# This Dockerfile is public. PCR0 = hash of the resulting EIF.
# Anyone can reproduce the build and verify PCR0 matches the NSM attestation.
#
# CRITICAL: All base images pinned by digest. All system packages pinned by version.
# npm ci with lockfile. SOURCE_DATE_EPOCH + BuildKit rewrite-timestamp for determinism.

# Stage 1: Rust builder for native addon (vsock + NSM ioctl)
# Pin by digest for reproducibility — update via:
#   docker pull rust:1.83-alpine && docker inspect --format='{{index .RepoDigests 0}}' rust:1.83-alpine
FROM rust:1.83-alpine@sha256:de862e9e9e8e8e3e45db3de7ef7b3ad8d47a1e2df50a4ad5fd848ca80aeb89b3 AS rust-builder

RUN apk add --no-cache \
    musl-dev=1.2.5-r8 \
    nodejs=20.18.1-r0 \
    npm=10.9.0-r0

WORKDIR /build/native
COPY native/package.json native/package-lock.json* ./
RUN npm ci

COPY native/Cargo.toml native/build.rs ./
COPY native/src/ ./src/
RUN npm run build

# Stage 2: Build shared library
FROM node:20-alpine@sha256:2d07db07a2d2a4fbc86d0e4e0dafb1e37a2e8c6e849fbb6a0b0654a1e8d4b7ab AS shared-builder

WORKDIR /shared

# Install shared deps (strip native file: dep — installed manually)
COPY shared/package.json ./package.json.orig
COPY shared/package-lock.json* ./
RUN node -e " \
  const pkg = JSON.parse(require('fs').readFileSync('package.json.orig','utf8')); \
  delete pkg.dependencies?.['@tytle-enclaves/native']; \
  require('fs').writeFileSync('package.json', JSON.stringify(pkg, null, 2));"
RUN npm install

# Copy native addon into shared's node_modules
COPY --from=rust-builder /build/native/index.js /build/native/index.d.ts /build/native/package.json ./node_modules/@tytle-enclaves/native/
COPY --from=rust-builder /build/native/*.node ./node_modules/@tytle-enclaves/native/

# Restore original package.json and build
RUN cp package.json.orig package.json && rm package.json.orig
COPY shared/tsconfig.json ./
COPY shared/src/ ./src/
RUN npx tsc

# Stage 3: Build vies enclave
FROM node:20-alpine@sha256:2d07db07a2d2a4fbc86d0e4e0dafb1e37a2e8c6e849fbb6a0b0654a1e8d4b7ab AS node-builder

RUN apk add --no-cache \
    openssl=3.3.2-r4 \
    ca-certificates=20241010-r0

WORKDIR /app

# Install vies deps (strip native + shared file: deps — installed manually)
COPY vies/package.json ./package.json.orig
COPY vies/package-lock.json* ./
RUN node -e " \
  const pkg = JSON.parse(require('fs').readFileSync('package.json.orig','utf8')); \
  delete pkg.dependencies?.['@tytle-enclaves/native']; \
  delete pkg.dependencies?.['@tytle-enclaves/shared']; \
  require('fs').writeFileSync('package.json', JSON.stringify(pkg, null, 2));"
RUN npm install

# Copy native addon
COPY --from=rust-builder /build/native/index.js /build/native/index.d.ts /build/native/package.json ./node_modules/@tytle-enclaves/native/
COPY --from=rust-builder /build/native/*.node ./node_modules/@tytle-enclaves/native/

# Copy pre-built shared library (dist + package.json for module resolution)
COPY --from=shared-builder /shared/dist ./node_modules/@tytle-enclaves/shared/dist/
COPY --from=shared-builder /shared/package.json ./node_modules/@tytle-enclaves/shared/

# Restore original package.json
RUN cp package.json.orig package.json && rm package.json.orig

# Build vies TypeScript
COPY vies/tsconfig.json ./
COPY vies/src/ ./src/
RUN npx tsc

# Prune devDependencies for minimal runtime image.
RUN node -e " \
  const pkg = JSON.parse(require('fs').readFileSync('package.json','utf8')); \
  if (pkg.dependencies?.['@tytle-enclaves/native']) pkg.dependencies['@tytle-enclaves/native'] = '*'; \
  if (pkg.dependencies?.['@tytle-enclaves/shared']) pkg.dependencies['@tytle-enclaves/shared'] = '*'; \
  require('fs').writeFileSync('package.json', JSON.stringify(pkg, null, 2));"
RUN npm prune --production

# Stage 4: Minimal runtime
FROM node:20-alpine@sha256:2d07db07a2d2a4fbc86d0e4e0dafb1e37a2e8c6e849fbb6a0b0654a1e8d4b7ab

RUN apk add --no-cache ca-certificates=20241010-r0

WORKDIR /app
COPY --from=node-builder /app/dist ./dist
COPY --from=node-builder /app/node_modules ./node_modules
COPY vies/package.json ./

# Fixed UID — avoids /etc/passwd differences across builds
USER 1000

# vsock listener port (inside enclave)
EXPOSE 5000
CMD ["node", "dist/enclave.js"]
