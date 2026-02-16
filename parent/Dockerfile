# syntax=docker/dockerfile:1
#
# Parent Server — routes requests from Fargate to Nitro Enclaves.
#
# NOT run as a Docker container in production. Instead, the EC2 user data
# extracts files from this image and runs them via systemd. The Docker image
# is used only as a packaging/distribution mechanism.

FROM node:20-alpine@sha256:2d07db07a2d2a4fbc86d0e4e0dafb1e37a2e8c6e849fbb6a0b0654a1e8d4b7ab AS builder

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src/ ./src/
RUN npx tsc

# Remove devDependencies from node_modules for minimal runtime
RUN npm prune --production

# Minimal runtime
FROM node:20-alpine@sha256:2d07db07a2d2a4fbc86d0e4e0dafb1e37a2e8c6e849fbb6a0b0654a1e8d4b7ab

WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./

USER 1000
EXPOSE 5001
CMD ["node", "dist/server.js"]
