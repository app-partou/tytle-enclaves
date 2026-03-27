# syntax=docker/dockerfile:1
#
# Parent Server — routes requests from Fargate to Nitro Enclaves.
#
# NOT run as a Docker container in production. Instead, the EC2 user data
# extracts files from this image and runs them via systemd. The Docker image
# is used only as a packaging/distribution mechanism.

FROM node:20-alpine@sha256:f598378b5240225e6beab68fa9f356db1fb8efe55173e6d4d8153113bb8f333c AS builder

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src/ ./src/
RUN npx tsc

# Remove devDependencies from node_modules for minimal runtime
RUN npm prune --production

# Minimal runtime
FROM node:20-alpine@sha256:f598378b5240225e6beab68fa9f356db1fb8efe55173e6d4d8153113bb8f333c

WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./

USER 1000
EXPOSE 5001
CMD ["node", "dist/server.js"]
