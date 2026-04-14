# rust-builder-apks

Vendored Alpine `.apk` packages for the `rust-builder` stage of the enclave Dockerfiles.

## Why vendor?

The `rust:1.83-alpine` base image (Alpine 3.21) does not include `nodejs`, `npm`, or `musl-dev`, which are required to build the napi-rs native addon. Installing these from Alpine's online repositories is NOT reproducible long-term because Alpine removes old package versions from its mirrors as it ships security updates (e.g., `musl-1.2.5-r8` is no longer available, replaced by `r11`).

Vendoring the exact `.apk` files into the repository makes the build **fully offline** and **bit-reproducible** regardless of what Alpine does with its mirrors. PCR0 computed today will match PCR0 computed in 5 years as long as the git commit is the same.

## What's in here?

13 `.apk` files required by the `rust-builder` stage, corresponding exactly to the output of:

```sh
docker run --rm rust:1.83-alpine@sha256:<digest> \
  apk add --simulate --no-cache musl-dev nodejs npm
```

at the time this was vendored. The list:

| Package         | Role                                                  |
| --------------- | ----------------------------------------------------- |
| musl-1.2.5-r11  | libc upgrade (required because 1.2.5-r8 is installed) |
| musl-dev        | libc headers for compiling native code                |
| nodejs          | Runtime for `npm run build`                           |
| npm             | Package manager                                       |
| ada-libs        | URL parser (nodejs dep)                               |
| brotli-libs     | Compression (nodejs dep)                              |
| c-ares          | Async DNS (nodejs dep)                                |
| icu-data-en     | Unicode data, English subset (nodejs dep)             |
| icu-libs        | Unicode libraries (nodejs dep)                        |
| nghttp2-libs    | HTTP/2 (nodejs dep)                                   |
| simdjson        | Fast JSON parsing (nodejs dep)                        |
| simdutf         | Fast UTF handling (nodejs dep)                        |
| sqlite-libs     | SQLite (nodejs dep)                                   |

## Integrity

`SHASUMS256.txt` contains SHA-256 checksums of all `.apk` files. The Dockerfiles verify these before installing. If any `.apk` file is tampered with, the build fails.

## How to regenerate

Run `./regenerate.sh` from this directory. The script uses the pinned `rust:1.83-alpine` base image (matching the Dockerfiles) and `apk fetch` to download the exact dependency closure.

If the base image digest in the Dockerfiles is bumped, update it in `regenerate.sh` too and re-run.

## Why not just `apk add` online?

Tried that. Alpine updated `musl` from `r8` to `r11` and `nodejs` from `22.15.1` to `22.22.2`, breaking every build overnight. Vendoring eliminates this entire failure class.
