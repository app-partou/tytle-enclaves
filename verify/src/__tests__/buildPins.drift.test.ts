/**
 * The build pins of every image (enclave audit P1.4 "runtime + build pins"; audit §5.1 F4, F5).
 *
 * Every enclave image and the parent build on Node.js 22 LTS, pinned by digest (Node 20 is end-of-life since
 * 2026-04-30). The Rust addon builds with --locked against the committed Cargo.lock, and rust-toolchain.toml names
 * the images' Rust release. Every image drops its whole dev tree. Until 2026-10 the enclaves ran Node 20, cargo could
 * re-resolve a stale lock at build time (a PCR0 no commit explains), and vitest's tree shipped in every enclave image.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';

const read = (path: string) => readFileSync(new URL(`../../../${path}`, import.meta.url), 'utf-8');
const json = <T>(path: string) => JSON.parse(read(path)) as T;

const ENCLAVES = ['vies', 'sicae', 'stripe-payment', 'monerium-payment'] as const;
const PACKAGES = ['shared', ...ENCLAVES, 'parent'] as const;
const froms = (dockerfile: string) => [...dockerfile.matchAll(/^FROM (\S+)/gm)].map((m) => m[1]);
const DIGEST = /@sha256:[0-9a-f]{64}$/;

interface Manifest {
  engines?: { node?: string };
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  scripts?: Record<string, string>;
}

describe('the Node.js runtime', () => {
  it('every enclave image builds and runs on ONE Node.js 22 image, pinned by digest (red)', () => {
    const nodeImages = ENCLAVES.flatMap((s) => froms(read(`${s}/Dockerfile`)).filter((f) => f.startsWith('node:')));
    expect(nodeImages).toHaveLength(ENCLAVES.length * 3);
    expect(new Set(nodeImages).size).toBe(1);
    expect(nodeImages[0]).toMatch(/^node:22-alpine@sha256:[0-9a-f]{64}$/);
  });

  it("the parent's images are pinned by digest, its Node on the enclaves' major (red)", () => {
    const dockerfile = read('parent/Dockerfile');
    const images = froms(dockerfile);
    expect(images.length).toBeGreaterThan(0);
    for (const image of images) expect(image).toMatch(DIGEST);
    expect(dockerfile.split('\n')[0]).toMatch(/^# syntax=docker\/dockerfile:1@sha256:[0-9a-f]{64}$/);
    const nodes = images.filter((f) => f.startsWith('node:'));
    expect(nodes).toHaveLength(3);
    for (const image of nodes) expect(image).toMatch(/^node:22-slim@/);
  });

  it('every package says Node 22, and types the runtime it runs on (red)', () => {
    for (const pkg of PACKAGES) {
      const manifest = json<Manifest>(`${pkg}/package.json`);
      expect(manifest.engines?.node, pkg).toBe('>=22');
      expect(manifest.devDependencies?.['@types/node'], pkg).toMatch(/^\^?22\./);
      expect(manifest.devDependencies?.typescript, pkg).toBeDefined();
    }
  });

  it('every docker manifest is its package.json minus the local packages, as the generator writes it (red)', () => {
    for (const pkg of PACKAGES) {
      const manifest = json<Manifest>(`${pkg}/package.json`);
      const local = pkg === 'shared' ? ['@tytle-enclaves/native'] : ['@tytle-enclaves/native', '@tytle-enclaves/shared'];
      const dependencies = Object.fromEntries(Object.entries(manifest.dependencies ?? {}).filter(([d]) => !local.includes(d)));
      expect(json<Manifest>(`${pkg}/package.docker.json`), pkg).toEqual({ ...manifest, dependencies });
    }
  });

  it("each enclave Dockerfile says TLS trusts Node's bundled root store, not the Alpine bundle (red)", () => {
    for (const s of ENCLAVES) {
      const dockerfile = read(`${s}/Dockerfile`);
      expect(dockerfile, s).toContain("TLS trusts Node's BUNDLED Mozilla root store");
      expect(dockerfile, s).not.toContain('which is everything Node.js needs for HTTPS/TLS');
    }
  });
});

describe('the Rust addon', () => {
  it('every enclave builds it in the image regenerate.sh vendors its packages for (lock)', () => {
    const vendored = /^RUST_BUILDER_IMAGE="([^"]+)"$/m.exec(read('deps/rust-builder-apks/regenerate.sh'))?.[1];
    expect(vendored).toMatch(/^rust:\d+\.\d+-alpine@sha256:[0-9a-f]{64}$/);
    for (const s of ENCLAVES) expect(froms(read(`${s}/Dockerfile`)).filter((f) => f.startsWith('rust:')), s).toEqual([vendored]);
  });

  it("rust-toolchain.toml names the Rust release of every image (red)", () => {
    const channel = /^channel = "(\d+\.\d+)\.\d+"$/m.exec(read('native/rust-toolchain.toml'))?.[1];
    expect(channel).toBeDefined();
    const rustImages = [...ENCLAVES, 'parent'].flatMap((s) => froms(read(`${s}/Dockerfile`)).filter((f) => f.startsWith('rust:')));
    expect(rustImages).toHaveLength(ENCLAVES.length + 1);
    for (const image of rustImages) expect(image.startsWith(`rust:${channel}-`), image).toBe(true);
  });

  it('a Cargo.lock that does not match Cargo.toml fails the build: cargo fetch --locked runs before napi (red)', () => {
    // napi build first runs `cargo metadata` WITHOUT --locked, which rewrites a stale lock, so a --locked passed to
    // its `cargo build` alone changes nothing (proved 2026-10-08: such a build re-resolved libc and succeeded).
    const scripts = json<Manifest>('native/package.json').scripts ?? {};
    for (const name of ['build', 'build:debug']) {
      expect(scripts[name], name).toMatch(/^cargo fetch --locked && napi build /);
      expect(scripts[name], name).toContain('--cargo-flags=--locked');
    }
  });
});

describe('the image contents', () => {
  it('every image removes its whole dev tree by the lockfile, not only the top-level dev packages (red)', () => {
    for (const s of [...ENCLAVES, 'parent']) {
      const dockerfile = read(`${s}/Dockerfile`);
      expect(dockerfile, s).toContain('if (path && entry.dev) fs.rmSync(path, { recursive: true, force: true });');
      expect(dockerfile, s).not.toContain('Object.keys(pkg.devDependencies');
    }
  });
});
