#!/usr/bin/env node

/**
 * @tytle-enclaves/verify — CLI tool to verify Tytle Nitro Enclave attestations.
 *
 * End-to-end verification: COSE signature, certificate chain, nonce, PCR0, and
 * optionally reproduces the Docker build to confirm code identity.
 *
 * Usage:
 *   npx @tytle-enclaves/verify --service vies --attestation attestation.json
 *   npx @tytle-enclaves/verify --service vies --attestation att.json --skip-build
 */

import { Command } from 'commander';
import { createInterface } from 'node:readline';
import { VALID_SERVICES, type ServiceName } from './lib/types.js';
import {
  validateServiceName,
  validateCommitHash,
  validateApiUrl,
  validatePcr0Hex,
  validateRepoDir,
} from './lib/validation.js';
import { runVerification } from './commands/verify.js';

const program = new Command();

program
  .name('verify')
  .description(
    'Verify Tytle Nitro Enclave attestations end-to-end',
  )
  .version('0.1.0')
  .option(
    '-s, --service <name>',
    `Enclave service to verify (${VALID_SERVICES.join(', ')})`,
  )
  .option(
    '-a, --attestation <file>',
    'Path to attestation JSON file, or - for stdin',
  )
  .option(
    '--api-url <url>',
    'Override API base URL',
    'https://api.tytle.io',
  )
  .option('--commit <hash>', 'Override git commit hash')
  .option('--repo-dir <path>', 'Use existing repo clone')
  .option('--skip-build', 'Skip Docker build + PCR0 extraction')
  .option(
    '--pcr0 <hex>',
    'Compare against this PCR0 instead of fetching from API',
  )
  .action(async (opts) => {
    let service: ServiceName = opts.service;
    let attestation: string = opts.attestation;

    // Interactive prompts if required options are missing
    if (!service) {
      service = await promptChoice(
        'Choose a service to verify:',
        VALID_SERVICES,
      ) as ServiceName;
    }

    // Validate all inputs
    try {
      service = validateServiceName(service);

      if (opts.apiUrl) validateApiUrl(opts.apiUrl);
      if (opts.commit) opts.commit = validateCommitHash(opts.commit);
      if (opts.pcr0) opts.pcr0 = validatePcr0Hex(opts.pcr0);
      if (opts.repoDir) validateRepoDir(opts.repoDir);
    } catch (err: any) {
      console.error(`\n\x1b[31mValidation error:\x1b[0m ${err.message}`);
      process.exit(1);
    }

    if (!attestation) {
      attestation = await promptInput(
        'Path to attestation JSON file (or - for stdin):',
      );
    }

    if (!attestation) {
      console.error('Attestation file is required.');
      process.exit(1);
    }

    try {
      const success = await runVerification({
        service,
        attestation,
        apiUrl: opts.apiUrl,
        commit: opts.commit,
        repoDir: opts.repoDir,
        skipBuild: opts.skipBuild,
        pcr0: opts.pcr0,
      });

      process.exit(success ? 0 : 1);
    } catch (err: any) {
      console.error(`\n\x1b[31mError:\x1b[0m ${err.message}`);
      process.exit(1);
    }
  });

program.parse();

async function promptChoice(
  question: string,
  choices: readonly string[],
): Promise<string> {
  const rl = createInterface({
    input: process.stdin,
    output: process.stderr,
  });

  return new Promise((resolve) => {
    console.error(`\n${question}`);
    choices.forEach((c, i) => console.error(`  ${i + 1}) ${c}`));
    rl.question('\nEnter number or name: ', (answer) => {
      rl.close();
      const num = parseInt(answer, 10);
      if (num >= 1 && num <= choices.length) {
        resolve(choices[num - 1]);
      } else if (choices.includes(answer.trim())) {
        resolve(answer.trim());
      } else {
        console.error(`Invalid choice: ${answer}`);
        process.exit(1);
      }
    });
  });
}

async function promptInput(question: string): Promise<string> {
  const rl = createInterface({
    input: process.stdin,
    output: process.stderr,
  });

  return new Promise((resolve) => {
    rl.question(`\n${question} `, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}
