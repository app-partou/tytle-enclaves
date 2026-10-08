/**
 * A fake `docker` for the tests of the build scripts (enclave audit P1.6). Docker is the one external boundary of
 * scripts/lib/recipe.sh: this program takes its place on PATH, records each call and answers as Docker and nitro-cli
 * 1.4.4 do. Everything else - bash, the scripts, recipe.mjs, tar - runs for real.
 *
 *   FAKE_DOCKER_LOG            a file: one JSON array of arguments per call
 *   FAKE_DOCKER_CONFIG_DIGEST  the config digest (sha256:<hex>) of every image it builds
 *   FAKE_DOCKER_MEASUREMENTS   a file: what nitro-cli build-enclave prints for the unsigned EIF (its standard output)
 *   FAKE_DOCKER_PCR8           the PCR8 it prints for an EIF signed with --signing-certificate
 */
import { execFileSync } from 'node:child_process';
import { appendFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

const args = process.argv.slice(2);
appendFileSync(process.env.FAKE_DOCKER_LOG, `${JSON.stringify(args)}\n`);
const valueAfter = (flag) => args[args.indexOf(flag) + 1];

if (args[0] === 'buildx' && args[1] === 'build') {
  // --output type=docker,dest=<tar>,rewrite-timestamp=true,name=<name>: a docker tarball of one image
  const output = Object.fromEntries(valueAfter('--output').split(',').map((pair) => pair.split('=')));
  const dir = mkdtempSync(path.join(tmpdir(), 'fake-docker-'));
  const config = process.env.FAKE_DOCKER_CONFIG_DIGEST.replace('sha256:', 'blobs/sha256/');
  writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify([{ Config: config, RepoTags: [output.name], Layers: [] }]));
  execFileSync('tar', ['-cf', output.dest, '-C', dir, 'manifest.json']);
  rmSync(dir, { recursive: true });
} else if (args[0] === 'run') {
  // nitro-cli build-enclave: the EIF goes where --output-file names, through the -v mounts; then the measurements
  const mounts = args.flatMap((arg, i) => (arg === '-v' ? [args[i + 1].split(':')] : []));
  const eif = valueAfter('--output-file');
  const mount = mounts.find(([, inside]) => eif.startsWith(`${inside}/`));
  if (mount) writeFileSync(path.join(mount[0], eif.slice(mount[1].length + 1)), 'a fake EIF\n');
  const printed = JSON.parse(readFileSync(process.env.FAKE_DOCKER_MEASUREMENTS, 'utf8'));
  if (args.includes('--signing-certificate')) printed.Measurements.PCR8 = process.env.FAKE_DOCKER_PCR8;
  process.stdout.write(`${JSON.stringify(printed, null, 2)}\n`);
}
// Every other call (buildx inspect, load, image inspect, rmi) succeeds and prints nothing.
