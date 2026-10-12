/**
 * A fake `aws` for the tests of scripts/rotate-pcr0.sh (enclave review 2026-10-09, E2b F-5). The AWS CLI is that
 * script's other external boundary: this program takes its place on PATH, records each call and answers SSM's
 * GetParameters as the AWS CLI v2 prints it with `--output json`, and GetParameter with
 * `--query Parameter.Value --output text` (a parameter that does not exist: ParameterNotFound, exit 254).
 *
 *   FAKE_AWS_LOG        a file: one JSON array of arguments per call
 *   FAKE_AWS_SSM_VALUE  the value of every parameter asked; unset = no such parameter (SSM names it in InvalidParameters)
 *   FAKE_AWS_FAILS      when set, every call fails as an expired session makes it fail (exit 254)
 *   FAKE_AWS_RAW        when set, what GetParameters prints instead (an answer that is not the usual shape)
 */
import { appendFileSync } from 'node:fs';

const args = process.argv.slice(2);
appendFileSync(process.env.FAKE_AWS_LOG, `${JSON.stringify(args)}\n`);

if (process.env.FAKE_AWS_FAILS) {
  process.stderr.write('\nAn error occurred (ExpiredTokenException) when calling the GetParameters operation: '
    + 'The security token included in the request is expired\n');
  process.exit(254);
}
if (args[0] === 'ssm' && args[1] === 'get-parameters' && process.env.FAKE_AWS_RAW !== undefined) {
  process.stdout.write(`${process.env.FAKE_AWS_RAW}\n`);
} else if (args[0] === 'ssm' && args[1] === 'get-parameters') {
  // --names takes every word up to the next flag
  const names = [];
  for (let i = args.indexOf('--names') + 1; i > 0 && i < args.length && !args[i].startsWith('--'); i += 1) names.push(args[i]);
  const value = process.env.FAKE_AWS_SSM_VALUE;
  process.stdout.write(`${JSON.stringify({
    Parameters: value === undefined ? [] : names.map((Name) => ({ Name, Type: 'String', Value: value, Version: 3 })),
    InvalidParameters: value === undefined ? names : [],
  }, null, 4)}\n`);
} else if (args[0] === 'ssm' && args[1] === 'get-parameter') {
  const value = process.env.FAKE_AWS_SSM_VALUE;
  if (value === undefined) {
    process.stderr.write('\nAn error occurred (ParameterNotFound) when calling the GetParameter operation: \n');
    process.exit(254);
  }
  process.stdout.write(`${value}\n`);
}
// Every other call succeeds and prints nothing.
