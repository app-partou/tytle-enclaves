/**
 * vsock Client — connects to Nitro Enclaves via AF_VSOCK using socat.
 *
 * Node.js's net module doesn't natively support AF_VSOCK, so we bridge
 * through socat (available on Amazon Linux 2023). socat opens a vsock
 * connection and pipes stdin/stdout, which we use for length-prefixed
 * message exchange.
 *
 * Alternative: The native addon could be used here too, but the parent
 * server is separate from the enclave image and doesn't need Rust compilation.
 */

import { spawn } from 'node:child_process';
import type { EnclaveRequest, EnclaveResponse } from './types.js';

const HEADER_SIZE = 4;

/**
 * Send a request to an enclave via vsock and return the response.
 *
 * @param cid - Enclave CID (e.g., 16 for VIES)
 * @param port - Enclave vsock port (e.g., 5000)
 * @param request - Request to forward
 * @param timeoutMs - Timeout in ms (default 30000)
 */
export function sendToEnclave(
  cid: number,
  port: number,
  request: EnclaveRequest,
  timeoutMs: number = 30_000,
): Promise<EnclaveResponse> {
  return new Promise<EnclaveResponse>((resolve, reject) => {
    const timer = setTimeout(() => {
      proc.kill('SIGKILL');
      reject(new Error(`Enclave request timed out after ${timeoutMs}ms (CID ${cid}, port ${port})`));
    }, timeoutMs);

    const cleanup = () => clearTimeout(timer);

    // socat bridges STDIO to a vsock connection
    const proc = spawn('socat', ['STDIO', `VSOCK-CONNECT:${cid}:${port}`], {
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    // Send the length-prefixed request
    const payload = Buffer.from(JSON.stringify(request), 'utf-8');
    const header = Buffer.alloc(HEADER_SIZE);
    header.writeUInt32BE(payload.length, 0);
    proc.stdin.write(Buffer.concat([header, payload]));
    proc.stdin.end();

    // Collect the response
    const chunks: Buffer[] = [];

    proc.stdout.on('data', (chunk: Buffer) => {
      chunks.push(chunk);
    });

    proc.stdout.on('end', () => {
      cleanup();
      try {
        const data = Buffer.concat(chunks);
        if (data.length < HEADER_SIZE) {
          reject(new Error(`Incomplete response from enclave (${data.length} bytes)`));
          return;
        }

        const responseLength = data.readUInt32BE(0);
        if (data.length < HEADER_SIZE + responseLength) {
          reject(new Error(`Truncated response: expected ${responseLength} bytes, got ${data.length - HEADER_SIZE}`));
          return;
        }

        const responseJson = data.subarray(HEADER_SIZE, HEADER_SIZE + responseLength).toString('utf-8');
        resolve(JSON.parse(responseJson) as EnclaveResponse);
      } catch (err: any) {
        reject(new Error(`Failed to parse enclave response: ${err.message}`));
      }
    });

    proc.on('error', (err: Error) => {
      cleanup();
      reject(new Error(`socat spawn failed (CID ${cid}, port ${port}): ${err.message}`));
    });

    let stderrOutput = '';
    proc.stderr.on('data', (data: Buffer) => {
      stderrOutput += data.toString();
    });

    proc.on('close', (code: number | null) => {
      if (code !== 0 && code !== null) {
        cleanup();
        reject(new Error(`socat exited with code ${code} (CID ${cid}, port ${port}): ${stderrOutput.trim()}`));
      }
    });
  });
}
