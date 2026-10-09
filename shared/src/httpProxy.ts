/**
 * TLS-over-vsock HTTP proxy.
 *
 * Makes HTTPS requests by tunneling TLS through vsock-proxy:
 * 1. Connect to host's vsock-proxy via AF_VSOCK (CID 3 = host)
 * 2. Wrap the vsock connection in a TLS socket (servername for SNI + cert verification)
 * 3. Send raw HTTP request over TLS
 * 4. Parse HTTP response
 *
 * The host's vsock-proxy is a blind TCP tunnel — it sees only encrypted TLS traffic.
 * TLS is negotiated end-to-end between the enclave and the remote server.
 * The CA bundle is baked into the Docker image (contributing to PCR0).
 */

import * as tls from 'node:tls';
import { Duplex } from 'node:stream';
import { VsockStream } from '@tytle-enclaves/native';
import { VsockDuplex } from './vsockStream.js';
import { ResponseCollector, type HttpResponse } from './httpParse.js';
import { DEFAULT_FETCH_TIMEOUT_MS } from './requestBudget.js';

export type { HttpResponse } from './httpParse.js';

/** CID 3 = host parent from inside the enclave */
const HOST_CID = 3;

/** The socket read/write timeout for a fetch budget: whole seconds, at least 1 (0 means "never" to the kernel). */
function socketTimeoutSecs(timeoutMs: number): number {
  return Math.max(1, Math.ceil(timeoutMs / 1000));
}

/**
 * Per-hostname TLS session cache for session resumption.
 * Avoids a full TLS handshake on subsequent requests to the same host.
 * Bounded naturally: each enclave has 1-2 fixed hosts.
 * Node.js TLS falls back to a full handshake if a cached ticket is rejected.
 */
const tlsSessionCache = new Map<string, Buffer>();

/**
 * Make an HTTPS request through a vsock-proxy tunnel.
 *
 * @param vsockPort - The vsock-proxy port on the host (e.g., 8443 for ec.europa.eu)
 * @param hostname - The remote hostname for TLS SNI + cert verification
 * @param method - HTTP method
 * @param path - Request path (e.g., /taxation_customs/vies/services/checkVatService)
 * @param headers - HTTP headers
 * @param body - Optional request body
 * @param timeoutMs - Timeout in ms (default DEFAULT_FETCH_TIMEOUT_MS, 25 s)
 */
export async function proxyFetch(
  vsockPort: number,
  hostname: string,
  method: string,
  path: string,
  headers: Record<string, string>,
  body?: string,
  timeoutMs: number = DEFAULT_FETCH_TIMEOUT_MS,
): Promise<HttpResponse> {
  return new Promise<HttpResponse>((resolve, reject) => {
    let duplex: VsockDuplex | null = null;

    const timer = setTimeout(() => {
      // Destroy the underlying socket to prevent FD leak on timeout
      duplex?.destroy();
      reject(new Error(`proxyFetch timeout after ${timeoutMs}ms to ${hostname}${path}`));
    }, timeoutMs);

    try {
      // Step 1: Connect to host's vsock-proxy. Every read and write on the socket gives up within the
      // fetch budget: a proxy that accepts and goes silent must not block libc::read forever.
      const vsockRaw = VsockStream.connect(HOST_CID, vsockPort, socketTimeoutSecs(timeoutMs));
      duplex = new VsockDuplex(vsockRaw);

      // Step 2: TLS handshake over vsock tunnel (with session resumption)
      const tlsSocket = tls.connect(
        {
          socket: duplex as Duplex,
          servername: hostname,
          rejectUnauthorized: true,
          session: tlsSessionCache.get(hostname),
        },
        () => {
          // TLS handshake complete - send HTTP request
          // Host and Connection are set AFTER spread to prevent caller override
          const reqHeaders = {
            ...headers,
            Host: hostname,
            Connection: 'close',
          };

          let httpReq = `${method} ${path} HTTP/1.1\r\n`;
          for (const [key, value] of Object.entries(reqHeaders)) {
            // Sanitize header keys and values to prevent CRLF injection
            const safeKey = key.replace(/[\r\n]/g, '');
            httpReq += `${safeKey}: ${value.replace(/[\r\n]/g, '')}\r\n`;
          }

          if (body) {
            httpReq += `Content-Length: ${Buffer.byteLength(body, 'utf-8')}\r\n`;
          }
          httpReq += '\r\n';

          if (body) {
            httpReq += body;
          }

          tlsSocket.write(httpReq);
        },
      );

      // Cache TLS session ticket for resumption on next connection
      tlsSocket.on('session', (session: Buffer) => {
        tlsSessionCache.set(hostname, session);
      });

      // Step 3: Collect the response (bytes, at most MAX_RESPONSE_BYTES) and read it under httpParse.ts's rules
      const collector = new ResponseCollector(hostname);
      tlsSocket.on('data', (chunk: Buffer) => {
        try {
          collector.push(chunk);
        } catch (err) {
          clearTimeout(timer);
          tlsSocket.destroy();
          duplex?.destroy();
          reject(err);
        }
      });

      tlsSocket.on('end', () => {
        clearTimeout(timer);
        try {
          resolve(collector.finish());
        } catch (err) {
          reject(err);
        }
      });

      tlsSocket.on('error', (err: Error) => {
        clearTimeout(timer);
        duplex?.destroy();
        reject(new Error(`TLS error to ${hostname}: ${err.message}`));
      });
    } catch (err) {
      clearTimeout(timer);
      duplex?.destroy();
      reject(err);
    }
  });
}

/**
 * Make a plain HTTP request through a vsock-proxy tunnel (no TLS).
 *
 * Same as proxyFetch but skips the TLS handshake - writes raw HTTP directly
 * to the VsockDuplex stream. Use for HTTP-only hosts (e.g., www.sicae.pt).
 *
 * TRUST MODEL: Without TLS, the host vsock-proxy sees plaintext traffic and
 * could modify responses before the enclave processes them. The attestation
 * still proves which code ran (PCR0) and which host was contacted, but
 * CANNOT prove the response was not tampered by the host operating system.
 * Only appropriate for public, non-sensitive data where integrity can be
 * cross-verified through other sources.
 */
export async function proxyFetchPlain(
  vsockPort: number,
  hostname: string,
  method: string,
  path: string,
  headers: Record<string, string>,
  body?: string,
  timeoutMs: number = DEFAULT_FETCH_TIMEOUT_MS,
): Promise<HttpResponse> {
  return new Promise<HttpResponse>((resolve, reject) => {
    let duplex: VsockDuplex | null = null;

    const timer = setTimeout(() => {
      // Destroy the underlying socket to prevent FD leak on timeout
      duplex?.destroy();
      reject(new Error(`proxyFetchPlain timeout after ${timeoutMs}ms to ${hostname}${path}`));
    }, timeoutMs);

    try {
      // Connect to host's vsock-proxy (no TLS — write raw HTTP); reads and writes give up within the budget
      const vsockRaw = VsockStream.connect(HOST_CID, vsockPort, socketTimeoutSecs(timeoutMs));
      duplex = new VsockDuplex(vsockRaw);

      // Build and send HTTP request directly over the vsock tunnel
      const reqHeaders = {
        ...headers,
        Host: hostname,
        Connection: 'close',
      };

      let httpReq = `${method} ${path} HTTP/1.1\r\n`;
      for (const [key, value] of Object.entries(reqHeaders)) {
        // Sanitize header keys and values to prevent CRLF injection
        const safeKey = key.replace(/[\r\n]/g, '');
        httpReq += `${safeKey}: ${value.replace(/[\r\n]/g, '')}\r\n`;
      }

      if (body) {
        httpReq += `Content-Length: ${Buffer.byteLength(body, 'utf-8')}\r\n`;
      }
      httpReq += '\r\n';

      if (body) {
        httpReq += body;
      }

      duplex.write(httpReq);

      // Collect the response (bytes, at most MAX_RESPONSE_BYTES) and read it under httpParse.ts's rules
      const collector = new ResponseCollector(hostname);
      const plain = duplex;
      plain.on('data', (chunk: Buffer) => {
        try {
          collector.push(chunk);
        } catch (err) {
          clearTimeout(timer);
          plain.destroy();
          reject(err);
        }
      });

      plain.on('end', () => {
        clearTimeout(timer);
        try {
          resolve(collector.finish());
        } catch (err) {
          reject(err);
        }
      });

      plain.on('error', (err: Error) => {
        clearTimeout(timer);
        plain.destroy();
        reject(new Error(`Plain HTTP error to ${hostname}: ${err.message}`));
      });
    } catch (err) {
      clearTimeout(timer);
      duplex?.destroy();
      reject(err);
    }
  });
}
