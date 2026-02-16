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
import { VsockStream } from '@tytle-enclaves/native';
import { VsockDuplex } from './vsockStream.js';

/** CID 3 = host parent from inside the enclave */
const HOST_CID = 3;

export interface HttpResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

/**
 * Make an HTTPS request through a vsock-proxy tunnel.
 *
 * @param vsockPort - The vsock-proxy port on the host (e.g., 8443 for ec.europa.eu)
 * @param hostname - The remote hostname for TLS SNI + cert verification
 * @param method - HTTP method
 * @param path - Request path (e.g., /taxation_customs/vies/services/checkVatService)
 * @param headers - HTTP headers
 * @param body - Optional request body
 * @param timeoutMs - Timeout in ms (default 25000)
 */
export async function proxyFetch(
  vsockPort: number,
  hostname: string,
  method: string,
  path: string,
  headers: Record<string, string>,
  body?: string,
  timeoutMs: number = 25_000,
): Promise<HttpResponse> {
  return new Promise<HttpResponse>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`proxyFetch timeout after ${timeoutMs}ms to ${hostname}${path}`));
    }, timeoutMs);

    try {
      // Step 1: Connect to host's vsock-proxy
      const vsockRaw = VsockStream.connect(HOST_CID, vsockPort);
      const duplex = new VsockDuplex(vsockRaw);

      // Step 2: TLS handshake over vsock tunnel
      const tlsSocket = tls.connect(
        {
          socket: duplex as any,
          servername: hostname,
          rejectUnauthorized: true, // Mandatory — validates server cert against CA bundle
        },
        () => {
          // TLS handshake complete — send HTTP request
          // Host and Connection are set AFTER spread to prevent caller override
          const reqHeaders = {
            ...headers,
            Host: hostname,
            Connection: 'close',
          };

          let httpReq = `${method} ${path} HTTP/1.1\r\n`;
          for (const [key, value] of Object.entries(reqHeaders)) {
            httpReq += `${key}: ${value}\r\n`;
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

      // Step 3: Collect response (as bytes — decode to string after de-chunking)
      const chunks: Buffer[] = [];
      tlsSocket.on('data', (chunk: Buffer) => {
        chunks.push(chunk);
      });

      tlsSocket.on('end', () => {
        clearTimeout(timer);
        try {
          const raw = Buffer.concat(chunks);
          const response = parseHttpResponse(raw);
          resolve(response);
        } catch (err) {
          reject(err);
        }
      });

      tlsSocket.on('error', (err: Error) => {
        clearTimeout(timer);
        reject(new Error(`TLS error to ${hostname}: ${err.message}`));
      });
    } catch (err) {
      clearTimeout(timer);
      reject(err);
    }
  });
}

/**
 * Make a plain HTTP request through a vsock-proxy tunnel (no TLS).
 *
 * Same as proxyFetch but skips the TLS handshake — writes raw HTTP directly
 * to the VsockDuplex stream. Use for HTTP-only hosts (e.g., www.sicae.pt).
 *
 * WARNING: Without TLS the host can read and modify traffic in transit.
 * Only appropriate for public, non-sensitive data.
 */
export async function proxyFetchPlain(
  vsockPort: number,
  hostname: string,
  method: string,
  path: string,
  headers: Record<string, string>,
  body?: string,
  timeoutMs: number = 25_000,
): Promise<HttpResponse> {
  return new Promise<HttpResponse>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`proxyFetchPlain timeout after ${timeoutMs}ms to ${hostname}${path}`));
    }, timeoutMs);

    try {
      // Connect to host's vsock-proxy (no TLS — write raw HTTP)
      const vsockRaw = VsockStream.connect(HOST_CID, vsockPort);
      const duplex = new VsockDuplex(vsockRaw);

      // Build and send HTTP request directly over the vsock tunnel
      const reqHeaders = {
        ...headers,
        Host: hostname,
        Connection: 'close',
      };

      let httpReq = `${method} ${path} HTTP/1.1\r\n`;
      for (const [key, value] of Object.entries(reqHeaders)) {
        httpReq += `${key}: ${value}\r\n`;
      }

      if (body) {
        httpReq += `Content-Length: ${Buffer.byteLength(body, 'utf-8')}\r\n`;
      }
      httpReq += '\r\n';

      if (body) {
        httpReq += body;
      }

      duplex.write(httpReq);

      // Collect response
      const chunks: Buffer[] = [];
      duplex.on('data', (chunk: Buffer) => {
        chunks.push(chunk);
      });

      duplex.on('end', () => {
        clearTimeout(timer);
        try {
          const raw = Buffer.concat(chunks);
          const response = parseHttpResponse(raw);
          resolve(response);
        } catch (err) {
          reject(err);
        }
      });

      duplex.on('error', (err: Error) => {
        clearTimeout(timer);
        reject(new Error(`Plain HTTP error to ${hostname}: ${err.message}`));
      });
    } catch (err) {
      clearTimeout(timer);
      reject(err);
    }
  });
}

/**
 * Parse raw HTTP/1.1 response into structured object.
 * Operates on Buffer to correctly handle chunked encoding with multi-byte characters.
 * Headers are ASCII, so safe to split as string. Body is decoded after de-chunking.
 */
function parseHttpResponse(raw: Buffer): HttpResponse {
  // Find header/body separator (\r\n\r\n) at byte level
  const separator = Buffer.from('\r\n\r\n');
  const headerEnd = raw.indexOf(separator);
  if (headerEnd === -1) {
    throw new Error('Malformed HTTP response: no header/body separator');
  }

  // Headers are ASCII — safe to decode as string
  const headerSection = raw.subarray(0, headerEnd).toString('ascii');
  const bodyBuf = raw.subarray(headerEnd + 4);

  const lines = headerSection.split('\r\n');
  const statusLine = lines[0];

  // Parse status line: "HTTP/1.1 200 OK"
  const statusMatch = statusLine.match(/^HTTP\/\d\.\d\s+(\d+)/);
  if (!statusMatch) {
    throw new Error(`Malformed status line: ${statusLine}`);
  }
  const status = parseInt(statusMatch[1], 10);

  // Parse headers
  const headers: Record<string, string> = {};
  for (let i = 1; i < lines.length; i++) {
    const colonIdx = lines[i].indexOf(':');
    if (colonIdx > 0) {
      const key = lines[i].substring(0, colonIdx).trim().toLowerCase();
      const value = lines[i].substring(colonIdx + 1).trim();
      headers[key] = value;
    }
  }

  // Handle chunked transfer encoding at byte level, then decode to string
  let responseBody: string;
  if (headers['transfer-encoding']?.includes('chunked')) {
    responseBody = decodeChunked(bodyBuf).toString('utf-8');
  } else {
    responseBody = bodyBuf.toString('utf-8');
  }

  return { status, headers, body: responseBody };
}

/**
 * Decode chunked transfer encoding.
 * Operates on Buffer so chunk sizes (byte counts) correctly index the data,
 * even when the body contains multi-byte UTF-8 characters.
 */
function decodeChunked(raw: Buffer): Buffer {
  const parts: Buffer[] = [];
  let offset = 0;
  const crlf = Buffer.from('\r\n');

  while (offset < raw.length) {
    const lineEnd = raw.indexOf(crlf, offset);
    if (lineEnd === -1) break;

    const chunkSizeHex = raw.subarray(offset, lineEnd).toString('ascii').trim();
    const chunkSize = parseInt(chunkSizeHex, 16);

    if (chunkSize === 0) break; // Terminal chunk

    const chunkStart = lineEnd + 2;
    const chunkEnd = chunkStart + chunkSize;
    parts.push(raw.subarray(chunkStart, chunkEnd));

    offset = chunkEnd + 2; // Skip \r\n after chunk data
  }

  return Buffer.concat(parts);
}
