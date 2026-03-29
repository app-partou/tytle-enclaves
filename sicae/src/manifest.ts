/**
 * SICAE Portuguese CAE Code Handler Manifest
 */

import {
  computeManifestHash, validateManifest, SICAE_SCHEMA,
} from '@tytle-enclaves/shared';
import type { HandlerManifest } from '@tytle-enclaves/shared';

const CHROME_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

export const HANDLER_MANIFEST: HandlerManifest = {
  version: '1.0.0',

  queries: [
    {
      id: 'sicae_get',
      description: 'GET initial SICAE page to extract ASP.NET ViewState/EventValidation tokens and session cookie',
      method: 'GET',
      host: 'www.sicae.pt',
      path: '/Consulta.aspx',
      headers: {
        'User-Agent': CHROME_UA,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'pt-PT,pt;q=0.9',
      },
    },
    {
      id: 'sicae_post',
      description: 'POST NIF lookup form with ASP.NET tokens (tries multiple form variants)',
      method: 'POST',
      host: 'www.sicae.pt',
      path: '/Consulta.aspx',
      headers: {
        'User-Agent': CHROME_UA,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Referer': 'http://www.sicae.pt/Consulta.aspx',
        'Origin': 'http://www.sicae.pt',
      },
    },
  ],

  schema: {
    name: 'SICAE_SCHEMA',
    outputBytes: 192,
    fields: [
      { name: 'nif',       encoding: 'shortString', source: { from: 'request', param: 'nif' } },
      { name: 'name',      encoding: 'sha256',      source: { from: 'parsed', query: 'sicae_post', parser: 'html_grid', field: 'officialName' } },
      { name: 'cae1Code',  encoding: 'shortString', source: { from: 'parsed', query: 'sicae_post', parser: 'html_grid', field: 'primaryCAE.code' } },
      { name: 'cae1Desc',  encoding: 'sha256',      source: { from: 'parsed', query: 'sicae_post', parser: 'html_grid', field: 'primaryCAE.description' } },
      { name: 'cae2Code',  encoding: 'shortString', source: { from: 'parsed', query: 'sicae_post', parser: 'html_grid', field: 'secondaryCAE[0].code' } },
      { name: 'cae2Desc',  encoding: 'sha256',      source: { from: 'parsed', query: 'sicae_post', parser: 'html_grid', field: 'secondaryCAE[0].description' } },
    ],
  },

  policies: [
    {
      id: 'nif_format',
      check: { type: 'field_matches', path: 'nif', pattern: '^\\d{9}$' },
      reason: 'NIF must be exactly 9 digits',
    },
    {
      id: 'asp_tokens_required',
      check: { type: 'field_required', paths: ['__VIEWSTATE', '__EVENTVALIDATION'] },
      reason: 'ASP.NET tokens must be extracted from initial GET response before POST',
    },
    {
      id: 'session_cookie_forwarding',
      check: { type: 'behavioral', description: 'ASP.NET_SessionId cookie from GET is forwarded to POST if present' },
      reason: 'SICAE requires session continuity between GET and POST',
    },
    {
      id: 'form_variant_fallback',
      check: { type: 'behavioral', description: 'Tries multiple ASP.NET form field names until one returns results' },
      reason: 'SICAE has changed form field names over time; handler supports both variants',
    },
    {
      id: 'not_found',
      check: { type: 'status_attest', code: 404, overrides: {} },
      reason: 'NIF not found or no CAE data is a valid, attestable answer (success: true, status: 404)',
    },
    {
      id: 'html_error_detection',
      check: { type: 'field_matches', path: 'responseBody', pattern: 'ClassErro' },
      reason: 'HTML responses containing ClassErro indicate validation errors (treated as not found)',
    },
    {
      id: 'http_transport',
      check: { type: 'behavioral', description: 'Uses HTTP (no TLS) — www.sicae.pt does not support HTTPS' },
      reason: 'Data is public and cross-referenced; host cannot forge NSM attestation',
    },
  ],

  repeatability: {
    hashAlgorithm: null,
    dataHashInput: null,
    outputFormat: 'BN254 big-endian, 6 × 32 bytes, base64',
    deterministic: true,
  },
};

validateManifest(HANDLER_MANIFEST, SICAE_SCHEMA);

export const MANIFEST_HASH = computeManifestHash(HANDLER_MANIFEST);
