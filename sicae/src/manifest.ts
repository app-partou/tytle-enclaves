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
    outputBytes: 256,
    fields: [
      { name: 'nif',       encoding: 'shortString', source: { from: 'request', param: 'nif' } },
      { name: 'name',      encoding: 'sha256',      source: { from: 'parsed', query: 'sicae_post', parser: 'html_grid', field: 'officialName' } },
      { name: 'cae1Code',  encoding: 'shortString', source: { from: 'parsed', query: 'sicae_post', parser: 'html_grid', field: 'primaryCAE.code' } },
      { name: 'cae1Desc',  encoding: 'sha256',      source: { from: 'parsed', query: 'sicae_post', parser: 'html_grid', field: 'primaryCAE.description' } },
      { name: 'cae2Code',  encoding: 'shortString', source: { from: 'parsed', query: 'sicae_post', parser: 'html_grid', field: 'secondaryCAE[0].code' } },
      { name: 'cae2Desc',  encoding: 'sha256',      source: { from: 'parsed', query: 'sicae_post', parser: 'html_grid', field: 'secondaryCAE[0].description' } },
      { name: 'dataHash',  encoding: 'sha256',      source: { from: 'derived', inputs: ['sicae_post:rawBody'], join: '', transform: 'sha256' } },
      { name: 'transport', encoding: 'shortString', source: { from: 'host', host: 'www.sicae.pt', property: 'tls' } },
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
      check: { type: 'behavioral', description: 'Tries the next ASP.NET form variant only while SICAE processed none (no results grid, no error label, or a non-200)' },
      reason: 'SICAE has changed form field names over time; handler supports both variants',
    },
    {
      id: 'not_found',
      check: { type: 'status_attest', code: 404, overrides: {} },
      reason: 'SICAE\'s own "no data" row or its "NIPC not valid" refusal is a definitive answer, attested (success: true, status: 404; nif set, every other field null)',
    },
    {
      id: 'no_data_row',
      check: { type: 'field_matches', path: 'responseBody', pattern: 'Não existem dados para o critério de pesquisa indicado\\.' },
      reason: 'The results grid\'s only row, with this exact text as its only text, is SICAE saying it holds nothing for the number (not_found)',
    },
    {
      id: 'html_error_detection',
      check: { type: 'field_matches', path: 'responseBody', pattern: "O campo 'NIPC' não é válido" },
      reason: 'Only this exact text in SICAE\'s error label (class ClassErro), with no results grid, is not_found; any other error text throws 502',
    },
    {
      id: 'parse_miss_is_error',
      check: { type: 'behavioral', description: 'A results grid or error label the handler cannot read, a results row for another NIPC, or no form variant processed throws 502 - never not_found' },
      reason: 'A page that is not one of SICAE\'s known answers is no answer (audit 2026-10 P1.4)',
    },
    {
      id: 'http_transport',
      check: { type: 'behavioral', description: 'Uses HTTP (no TLS) - www.sicae.pt does not support HTTPS; the signed vector says so (transport = \'http\')' },
      reason: 'The host relays plaintext and could change the page before the enclave reads it: the answer records which code read which page (dataHash), never that the page is genuine (audit P1.5, D-P1-1)',
    },
  ],

  repeatability: {
    hashAlgorithm: 'sha256',
    dataHashInput: 'sicae_post:rawBody - the page the answer was read from, UTF-8',
    outputFormat: 'BN254 big-endian, 8 × 32 bytes, base64',
    deterministic: true,
  },
};

validateManifest(HANDLER_MANIFEST, SICAE_SCHEMA);

export const MANIFEST_HASH = computeManifestHash(HANDLER_MANIFEST);
