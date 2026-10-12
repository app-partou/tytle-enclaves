/**
 * SICAE Portuguese CAE Code Handler Manifest
 *
 * Its status rules are run against the handler by the package's tests (sicaeHandler.factory.test.ts).
 */

import {
  computeManifestHash, validateManifest, SICAE_SCHEMA,
} from '@tytle-enclaves/shared';
import type { HandlerManifest } from '@tytle-enclaves/shared';

const CHROME_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

export const HANDLER_MANIFEST: HandlerManifest = {
  // 1.0.0 was kept across vector version 2 (the 2026-10-09 release); 1.1.0 is the second enclave release (R4)
  version: '1.1.0',

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
      reason: 'NIF must be text of exactly 9 digits (a number or an array is a 400)',
    },
    {
      id: 'nif_check_digit',
      check: { type: 'behavioral', description: 'The NIF\'s mod-11 check digit (weights 9 to 2 over the first eight digits; a remainder of 0 or 1 gives 0) is checked before any fetch: a wrong one is a 400' },
      reason: 'SICAE refuses such a number, and that refusal read as "not found", the same signed answer as "SICAE holds nothing for this number" (enclave review 2026-10-09, E2a F-7)',
    },
    {
      id: 'asp_tokens_required',
      check: { type: 'field_required', paths: ['__VIEWSTATE', '__EVENTVALIDATION'] },
      reason: 'ASP.NET tokens must be extracted from initial GET response before POST',
    },
    {
      id: 'session_cookie_forwarding',
      check: { type: 'behavioral', description: 'The ASP.NET_SessionId cookie, among every Set-Cookie the GET answered, is forwarded to the POST if present' },
      reason: 'SICAE requires session continuity between GET and POST; a cookie after the session one used to drop it (enclave review 2026-10-09, E1 F-1)',
    },
    {
      id: 'form_variant_fallback',
      check: { type: 'behavioral', description: 'Tries the next ASP.NET form variant only while SICAE processed none (no results grid, no error label, or a non-200)' },
      reason: 'SICAE has changed form field names over time; handler supports both variants',
    },
    {
      id: 'status',
      check: { type: 'behavioral', description: 'A search page (GET) other than 200 throws 502; a form post other than 200 tries the next form variant, and when SICAE refused every one the answer is a 502. Nothing is passed on unsigned' },
      reason: 'Only SICAE\'s own page is read',
    },
    {
      id: 'not_found',
      check: { type: 'behavioral', description: 'SICAE\'s own "no data" row, or its "NIPC not valid" refusal of a number whose check digit is right, is signed as not found: the enclave answers status 404 (success: true), nif set, every other field null. SICAE itself answers these with a 200 page' },
      reason: 'A definitive answer is signed like any other; SICAE never answers a 404, so this is no rule on an upstream status (enclave review 2026-10-09, E2a F-17)',
    },
    {
      id: 'no_data_row',
      check: { type: 'behavioral', description: 'The results grid\'s only row, with "Não existem dados para o critério de pesquisa indicado." as its only text, is not_found; the same text anywhere else on the page is not' },
      reason: 'SICAE saying it holds nothing for the number; a substring of the whole page would accept pages the enclave refuses',
    },
    {
      id: 'html_error_detection',
      check: { type: 'behavioral', description: 'SICAE\'s error label (class ClassErro), with "O campo \'NIPC\' não é válido" as its only text and no results grid, is not_found; any other error text throws 502' },
      reason: 'SICAE refusing a number whose check digit is right; a substring of the whole page would accept pages the enclave refuses',
    },
    {
      id: 'parse_miss_is_error',
      check: { type: 'behavioral', description: 'A results grid or error label the handler cannot read, a results row for another NIPC or without its NIPC, or no form variant processed throws 502 - never not_found' },
      reason: 'A page that is not one of SICAE\'s known answers is no answer (audit 2026-10 P1.4)',
    },
    {
      id: 'one_strict_row_reader',
      check: { type: 'behavioral', description: 'One reader for the results row: SICAE\'s five column names in order; a code is the text its cell shows (a primary CAE, then secondary ones each with a description); the name\'s shown text is its title; character references decoded, an unknown one unreadable; a double quote that cuts a title unreadable. No looser reader answers when this one does not' },
      reason: 'The looser reader signed the first five-digit number of the row as the primary CAE and every secondary CAE without its description (enclave review 2026-10-09, E-2, E2a F-6)',
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
