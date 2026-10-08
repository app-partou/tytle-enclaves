/**
 * SICAE Custom Handler
 *
 * Multi-step HTTP + HTML parsing inside the enclave, outputting
 * concatenated BN254 field elements (compact binary, 256 bytes).
 *
 * Flow:
 * 1. Parse request body as JSON: { nif: string }
 * 2. GET www.sicae.pt/Consulta.aspx -> extract __VIEWSTATE, __EVENTVALIDATION, cookie
 * 3. POST NIF search -> get results HTML
 * 4. Read the page: a results row (officialName, primary CAE, secondary CAE), SICAE's "no data" row,
 *    its "NIPC not valid" refusal, or a page it cannot read (an error, never an answer)
 * 5. Encode as BN254 field elements (8 x 32 bytes = 256 bytes): the answer, dataHash (the SHA-256 of the page it
 *    was read from) and transport ('http': www.sicae.pt has no HTTPS); "not found" is nif + five nulls, status 404
 * 6. Attest the encoded bytes
 * 7. Return response with attestation + human-readable headers
 */

import crypto from 'node:crypto';
import { SICAE_SCHEMA } from '@tytle-enclaves/shared';
import type { HandlerDef, HandlerResult, HandlerContext, AllowedHost } from '@tytle-enclaves/shared';
import { HANDLER_MANIFEST, MANIFEST_HASH } from './manifest.js';

/** The enclave's allowlist: www.sicae.pt over the host's vsock-proxy on port 8445, plain HTTP (no HTTPS there). */
export const SICAE_HOSTS: AllowedHost[] = [
  { hostname: 'www.sicae.pt', vsockProxyPort: 8445, tls: false },
];

// =============================================================================
// SICAE Lookup Types
// =============================================================================

interface SicaeResult {
  officialName: string;
  caePrimary: string;
  caePrimaryDescription: string;
  caeSecondary: Array<{ code: string; description: string }>;
}

interface FormVariant {
  nifField: string;
  submitField: string;
  submitValue: string;
}

const FORM_VARIANTS: FormVariant[] = [
  { nifField: 'ctl00$MainContent$ipNipc', submitField: 'ctl00$MainContent$btnPesquisa', submitValue: 'Pesquisar' },
  { nifField: 'ctl00$MainContent$consultaSimplesNIPCNIPC', submitField: 'ctl00$MainContent$consultaSimplesSubmit', submitValue: 'Pesquisar' },
];

// =============================================================================
// What SICAE answers (www.sicae.pt/Consulta.aspx, read live 2026-10-07)
// =============================================================================

/** SICAE's own words in the results grid's only row when it holds nothing for the number (NIF 980494796). */
export const SICAE_NO_DATA = 'Não existem dados para o critério de pesquisa indicado.';

/** SICAE's own words in its error label (class ClassErro) when it refuses the number as a NIPC (a bad check digit). */
export const SICAE_INVALID_NIPC = "O campo 'NIPC' não é válido";

/** What one POST answered. Only `found` and `not_found` are answers; the rest are errors, never signed. */
type PageOutcome =
  | { kind: 'found'; result: SicaeResult }
  | { kind: 'not_found'; why: 'no_data' | 'invalid_nipc' }
  | { kind: 'unreadable'; detail: string }
  | { kind: 'not_processed' };

/** The text of an HTML fragment: tags dropped, &nbsp; as a space, trimmed. */
function textOf(fragment: string): string {
  return fragment.replace(/<[^>]*>/g, '').replace(/&nbsp;/g, ' ').trim();
}

/** The results table (class gridMain, or the grid's id when the class is gone), or null. */
function gridTableOf(html: string): string | null {
  return html.match(/<table[^>]*(?:class="gridMain"|id="[^"]*ConsultaDataGrid")[^>]*>[\s\S]*?<\/table>/)?.[0] ?? null;
}

/** The non-empty texts of SICAE's error labels (class ClassErro). */
function errorLabelsOf(html: string): string[] {
  return [...html.matchAll(/<span[^>]*\bclass="ClassErro"[^>]*>([\s\S]*?)<\/span>/g)]
    .map((m) => textOf(m[1]))
    .filter((t) => t !== '');
}

/** SICAE's "no data" grid: one data row whose only text is SICAE's own no-data message. */
function isNoDataGrid(table: string): boolean {
  const rows = [...table.matchAll(/<tr[^>]*>([\s\S]*?)<\/tr>/g)].slice(1);
  if (rows.length !== 1) return false;
  const texts = [...rows[0][1].matchAll(/<td[^>]*>([\s\S]*?)<\/td>/g)].map((c) => textOf(c[1])).filter((t) => t !== '');
  return texts.length === 1 && texts[0] === SICAE_NO_DATA;
}

/**
 * Read one POST's page. A miss is never an answer (audit 2026-10 P1.4): only a results row, SICAE's own
 * "no data" row and its "NIPC not valid" refusal are answers; a grid or an error label this handler cannot
 * read is `unreadable`; a page with neither is `not_processed` (the form variant was not taken).
 */
function readSicaePage(html: string, nif: string): PageOutcome {
  const labels = errorLabelsOf(html);
  const table = gridTableOf(html);
  if (labels.length > 0) {
    if (!table && labels.length === 1 && labels[0] === SICAE_INVALID_NIPC) return { kind: 'not_found', why: 'invalid_nipc' };
    const said = `"${labels.join(' | ').slice(0, 120)}"`;
    return { kind: 'unreadable', detail: table ? `an error label beside a results grid: ${said}` : `an error label this handler does not know: ${said}` };
  }
  if (!table) return { kind: 'not_processed' };
  const parsed = parseSicaeResults(html);
  if (parsed) {
    // The row names the number it answers for: another number's row is never signed under this one.
    if (parsed.rowNipc !== null && parsed.rowNipc !== nif) {
      return { kind: 'unreadable', detail: `the results row is for another NIPC (${parsed.rowNipc})` };
    }
    return { kind: 'found', result: parsed.result };
  }
  if (isNoDataGrid(table)) return { kind: 'not_found', why: 'no_data' };
  return { kind: 'unreadable', detail: 'a results grid this handler cannot read' };
}

// =============================================================================
// HTML Parsing (ported from ai-agent-server/src/invoicing/services/sicaeLookup.ts)
// =============================================================================

function detectNameColumnOffset(cells: string[]): number {
  const firstCellText = cells[0].replace(/<[^>]*>/g, '').trim();
  return /^\d{9}$/.test(firstCellText) ? 1 : 0;
}

/** The row's NIPC (its first cell, when the grid has the NIPC column), or null. */
function rowNipcOf(cells: string[], off: number): string | null {
  return off === 1 ? cells[0].replace(/<[^>]*>/g, '').trim() : null;
}

interface ParsedRow {
  result: SicaeResult;
  rowNipc: string | null;
}

function parsePrimaryStrategy(html: string): ParsedRow | null {
  // The header row, then the first data row's cells. The data row's own <tr> stays out of the capture: left in,
  // it became cells[0], the NIPC column was never seen, and this strategy failed on every real page (the
  // fallback answered, without the secondary CAE's description).
  const gridMatch = html.match(/class="gridHeader"[\s\S]*?<\/tr>\s*<tr[^>]*>([\s\S]*?)<\/tr>/);
  if (!gridMatch) return null;

  const dataRow = gridMatch[1];
  const cells = dataRow.split(/<td[^>]*>/).filter(c => c.trim());
  if (cells.length < 3) return null;

  const off = detectNameColumnOffset(cells);

  const nameMatch = cells[off]?.match(/title="([^"]+)"/);
  const officialName = nameMatch ? nameMatch[1].trim() : '';
  if (!officialName) return null;

  const caeCell = cells[off + 1];
  if (!caeCell) return null;
  const primaryCodeMatch = caeCell.match(/\b(\d{5})\b/);
  const primaryDescMatch = caeCell.match(/title="([^"]+)"/);
  const caePrimary = primaryCodeMatch ? primaryCodeMatch[1] : '';
  const caePrimaryDescription = primaryDescMatch ? primaryDescMatch[1].trim() : '';

  if (!/^\d{5}$/.test(caePrimary)) return null;

  const secondaryCell = cells[off + 2];
  const caeSecondary: Array<{ code: string; description: string }> = [];
  const secondaryDivs = secondaryCell?.match(/<div[^>]*title="([^"]*)"[^>]*>([\s\S]*?)<\/div>/g) || [];
  const seenCodes = new Set<string>();

  for (const div of secondaryDivs) {
    const descMatch = div.match(/title="([^"]+)"/);
    const codeMatch = div.match(/\b(\d{5})\b/);
    if (descMatch && codeMatch) {
      const code = codeMatch[1].replace(/,$/, '');
      const description = descMatch[1].trim();
      if (/^\d{5}$/.test(code) && description && !seenCodes.has(code)) {
        seenCodes.add(code);
        caeSecondary.push({ code, description });
      }
    }
  }

  return { result: { officialName, caePrimary, caePrimaryDescription, caeSecondary }, rowNipc: rowNipcOf(cells, off) };
}

function parseFallbackStrategy(html: string): ParsedRow | null {
  const tableMatch = html.match(/class="gridMain"[\s\S]*?<\/table>/) || html.match(/id="[^"]*ConsultaDataGrid"[\s\S]*?<\/table>/);
  if (!tableMatch) return null;

  const table = tableMatch[0];
  const rows = table.split(/<tr[^>]*>/).slice(2);
  if (rows.length === 0) return null;

  const dataRow = rows[0];
  const cells = dataRow.split(/<td[^>]*>/).filter(c => c.trim());
  if (cells.length < 3) return null;

  const off = detectNameColumnOffset(cells);

  const nameMatch = cells[off]?.match(/title="([^"]+)"/) || cells[off]?.match(/>([^<]+)</);
  const officialName = nameMatch ? nameMatch[1].trim() : '';
  if (!officialName) return null;

  const allCodes = dataRow.match(/\b\d{5}\b/g) || [];
  const validCodes = [...new Set(allCodes)].filter(c => /^\d{5}$/.test(c));
  if (validCodes.length === 0) return null;

  const caePrimary = validCodes[0];
  const caeSecondary = validCodes.slice(1).map(code => ({ code, description: '' }));

  const primaryDescMatch = cells[off + 1]?.match(/title="([^"]+)"/);
  const caePrimaryDescription = primaryDescMatch ? primaryDescMatch[1].trim() : '';

  return { result: { officialName, caePrimary, caePrimaryDescription, caeSecondary }, rowNipc: rowNipcOf(cells, off) };
}

/** A results row read by the primary strategy, else the fallback one; null when neither reads it. */
function parseSicaeResults(html: string): ParsedRow | null {
  try {
    const result = parsePrimaryStrategy(html);
    if (result) return result;
  } catch { /* fall through */ }

  try {
    const result = parseFallbackStrategy(html);
    if (result) return result;
  } catch { /* fall through */ }

  return null;
}

// =============================================================================
// HTTP Helpers
// =============================================================================

function detectFormVariants(pageHtml: string): FormVariant[] {
  return [...FORM_VARIANTS].sort((a, b) => {
    const aPresent = pageHtml.includes(a.nifField.replace(/\$/g, '_')) ? 1 : 0;
    const bPresent = pageHtml.includes(b.nifField.replace(/\$/g, '_')) ? 1 : 0;
    return bPresent - aPresent;
  });
}

function buildFormBody(nif: string, viewState: string, eventValidation: string, variant: FormVariant): string {
  const params = new URLSearchParams({
    '__VIEWSTATE': viewState,
    '__EVENTVALIDATION': eventValidation,
    [variant.nifField]: nif,
    [variant.submitField]: variant.submitValue,
  });
  return params.toString();
}

// =============================================================================
// Handler Definition
// =============================================================================

interface SicaeParams {
  nif: string;
}

export const sicaeHandlerDef: HandlerDef<SicaeParams> = {
  name: 'sicae',
  schema: SICAE_SCHEMA,
  manifestHash: MANIFEST_HASH,
  policies: HANDLER_MANIFEST.policies,
  requiredHosts: ['www.sicae.pt'],

  parseParams(body: unknown): SicaeParams {
    const b = body as Record<string, unknown>;
    const nif = b.nif as string | undefined;

    if (!nif || !/^\d{9}$/.test(nif)) {
      throw new Error(`Invalid NIF: "${nif ?? ''}" - must be exactly 9 digits`);
    }

    return { nif };
  },

  async execute(params: SicaeParams, ctx: HandlerContext): Promise<HandlerResult> {
    const { nif } = params;
    const sicaeHost = ctx.hosts.find((h) => h.hostname === 'www.sicae.pt')!;

    // Step 1: GET page to extract ASP.NET tokens
    const getResponse = await ctx.fetch(
      sicaeHost,
      'GET',
      '/Consulta.aspx',
      {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'pt-PT,pt;q=0.9',
      },
    );

    if (getResponse.status !== 200) {
      throw new Error(`SICAE GET failed: ${getResponse.status}`);
    }

    const pageHtml = getResponse.body;

    // Extract __VIEWSTATE
    const vsMatch = pageHtml.match(/id="__VIEWSTATE"\s+value="([^"]*)"/);
    if (!vsMatch) {
      throw new Error('Could not extract __VIEWSTATE');
    }

    // Extract __EVENTVALIDATION
    const evMatch = pageHtml.match(/id="__EVENTVALIDATION"\s+value="([^"]*)"/);
    if (!evMatch) {
      throw new Error('Could not extract __EVENTVALIDATION');
    }

    // Extract session cookie
    const cookieHeader = getResponse.headers['set-cookie'] || '';
    const cookieMatch = cookieHeader.match(/ASP\.NET_SessionId=([^;]+)/);
    const sessionCookie = cookieMatch ? `ASP.NET_SessionId=${cookieMatch[1]}` : '';

    const viewState = vsMatch[1];
    const eventValidation = evMatch[1];
    const variants = detectFormVariants(pageHtml);

    // Step 2: POST NIF search - try each variant until SICAE processes one
    let outcome: PageOutcome = { kind: 'not_processed' };
    let answeredPage = '';
    const refusedStatuses: number[] = [];
    for (const variant of variants) {
      const formBody = buildFormBody(nif, viewState, eventValidation, variant);

      const postHeaders: Record<string, string> = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Referer': `http://${sicaeHost.hostname}/Consulta.aspx`,
        'Origin': `http://${sicaeHost.hostname}`,
      };
      if (sessionCookie) {
        postHeaders['Cookie'] = sessionCookie;
      }

      const postResponse = await ctx.fetch(
        sicaeHost,
        'POST',
        '/Consulta.aspx',
        postHeaders,
        formBody,
      );

      if (postResponse.status !== 200) {
        refusedStatuses.push(postResponse.status);
        continue;
      }
      outcome = readSicaePage(postResponse.body, nif);
      answeredPage = postResponse.body;
      // A processed page - an answer or one this handler cannot read - is what any other variant would get too.
      if (outcome.kind !== 'not_processed') break;
    }

    const apiEndpoint = `${sicaeHost.hostname}/Consulta.aspx`;
    // Committed with every answer (audit P1.4 / P1.5): the page it was read from, and how the bytes came - plain HTTP
    // here, so the answer is a provenance record, never evidence the page itself is genuine.
    const dataHash = crypto.createHash('sha256').update(answeredPage, 'utf8').digest('hex');
    const transport = sicaeHost.tls === false ? 'http' : 'https';

    if (outcome.kind === 'unreadable') {
      throw new Error(`SICAE page unreadable: ${outcome.detail}`);
    }
    if (outcome.kind === 'not_processed') {
      throw new Error(refusedStatuses.length === variants.length
        ? `SICAE refused every form variant (HTTP ${refusedStatuses.join(', ')})`
        : 'SICAE processed no form variant (no results grid, no error label)');
    }
    if (outcome.kind === 'not_found') {
      // SICAE's own "no data" row or its "NIPC not valid" refusal: a definitive answer, signed like any other
      // (audit 2026-10 P1.4: only an attested 200 with an empty result is not_found). nif is set, every other
      // field is null - a found row always has a name and a primary CAE.
      return {
        values: { nif, name: null, cae1Code: null, cae1Desc: null, cae2Code: null, cae2Desc: null, dataHash, transport },
        apiEndpoint,
        method: 'POST',
        url: `http://${sicaeHost.hostname}/Consulta.aspx`,
        requestHeaders: { nif },
        responseHeaders: { 'x-sicae-nif': nif, 'x-sicae-not-found': outcome.why, 'x-sicae-data-hash': dataHash, 'x-sicae-transport': transport },
        bn254Headers: { 'x-sicae-data-hash': dataHash },
        status: 404,
      };
    }
    const sicaeResult = outcome.result;

    // Step 3: Build result for BN254 encoding + attestation
    const cae2Code = sicaeResult.caeSecondary.length > 0 ? sicaeResult.caeSecondary[0].code : null;
    const cae2Desc = sicaeResult.caeSecondary.length > 0 ? sicaeResult.caeSecondary[0].description : null;

    return {
      values: {
        nif,
        name: sicaeResult.officialName,
        cae1Code: sicaeResult.caePrimary,
        cae1Desc: sicaeResult.caePrimaryDescription,
        cae2Code,
        cae2Desc,
        dataHash,
        transport,
      },
      apiEndpoint,
      method: 'POST',
      url: `http://${sicaeHost.hostname}/Consulta.aspx`,
      requestHeaders: { nif },
      responseHeaders: {
        'x-sicae-nif': nif,
        'x-sicae-name': sicaeResult.officialName,
        'x-sicae-cae1-code': sicaeResult.caePrimary,
        'x-sicae-cae1-desc': sicaeResult.caePrimaryDescription,
        'x-sicae-cae2-code': cae2Code || '',
        'x-sicae-cae2-desc': cae2Desc || '',
        'x-sicae-data-hash': dataHash,
        'x-sicae-transport': transport,
      },
      bn254Headers: {
        'x-sicae-name': sicaeResult.officialName,
        'x-sicae-cae1-desc': sicaeResult.caePrimaryDescription,
        'x-sicae-cae2-desc': cae2Desc || '',
        'x-sicae-data-hash': dataHash,
      },
    };
  },
};
