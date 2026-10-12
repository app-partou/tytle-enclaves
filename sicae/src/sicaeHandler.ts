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
  const parsed = parseResultsRow(html);
  if (parsed) {
    // The row names the number it answers for: another number's row is never signed under this one.
    if (parsed.rowNipc !== nif) {
      return { kind: 'unreadable', detail: `the results row is for another NIPC (${parsed.rowNipc})` };
    }
    return { kind: 'found', result: parsed.result };
  }
  if (isNoDataGrid(table)) return { kind: 'not_found', why: 'no_data' };
  return { kind: 'unreadable', detail: 'a results grid this handler cannot read' };
}

// =============================================================================
// The results row (enclave review 2026-10-09, E-2 and E2a F-6, F-8)
// =============================================================================

/** SICAE's own words in the results grid's header row, in order (www.sicae.pt/Consulta.aspx, read live 2026-10-07). */
export const SICAE_GRID_HEADER = ['NIPC', 'Denominação Social/Firma', 'CAE Principal', 'CAEs Secundários', 'Mais CAE'];

/** The named character references SICAE's markup can hold; any other is not guessed. */
const NAMED_REFERENCES: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };

/** A text's character references decoded (named and numeric), or null when one is not a reference this reader knows. */
function decodeHtml(text: string): string | null {
  let unknown = false;
  const decoded = text.replace(/&(#[0-9]{1,7}|#[xX][0-9a-fA-F]{1,6}|[A-Za-z][A-Za-z0-9]*);/g, (whole, ref: string) => {
    const point = ref.startsWith('#x') || ref.startsWith('#X') ? parseInt(ref.slice(2), 16)
      : ref.startsWith('#') ? parseInt(ref.slice(1), 10) : null;
    if (point === null) {
      const named = NAMED_REFERENCES[ref];
      if (named === undefined) unknown = true;
      return named ?? whole;
    }
    if (point < 1 || point > 0x10ffff || (point >= 0xd800 && point <= 0xdfff)) {
      unknown = true;
      return whole;
    }
    return String.fromCodePoint(point);
  });
  return unknown ? null : decoded;
}

/** One `<div ... title="...">...</div>` of a grid cell: its title and the text it shows, both decoded and trimmed. */
interface GridDiv {
  title: string;
  text: string;
}

/**
 * Every div of a grid cell, or null when one cannot be read. A double quote inside a title (SICAE's template does not
 * encode one) ends the attribute early, so its tag no longer matches and the cell is unreadable: the name was signed
 * cut short at the quote (F-6). A nested div, or a reference this reader does not know, is unreadable too.
 */
function divsOf(cell: string): GridDiv[] | null {
  const opened = cell.match(/<div\b/g)?.length ?? 0;
  const divs: GridDiv[] = [];
  for (const m of cell.matchAll(/<div\b[^>]*?\btitle="([^"]*)"\s*>([\s\S]*?)<\/div>/g)) {
    const title = decodeHtml(m[1]);
    const text = decodeHtml(textOf(m[2]));
    if (title === null || text === null) return null;
    divs.push({ title: title.trim(), text: text.trim() });
  }
  return divs.length === opened ? divs : null;
}

interface ParsedRow {
  result: SicaeResult;
  /** The NIPC the row names (its first cell). */
  rowNipc: string;
}

/**
 * The results row, read by ONE rule: the header row (class gridHeader) with SICAE's five column names, then the
 * first data row's five cells - NIPC, name, primary CAE, secondary CAEs, "Mais CAE". A code is the text a cell SHOWS,
 * never a number in a title or in another cell; the name's shown text must be its title; every div of the CAE cells
 * is read, or none. Any other shape is null, and the page is unreadable (502).
 *
 * The looser rule that answered when this one did not is gone (E-2). It took the FIRST five-digit number anywhere in
 * the row as the primary CAE - a company named "CLINICA 24500 SAUDE" was signed with CAE 24500 - and signed every
 * secondary CAE without its description; nothing said it had answered, and it read SICAE's real pages for months
 * while this rule failed on all of them.
 */
function parseResultsRow(html: string): ParsedRow | null {
  const grid = html.match(/<tr[^>]*class="gridHeader"[^>]*>([\s\S]*?)<\/tr>\s*<tr[^>]*>([\s\S]*?)<\/tr>/);
  if (!grid) return null;
  const cellsOf = (row: string) => [...row.matchAll(/<td[^>]*>([\s\S]*?)<\/td>/g)].map((m) => m[1]);
  const header = cellsOf(grid[1]).map(textOf);
  if (header.length !== SICAE_GRID_HEADER.length || header.some((text, i) => text !== SICAE_GRID_HEADER[i])) return null;
  const cells = cellsOf(grid[2]);
  if (cells.length !== SICAE_GRID_HEADER.length) return null;

  // The row names its number (F-8: a grid without the NIPC column was signed under the number asked).
  const rowNipc = textOf(cells[0]);
  if (!/^\d{9}$/.test(rowNipc)) return null;

  const name = divsOf(cells[1]);
  if (!name || name.length !== 1 || name[0].title === '' || name[0].title !== name[0].text) return null;

  const primary = divsOf(cells[2]);
  if (!primary || primary.length !== 1 || !/^\d{5}$/.test(primary[0].text) || primary[0].title === '') return null;

  const secondaryDivs = divsOf(cells[3]);
  if (!secondaryDivs) return null;
  const caeSecondary: Array<{ code: string; description: string }> = [];
  for (const div of secondaryDivs) {
    if (div.title === '' && div.text === '') continue; // SICAE's empty last div
    const code = /^(\d{5}),?$/.exec(div.text)?.[1];
    if (code === undefined || div.title === '') return null;
    if (!caeSecondary.some((cae) => cae.code === code)) caeSecondary.push({ code, description: div.title });
  }

  return {
    result: { officialName: name[0].title, caePrimary: primary[0].text, caePrimaryDescription: primary[0].title, caeSecondary },
    rowNipc,
  };
}

/**
 * The check digit of a Portuguese NIF or NIPC: mod 11, weights 9 to 2 over the first eight digits, a remainder of 0
 * or 1 giving 0. SICAE refuses a number that fails it ("O campo 'NIPC' não é válido"), and that refusal was fetched
 * and signed as "not found" - the same signed answer as "SICAE holds nothing for this number", so a typo read as a
 * fact (E2a F-7). It is now a 400, before any fetch.
 */
export function hasValidNifCheckDigit(nif: string): boolean {
  const digits = [...nif].map(Number);
  const remainder = digits.slice(0, 8).reduce((sum, digit, i) => sum + digit * (9 - i), 0) % 11;
  return digits[8] === (remainder < 2 ? 0 : 11 - remainder);
}

/**
 * `ASP.NET_SessionId=<value>` from a reply's Set-Cookie values (one per line: shared/src/httpParse.ts), or '' when none
 * names it. Each value is read by its name, before its first ';' - wherever it comes among the others (E1 F-1: the
 * last Set-Cookie was the only one kept, so a balancer cookie after the session one dropped it).
 */
function sessionCookieOf(setCookie: string): string {
  for (const line of setCookie.split('\n')) {
    const pair = line.split(';', 1)[0];
    const eq = pair.indexOf('=');
    if (eq > 0 && pair.slice(0, eq).trim() === 'ASP.NET_SessionId') return `ASP.NET_SessionId=${pair.slice(eq + 1).trim()}`;
  }
  return '';
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
    const nif: unknown = b.nif;

    // A number or an array passed the 9-digit rule (RegExp.test stringifies it), and then a found page failed the
    // row's NIPC check while a no-data page was signed (E2a F-8).
    if (nif !== undefined && typeof nif !== 'string') {
      throw new Error(`Invalid NIF: must be text, not ${Array.isArray(nif) ? 'an array' : typeof nif}`);
    }
    if (!nif || !/^\d{9}$/.test(nif)) {
      throw new Error(`Invalid NIF: "${nif ?? ''}" - must be exactly 9 digits`);
    }
    if (!hasValidNifCheckDigit(nif)) {
      throw new Error(`Invalid NIF: "${nif}" fails its check digit`);
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

    // The session cookie, among every Set-Cookie the GET answered
    const sessionCookie = sessionCookieOf(getResponse.headers['set-cookie'] ?? '');

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
        upstreamBody: answeredPage,
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
      // The page dataHash commits to, beside the answer and never signed: a reader uses it only when its SHA-256 is the
      // signed dataHash, so the commitment can be opened (enclave review 2026-10-09, E-4).
      upstreamBody: answeredPage,
    };
  },
};
