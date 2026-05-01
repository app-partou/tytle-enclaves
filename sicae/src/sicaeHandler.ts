/**
 * SICAE Custom Handler
 *
 * Multi-step HTTP + HTML parsing inside the enclave, outputting
 * concatenated BN254 field elements (compact binary, 192 bytes).
 *
 * Flow:
 * 1. Parse request body as JSON: { nif: string }
 * 2. GET www.sicae.pt/Consulta.aspx -> extract __VIEWSTATE, __EVENTVALIDATION, cookie
 * 3. POST NIF search -> get results HTML
 * 4. Parse HTML -> extract officialName, primary CAE, secondary CAE
 * 5. Encode as BN254 field elements (6 x 32 bytes = 192 bytes)
 * 6. Attest the encoded bytes
 * 7. Return response with attestation + human-readable headers
 */

import { SICAE_SCHEMA } from '@tytle-enclaves/shared';
import type { HandlerDef, HandlerResult, HandlerContext } from '@tytle-enclaves/shared';
import { HANDLER_MANIFEST, MANIFEST_HASH } from './manifest.js';

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
// HTML Parsing (ported from ai-agent-server/src/invoicing/services/sicaeLookup.ts)
// =============================================================================

function detectNameColumnOffset(cells: string[]): number {
  const firstCellText = cells[0].replace(/<[^>]*>/g, '').trim();
  return /^\d{9}$/.test(firstCellText) ? 1 : 0;
}

function parsePrimaryStrategy(html: string): SicaeResult | null {
  const gridMatch = html.match(/class="gridHeader"[\s\S]*?<\/tr>([\s\S]*?)<\/tr>/);
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

  return { officialName, caePrimary, caePrimaryDescription, caeSecondary };
}

function parseFallbackStrategy(html: string): SicaeResult | null {
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

  return { officialName, caePrimary, caePrimaryDescription, caeSecondary };
}

function parseSicaeResults(html: string): SicaeResult | null {
  if (html.includes('ClassErro')) return null;
  if (!html.includes('gridMain')) return null;

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

    // Step 2: POST NIF search - try each variant
    let sicaeResult: SicaeResult | null = null;
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

      if (postResponse.status === 200) {
        sicaeResult = parseSicaeResults(postResponse.body);
        if (sicaeResult) break;

        const serverProcessed = postResponse.body.includes('ClassErro') || postResponse.body.includes('gridMain');
        if (serverProcessed) break;
      }
    }

    if (!sicaeResult) {
      // "NIF not found" is a valid, definitive answer - not an enclave error.
      // rawPassthrough so the factory passes the 404 status through without attestation.
      return {
        values: {},
        apiEndpoint: `${sicaeHost.hostname}/Consulta.aspx`,
        method: 'POST',
        url: `http://${sicaeHost.hostname}/Consulta.aspx`,
        requestHeaders: { nif },
        responseHeaders: { 'x-sicae-nif': nif },
        rawPassthrough: {
          status: 404,
          headers: { 'x-sicae-nif': nif },
          rawBody: '',
        },
      };
    }

    // Step 3: Build result for BN254 encoding + attestation
    const cae2Code = sicaeResult.caeSecondary.length > 0 ? sicaeResult.caeSecondary[0].code : null;
    const cae2Desc = sicaeResult.caeSecondary.length > 0 ? sicaeResult.caeSecondary[0].description : null;

    const apiEndpoint = `${sicaeHost.hostname}/Consulta.aspx`;

    return {
      values: {
        nif,
        name: sicaeResult.officialName,
        cae1Code: sicaeResult.caePrimary,
        cae1Desc: sicaeResult.caePrimaryDescription,
        cae2Code,
        cae2Desc,
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
      },
      bn254Headers: {
        'x-sicae-name': sicaeResult.officialName,
        'x-sicae-cae1-desc': sicaeResult.caePrimaryDescription,
        'x-sicae-cae2-desc': cae2Desc || '',
      },
    };
  },
};
