/**
 * VIES/HMRC Custom Handler
 *
 * Routes to VIES SOAP (ec.europa.eu) or HMRC REST (api.service.hmrc.gov.uk)
 * based on countryCode. Parses the response, encodes as BN254 field elements,
 * and attests the encoded output.
 *
 * Request body:  { countryCode: string, vatNumber: string }
 * Response:      BN254-encoded field elements (5 x 32 = 160 bytes, base64)
 *                + human-readable headers (x-vies-*)
 */

import { VIES_SCHEMA } from '@tytle-enclaves/shared';
import type { HandlerDef, HandlerResult, HandlerContext, AllowedHost } from '@tytle-enclaves/shared';
import { HANDLER_MANIFEST, MANIFEST_HASH } from './manifest.js';

/** The enclave's allowlist: VIES and HMRC, each over its own host vsock-proxy port, both HTTPS. */
export const VIES_HOSTS: AllowedHost[] = [
  { hostname: 'ec.europa.eu', vsockProxyPort: 8443 },
  { hostname: 'api.service.hmrc.gov.uk', vsockProxyPort: 8444 },
];

// =============================================================================
// Caller input rules (checked before anything is fetched or signed)
// =============================================================================

/**
 * VIES's own rule for the field, from checkVatService.wsdl (read 2026-10-07): "The vatNumber input
 * parameter must follow the pattern [0-9A-Za-z\+\*\.]{2,12}".
 */
const VIES_VAT_NUMBER = /^[0-9A-Za-z+*.]{2,12}$/;

/**
 * HMRC's rule for targetVrn, from the Check a UK VAT number API definition (hmrc/vat-registered-companies-api,
 * public/api/conf/2.0/application.yaml): "A 9-digit or 12-digit number".
 */
const HMRC_VRN = /^(\d{9}|\d{12})$/;

// =============================================================================
// SOAP Helpers
// =============================================================================

function escapeXml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function buildCheckVatSoapRequest(countryCode: string, vatNumber: string): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:urn="urn:ec.europa.eu:taxud:vies:services:checkVat:types">
  <soapenv:Header/>
  <soapenv:Body>
    <urn:checkVat>
      <urn:countryCode>${escapeXml(countryCode)}</urn:countryCode>
      <urn:vatNumber>${escapeXml(vatNumber)}</urn:vatNumber>
    </urn:checkVat>
  </soapenv:Body>
</soapenv:Envelope>`;
}

/** VIES escapes &, <, >, " and ' in text; the signed name and address are the text itself (as the data-bridge reads it). */
function unescapeXml(str: string): string {
  return str
    .replace(/&apos;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/&gt;/g, '>')
    .replace(/&lt;/g, '<')
    .replace(/&amp;/g, '&');
}

function parseCheckVatSoapResponse(xml: string): {
  valid: boolean;
  name?: string;
  address?: string;
} {
  // VIES's answer is <valid>true</valid> or <valid>false</valid>. A reply without it - a WAF page, a cut
  // body, a schema change - is no answer and must never be signed as "not valid" (audit 2026-10 r2 row 5.5).
  const validMatch = xml.match(/<(?:\w+:)?valid>(true|false)<\/(?:\w+:)?valid>/);
  if (!validMatch) {
    throw new Error('VIES response has no <valid>true|false</valid> answer');
  }
  const nameMatch = xml.match(/<(?:\w+:)?name>([^<]*)<\/(?:\w+:)?name>/);
  const addressMatch = xml.match(/<(?:\w+:)?address>([^<]*)<\/(?:\w+:)?address>/);

  return {
    valid: validMatch[1] === 'true',
    name: nameMatch?.[1] ? unescapeXml(nameMatch[1]) : undefined,
    address: addressMatch?.[1] ? unescapeXml(addressMatch[1]) : undefined,
  };
}

// =============================================================================
// HMRC JSON Helpers
// =============================================================================

/** The part of HMRC's lookup answer this handler reads (OAS 2.0: target.name, target.address.line1..). */
interface HmrcTarget {
  name?: unknown;
  address?: { line1?: unknown; line2?: unknown; postcode?: unknown } | null;
}

/** The `code` of an HMRC JSON error body, or null when the body is not one. */
function hmrcErrorCodeOf(json: string): string | null {
  try {
    const data: unknown = JSON.parse(json);
    if (data !== null && typeof data === 'object' && typeof (data as { code?: unknown }).code === 'string') {
      return (data as { code: string }).code;
    }
  } catch {
    // not JSON
  }
  return null;
}

function parseHmrcResponse(json: string, status: number): {
  valid: boolean;
  name?: string;
  address?: string;
} {
  if (status === 404) {
    // HMRC's "not registered" answer is a 404 whose body is {"code":"NOT_FOUND","message":"targetVrn does not
    // match a registered company"} (the API definition, hmrc/vat-registered-companies-api,
    // public/api/conf/2.0/application.yaml). Any other 404 is no answer: MATCHING_RESOURCE_NOT_FOUND is what the
    // API platform answers for version 1.0, which HMRC removed on 17 February 2025 (same file; seen live
    // 2026-10-07), and a WAF or proxy page has no code at all.
    const code = hmrcErrorCodeOf(json);
    if (code === 'NOT_FOUND') {
      return { valid: false };
    }
    throw new Error(`HMRC returned 404 ${code ?? 'without an error code'} - not a "not registered" answer`);
  }

  if (status !== 200) {
    throw new Error(`HMRC returned unexpected status ${status}`);
  }

  let data: unknown;
  try {
    data = JSON.parse(json);
  } catch {
    throw new Error('HMRC returned invalid JSON response');
  }
  const target = (data !== null && typeof data === 'object') ? (data as { target?: unknown }).target : undefined;
  if (target === null || typeof target !== 'object') {
    // A 200 that names no target is no answer: never signed as "valid".
    throw new Error('HMRC response has no target');
  }
  const { name, address } = target as HmrcTarget;
  const textOf = (v: unknown): string | undefined => (typeof v === 'string' && v !== '' ? v : undefined);

  return {
    valid: true,
    name: textOf(name),
    address: address
      ? [address.line1, address.line2, address.postcode].map(textOf).filter(Boolean).join(', ') || undefined
      : undefined,
  };
}

// =============================================================================
// Handler Definition
// =============================================================================

interface ViesParams {
  countryCode: string;
  vatNumber: string;
}

export const viesHandlerDef: HandlerDef<ViesParams> = {
  name: 'vies',
  schema: VIES_SCHEMA,
  manifestHash: MANIFEST_HASH,
  policies: HANDLER_MANIFEST.policies,
  requiredHosts: ['ec.europa.eu', 'api.service.hmrc.gov.uk'],

  parseParams(body: unknown): ViesParams {
    const b = (body ?? {}) as Record<string, unknown>;
    const { countryCode, vatNumber } = b;

    if (!countryCode || !vatNumber) {
      throw new Error('Both countryCode and vatNumber are required');
    }
    if (typeof countryCode !== 'string' || !/^[A-Z]{2}$/.test(countryCode)) {
      throw new Error(`Invalid countryCode: "${countryCode}" - must be 2-letter uppercase ISO code`);
    }
    // The register's own rule, checked before the fetch: a value the register would refuse is never asked,
    // and never signed as caller input (audit 2026-10 agent 1 §2.3b).
    const vatRule = countryCode === 'GB' ? HMRC_VRN : VIES_VAT_NUMBER;
    if (typeof vatNumber !== 'string' || !vatRule.test(vatNumber)) {
      throw new Error(countryCode === 'GB'
        ? 'Invalid vatNumber: a UK VAT registration number is 9 or 12 digits'
        : 'Invalid vatNumber: VIES accepts 2 to 12 characters of 0-9, A-Z, a-z, +, *, .');
    }

    return { countryCode, vatNumber };
  },

  async execute(params: ViesParams, ctx: HandlerContext): Promise<HandlerResult> {
    const { countryCode, vatNumber } = params;
    const isHmrc = countryCode === 'GB';

    const viesHost = ctx.hosts.find((h) => h.hostname === 'ec.europa.eu')!;
    const hmrcHost = ctx.hosts.find((h) => h.hostname === 'api.service.hmrc.gov.uk')!;

    let valid: boolean;
    let name: string | undefined;
    let address: string | undefined;
    let apiEndpoint: string;

    if (isHmrc) {
      const path = `/organisations/vat/check-vat-number/lookup/${encodeURIComponent(vatNumber)}`;
      apiEndpoint = `${hmrcHost.hostname}${path}`;

      const response = await ctx.fetch(
        hmrcHost, 'GET', path,
        { 'Accept': 'application/vnd.hmrc.1.0+json' },
      );

      const parsed = parseHmrcResponse(response.body, response.status);
      valid = parsed.valid;
      name = parsed.name;
      address = parsed.address;
    } else {
      const soapBody = buildCheckVatSoapRequest(countryCode, vatNumber);
      const path = '/taxation_customs/vies/services/checkVatService';
      apiEndpoint = `${viesHost.hostname}${path}`;

      const response = await ctx.fetch(
        viesHost, 'POST', path,
        { 'Content-Type': 'text/xml;charset=UTF-8', 'SOAPAction': '' },
        soapBody,
      );

      const hasSoapFault = /<(?:\w+:)?Fault[\s>\/]/.test(response.body);
      if (hasSoapFault || response.status !== 200) {
        const faultMatch = response.body.match(/<(?:\w+:)?faultstring>([^<]*)<\/(?:\w+:)?faultstring>/);
        const faultCode = faultMatch?.[1] || `HTTP ${response.status}`;
        throw new Error(`VIES SOAP error: ${faultCode}`);
      }

      const parsed = parseCheckVatSoapResponse(response.body);
      valid = parsed.valid;
      name = parsed.name;
      address = parsed.address;
    }

    return {
      values: {
        countryCode,
        vatNumber,
        valid: valid ? 1 : 0,
        name: name || null,
        address: address || null,
      },
      apiEndpoint,
      method: isHmrc ? 'GET' : 'POST',
      url: isHmrc
        ? `https://${hmrcHost.hostname}/organisations/vat/check-vat-number/lookup/${vatNumber}`
        : `https://${viesHost.hostname}/taxation_customs/vies/services/checkVatService`,
      requestHeaders: { countryCode, vatNumber },
      responseHeaders: {
        'x-vies-country-code': countryCode,
        'x-vies-vat-number': vatNumber,
        'x-vies-valid': String(valid),
        'x-vies-name': name || '',
        'x-vies-address': address || '',
      },
      bn254Headers: {
        'x-vies-name': name || '',
        'x-vies-address': address || '',
      },
    };
  },
};
