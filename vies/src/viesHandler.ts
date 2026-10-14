/**
 * VIES/HMRC Custom Handler
 *
 * Routes to VIES SOAP (ec.europa.eu) or HMRC REST (api.service.hmrc.gov.uk)
 * based on countryCode. Parses the response, encodes as BN254 field elements,
 * and attests the encoded output.
 *
 * Request body:  { countryCode: string, vatNumber: string, hmrcAccessToken?: string } - the token for a GB number only
 * Response:      BN254-encoded field elements (6 x 32 = 192 bytes, base64; the last is dataHash, the SHA-256
 *                of the upstream body the answer was read from) + human-readable headers (x-vies-*)
 */

import crypto from 'node:crypto';
import { VIES_SCHEMA } from '@tytle-enclaves/shared';
import type { HandlerDef, HandlerResult, HandlerContext, AllowedHost, HttpResponse } from '@tytle-enclaves/shared';
import { HANDLER_MANIFEST, MANIFEST_HASH, PASSED_ON_STATUSES } from './manifest.js';

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

/**
 * An OAuth 2.0 bearer token as RFC 6750 §2.1 writes one (b64token: 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" /
 * "/" ) *"="), at most 4096 characters: what HMRC's token endpoint answers as access_token. Checked before it goes into
 * a header line, so a caller value can never add a header of its own.
 */
const BEARER_TOKEN = /^[A-Za-z0-9\-._~+/]+=*$/;
const BEARER_TOKEN_MAX = 4096;

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

function parseCheckVatSoapResponse(xml: string, countryCode: string, vatNumber: string): {
  valid: boolean;
  name?: string;
  address?: string;
} {
  // Every field is read inside the one checkVatResponse element, and only when it is complete: its closing tag must
  // be there. A reply that ended early (no length framing, the connection closed) once kept <valid> and lost the
  // name, and was signed valid with no name (enclave review 2026-10-09, E2a F-2).
  const answer = xml.match(/<(\w+:)?checkVatResponse(?:\s[^>]*)?>([\s\S]*)<\/\1checkVatResponse>/)?.[2];
  if (answer === undefined) {
    throw new Error('VIES response has no complete checkVatResponse');
  }
  // VIES says which number it checked. Only that number is signed, and it must be the one asked: the handler once
  // signed the request's spelling, which VIES may have rewritten (E2a F-1).
  const echoedCountry = answer.match(/<(?:\w+:)?countryCode>([^<]*)<\/(?:\w+:)?countryCode>/)?.[1];
  const echoedNumber = answer.match(/<(?:\w+:)?vatNumber>([^<]*)<\/(?:\w+:)?vatNumber>/)?.[1];
  if (echoedCountry === undefined || echoedNumber === undefined) {
    throw new Error('VIES response does not say which number it checked');
  }
  if (echoedCountry !== countryCode || echoedNumber !== vatNumber) {
    throw new Error(`VIES answered for ${echoedCountry}${echoedNumber}, not for ${countryCode}${vatNumber}`);
  }
  // VIES's answer is <valid>true</valid> or <valid>false</valid>. A reply without it - a WAF page, a cut
  // body, a schema change - is no answer and must never be signed as "not valid" (audit 2026-10 r2 row 5.5).
  const validMatch = answer.match(/<(?:\w+:)?valid>(true|false)<\/(?:\w+:)?valid>/);
  if (!validMatch) {
    throw new Error('VIES response has no <valid>true|false</valid> answer');
  }
  const nameMatch = answer.match(/<(?:\w+:)?name>([^<]*)<\/(?:\w+:)?name>/);
  const addressMatch = answer.match(/<(?:\w+:)?address>([^<]*)<\/(?:\w+:)?address>/);

  return {
    valid: validMatch[1] === 'true',
    name: nameMatch?.[1] ? unescapeXml(nameMatch[1]) : undefined,
    address: addressMatch?.[1] ? unescapeXml(addressMatch[1]) : undefined,
  };
}

// =============================================================================
// HMRC JSON Helpers
// =============================================================================

/** The part of HMRC's lookup answer this handler reads (OAS 2.0: target.name, target.vatNumber, target.address.line1..). */
interface HmrcTarget {
  name?: unknown;
  vatNumber?: unknown;
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

function parseHmrcResponse(json: string, status: number, vatNumber: string): {
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
  if (target === null || typeof target !== 'object' || Array.isArray(target)) {
    // A 200 that names no target is no answer: never signed as "valid".
    throw new Error('HMRC response has no target');
  }
  const { name, vatNumber: answeredVrn, address } = target as HmrcTarget;
  const textOf = (v: unknown): string | undefined => (typeof v === 'string' && v !== '' ? v : undefined);
  // The company HMRC named is the one asked, and HMRC names it: before, any object or array under target was signed
  // valid (enclave review 2026-10-09, E2a F-3).
  if (answeredVrn !== vatNumber) {
    throw new Error(`HMRC answered for another VRN than ${vatNumber}`);
  }
  if (textOf(name) === undefined) {
    throw new Error("HMRC's target has no name");
  }

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
  /** For a GB number only: the caller's OAuth token for HMRC (Check a UK VAT number 2.0, scope read:vat). */
  hmrcAccessToken?: string;
}

/**
 * The register's refusal or rate limit, passed on unsigned as it was sent (manifest.ts PASSED_ON_STATUSES): its status
 * and body, and only its Content-Type of its headers. No value is signed and no x-vies header is set, so nothing reads
 * it as a verdict. The token went in the request only: no register answer repeats it.
 */
function passedOn(response: HttpResponse, apiEndpoint: string, method: string, url: string): HandlerResult {
  const contentType = Object.entries(response.headers).find(([name]) => name.toLowerCase() === 'content-type')?.[1];
  return {
    values: {},
    apiEndpoint,
    method,
    url,
    requestHeaders: {},
    responseHeaders: {},
    rawPassthrough: {
      status: response.status,
      headers: contentType === undefined ? {} : { 'content-type': contentType },
      rawBody: response.body,
    },
  };
}

export const viesHandlerDef: HandlerDef<ViesParams> = {
  name: 'vies',
  schema: VIES_SCHEMA,
  manifestHash: MANIFEST_HASH,
  policies: HANDLER_MANIFEST.policies,
  requiredHosts: ['ec.europa.eu', 'api.service.hmrc.gov.uk'],

  parseParams(body: unknown): ViesParams {
    const b = (body ?? {}) as Record<string, unknown>;
    const { countryCode, vatNumber, hmrcAccessToken } = b;

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

    // HMRC removed version 1.0 of Check a UK VAT number on 17 February 2025; version 2.0 needs an OAuth 2.0 bearer
    // token with the read:vat scope (D-P1-9, LJ "A"). The caller gets it with its own HMRC client credentials and passes
    // it with each UK lookup; it goes to HMRC as the Authorization header and nowhere else - never signed, never
    // logged, never in an error (no message below repeats it).
    if (countryCode === 'GB') {
      if (typeof hmrcAccessToken !== 'string') {
        throw new Error('hmrcAccessToken is required for a UK number (HMRC Check a UK VAT number 2.0 takes an OAuth token)');
      }
      if (hmrcAccessToken.length > BEARER_TOKEN_MAX || !BEARER_TOKEN.test(hmrcAccessToken)) {
        throw new Error(`Invalid hmrcAccessToken: an OAuth 2.0 bearer token (RFC 6750 b64token) of at most ${BEARER_TOKEN_MAX} characters`);
      }
      return { countryCode, vatNumber, hmrcAccessToken };
    }
    if (hmrcAccessToken !== undefined) {
      throw new Error('hmrcAccessToken is only for a UK number');
    }
    return { countryCode, vatNumber };
  },

  async execute(params: ViesParams, ctx: HandlerContext): Promise<HandlerResult> {
    const { countryCode, vatNumber, hmrcAccessToken } = params;
    const isHmrc = countryCode === 'GB';

    const viesHost = ctx.hosts.find((h) => h.hostname === 'ec.europa.eu')!;
    const hmrcHost = ctx.hosts.find((h) => h.hostname === 'api.service.hmrc.gov.uk')!;

    let valid: boolean;
    let name: string | undefined;
    let address: string | undefined;
    let apiEndpoint: string;
    let upstreamBody: string;

    if (isHmrc) {
      if (hmrcAccessToken === undefined) {
        throw new Error('hmrcAccessToken is required for a UK number'); // parseParams refuses this already
      }
      const path = `/organisations/vat/check-vat-number/lookup/${encodeURIComponent(vatNumber)}`;
      apiEndpoint = `${hmrcHost.hostname}${path}`;

      // Check a UK VAT number 2.0, the simple check: the number in; valid, name and address out (no requester VRN, so
      // no reference number - a Portuguese seller has no UK VRN). requestHeaders below name the number only: the token
      // is in no attested value (the manifest's strip_auth and redact_bearer guard the rest).
      const response = await ctx.fetch(
        hmrcHost, 'GET', path,
        { 'Accept': 'application/vnd.hmrc.2.0+json', 'Authorization': `Bearer ${hmrcAccessToken}` },
      );
      if (PASSED_ON_STATUSES.includes(response.status)) {
        return passedOn(response, apiEndpoint, 'GET', `https://${hmrcHost.hostname}${path}`);
      }

      const parsed = parseHmrcResponse(response.body, response.status, vatNumber);
      upstreamBody = response.body;
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
      if (PASSED_ON_STATUSES.includes(response.status)) {
        return passedOn(response, apiEndpoint, 'POST', `https://${viesHost.hostname}${path}`);
      }

      const hasSoapFault = /<(?:\w+:)?Fault[\s>\/]/.test(response.body);
      if (hasSoapFault || response.status !== 200) {
        const faultMatch = response.body.match(/<(?:\w+:)?faultstring>([^<]*)<\/(?:\w+:)?faultstring>/);
        const faultCode = faultMatch?.[1] || `HTTP ${response.status}`;
        throw new Error(`VIES SOAP error: ${faultCode}`);
      }

      const parsed = parseCheckVatSoapResponse(response.body, countryCode, vatNumber);
      upstreamBody = response.body;
      valid = parsed.valid;
      name = parsed.name;
      address = parsed.address;
    }

    // The whole upstream body is committed, so a later parser change or a dispute can be checked against what the
    // register sent (audit P1.4 `dataHash`; the same rule as Stripe's): the hex digest is the value, encoded as sha256.
    const dataHash = crypto.createHash('sha256').update(upstreamBody, 'utf8').digest('hex');

    return {
      values: {
        countryCode,
        vatNumber,
        valid: valid ? 1 : 0,
        name: name || null,
        address: address || null,
        dataHash,
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
        'x-vies-data-hash': dataHash,
      },
      bn254Headers: {
        'x-vies-name': name || '',
        'x-vies-address': address || '',
        'x-vies-data-hash': dataHash,
      },
      // The body dataHash commits to, beside the answer and never signed: a reader uses it only when its SHA-256 is
      // the signed dataHash, so the commitment can be opened (enclave review 2026-10-09, E-4).
      upstreamBody,
    };
  },
};
