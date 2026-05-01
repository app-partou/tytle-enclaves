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
import type { HandlerDef, HandlerResult, HandlerContext } from '@tytle-enclaves/shared';
import { HANDLER_MANIFEST, MANIFEST_HASH } from './manifest.js';

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

function parseCheckVatSoapResponse(xml: string): {
  valid: boolean;
  name?: string;
  address?: string;
} {
  const validMatch = xml.match(/<(?:\w+:)?valid>(\w+)<\/(?:\w+:)?valid>/);
  const nameMatch = xml.match(/<(?:\w+:)?name>([^<]*)<\/(?:\w+:)?name>/);
  const addressMatch = xml.match(/<(?:\w+:)?address>([^<]*)<\/(?:\w+:)?address>/);

  return {
    valid: validMatch ? validMatch[1].toLowerCase() === 'true' : false,
    name: nameMatch?.[1] || undefined,
    address: addressMatch?.[1] || undefined,
  };
}

// =============================================================================
// HMRC JSON Helpers
// =============================================================================

function parseHmrcResponse(json: string, status: number): {
  valid: boolean;
  name?: string;
  address?: string;
} {
  if (status === 404) {
    return { valid: false };
  }

  if (status !== 200) {
    throw new Error(`HMRC returned unexpected status ${status}`);
  }

  try {
    const data = JSON.parse(json);
    const target = data?.target;
    const address = target?.address
      ? [target.address.line1, target.address.line2, target.address.postcode]
          .filter(Boolean)
          .join(', ')
      : undefined;

    return {
      valid: true,
      name: target?.name,
      address,
    };
  } catch {
    throw new Error('HMRC returned invalid JSON response');
  }
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
    const b = body as Record<string, unknown>;
    const countryCode = b.countryCode as string | undefined;
    const vatNumber = b.vatNumber as string | undefined;

    if (!countryCode || !vatNumber) {
      throw new Error('Both countryCode and vatNumber are required');
    }
    if (!/^[A-Z]{2}$/.test(countryCode)) {
      throw new Error(`Invalid countryCode: "${countryCode}" - must be 2-letter uppercase ISO code`);
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
