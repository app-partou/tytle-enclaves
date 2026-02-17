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
 *
 * VIES_SCHEMA:
 *   [0..31]   countryCode   shortString
 *   [32..63]  vatNumber     shortString
 *   [64..95]  valid         uint (1 = valid, 0 = invalid)
 *   [96..127] name          sha256 (0 if absent)
 *   [128..159] address      sha256 (0 if absent)
 */

import { proxyFetch, attest, encodeFieldElements, VIES_SCHEMA } from '@tytle-enclaves/shared';
import type { EnclaveRequest, EnclaveResponse } from '@tytle-enclaves/shared';

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
    return { valid: false };
  }
}

// =============================================================================
// Custom Handler
// =============================================================================

interface ViesHandlerConfig {
  viesHostname: string;
  viesVsockPort: number;
  hmrcHostname: string;
  hmrcVsockPort: number;
}

export function createViesHandler(cfg: ViesHandlerConfig) {
  return async (request: EnclaveRequest): Promise<EnclaveResponse> => {
    try {
      // Parse request
      let countryCode: string;
      let vatNumber: string;
      try {
        const body = JSON.parse(request.body || '{}');
        countryCode = body.countryCode;
        vatNumber = body.vatNumber;
      } catch {
        return {
          success: false,
          status: 400,
          headers: {},
          rawBody: '',
          error: 'Invalid request body — expected JSON with { countryCode, vatNumber }',
        };
      }

      if (!countryCode || !vatNumber) {
        return {
          success: false,
          status: 400,
          headers: {},
          rawBody: '',
          error: 'Both countryCode and vatNumber are required',
        };
      }

      // Route to VIES or HMRC
      let valid: boolean;
      let name: string | undefined;
      let address: string | undefined;
      let apiEndpoint: string;

      if (countryCode === 'GB') {
        // HMRC REST
        const path = `/organisations/vat/check-vat-number/lookup/${encodeURIComponent(vatNumber)}`;
        apiEndpoint = `${cfg.hmrcHostname}${path}`;

        const response = await proxyFetch(
          cfg.hmrcVsockPort,
          cfg.hmrcHostname,
          'GET',
          path,
          { 'Accept': 'application/vnd.hmrc.1.0+json' },
        );

        const parsed = parseHmrcResponse(response.body, response.status);
        valid = parsed.valid;
        name = parsed.name;
        address = parsed.address;
      } else {
        // VIES SOAP
        const soapBody = buildCheckVatSoapRequest(countryCode, vatNumber);
        const path = '/taxation_customs/vies/services/checkVatService';
        apiEndpoint = `${cfg.viesHostname}${path}`;

        const response = await proxyFetch(
          cfg.viesVsockPort,
          cfg.viesHostname,
          'POST',
          path,
          {
            'Content-Type': 'text/xml;charset=UTF-8',
            'SOAPAction': '',
          },
          soapBody,
        );

        // Check for SOAP faults
        if (response.body.includes('Fault') || response.status !== 200) {
          // Extract fault string for error reporting
          const faultMatch = response.body.match(/<(?:\w+:)?faultstring>([^<]*)<\/(?:\w+:)?faultstring>/);
          const faultCode = faultMatch?.[1] || `HTTP ${response.status}`;
          throw new Error(`VIES SOAP error: ${faultCode}`);
        }

        const parsed = parseCheckVatSoapResponse(response.body);
        valid = parsed.valid;
        name = parsed.name;
        address = parsed.address;
      }

      // Encode as BN254 field elements
      const encodedBytes = encodeFieldElements(VIES_SCHEMA, {
        countryCode,
        vatNumber,
        valid: valid ? 1 : 0,
        name: name || null,
        address: address || null,
      });

      const rawBody = encodedBytes.toString('base64');

      // Attest the encoded bytes
      const attestation = await attest(
        apiEndpoint,
        countryCode === 'GB' ? 'GET' : 'POST',
        rawBody,
        countryCode === 'GB'
          ? `https://${cfg.hmrcHostname}/organisations/vat/check-vat-number/lookup/${vatNumber}`
          : `https://${cfg.viesHostname}/taxation_customs/vies/services/checkVatService`,
        { countryCode, vatNumber },
      );

      // Return with human-readable headers
      return {
        success: true,
        status: 200,
        headers: {
          'x-vies-country-code': countryCode,
          'x-vies-vat-number': vatNumber,
          'x-vies-valid': String(valid),
          'x-vies-name': name || '',
          'x-vies-address': address || '',
        },
        rawBody,
        attestation,
      };
    } catch (err: any) {
      console.error(`[vies-handler] Error: ${err.message}`);
      return {
        success: false,
        status: 502,
        headers: {},
        rawBody: '',
        error: err.message,
      };
    }
  };
}
