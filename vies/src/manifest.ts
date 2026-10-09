/**
 * VIES/HMRC VAT Handler Manifest
 */

import {
  computeManifestHash, validateManifest, VIES_SCHEMA,
} from '@tytle-enclaves/shared';
import type { HandlerManifest } from '@tytle-enclaves/shared';

export const HANDLER_MANIFEST: HandlerManifest = {
  version: '1.0.0',

  queries: [
    {
      id: 'vies_soap',
      description: 'VIES SOAP checkVat service (EU countries, countryCode !== "GB")',
      method: 'POST',
      host: 'ec.europa.eu',
      path: '/taxation_customs/vies/services/checkVatService',
      headers: {
        'Content-Type': 'text/xml;charset=UTF-8',
        'SOAPAction': '',
      },
    },
    {
      id: 'hmrc_rest',
      description: 'HMRC VAT lookup (UK only, countryCode === "GB")',
      method: 'GET',
      host: 'api.service.hmrc.gov.uk',
      path: '/organisations/vat/check-vat-number/lookup/{vatNumber}',
      headers: {
        'Accept': 'application/vnd.hmrc.1.0+json',
      },
    },
  ],

  schema: {
    name: 'VIES_SCHEMA',
    outputBytes: 192,
    fields: [
      { name: 'countryCode', encoding: 'shortString', source: { from: 'request', param: 'countryCode' } },
      { name: 'vatNumber',   encoding: 'shortString', source: { from: 'request', param: 'vatNumber' } },
      { name: 'valid',       encoding: 'uint',         source: { from: 'parsed', query: 'vies_soap', parser: 'soap_xml', field: 'valid' } },
      { name: 'name',        encoding: 'sha256',       source: { from: 'parsed', query: 'vies_soap', parser: 'soap_xml', field: 'name' } },
      { name: 'address',     encoding: 'sha256',       source: { from: 'parsed', query: 'vies_soap', parser: 'soap_xml', field: 'address' } },
      { name: 'dataHash',    encoding: 'sha256',       source: { from: 'derived', inputs: ['vies_soap:rawBody', 'hmrc_rest:rawBody'], join: '', transform: 'sha256' } },
    ],
  },

  policies: [
    {
      id: 'country_code_format',
      check: { type: 'field_matches', path: 'countryCode', pattern: '^[A-Z]{2}$' },
      reason: 'Country code must be 2-letter uppercase ISO code',
    },
    {
      id: 'required_fields',
      check: { type: 'field_required', paths: ['countryCode', 'vatNumber'] },
      reason: 'Both countryCode and vatNumber are required for lookup',
    },
    {
      id: 'vat_number_format',
      check: { type: 'field_matches', path: 'vatNumber', pattern: '^[0-9A-Za-z+*.]{2,12}$' },
      reason: 'The register\'s own rule, checked before any fetch: VIES checkVatService.wsdl "[0-9A-Za-z\\+\\*\\.]{2,12}"',
    },
    {
      id: 'gb_vat_number_format',
      check: { type: 'behavioral', description: 'countryCode === "GB": vatNumber must be 9 or 12 digits (HMRC targetVrn), else 400 before any fetch' },
      reason: 'HMRC refuses any other targetVrn; a refused value is never asked and never signed',
    },
    {
      id: 'routing',
      check: { type: 'behavioral', description: 'countryCode === "GB" routes to hmrc_rest; all others route to vies_soap' },
      reason: 'UK VAT is verified via HMRC REST API, EU VAT via VIES SOAP',
    },
    {
      id: 'hmrc_404_is_invalid',
      check: { type: 'status_attest', code: 404, overrides: { valid: 0 } },
      reason: 'Only HMRC\'s 404 whose JSON body code is NOT_FOUND ("targetVrn does not match a registered company") is valid=false, attested; any other 404 throws 502',
    },
    {
      id: 'hmrc_200_needs_target',
      check: { type: 'behavioral', description: 'An HMRC 200 without a target object throws 502 (never valid=true)' },
      reason: 'A 200 that names no registered company is no answer',
    },
    {
      id: 'vies_valid_required',
      check: { type: 'field_matches', path: 'responseBody', pattern: '<(?:\\w+:)?valid>(true|false)</(?:\\w+:)?valid>' },
      reason: 'A VIES reply without <valid>true|false</valid> throws 502 (a parse miss is never valid=false)',
    },
    {
      id: 'hmrc_non_200_error',
      check: { type: 'status_skip', codes: [429, 500, 502, 503], except: [404] },
      reason: 'HMRC non-200/non-404 responses throw 502',
    },
    {
      id: 'vies_soap_fault',
      check: { type: 'field_matches', path: 'responseBody', pattern: '<(?:\\w+:)?Fault[\\s>/]' },
      reason: 'VIES SOAP faults (MS_UNAVAILABLE, INVALID_INPUT, etc.) throw 502',
    },
    {
      id: 'vies_non_200_error',
      check: { type: 'status_skip', codes: [500, 502, 503], except: [] },
      reason: 'VIES non-200 HTTP status throws 502',
    },
  ],

  repeatability: {
    hashAlgorithm: 'sha256',
    dataHashInput: 'the routed query\'s raw body (vies_soap:rawBody, or hmrc_rest:rawBody for GB), UTF-8',
    outputFormat: 'BN254 big-endian, 6 × 32 bytes, base64',
    deterministic: true,
  },
};

validateManifest(HANDLER_MANIFEST, VIES_SCHEMA);

export const MANIFEST_HASH = computeManifestHash(HANDLER_MANIFEST);
