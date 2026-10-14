/**
 * VIES/HMRC VAT Handler Manifest
 *
 * Its status rules are run against the handler by the package's tests (viesHandler.factory.test.ts).
 */

import {
  computeManifestHash, validateManifest, VIES_SCHEMA, STRIP_AUTH, REDACT_BEARER,
} from '@tytle-enclaves/shared';
import type { HandlerManifest } from '@tytle-enclaves/shared';

/**
 * The register's statuses passed on unsigned, as they were sent: a refused token (401), forbidden (403), a version not
 * acceptable (406) and a rate limit (429). Each is a hint for the caller's retries, never a verdict. Through the
 * enclave each was a 502, so data-bridge read HMRC's rate limit as an outage and asked the enclave again, each try one
 * more HMRC request on the rate limit (OPEN_ISSUES 9 item 2, the third release's part 2). Every other status but the
 * answers the handler reads is a 502, as before.
 */
export const PASSED_ON_STATUSES: readonly number[] = [401, 403, 406, 429];

export const HANDLER_MANIFEST: HandlerManifest = {
  // 1.0.0 was kept across vector version 2 (the 2026-10-09 release); 1.1.0 is the second enclave release (R4); 1.2.0
  // the third (R5: the register's refusals and rate limit passed on)
  version: '1.2.0',

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
      description: 'HMRC Check a UK VAT number 2.0, the simple check (UK only, countryCode === "GB"), with the caller\'s OAuth token (scope read:vat)',
      method: 'GET',
      host: 'api.service.hmrc.gov.uk',
      path: '/organisations/vat/check-vat-number/lookup/{vatNumber}',
      headers: {
        'Accept': 'application/vnd.hmrc.2.0+json',
      },
      auth: {
        header: 'Authorization',
        scheme: 'Bearer',
        strippedBeforeAttestation: true,
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
      id: 'gb_needs_hmrc_token',
      check: { type: 'behavioral', description: 'countryCode === "GB": hmrcAccessToken, an OAuth 2.0 bearer token (RFC 6750 b64token, at most 4096 characters), is required, else 400 before any fetch; it is sent to HMRC as "Authorization: Bearer" and nowhere else, and it is never signed, logged or repeated in an error. Any other countryCode with hmrcAccessToken is a 400' },
      reason: 'HMRC removed Check a UK VAT number 1.0 on 17 February 2025; 2.0 is application-restricted (OAuth client credentials, scope read:vat), and the token is the caller\'s',
    },
    STRIP_AUTH,
    REDACT_BEARER,
    {
      id: 'routing',
      check: { type: 'behavioral', description: 'countryCode === "GB" routes to hmrc_rest; all others route to vies_soap' },
      reason: 'UK VAT is verified via HMRC REST API, EU VAT via VIES SOAP',
    },
    {
      id: 'gb_provenance',
      check: { type: 'behavioral', description: 'For GB, valid, name and address are read from hmrc_rest\'s JSON, not from vies_soap: valid 1 for a 200 (name = target.name; address = target.address line1, line2 and postcode, joined by ", "), valid 0 for HMRC\'s NOT_FOUND 404 (no name, no address)' },
      reason: 'The schema names vies_soap as the source of these three fields; a GB answer comes from HMRC',
    },
    {
      id: 'hmrc_404_is_invalid',
      check: { type: 'behavioral', description: 'HMRC: a 404 whose JSON body code is NOT_FOUND ("targetVrn does not match a registered company") is signed valid 0; any other 404 throws 502' },
      reason: 'The 404 of HMRC\'s removed version-1.0 API, or a proxy\'s page, is not HMRC saying the number is not registered',
    },
    {
      id: 'hmrc_200_needs_target',
      check: { type: 'behavioral', description: 'HMRC: a 200 is signed valid 1 only when its target is an object (not an array) whose vatNumber is the VRN asked and whose name is text; otherwise 502' },
      reason: 'A 200 that names no company, or another company, is no answer (enclave review 2026-10-09, E2a F-3)',
    },
    {
      id: 'register_refusal_passed_on',
      check: { type: 'status_skip', codes: [...PASSED_ON_STATUSES] },
      reason: 'A refused token, forbidden, a version not acceptable or a rate limit of HMRC or VIES is no answer and no outage: it is passed on unsigned, with the register\'s body, so the caller does not ask the enclave again and keeps HMRC\'s rate limit (OPEN_ISSUES 9 item 2)',
    },
    {
      id: 'hmrc_non_200_error',
      check: { type: 'behavioral', description: 'HMRC: a status other than 200, 404 and the four passed on (401, 403, 406, 429) throws 502' },
      reason: 'Only HMRC\'s own answer is read',
    },
    {
      id: 'vies_answer_complete',
      check: { type: 'behavioral', description: 'VIES: every field is read inside the one checkVatResponse element, and only when its closing tag is there; a reply without it throws 502' },
      reason: 'A reply cut after <valid> was signed valid with no name and no address (enclave review 2026-10-09, E2a F-2)',
    },
    {
      id: 'vies_echo_is_the_number_asked',
      check: { type: 'behavioral', description: 'VIES: the countryCode and vatNumber VIES says it checked must be the ones asked, character for character; a different or missing one throws 502' },
      reason: 'The signed countryCode and vatNumber are the number VIES confirmed, never only the caller\'s spelling (enclave review 2026-10-09, E2a F-1)',
    },
    {
      id: 'vies_valid_required',
      check: { type: 'behavioral', description: 'VIES: an answer without <valid>true</valid> or <valid>false</valid> throws 502' },
      reason: 'A parse miss is never valid=false',
    },
    {
      id: 'vies_soap_fault',
      check: { type: 'field_matches', path: 'responseBody', pattern: '<(?:\\w+:)?Fault[\\s>/]' },
      reason: 'VIES SOAP faults (MS_UNAVAILABLE, INVALID_INPUT, etc.) throw 502',
    },
    {
      id: 'vies_non_200_error',
      check: { type: 'behavioral', description: 'VIES: a status other than 200 and the four passed on (401, 403, 406, 429) throws 502' },
      reason: 'Only VIES\'s own answer is read',
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
