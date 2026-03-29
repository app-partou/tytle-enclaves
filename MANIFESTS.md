# Handler Manifests

Every enclave handler declares a **manifest** — a structured, machine-parseable specification of what the handler does. The manifest is baked into the Docker image (contributing to PCR0) and its SHA-256 hash is included in every attestation.

## Why Manifests Exist

PCR0 proves which code ran, but it's an opaque hash. The manifest makes the handler's behavior inspectable without reading source code. Verification tools can use it to:

1. **Trace field provenance** — which API response field each BN254 value came from
2. **Validate policies** — confirm error handling and security rules match expectations
3. **Reproduce encodings** — independently recompute BN254 output from raw API responses
4. **Detect changes** — the manifest version and hash change when behavior changes

## Cryptographic Chain

```
PCR0 → proves which Docker image ran (includes manifest code)
requestHash → includes manifest hash → proves which specification
BN254 fields + dataHash → proves the data transformation
NSM signature → proves genuine Nitro hardware
```

The manifest hash appears in:
- **Response headers**: `x-{service}-manifest-hash`
- **Attestation requestHash**: via `x-manifest-hash` in the attested request headers

## Manifest Structure

```typescript
interface HandlerManifest {
  version: string;           // Semantic version, bumped on any change
  queries: QueryDef[];       // Every external API call
  schema: {                  // BN254 field-level provenance
    name: string;
    outputBytes: number;
    fields: FieldProvenance[];
  };
  policies: PolicyDef[];     // Validation and attestation rules
  repeatability: RepeatabilityDef;  // How to reproduce the encoding
}
```

### Queries

Each external API call is formally defined:

```typescript
{
  id: 'fetch_order',                              // Referenced by field provenance
  description: 'Fetch Monerium order by ID',
  method: 'GET',
  host: 'api.monerium.app',                       // Must be in enclave allowlist
  path: '/orders/{orderId}',
  headers: { 'Accept': 'application/vnd.monerium.api-v2+json' },
  auth: { header: 'Authorization', scheme: 'Bearer', strippedBeforeAttestation: true },
}
```

For on-chain queries, the `rpc` field describes the contract call:

```typescript
{
  id: 'fetch_balance',
  method: 'POST',
  host: 'rpc.gnosischain.com',
  path: '/',
  rpc: {
    protocol: 'json-rpc',
    method: 'eth_call',
    contract: '0xcB444e90D8198415266c6a2724b7900fb12FC56E',
    function: 'balanceOf(address)',
    selector: '0x70a08231',
    blockTag: 'latest',
  },
}
```

### Field Provenance

Each BN254 field traces to its data source. Two shapes:

**Direct** — extracted from a single query response:
```typescript
{ name: 'state', encoding: 'shortString', source: { query: 'fetch_order', path: 'state' } }
{ name: 'balance', encoding: 'uint', source: { query: 'fetch_balance', path: 'result', transform: 'BigInt(hex)' } }
```

**Derived** — computed from multiple sources:
```typescript
{ name: 'dataHash', encoding: 'sha256', source: {
    inputs: ['fetch_order:rawBody', 'fetch_balance:rawBody'],
    join: '\n',
    transform: 'sha256',
} }
```

Available transforms: `identity`, `BigInt(hex)`, `sha256`, `boolean_uint`, `array_length`.

### Policies

Policies are composable building blocks. Four standard policies ship with the shared library:

| Policy | Type | Description |
|--------|------|-------------|
| `SKIP_TRANSIENT_ERRORS` | error_handling | HTTP 4xx/5xx (except 404) returned without attestation |
| `ATTEST_NOT_FOUND` | error_handling | HTTP 404 attested with `state="not_found"` |
| `STRIP_AUTH` | security | Authorization header excluded from attestation hash |
| `REDACT_BEARER` | security | Bearer tokens redacted from error messages |

Services compose standard policies and add custom ones:

```typescript
import { SKIP_TRANSIENT_ERRORS, ATTEST_NOT_FOUND, STRIP_AUTH, REDACT_BEARER } from '@tytle-enclaves/shared';

policies: [
  SKIP_TRANSIENT_ERRORS,
  ATTEST_NOT_FOUND,
  STRIP_AUTH,
  REDACT_BEARER,
  // Custom: only Gnosis chain supported
  { id: 'chain_restriction', check: { type: 'field_equals', path: 'chain', value: 'gnosis' }, reason: '...' },
]
```

Policy check types:

| Check Type | Parameters | Example |
|-----------|------------|---------|
| `field_equals` | `path`, `value` | `order.chain === "gnosis"` |
| `field_matches` | `path`, `pattern` | `address matches /^0x[a-fA-F0-9]{40}$/` |
| `field_required` | `paths[]` | `id, state, amount must exist` |
| `status_skip` | `codes[]`, `except[]?` | `skip attestation for 401, 429, 5xx` |
| `status_attest` | `code`, `overrides?` | `attest 404 with state=not_found` |
| `header_strip` | `headers[]` | `remove Authorization before attestation` |
| `error_redact` | `pattern`, `replacement` | `redact Bearer tokens in errors` |

### Repeatability

Tells verifiers how to reproduce the BN254 encoding:

```typescript
{
  hashAlgorithm: 'sha256',
  dataHashInput: 'fetch_order:rawBody + "\\n" + fetch_balance:rawBody',
  outputFormat: 'BN254 big-endian, 6 × 32 bytes, base64',
  deterministic: true,
}
```

## Manifest Validation

Each service calls `validateManifest(manifest, schema)` at module load time. This asserts:
- Field count matches the BN254 schema
- Field names match (in order)
- Field encodings match
- Every field source references a valid query ID

If the manifest drifts from the schema, the handler crashes at startup — not silently in production.

## Manifest Hash Stability

The manifest hash uses `stableStringify()` — a deterministic JSON serialization with recursively sorted object keys. This guarantees the same manifest always produces the same hash, regardless of JavaScript property insertion order.

## Adding a Manifest to a New Service

1. Create `your-service/src/manifest.ts`
2. Import standard policies from `@tytle-enclaves/shared`
3. Define `HANDLER_MANIFEST` with queries, schema, policies, repeatability
4. Call `validateManifest(HANDLER_MANIFEST, YOUR_SCHEMA)` at module level
5. Export `MANIFEST_HASH = computeManifestHash(HANDLER_MANIFEST)`
6. In your handler, add `'x-manifest-hash': MANIFEST_HASH` to attestation headers and response headers
