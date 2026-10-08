# VIES and HMRC answers, recorded live

Recorded on 2026-10-08 (UTC) with the handler's own requests. Bodies are byte-for-byte what the service sent.

| File | Request | Answer |
|---|---|---|
| `checkvat-valid-PT503504564.xml` | VIES checkVat PT 503504564 | HTTP 200, `<valid>true</valid>`, name and a three-line address |
| `checkvat-not-valid-PT123456789.xml` | VIES checkVat PT 123456789 | HTTP 200, `<valid>false</valid>`, empty name and address |
| `checkvat-fault-invalid-input.xml` | VIES checkVat XX 123456789 | HTTP 200, SOAP Fault `INVALID_INPUT` |
| `hmrc-v1-404-matching-resource-not-found.json` | HMRC lookup 123456789, `Accept: application/vnd.hmrc.1.0+json` | HTTP 404 `MATCHING_RESOURCE_NOT_FOUND`: HMRC removed version 1.0 on 17 February 2025 |

HMRC's own answers for version 2.0 (`NOT_FOUND` "targetVrn does not match a registered company", and a 200 with
`target`) need OAuth credentials; the tests build them from the API definition
(`hmrc/vat-registered-companies-api`, `public/api/conf/2.0/application.yaml`). The company is a large utility on
the fixtures allowlist.
