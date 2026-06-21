/**
 * openapi.ts
 * ----------
 * A complete, hand-maintained OpenAPI 3.1 document for the OnchainDiligence
 * HTTP API. Replaces the auto-generated discovery stub with a full spec that
 * documents every route (paid and free), parameters, response schemas, the
 * payment terms, and the honest error responses.
 *
 * Prices, recipient, and currency are read from config so they never drift
 * from what the server actually charges. Anything else is static.
 */

import { config } from './config.js'

// Atomic amount (6-decimal pathUSD) for a USD price string, e.g. "0.01" -> "10000".
function atomic(usd: string): string {
  return Math.round(parseFloat(usd) * 1_000_000).toString()
}

function paymentExtension(usd: string) {
  return {
    offers: [
      {
        amount: atomic(usd),
        currency: config.tempo.currencyAddress,
        intent: 'charge',
        method: 'tempo',
        recipient: config.tempo.recipient,
      },
    ],
  }
}

export function buildOpenApiSpec() {
  const p = config.pricing
  return {
    openapi: '3.1.0',
    info: {
      title: config.service.title,
      version: config.service.version,
      description:
        'Pay-per-call compliance checks — crypto sanctions screening and UK ' +
        'company verification — billed per request via the Machine Payments ' +
        'Protocol (MPP) on Tempo. No account or API key. Every paid response ' +
        'is an Ed25519-signed attestation that can be verified independently ' +
        'against the public key at /.well-known/attestation-key.\n\n' +
        'Not legal or compliance advice, and not a substitute for a full ' +
        'compliance program. The sanctions oracle returns a match flag only.',
      contact: { name: 'OnchainDiligence', url: 'https://onchaindiligence.com' },
      license: { name: 'MIT' },
    },
    servers: [
      { url: 'https://api.onchaindiligence.com', description: 'Production' },
    ],
    externalDocs: {
      description: 'Full documentation',
      url: 'https://onchaindiligence.com/docs',
    },
    tags: [
      { name: 'Checks', description: 'Paid compliance checks.' },
      { name: 'Service', description: 'Free discovery, health, and attestation routes.' },
    ],
    paths: {
      '/screen/{address}': {
        get: {
          tags: ['Checks'],
          summary: 'Sanctions screen a wallet address',
          description:
            'Screens a single wallet address against the Chainalysis on-chain ' +
            'sanctions oracle (US/EU/UN lists) via a read-only isSanctioned() ' +
            'call on Ethereum mainnet. Returns a signed boolean flag.',
          operationId: 'screenWallet',
          parameters: [
            {
              name: 'address',
              in: 'path',
              required: true,
              description: 'EVM wallet address (0x + 40 hex).',
              schema: { type: 'string', pattern: '^0x[a-fA-F0-9]{40}$' },
              example: '0x7f268357A8c2552623316e2562D90e642bB538E5',
            },
          ],
          responses: {
            '200': {
              description: 'Signed sanctions result.',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/SignedSanctionsResult' },
                },
              },
            },
            '400': { $ref: '#/components/responses/BadRequest' },
            '402': { $ref: '#/components/responses/PaymentRequired' },
            '502': { $ref: '#/components/responses/UpstreamError' },
            '503': { $ref: '#/components/responses/Unavailable' },
          },
          'x-payment-info': paymentExtension(p.sanctionsCheck),
        },
      },
      '/company/{companyNumber}': {
        get: {
          tags: ['Checks'],
          summary: 'Verify a UK company',
          description:
            'Looks up a UK company by registration number via Companies House: ' +
            'status, type, incorporation date, registered address, and people ' +
            'with significant control (PSC).',
          operationId: 'verifyUkCompany',
          parameters: [
            {
              name: 'companyNumber',
              in: 'path',
              required: true,
              description: 'UK Companies House registration number.',
              schema: { type: 'string' },
              example: '00000006',
            },
          ],
          responses: {
            '200': {
              description: 'Signed company result.',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/SignedCompanyResult' },
                },
              },
            },
            '400': { $ref: '#/components/responses/BadRequest' },
            '402': { $ref: '#/components/responses/PaymentRequired' },
            '404': { $ref: '#/components/responses/NotFound' },
            '502': { $ref: '#/components/responses/UpstreamError' },
            '503': { $ref: '#/components/responses/Unavailable' },
          },
          'x-payment-info': paymentExtension(p.companyCheck),
        },
      },
      '/diligence': {
        get: {
          tags: ['Checks'],
          summary: 'Combined diligence (wallet + company)',
          description:
            'Runs the sanctions screen and the company check in parallel. ' +
            'At least one of wallet or company must be supplied. The two ' +
            'checks are independent — the response always includes a ' +
            'link_disclaimer stating that no link between the wallet and the ' +
            'company is established by this data. If every requested check ' +
            'fails during lookup, the API returns 502 (unsigned) rather than ' +
            'a signed success.',
          operationId: 'diligence',
          parameters: [
            {
              name: 'wallet',
              in: 'query',
              required: false,
              description: 'EVM wallet address to screen (0x + 40 hex).',
              schema: { type: 'string', pattern: '^0x[a-fA-F0-9]{40}$' },
            },
            {
              name: 'company',
              in: 'query',
              required: false,
              description: 'UK company registration number.',
              schema: { type: 'string' },
            },
          ],
          responses: {
            '200': {
              description: 'Signed combined result (full or partial).',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/SignedDiligenceResult' },
                },
              },
            },
            '400': { $ref: '#/components/responses/BadRequest' },
            '402': { $ref: '#/components/responses/PaymentRequired' },
            '502': { $ref: '#/components/responses/UpstreamError' },
            '503': { $ref: '#/components/responses/Unavailable' },
          },
          'x-payment-info': paymentExtension(p.combinedDiligence),
        },
      },
      '/health': {
        get: {
          tags: ['Service'],
          summary: 'Service health',
          description:
            'Free. Reports whether each upstream data source is reachable and ' +
            'whether response signing is configured. Returns 200 when healthy, ' +
            '503 when any upstream is degraded.',
          operationId: 'health',
          responses: {
            '200': {
              description: 'Healthy.',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/Health' },
                },
              },
            },
            '503': {
              description: 'Degraded — an upstream is unreachable.',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/Health' },
                },
              },
            },
          },
        },
      },
      '/.well-known/attestation-key': {
        get: {
          tags: ['Service'],
          summary: 'Attestation public key',
          description:
            'Free. Returns the Ed25519 public key used to sign responses, so ' +
            'a stored attestation can be verified without contacting the API.',
          operationId: 'attestationKey',
          responses: {
            '200': {
              description: 'Public key material.',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/AttestationKey' },
                },
              },
            },
            '404': { description: 'Signing not configured on this deployment.' },
          },
        },
      },
      '/': {
        get: {
          tags: ['Service'],
          summary: 'Service info',
          description: 'Free. Lists routes, prices, and the attestation key URL.',
          operationId: 'root',
          responses: { '200': { description: 'Service metadata.' } },
        },
      },
      '/openapi.json': {
        get: {
          tags: ['Service'],
          summary: 'This document',
          description: 'Free. The machine-readable OpenAPI specification.',
          operationId: 'openapi',
          responses: { '200': { description: 'OpenAPI 3.1 document.' } },
        },
      },
    },
    components: {
      schemas: {
        Attestation: {
          type: 'object',
          description: 'Ed25519 signature over { data, issued_at, key_id }.',
          properties: {
            signed: { type: 'boolean' },
            key_id: { type: 'string', example: 'ed25519-D8wfc7civVNG05Ds' },
            algorithm: { type: 'string', example: 'ed25519' },
            signature: { type: 'string', description: 'base64url signature.' },
            issued_at: { type: 'string', format: 'date-time' },
          },
        },
        SanctionsData: {
          type: 'object',
          properties: {
            address: { type: 'string' },
            sanctioned: { type: 'boolean' },
            identifications: { type: 'array', items: { type: 'object' } },
            source: { type: 'string' },
            checked_at: { type: 'string', format: 'date-time' },
          },
        },
        CompanyData: {
          type: 'object',
          properties: {
            profile: {
              type: 'object',
              properties: {
                companyNumber: { type: 'string' },
                companyName: { type: 'string' },
                status: { type: 'string' },
                incorporatedOn: { type: 'string' },
                registeredAddress: { type: 'string' },
              },
            },
            pscList: { type: 'array', items: { type: 'object' } },
            source: { type: 'string' },
            checked_at: { type: 'string', format: 'date-time' },
          },
        },
        SignedSanctionsResult: {
          allOf: [
            { $ref: '#/components/schemas/SanctionsData' },
            {
              type: 'object',
              properties: { attestation: { $ref: '#/components/schemas/Attestation' } },
            },
          ],
        },
        SignedCompanyResult: {
          allOf: [
            { $ref: '#/components/schemas/CompanyData' },
            {
              type: 'object',
              properties: { attestation: { $ref: '#/components/schemas/Attestation' } },
            },
          ],
        },
        SignedDiligenceResult: {
          type: 'object',
          properties: {
            wallet_check: { type: 'object' },
            company_check: { type: 'object' },
            link_disclaimer: {
              type: 'string',
              description:
                'Always present. States that no link between wallet and ' +
                'company is established by this data.',
            },
            checked_at: { type: 'string', format: 'date-time' },
            attestation: { $ref: '#/components/schemas/Attestation' },
          },
        },
        Health: {
          type: 'object',
          properties: {
            status: { type: 'string', enum: ['ok', 'degraded'] },
            checked_at: { type: 'string', format: 'date-time' },
            upstreams: {
              type: 'object',
              properties: {
                sanctions_oracle: { type: 'string', enum: ['reachable', 'unreachable'] },
                companies_house: { type: 'string', enum: ['reachable', 'unreachable'] },
              },
            },
            attestation: { type: 'string', enum: ['configured', 'not_configured'] },
          },
        },
        AttestationKey: {
          type: 'object',
          properties: {
            enabled: { type: 'boolean' },
            key_id: { type: 'string' },
            algorithm: { type: 'string', example: 'ed25519' },
            public_key_pem: { type: 'string' },
            verify_hint: { type: 'string' },
          },
        },
        Error: {
          type: 'object',
          properties: {
            error: { type: 'string' },
            detail: { type: 'string' },
          },
        },
      },
      responses: {
        BadRequest: {
          description: 'Malformed input. No payment requested.',
          content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } },
        },
        PaymentRequired: {
          description:
            'Payment required. The WWW-Authenticate header carries the MPP ' +
            'challenge; pay and retry.',
        },
        NotFound: {
          description: 'No record found (e.g. unknown company number).',
          content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } },
        },
        UpstreamError: {
          description: 'An upstream data source errored.',
          content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } },
        },
        Unavailable: {
          description:
            'An upstream is unreachable. Returned before payment, so you are ' +
            'not charged. Retry after the Retry-After interval.',
          content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } },
        },
      },
    },
  }
}
