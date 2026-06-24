/**
 * config.ts
 * ---------
 * Central place for every value that's environment-specific, a price, or
 * an external endpoint. Nothing here should be a secret — secrets stay in
 * .env and are read via process.env, never hardcoded.
 */

// pathUSD is a Tempo PREDEPLOYED SYSTEM CONTRACT — the same address is used
// regardless of network; it is not a "testnet-only" value. Verified against
// Tempo's official docs: https://docs.tempo.xyz/quickstart/predeployed-contracts
// ("pathUSD — First stablecoin deployed" — 0x20c0000000000000000000000000000000000000).
// An earlier version of this file incorrectly treated this address as
// testnet-only and blocked it on mainnet. That was wrong and has been removed.

export const config = {
  // --- Tempo / MPP payment settings -----------------------------------
  tempo: {
    // The TIP-20 stablecoin contract clients must pay in. pathUSD's address
    // is a Tempo predeployed system contract, the same on every network:
    // 0x20c0000000000000000000000000000000000000 — per Tempo's official
    // "Predeployed Contracts" docs. Set via TEMPO_CURRENCY_ADDRESS so it's
    // still explicit/overridable rather than hardcoded, but you do not need
    // to hunt for a separate "mainnet" address — this is it.
    currencyAddress: (process.env.TEMPO_CURRENCY_ADDRESS ?? '') as `0x${string}`,

    // Explicit network selection. For a mainnet money deployment this is
    // false and is set explicitly rather than relying on an SDK default.
    // Driven by env so the same code can't silently flip networks.
    testnet: process.env.TEMPO_TESTNET === 'true',

    // Cast at the boundary: the env var is a plain string at runtime,
    // but mppx's TempoAddress type requires the branded `0x${string}`
    // literal type. Validated in assertConfigured() below.
    recipient: (process.env.MPP_RECIPIENT_ADDRESS ?? '') as `0x${string}`,
  },

  // --- Pricing -----------------------------------------------------------
  // Each price is deliberately small and framed as covering infra/API
  // cost, not as a markup on the underlying public-good or open-government
  // data. See README.md "Licensing & pricing rationale" for the reasoning.
  // Prices differ by value delivered and cost to serve, not a flat rate.
  // The wallet check is a single cheap oracle read (commodity, high volume);
  // the company check returns a structured corporate record (higher value,
  // lower volume); name screening parses and fuzzy-matches the full OFAC list.
  pricing: {
    sanctionsCheck: '0.01', // one on-chain oracle read — cheap, agent-friendly
    nameScreen: '0.02', // parses + fuzzy-matches the full OFAC SDN list
    companyCheck: '0.05', // structured KYB record (status + ownership/PSC)
    combinedDiligence: '0.05', // wallet + company together — a discount vs. $0.06 apart
  },

  // --- Sanctions oracle (on-chain, no API key) --------------------------
  // The Chainalysis sanctions oracle is a public smart contract — no key,
  // no signup. We read isSanctioned() on Ethereum mainnet (the oracle is
  // NOT deployed on Tempo). The RPC URL is overridable so you can point at
  // a private/paid RPC if a public one rate-limits you under load; it
  // defaults to a public endpoint.
  sanctionsOracle: {
    // Chainalysis oracle on Ethereum mainnet (same address on most EVM
    // chains; Base differs). Verified from Chainalysis oracle docs.
    // NOTE: `|| ` (not `??`) is deliberate here — an .env line left as
    // `SANCTIONS_ORACLE_ADDRESS=` (present but empty string) must also
    // fall back to the default, not be treated as "explicitly set to
    // blank." ?? only catches undefined/null, not ''.
    contractAddress:
      process.env.SANCTIONS_ORACLE_ADDRESS || '0x40C57923924B5c5c5455c48D93317139ADDaC8fb',
    // Public Ethereum RPC by default. Override with SANCTIONS_ORACLE_RPC_URL.
    rpcUrl: process.env.SANCTIONS_ORACLE_RPC_URL || 'https://eth.llamarpc.com',
  },

  companiesHouse: {
    apiKey: process.env.COMPANIES_HOUSE_API_KEY ?? '',
    baseUrl: 'https://api.company-information.service.gov.uk',
  },

  // --- OFAC SDN name screening (public-domain US Treasury data) ----------
  // Official OFAC CSV endpoints. Overridable via env for testing/mirrors.
  ofac: {
    sdnUrl: process.env.OFAC_SDN_URL || 'https://www.treasury.gov/ofac/downloads/sdn.csv',
    altUrl: process.env.OFAC_ALT_URL || 'https://www.treasury.gov/ofac/downloads/alt.csv',
  },

  // --- On-chain attestation anchoring (Tempo) ----------------------------
  // Optional. When configured, attestation hashes can be anchored on Tempo for
  // independent, tamper-evident proof. Anchoring never blocks a paid check.
  anchor: {
    rpcUrl: process.env.ANCHOR_RPC_URL || 'https://rpc.moderato.tempo.xyz',
    chainId: Number(process.env.ANCHOR_CHAIN_ID || '42431'), // Moderato testnet
    contractAddress: (process.env.ANCHOR_CONTRACT_ADDRESS || '') as `0x${string}` | '',
    // Separate key from the attestation signing key; pays Tempo gas (pathUSD).
    privateKey: (process.env.ANCHOR_PRIVATE_KEY || '') as `0x${string}` | '',
  },

  // --- Service metadata (used in discovery / OpenAPI generation) --------
  service: {
    title: 'OnchainDiligence',
    version: '1.0.0',
    description:
      'Pay-per-call sanctions screening and UK company verification, ' +
      'bundled or standalone, settled via MPP on Tempo. Every paid response ' +
      'is a signed attestation you can verify yourself.',
  },
}

/**
 * Fails loudly and immediately at boot if anything required is missing,
 * rather than letting the server start and 500 on first real request.
 */
export function assertConfigured() {
  const missing: string[] = []
  if (!config.tempo.recipient) missing.push('MPP_RECIPIENT_ADDRESS')
  if (!config.tempo.currencyAddress) missing.push('TEMPO_CURRENCY_ADDRESS')
  if (!config.companiesHouse.apiKey) missing.push('COMPANIES_HOUSE_API_KEY')

  if (missing.length > 0) {
    throw new Error(
      `Missing required environment variables: ${missing.join(', ')}.\n` +
        `Copy .env.example to .env and fill these in before starting the server.`
    )
  }

  if (!/^0x[a-fA-F0-9]{40}$/.test(config.sanctionsOracle.contractAddress)) {
    throw new Error(
      `SANCTIONS_ORACLE_ADDRESS ("${config.sanctionsOracle.contractAddress}") doesn't ` +
        `look like a valid contract address (expected 0x + 40 hex chars).`
    )
  }

  if (!/^0x[a-fA-F0-9]{40}$/.test(config.tempo.recipient)) {
    throw new Error(
      `MPP_RECIPIENT_ADDRESS ("${config.tempo.recipient}") doesn't look like a ` +
        `valid 0x-prefixed Ethereum/Tempo address (expected 0x + 40 hex chars).`
    )
  }

  if (!/^0x[a-fA-F0-9]{40}$/.test(config.tempo.currencyAddress)) {
    throw new Error(
      `TEMPO_CURRENCY_ADDRESS ("${config.tempo.currencyAddress}") doesn't look like ` +
        `a valid 0x-prefixed token address (expected 0x + 40 hex chars).`
    )
  }
}
