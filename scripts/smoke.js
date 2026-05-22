#!/usr/bin/env node
// scripts/smoke.js
//
// Live verification of every production attestation endpoint we ship today.
// Exits 0 on full success, 1 on any failure. This is the gate the brief
// requires before any web-app code is touched.
//
// Run with:  node scripts/smoke.js
// Or via:    npm run smoke

import { verifyUrl } from '../src/index.js'

const ENDPOINTS = [
  {
    name: 'kxco-bank (chain.kxco.ai/wallet)',
    url:  'https://chain.kxco.ai/wallet/api/.well-known/kxco-pq-attestation',
  },
  {
    name: 'target150.com',
    url:  'https://www.target150.com/api/attestation',
  },
]

const ANSI = {
  reset:  '\x1b[0m',
  bold:   '\x1b[1m',
  green:  '\x1b[32m',
  yellow: '\x1b[33m',
  red:    '\x1b[31m',
  dim:    '\x1b[2m',
}

function colorForState(state) {
  if (state === 'valid')   return ANSI.green
  if (state === 'rotated') return ANSI.yellow
  return ANSI.red
}

async function main() {
  console.log(`${ANSI.bold}kxco-verify smoke test${ANSI.reset}\n`)
  let failed = 0
  for (const ep of ENDPOINTS) {
    process.stdout.write(`  ${ep.name}\n`)
    process.stdout.write(`  ${ANSI.dim}${ep.url}${ANSI.reset}\n`)
    const t0 = Date.now()
    const r = await verifyUrl(ep.url, { timeoutMs: 5000 })
    const dt = Date.now() - t0
    const color = colorForState(r.state)
    process.stdout.write(`  → ${color}${r.state.toUpperCase()}${ANSI.reset}`)
    process.stdout.write(` (${dt}ms, kid=${r.manifestKid || '?'})\n`)
    if (r.error) {
      process.stdout.write(`    ${ANSI.dim}${r.error.kind}/${r.error.code}: ${r.error.message}${ANSI.reset}\n`)
    }
    if (r.deployment) {
      process.stdout.write(`    ${ANSI.dim}deployment: ${JSON.stringify(r.deployment)}${ANSI.reset}\n`)
    }
    process.stdout.write('\n')
    if (r.state !== 'valid') failed++
  }
  if (failed > 0) {
    console.log(`${ANSI.red}${failed} endpoint(s) did not return state="valid"${ANSI.reset}`)
    process.exit(1)
  }
  console.log(`${ANSI.green}All ${ENDPOINTS.length} endpoints verified.${ANSI.reset}`)
}

main().catch(err => {
  console.error('smoke test crashed:', err)
  process.exit(1)
})
