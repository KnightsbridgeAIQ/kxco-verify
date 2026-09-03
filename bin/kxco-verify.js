#!/usr/bin/env node
// kxco-verify — check a site's post-quantum deploy attestation from a terminal.
//
// The default is the whole point of this package: the maths, and nothing else.
// No KXCO server is contacted, no licence is needed, no account exists. It
// fetches the manifest the site publishes and checks the signature against the
// key the site published. That path must keep working forever, offline, for
// anyone, which is why the library this CLI wraps has one dependency and no
// notion of a chain.
//
// `--live` is the other thing. A signature made by a key that was revoked an
// hour ago is still a perfectly valid signature, and the maths cannot tell you
// so. `--live` asks the KXCO key registry whether the kid is still active.
// That needs kxco-pq-network, which is an OPTIONAL peer: install it and the
// flag works, leave it out and everything else is unaffected.
//
// Exit codes are meant for CI:
//   0  valid
//   1  invalid, or revoked under --live
//   2  could not reach or parse the target
//   3  rotated (the signature checks, but the live key differs)

import { verifyUrl, verifyManifest } from '../src/index.js'
import { readFileSync } from 'node:fs'

const ANSI = process.stdout.isTTY
  ? { reset: '\x1b[0m', bold: '\x1b[1m', green: '\x1b[32m', yellow: '\x1b[33m', red: '\x1b[31m', dim: '\x1b[2m' }
  : { reset: '', bold: '', green: '', yellow: '', red: '', dim: '' }

const USAGE = `
kxco-verify — verify a post-quantum deploy attestation

  kxco-verify <url>                    fetch and verify. No KXCO server involved.
  kxco-verify --file <path>            verify a manifest you already have
  kxco-verify <url> --live             also ask the registry whether the key is still active
  kxco-verify <url> --json             machine-readable output

Options
  --live                  check the signing kid against the KXCO key registry.
                          Needs kxco-pq-network installed. Fails CLOSED: if the
                          registry cannot be reached, the result is not valid.
  --registry <url>        registry base URL (default https://chain.kxco.ai)
  --licence <key>         licence key for the registry, or set KXCO_LICENCE_KEY
  --timeout <ms>          network timeout (default 10000)
  --json                  print JSON instead of a human summary
  --help

Exit codes
  0 valid    1 invalid or revoked    2 fetch/parse error    3 rotated
`.trimStart()

function parseArgs(argv) {
  const opts = { live: false, json: false, timeout: 10_000, registry: undefined, licence: undefined, file: undefined }
  const positional = []
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    switch (arg) {
      case '--help': case '-h': opts.help = true; break
      case '--live': opts.live = true; break
      case '--json': opts.json = true; break
      case '--file': opts.file = argv[++i]; break
      case '--registry': opts.registry = argv[++i]; break
      case '--licence': case '--license': opts.licence = argv[++i]; break
      case '--timeout': opts.timeout = Number(argv[++i]); break
      default:
        if (arg.startsWith('-')) throw new Error(`unknown option ${arg}`)
        positional.push(arg)
    }
  }
  opts.url = positional[0]
  return opts
}

// Loaded only when --live is asked for, so the default path has no chance of
// reaching for a package that may not be installed.
async function loadNetwork() {
  try {
    return await import('kxco-pq-network')
  } catch {
    throw new Error(
      '--live needs kxco-pq-network, which is an optional peer dependency.\n' +
      '  npm install kxco-pq-network\n' +
      'Without it, kxco-verify still checks the signature offline, which is what it is for.',
    )
  }
}

async function checkLive(kid, opts) {
  const { networkConfig, KeyRegistry, KxcoPqNetworkError } = await loadNetwork()
  const config = networkConfig({
    registryUrl: opts.registry,
    licenceKey: opts.licence ?? process.env.KXCO_LICENCE_KEY ?? null,
    timeoutMs: opts.timeout,
  })
  try {
    return { ok: true, record: await new KeyRegistry(config).lookup(kid) }
  } catch (err) {
    if (!(err instanceof KxcoPqNetworkError)) throw err
    // Fails closed. A check that cannot run has not passed.
    return { ok: false, error: err.message }
  }
}

function render(result, live, opts) {
  if (opts.json) {
    console.log(JSON.stringify({ ...result, live }, null, 2))
    return
  }

  const colour = { valid: ANSI.green, rotated: ANSI.yellow }[result.state] ?? ANSI.red
  console.log(`${ANSI.bold}${colour}${result.state.toUpperCase()}${ANSI.reset}  ${result.site ?? result.attestationUrl ?? ''}`)
  if (result.algorithm) console.log(`  algorithm    ${result.algorithm}`)
  if (result.manifestKid) console.log(`  kid          ${result.manifestKid}`)
  if (result.livePubkeyKid && result.livePubkeyKid !== result.manifestKid) {
    console.log(`  live kid     ${result.livePubkeyKid}`)
  }
  if (result.error) console.log(`  ${ANSI.dim}${result.error.message}${ANSI.reset}`)

  if (live) {
    const label = live.ok ? live.record.status : 'unreachable'
    const c = live.ok && live.record.status === 'active' ? ANSI.green : ANSI.red
    console.log(`  registry     ${c}${label}${ANSI.reset}${live.ok && live.record.cached ? ' (cached)' : ''}`)
    if (!live.ok) console.log(`  ${ANSI.dim}${live.error}${ANSI.reset}`)
    if (live.ok && live.record.rotatedTo) console.log(`  rotated to   ${live.record.rotatedTo}`)
  }

  // A valid result means one thing, and people read more into it than it says.
  if (result.state === 'valid') {
    console.log(`\n${ANSI.dim}This means the site signed its own manifest with a key it published.`)
    console.log(`It is not an endorsement of the site, its owner, or its content.${ANSI.reset}`)
  }
}

async function main() {
  let opts
  try {
    opts = parseArgs(process.argv.slice(2))
  } catch (err) {
    console.error(err.message)
    process.exit(2)
  }

  if (opts.help || (!opts.url && !opts.file)) {
    console.log(USAGE)
    process.exit(opts.help ? 0 : 2)
  }

  let result
  if (opts.file) {
    result = await verifyManifest(readFileSync(opts.file, 'utf8'))
  } else {
    result = await verifyUrl(opts.url, { timeoutMs: opts.timeout })
  }

  if (result.state === 'error') {
    render(result, null, opts)
    process.exit(2)
  }

  // The registry is only asked once the maths has passed. A forged manifest is
  // a forged manifest whatever the registry says about the key it names, and
  // reporting it as a revocation would mislead.
  let live = null
  if (opts.live && result.state !== 'invalid') {
    try {
      live = await checkLive(result.manifestKid, opts)
    } catch (err) {
      console.error(err.message)
      process.exit(2)
    }
  }

  render(result, live, opts)

  if (result.state === 'invalid') process.exit(1)
  if (live && (!live.ok || live.record.status !== 'active')) process.exit(1)
  if (result.state === 'rotated') process.exit(3)
  process.exit(0)
}

main().catch((err) => {
  console.error(err.stack ?? err.message)
  process.exit(2)
})
