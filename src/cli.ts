#!/usr/bin/env node
import * as fs from 'fs';
import * as path from 'path';
import { scanBytecode, loadSignatures, FLAG_EXPLAIN, minimalProxyTarget, EIP1967_IMPL_SLOT, ZOS_IMPL_SLOT, EIP1967_BEACON_SLOT, ScanResult } from './scan';

// Public endpoints, may rate-limit; use --rpc or BYTECODE_RPC for your own.
const CHAINS: Record<string, string> = {
  ethereum: 'https://ethereum-rpc.publicnode.com',
  base: 'https://mainnet.base.org',
  arbitrum: 'https://arb1.arbitrum.io/rpc',
  optimism: 'https://mainnet.optimism.io',
  bsc: 'https://bsc-dataseed.binance.org',
  polygon: 'https://polygon-rpc.com',
  avalanche: 'https://api.avax.network/ext/bc/C/rpc',
  robinhood: 'https://robinhood.drpc.org',
};

const HELP = `bytecode - static EVM bytecode triage

usage:
  bytecode <address> [--chain <name> | --rpc <url>] [--follow-proxy] [--json] [--no-listing] [--fail-on high] [--signatures <file>]
  bytecode --hex 0x6080...
  bytecode --file code.hex
  bytecode --help | --version

options:
  --chain <name>   ${Object.keys(CHAINS).join(', ')} (default: ethereum)
                   built-in RPCs are public endpoints, may rate-limit; use --rpc for your own
  --rpc <url>      JSON-RPC endpoint (default: env BYTECODE_RPC, else the --chain endpoint)
  --follow-proxy   detect EIP-1167 / EIP-1967 proxies and scan the implementation too
  --json           machine-readable output
  --no-listing     skip per-function annotated listings
  --signatures <file>  JSON {"codeHashes":{},"addresses":{}} of known-bad entries, merged over the
                   shipped (empty) tables; env BYTECODE_SIGNATURES. Enables known_scam_* flags.
  --fail-on high   exit 1 if any high-severity flag is found

exit codes: 0 analysed, 1 --fail-on tripped, 2 usage/fetch error`;

function die(msg: string): never { console.error(msg); process.exit(2); }

const args = process.argv.slice(2);
const has = (f: string): boolean => args.includes(f);
const val = (f: string): string | undefined => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : undefined; };
const FLAGS_WITH_VALUE = new Set(['--chain', '--rpc', '--hex', '--file', '--fail-on', '--signatures']);

let rpcId = 0;
async function rpc(url: string, method: string, params: unknown[]): Promise<string> {
  let res: Response;
  try {
    res = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: ++rpcId, method, params }), signal: AbortSignal.timeout(15000) });
  } catch (e) { return die(`fetch error: ${(e as Error).message}`); }
  const j = await res.json().catch(() => ({})) as { result?: string; error?: { message: string } };
  if (!res.ok || j.error || typeof j.result !== 'string') die(`${method} failed: HTTP ${res.status} ${j.error?.message ?? ''}`);
  return j.result!;
}
const getCode = (url: string, a: string): Promise<string> => rpc(url, 'eth_getCode', [a, 'latest']);
async function slotAddress(url: string, a: string, slot: string): Promise<string | null> {
  const w = (await rpc(url, 'eth_getStorageAt', [a, '0x' + slot, 'latest'])).replace(/^0x/, '').padStart(64, '0');
  return /^0+$/.test(w) ? null : '0x' + w.slice(24);
}

interface Target { title: string; address?: string; result: ScanResult; raw?: string }
function show(t: Target, listing: boolean): void {
  const r = t.result;
  console.log(`== ${t.title}: ${r.size} bytes (${r.strippedSize} without metadata)`);
  console.log(`code hash          ${r.codeHash}\nstripped code hash ${r.strippedCodeHash}`);
  console.log(`\nselectors (${r.selectors.length}):`);
  for (const s of r.selectors) console.log(`  ${s.selector}  @0x${s.entry.toString(16).padEnd(5)} ${s.name ?? '(unknown)'}`);
  console.log('\nred flags:');
  if (!r.flags.length) console.log('  none');
  for (const f of r.flags) console.log(`  [${f.severity}] ${f.tag}: ${f.detail}\n        ${FLAG_EXPLAIN[f.tag] ?? ''}`);
  if (listing) {
    console.log('\nfunctions:');
    for (const f of r.functions) console.log(`\n-- ${f.selector} ${f.name ?? '(unknown)'}\n${f.lines.join('\n') || '  (no listing)'}`);
  }
  console.log('');
}

async function main(): Promise<void> {
  if (has('--help') || has('-h')) { console.log(HELP); return; }
  if (has('--version')) { console.log(JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8')).version); return; }
  const failOn = val('--fail-on');
  if (failOn !== undefined && failOn !== 'high') die('--fail-on only supports "high"');
  const sigFile = val('--signatures') ?? process.env.BYTECODE_SIGNATURES;
  if (sigFile) { try { loadSignatures(sigFile); } catch (e) { die(`cannot load signatures: ${(e as Error).message}`); } }
  const json = has('--json'), listing = !has('--no-listing');
  const valid = (h: string): boolean => /^(0x)?([0-9a-fA-F]{2})+$/.test(h);
  const targets: Target[] = [];

  let hex = val('--hex');
  if (!hex && val('--file')) { try { hex = fs.readFileSync(val('--file')!, 'utf8').trim(); } catch (e) { die(`cannot read file: ${(e as Error).message}`); } }
  if (hex !== undefined) {
    if (!valid(hex)) die('no code (empty/invalid hex)');
    targets.push({ title: 'bytecode', result: scanBytecode(hex) });
  } else {
    const addr = args.find((a, i) => /^0x[0-9a-fA-F]{40}$/.test(a) && !FLAGS_WITH_VALUE.has(args[i - 1]));
    if (!addr) die(HELP);
    const chain = val('--chain') ?? 'ethereum';
    if (!CHAINS[chain] && !val('--rpc') && !process.env.BYTECODE_RPC) die(`unknown chain "${chain}" (known: ${Object.keys(CHAINS).join(', ')}); or pass --rpc`);
    const url = val('--rpc') ?? process.env.BYTECODE_RPC ?? CHAINS[chain];
    const fetchScan = async (a: string, title: string): Promise<Target> => {
      const code = await getCode(url, a);
      if (!valid(code)) die(`no code at ${a} (EOA or empty account)`);
      return { title, address: a, result: scanBytecode(code), raw: code };
    };
    const main = await fetchScan(addr, addr);
    targets.push(main);
    if (has('--follow-proxy')) {
      const raw = Buffer.from(main.raw!.replace(/^0x/, ''), 'hex');
      let impl: string | null = minimalProxyTarget(raw);
      let how = 'EIP-1167 minimal proxy';
      if (!impl) { impl = await slotAddress(url, addr, EIP1967_IMPL_SLOT); how = 'EIP-1967 implementation slot'; }
      if (!impl) { impl = await slotAddress(url, addr, ZOS_IMPL_SLOT); how = 'legacy OpenZeppelin (zos) implementation slot'; }
      if (!impl) {
        const beacon = await slotAddress(url, addr, EIP1967_BEACON_SLOT);
        if (beacon) {
          // beacon.implementation() = 0x5c60da1b
          const w = (await rpc(url, 'eth_call', [{ to: beacon, data: '0x5c60da1b' }, 'latest'])).replace(/^0x/, '').padStart(64, '0');
          impl = '0x' + w.slice(24); how = `EIP-1967 beacon ${beacon}`;
        }
      }
      if (impl) targets.push(await fetchScan(impl, `${impl} (implementation via ${how})`));
      else console.error('--follow-proxy: no proxy pattern detected');
    }
  }

  if (json) {
    const out = targets.map(t => ({ address: t.address ?? null, ...t.result, functions: listing ? t.result.functions : undefined }));
    console.log(JSON.stringify(out.length === 1 ? out[0] : out, null, 2));
  } else targets.forEach(t => show(t, listing));
  if (failOn === 'high' && targets.some(t => t.result.flags.some(f => f.severity === 'high'))) process.exit(1);
}
main().catch(e => die(String(e)));
