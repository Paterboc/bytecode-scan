#!/usr/bin/env node
import * as fs from 'fs';
import * as path from 'path';
import { autoDetect } from './auto';
import { scanBytecode, loadSignatures, FLAG_EXPLAIN, minimalProxyTarget, EIP1967_IMPL_SLOT, ZOS_IMPL_SLOT, EIP1967_BEACON_SLOT, ScanResult } from './scan';

// Public endpoints, may rate-limit; use --rpc or BYTECODE_RPC for your own.
const CHAINS: Record<string, string> = {
  ethereum: 'https://ethereum-rpc.publicnode.com',
  base: 'https://mainnet.base.org',
  arbitrum: 'https://arb1.arbitrum.io/rpc',
  optimism: 'https://mainnet.optimism.io',
  bsc: 'https://bsc-dataseed.binance.org',
  polygon: 'https://polygon-bor-rpc.publicnode.com',
  avalanche: 'https://api.avax.network/ext/bc/C/rpc',
  robinhood: 'https://robinhood.drpc.org',
};

const HELP = `bytecode - static EVM bytecode triage

usage:
  bytecode <address> [--chain <name>|auto | --rpc <url>] [--follow-proxy] [--json] [--no-listing] [--fail-on high] [--signatures <file>]
  bytecode --hex 0x6080...
  bytecode --file code.hex
  bytecode --help | --version

options:
  --chain <name>   auto, ${Object.keys(CHAINS).join(', ')} (default: auto)
                   auto queries every built-in chain concurrently (8 s timeout each) and scans each
                   chain where code exists; the chain is reported per result. Failed chains are noted
                   on stderr (JSON: rpcErrors). Used when no --chain/--rpc/BYTECODE_RPC is given.
                   built-in RPCs are public endpoints, may rate-limit; use --rpc for your own
  --rpc <url>      JSON-RPC endpoint (overrides --chain; env BYTECODE_RPC)
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
async function rpc(url: string, method: string, params: unknown[], timeoutMs = 15000): Promise<string> {
  let res: Response;
  try {
    res = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: ++rpcId, method, params }), signal: AbortSignal.timeout(timeoutMs) });
  } catch (e) { throw new Error(`fetch error: ${(e as Error).message}`); }
  const j = await res.json().catch(() => ({})) as { result?: string; error?: { message: string } };
  if (!res.ok || j.error || typeof j.result !== 'string') throw new Error(`${method} failed: HTTP ${res.status} ${j.error?.message ?? ''}`);
  return j.result!;
}
const getCode = (url: string, a: string, t?: number): Promise<string> => rpc(url, 'eth_getCode', [a, 'latest'], t);
async function slotAddress(url: string, a: string, slot: string, timeoutMs?: number): Promise<string | null> {
  const w = (await rpc(url, 'eth_getStorageAt', [a, '0x' + slot, 'latest'], timeoutMs)).replace(/^0x/, '').padStart(64, '0');
  return /^0+$/.test(w) ? null : '0x' + w.slice(24);
}

interface Target { title: string; address?: string; result: ScanResult; raw?: string; chain: string | null; url?: string; rpcErrors?: Record<string, string>; incomplete: string[] }
function show(t: Target, listing: boolean): void {
  const r = t.result;
  console.log(`== ${t.title}${t.chain ? ` [${t.chain}]` : ''}: ${r.size} bytes (${r.strippedSize} without metadata)`);
  console.log(`code hash          ${r.codeHash}\nstripped code hash ${r.strippedCodeHash}`);
  console.log(`\nselectors (${r.selectors.length}):`);
  for (const s of r.selectors) console.log(`  ${s.selector}  @0x${s.entry.toString(16).padEnd(5)} ${s.name ?? '(unknown)'}`);
  console.log('\nred flags:');
  if (!r.flags.length) console.log('  none');
  for (const f of r.flags) {
    console.log(`  [${f.severity}] ${f.tag}: ${f.detail}\n        ${FLAG_EXPLAIN[f.tag] ?? ''}`);
    if (f.functions.length) console.log(`        in: ${f.functions.map(x => x.name ?? x.selector).join(', ')}`);
  }
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
    targets.push({ title: 'bytecode', result: scanBytecode(hex), chain: null, incomplete: [] });
  } else {
    const addr = args.find((a, i) => /^0x[0-9a-fA-F]{40}$/.test(a) && !FLAGS_WITH_VALUE.has(args[i - 1]));
    if (!addr) die(HELP);
    const customRpc = val('--rpc') ?? process.env.BYTECODE_RPC;
    const chain = val('--chain') ?? (customRpc ? null : 'auto');
    if (chain && chain !== 'auto' && !CHAINS[chain] && !customRpc) die(`unknown chain "${chain}" (known: auto, ${Object.keys(CHAINS).join(', ')}); or pass --rpc`);
    const where: { chain: string | null; url: string; code?: string }[] = [];
    let rpcErrors: Record<string, string> | undefined;
    if (chain === 'auto' && !val('--rpc')) {
      const r = await autoDetect(addr, CHAINS, (u, a) => getCode(u, a, 8000)).catch(e => die((e as Error).message));
      for (const [c, m] of Object.entries(r.rpcErrors)) console.error(`rpc error on ${c}: ${m}`);
      if (Object.keys(r.rpcErrors).length) rpcErrors = r.rpcErrors;
      where.push(...r.found.map(f => ({ chain: f.chain, url: CHAINS[f.chain], code: f.code })));
    } else where.push({ chain: customRpc ? null : chain, url: customRpc ?? CHAINS[chain!] });
    for (const w of where) {
      const fetchScan = async (a: string, title: string, code?: string): Promise<Target> => {
        code ??= await getCode(w.url, a);
        if (!valid(code)) die(`no code at ${a} (EOA or empty account)`);
        return { title, address: a, result: scanBytecode(code), raw: code, chain: w.chain, rpcErrors, incomplete: [] };
      };
      const main = await fetchScan(addr, addr, w.code);
      targets.push(main);
      if (has('--follow-proxy')) {
        // best-effort: any failure here warns on stderr and keeps the main target's result
        try {
          const url = w.url, T = 5000;
          let impl: string | null = minimalProxyTarget(Buffer.from(main.raw!.replace(/^0x/, ''), 'hex'));
          let how = 'EIP-1167 minimal proxy';
          if (!impl) {
            const reads = await Promise.allSettled([EIP1967_IMPL_SLOT, ZOS_IMPL_SLOT, EIP1967_BEACON_SLOT].map(sl => slotAddress(url, addr, sl, T)));
            const [i67, zos, beacon] = reads.map(r => r.status === 'fulfilled' ? r.value : null);
            for (const r of reads) if (r.status === 'rejected') main.incomplete.push(`follow-proxy: proxy slot read failed: ${(r.reason as Error).message}`);
            if (i67) { impl = i67; how = 'EIP-1967 implementation slot'; }
            else if (zos) { impl = zos; how = 'legacy OpenZeppelin (zos) implementation slot'; }
            else if (beacon) {
              // beacon.implementation() = 0x5c60da1b
              const bw = (await rpc(url, 'eth_call', [{ to: beacon, data: '0x5c60da1b' }, 'latest'], T)).replace(/^0x/, '').padStart(64, '0');
              impl = '0x' + bw.slice(24); how = `EIP-1967 beacon ${beacon}`;
            } else if (reads.some(r => r.status === 'rejected')) throw new Error('slot read failed');
          }
          if (impl) {
            const code = await getCode(url, impl, T);
            if (!valid(code)) throw new Error(`no code at ${impl}`);
            targets.push({ title: `${impl} (implementation via ${how})`, address: impl, result: scanBytecode(code), raw: code, chain: w.chain, rpcErrors, incomplete: [] });
          } else console.error('--follow-proxy: no proxy pattern detected');
        } catch (e) {
          const m = `follow-proxy: implementation unavailable: ${(e as Error).message}`;
          console.error('--' + m); main.incomplete.push(m);
        }
      }
    }
  }

  if (json) {
    const out = targets.map(t => ({ address: t.address ?? null, chain: t.chain, ...(t.rpcErrors ? { rpcErrors: t.rpcErrors } : {}), ...(t.incomplete.length ? { incomplete: t.incomplete } : {}), ...t.result, functions: listing ? t.result.functions : undefined }));
    console.log(JSON.stringify(out.length === 1 ? out[0] : out, null, 2));
  } else targets.forEach(t => show(t, listing));
  if (failOn === 'high' && targets.some(t => t.result.flags.some(f => f.severity === 'high'))) process.exit(1);
}
main().catch(e => die(String(e)));
