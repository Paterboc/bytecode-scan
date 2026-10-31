/**
 * scan.ts -- pure (no network) EVM runtime-bytecode scanner for triage of
 * suspicious contracts. scanBytecode(hex) -> selectors, per-function annotated listings,
 * red flags, metadata-stripped code hash. Optional signature tables: data/signatures.json + loadSignatures().
 *
 * ponytail: linear-sweep disassembly (no data-section detection beyond the
 * metadata tail; bytes after a trailing 0xfe may decode as junk ops but are
 * never reached by the bounded walks); bounded block walk, not a CFG.
 * Upgrade path: real CFG + stack-tracking if listings need to be exact.
 */
import { keccak_256 } from '@noble/hashes/sha3';
import * as fs from 'fs';
import * as path from 'path';

const hexOf = (b: Uint8Array): string => Buffer.from(b).toString('hex');
const keccak256 = (b: Uint8Array): string => '0x' + hexOf(keccak_256(b));
const keccakId = (s: string): string => keccak256(Buffer.from(s, 'utf8'));

export interface Op { pc: number; op: number; name: string; data?: string }
export interface Selector { selector: string; name: string | null; entry: number }
export interface FlagFunction { selector: string | null; name: string | null }
export interface Flag { tag: string; severity: 'high' | 'medium' | 'info'; detail: string; functions: FlagFunction[] }
export interface FuncListing { selector: string; name: string | null; entry: number; lines: string[] }
export interface ScanResult {
  size: number; strippedSize: number; codeHash: string; strippedCodeHash: string;
  selectors: Selector[]; functions: FuncListing[]; flags: Flag[];
}

interface Signatures { codeHashes: Record<string, string>; addresses: Record<string, string> }
const sigs = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'data', 'signatures.json'), 'utf8')) as Signatures;

/** Merge a user-supplied signatures JSON file over the shipped tables. Throws on unreadable/invalid input. */
export function loadSignatures(file: string): void {
  const j = JSON.parse(fs.readFileSync(file, 'utf8')) as Partial<Signatures>;
  for (const k of ['codeHashes', 'addresses'] as const) {
    const t = j[k] ?? {};
    if (typeof t !== 'object' || Array.isArray(t)) throw new Error(`"${k}" must be an object`);
    for (const [key, v] of Object.entries(t)) sigs[k][key.toLowerCase()] = String(v);
  }
}

export const FLAG_EXPLAIN: Record<string, string> = {
  hardcoded_privileged_caller: 'A fixed address constant is compared with msg.sender/tx.origin: a compile-time privileged role that owner()-style checks cannot see.',
  selfdestruct: 'Contains SELFDESTRUCT: code can be destroyed or its balance swept.',
  delegatecall: 'Contains DELEGATECALL: executes foreign code in this contract\'s storage context.',
  callcode: 'Contains CALLCODE (deprecated delegatecall variant).',
  known_scam_codehash: 'Metadata-stripped code hash matches an entry in the loaded signatures file.',
  known_scam_address: 'A PUSH20 constant matches an entry in the loaded signatures file.',
  minimal_proxy: 'EIP-1167 minimal proxy: real logic lives at the embedded address (use --follow-proxy).',
  eip1967_proxy: 'References the EIP-1967 implementation or beacon storage slot: upgradeable proxy, real logic lives in another contract (use --follow-proxy).',
  owner_switch: 'owner() exists and a non-standard function guarded by a CALLER check writes a constant storage slot that transfer/transferFrom read: the owner can flip a setting transfers depend on (sell lock, trading switch, limits, blacklist toggle).',
  hidden_admin: 'No owner() getter, yet a non-standard function is guarded by CALLER == a stored constant-slot value and writes state: an admin role with no public getter.',
  self_liquidity: 'The token itself exposes removeLiquidity-style or Uniswap v4 unlockCallback selectors: it can manage or remove its own pool liquidity.',
  no_owner_getter: 'Info: no owner() selector; owner-based probes are not applicable.',
};

// ---- opcodes ----
const NAMES: Record<number, string> = {
  0x00: 'STOP', 0x01: 'ADD', 0x02: 'MUL', 0x03: 'SUB', 0x04: 'DIV', 0x05: 'SDIV', 0x06: 'MOD', 0x07: 'SMOD', 0x08: 'ADDMOD', 0x09: 'MULMOD', 0x0a: 'EXP', 0x0b: 'SIGNEXTEND',
  0x10: 'LT', 0x11: 'GT', 0x12: 'SLT', 0x13: 'SGT', 0x14: 'EQ', 0x15: 'ISZERO', 0x16: 'AND', 0x17: 'OR', 0x18: 'XOR', 0x19: 'NOT', 0x1a: 'BYTE', 0x1b: 'SHL', 0x1c: 'SHR', 0x1d: 'SAR',
  0x20: 'KECCAK256', 0x30: 'ADDRESS', 0x31: 'BALANCE', 0x32: 'ORIGIN', 0x33: 'CALLER', 0x34: 'CALLVALUE', 0x35: 'CALLDATALOAD', 0x36: 'CALLDATASIZE', 0x37: 'CALLDATACOPY',
  0x38: 'CODESIZE', 0x39: 'CODECOPY', 0x3a: 'GASPRICE', 0x3b: 'EXTCODESIZE', 0x3c: 'EXTCODECOPY', 0x3d: 'RETURNDATASIZE', 0x3e: 'RETURNDATACOPY', 0x3f: 'EXTCODEHASH',
  0x40: 'BLOCKHASH', 0x41: 'COINBASE', 0x42: 'TIMESTAMP', 0x43: 'NUMBER', 0x44: 'PREVRANDAO', 0x45: 'GASLIMIT', 0x46: 'CHAINID', 0x47: 'SELFBALANCE', 0x48: 'BASEFEE',
  0x50: 'POP', 0x51: 'MLOAD', 0x52: 'MSTORE', 0x53: 'MSTORE8', 0x54: 'SLOAD', 0x55: 'SSTORE', 0x56: 'JUMP', 0x57: 'JUMPI', 0x58: 'PC', 0x59: 'MSIZE', 0x5a: 'GAS', 0x5b: 'JUMPDEST',
  0x5c: 'TLOAD', 0x5d: 'TSTORE', 0x5e: 'MCOPY', 0x5f: 'PUSH0',
  0x49: 'BLOBHASH', 0x4a: 'BLOBBASEFEE',
  0xf0: 'CREATE', 0xf1: 'CALL', 0xf2: 'CALLCODE', 0xf3: 'RETURN', 0xf4: 'DELEGATECALL', 0xf5: 'CREATE2', 0xfa: 'STATICCALL', 0xfd: 'REVERT', 0xfe: 'INVALID', 0xff: 'SELFDESTRUCT',
};
const nameOf = (b: number): string => {
  if (b >= 0x60 && b <= 0x7f) return `PUSH${b - 0x5f}`;
  if (b >= 0x80 && b <= 0x8f) return `DUP${b - 0x7f}`;
  if (b >= 0x90 && b <= 0x9f) return `SWAP${b - 0x8f}`;
  if (b >= 0xa0 && b <= 0xa4) return `LOG${b - 0xa0}`;
  return NAMES[b] ?? `0x${b.toString(16).padStart(2, '0')}`;
};
const TERMINATORS = new Set(['STOP', 'RETURN', 'REVERT', 'INVALID', 'SELFDESTRUCT', 'JUMP']);

const KNOWN_SIGS = [
  'name()', 'symbol()', 'decimals()', 'totalSupply()', 'balanceOf(address)', 'transfer(address,uint256)', 'transferFrom(address,address,uint256)',
  'approve(address,uint256)', 'allowance(address,address)', 'increaseAllowance(address,uint256)', 'decreaseAllowance(address,uint256)',
  'owner()', 'renounceOwnership()', 'transferOwnership(address)', 'multicall(bytes[])', 'mint(address,uint256)', 'mint(uint256)', 'burn(uint256)',
  'burn(address,uint256)', 'burnFrom(address,uint256)', 'blacklist(address)', 'addBlacklist(address)', 'removeBlacklist(address)', 'isBlacklisted(address)',
  'setFee(uint256)', 'setFees(uint256,uint256)', 'setTax(uint256)', 'setMaxTx(uint256)', 'setMaxTxAmount(uint256)', 'setMaxWallet(uint256)',
  'setTradingEnabled(bool)', 'enableTrading()', 'openTrading()', 'pause()', 'unpause()', 'paused()', 'withdraw()', 'withdraw(uint256)', 'rescueTokens(address,uint256)',
  'ownerOf(uint256)', 'safeTransferFrom(address,address,uint256)', 'setApprovalForAll(address,bool)', 'tokenURI(uint256)', 'supportsInterface(bytes4)',
  'permit(address,address,uint256,uint256,uint8,bytes32,bytes32)', 'nonces(address)', 'DOMAIN_SEPARATOR()', 'factory()', 'WETH()', 'WETH9()',
  'swapExactTokensForTokens(uint256,uint256,address[],address,uint256)', 'swapExactETHForTokens(uint256,address[],address,uint256)',
  'addLiquidity(address,address,uint256,uint256,uint256,uint256,address,uint256)', 'addLiquidityETH(address,uint256,uint256,uint256,address,uint256)',
  'removeLiquidity(address,address,uint256,uint256,uint256,address,uint256)', 'execute(bytes,bytes[],uint256)', 'initialize()', 'upgradeTo(address)', 'implementation()',
];
const SEL_NAMES = new Map<string, string>(KNOWN_SIGS.map(s => [keccakId(s).slice(0, 10), s]));
const TOPICS = new Map<string, string>(
  ['Transfer(address,address,uint256)', 'Approval(address,address,uint256)', 'OwnershipTransferred(address,address)'].map(s => [keccakId(s), s.split('(')[0]]));

// ---- metadata strip + disassembly ----
const norm = (hex: string): string => hex.trim().replace(/^0x/i, '').toLowerCase();

/** Byte length of the solc CBOR metadata tail (incl. its 2-byte length), or 0. */
export function metadataLength(code: Buffer): number {
  if (code.length < 4) return 0;
  const n = code.readUInt16BE(code.length - 2);
  const start = code.length - 2 - n;
  if (n < 8 || n > 128 || start < 0) return 0;
  const m = code[start];
  return m >= 0xa1 && m <= 0xa6 ? n + 2 : 0; // CBOR map (a1..a6) = solc/vyper metadata
}
/** ponytail: solc CBOR tail only; Vyper tails differ (best effort, may leave a few trailing bytes in the hash). */
export const stripMetadata = (code: Buffer): Buffer => code.subarray(0, code.length - metadataLength(code));

export function disassemble(code: Buffer): Op[] {
  const ops: Op[] = [];
  for (let pc = 0; pc < code.length;) {
    const b = code[pc];
    const n = b >= 0x60 && b <= 0x7f ? b - 0x5f : 0;
    const op: Op = { pc, op: b, name: nameOf(b) };
    if (n) op.data = code.subarray(pc + 1, pc + 1 + n).toString('hex');
    ops.push(op);
    pc += 1 + n;
  }
  return ops;
}

// ---- dispatcher ----
const isPush = (o?: Op): boolean => !!o && o.op >= 0x60 && o.op <= 0x7f;
function extractSelectors(ops: Op[]): Selector[] {
  const out = new Map<string, Selector>();
  for (let i = 0; i < ops.length; i++) {
    const o = ops[i];
    if (o.name !== 'PUSH4' || o.data === 'ffffffff' || o.data === '00000000') continue;
    let j = i + 1;
    while (j < i + 4 && ops[j] && ops[j].name !== 'EQ' && !TERMINATORS.has(ops[j].name)) j++; // PUSH4 sel [DUP2 | PUSH0 CALLDATALOAD...] EQ
    if (ops[j]?.name !== 'EQ' || !isPush(ops[j + 1]) || ops[j + 2]?.name !== 'JUMPI') continue;
    const sel = '0x' + o.data;
    if (!out.has(sel)) out.set(sel, { selector: sel, name: SEL_NAMES.get(sel) ?? null, entry: parseInt(ops[j + 1].data!, 16) });
  }
  return [...out.values()];
}

// ---- annotated listing ----
const printable = (b: Buffer): boolean => b.length >= 3 && b.every(c => c >= 0x20 && c < 0x7f);
function wordString(hex: string): string | null {
  const b = Buffer.from(hex.padEnd(64, '0'), 'hex');
  let end = 32;
  while (end > 0 && b[end - 1] === 0) end--;
  return printable(b.subarray(0, end)) ? b.subarray(0, end).toString('latin1') : null;
}

function listFunction(ops: Op[], byPc: Map<number, number>, dests: Set<number>, entry: number, code: Buffer): { lines: string[]; pcs: Set<number> } {
  const lines: string[] = []; const pcs = new Set<number>(); // pcs: every op the bounded walk visited (flag attribution)
  const queue = [entry]; const seen = new Set<number>();
  const MAX_BLOCKS = 80, MAX_LINES = 120;
  let strWords: string[] = []; let cond: string | null = null; // function-scoped: revert strings are built in shared helper blocks
  while (queue.length && seen.size < MAX_BLOCKS && lines.length < MAX_LINES) {
    const start = queue.shift()!;
    if (seen.has(start) || (start !== entry && !dests.has(start)) || !byPc.has(start)) continue;
    seen.add(start);
    let labelled = false;
    const push = (l: string): void => { if (!labelled) { lines.push(`@0x${start.toString(16)}:`); labelled = true; } lines.push('  ' + l); };
    for (let i = byPc.get(start)!; i < ops.length; i++) {
      const o = ops[i]; const prev = ops[i - 1]; pcs.add(o.pc);
      const prevData = prev?.data !== undefined ? prev.data.replace(/^0+(?=.)/, '') : '';
      let line: string | null = null;
      if (o.name === 'PUSH32') { const s = wordString(o.data!); if (s) strWords.push(s); }
      switch (o.name) {
        case 'CALLER': case 'ORIGIN': {
          const k = ops.slice(i + 1, i + 6); const eq = k.findIndex(x => x.name === 'EQ');
          const c = [prev, ...k.slice(0, eq < 0 ? 0 : eq)].find(x => x?.name === 'PUSH20' && !/^f+$/.test(x.data!));
          if (c) cond = `${o.name} == 0x${c.data}${sigs.addresses['0x' + c.data] ? ' [' + sigs.addresses['0x' + c.data] + ']' : ''}`; else line = o.name;
          break;
        }
        case 'JUMPI': { const d = isPush(prev) ? parseInt(prev.data!, 16) : null; const c = cond ?? '...'; cond = null; line = `if (${prev?.name === 'PUSH2' && ops[i - 2]?.name === 'ISZERO' ? `!(${c})` : c}) goto ${d === null ? '?' : '@0x' + d.toString(16)}`; if (d !== null) queue.push(d); break; }
        case 'SLOAD': case 'SSTORE': line = isPush(prev) ? `${o.name} slot ${parseInt(prevData, 16)}` : `${o.name} slot ?`; break;
        case 'KECCAK256': line = 'KECCAK256 (mapping/array slot)'; break;
        case 'CALL': case 'STATICCALL': case 'DELEGATECALL': case 'CALLCODE': case 'SELFDESTRUCT': case 'CREATE': case 'CREATE2': line = o.name; break;
        case 'LOG1': case 'LOG2': case 'LOG3': case 'LOG4': {
          const t = ops.slice(Math.max(0, i - 8), i).reverse().find(x => x.name === 'PUSH32' && TOPICS.has('0x' + x.data!));
          line = `${o.name}${t ? ' ' + TOPICS.get('0x' + t.data!) : ''}`; break;
        }
        case 'CODECOPY': { // PUSH len, PUSH off, PUSH dest, CODECOPY
          const [l, f] = [ops[i - 3], ops[i - 2]];
          if (isPush(l) && isPush(f)) { const off = parseInt(f.data!, 16), len = parseInt(l.data!, 16); const s = code.subarray(off, off + len); if (printable(s)) strWords.push(s.toString('latin1')); }
          break;
        }
        case 'REVERT': line = strWords.length ? `revert("${strWords.join('')}")` : 'REVERT'; strWords = []; break;
        case 'RETURN': case 'STOP': case 'INVALID': line = o.name; break;
        case 'EQ': if (isPush(prev) && prev.name === 'PUSH20' && !/^f+$/.test(prev.data!)) line = `EQ 0x${prev.data}`; break;
        default: break;
      }
      if (line) push(line);
      if (o.name === 'JUMP') {
        const d = isPush(prev) ? parseInt(prev.data!, 16) : null;
        if (d !== null) queue.unshift(d);
        // ponytail: internal-call return label (PUSH ret, ..., PUSH fn, JUMP) is queued too; no stack tracking
        const ret = ops.slice(Math.max(0, i - 6), i - 1).reverse().find(x => x.name === 'PUSH2' && dests.has(parseInt(x.data!, 16)));
        if (ret) queue.push(parseInt(ret.data!, 16));
      }
      if (TERMINATORS.has(o.name)) break;
      if (o.name === 'JUMPDEST' && o.pc !== start && lines.length > 1 && !strWords.length) { queue.push(o.pc); break; } // fell into next block
    }
  }
  return { lines, pcs };
}

// ---- proxies ----
export const EIP1967_IMPL_SLOT = '360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc';
/** Pre-EIP-1967 OpenZeppelin (zos) slot: keccak256('org.zeppelinos.proxy.implementation'), e.g. USDC's FiatTokenProxy. */
export const ZOS_IMPL_SLOT = '7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3';
export const EIP1967_BEACON_SLOT = 'a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50';
const MIN_PROXY = /^363d3d373d3d3d363d73([0-9a-f]{40})5af43d82803e903d91602b57fd5bf3/;
/** Implementation address embedded in an EIP-1167 minimal proxy, or null. */
export const minimalProxyTarget = (code: Buffer): string | null => {
  const m = MIN_PROXY.exec(code.toString('hex'));
  return m ? '0x' + m[1] : null;
};

/** Op pcs reachable from the dispatcher fallthrough (code after the last `PUSH4 sel EQ PUSH JUMPI`), or empty. */
function fallthroughPcs(ops: Op[], byPc: Map<number, number>, dests: Set<number>, code: Buffer): Set<number> {
  // ponytail: assumes a linear dispatcher; a binary-search dispatcher's tail may not be the true fallback
  for (let i = ops.length - 1; i >= 3; i--) {
    if (ops[i].name === 'JUMPI' && isPush(ops[i - 1]) && ops[i - 2].name === 'EQ' && ops.slice(Math.max(0, i - 6), i - 2).some(x => x.name === 'PUSH4') && ops[i + 1])
      return listFunction(ops, byPc, dests, ops[i + 1].pc, code).pcs;
  }
  return new Set();
}

// ---- reachability and per-function facts ----
/** Pcs of ops reachable from pc 0 via fallthrough and PUSH-ed JUMPDEST targets; the rest is data/string tail. */
function livePcs(ops: Op[], byPc: Map<number, number>, dests: Set<number>): Set<number> {
  const live = new Set<number>(); const q = [0];
  while (q.length) {
    const p = q.pop()!; if (!byPc.has(p)) continue;
    for (let i = byPc.get(p)!; i < ops.length && !live.has(ops[i].pc); i++) {
      const o = ops[i]; live.add(o.pc);
      if (o.data && o.data.length <= 16) { const v = parseInt(o.data, 16); if (dests.has(v) && !live.has(v)) q.push(v); }
      if (TERMINATORS.has(o.name)) break;
    }
  }
  return live;
}
/** >= 75% printable ASCII bytes: a string literal that happens to be PUSH20-sized, not an address. */
const looksAscii = (hex: string): boolean => Buffer.from(hex, 'hex').filter(c => c >= 0x20 && c < 0x7f).length * 4 >= hex.length / 2 * 3;

/** Op names, constant slots read (PUSHn slot SLOAD) and written (small PUSH within 14 ops before SSTORE) on the walk from `entry`. */
function reachFacts(ops: Op[], byPc: Map<number, number>, dests: Set<number>, entry: number): { names: Set<string>; rd: Set<number>; wr: Set<number> } {
  // ponytail: heuristic slot detection (constants <= 0x40 near SSTORE), not symbolic; capped at 4000 ops. Upgrade path: stack tracking.
  const names = new Set<string>(), rd = new Set<number>(), wr = new Set<number>(), seen = new Set<number>(); const q = [entry]; let n = 0;
  while (q.length && n < 4000) {
    const p = q.pop()!; if (seen.has(p) || !byPc.has(p)) continue;
    seen.add(p);
    for (let i = byPc.get(p)!; i < ops.length; n++) {
      const o = ops[i];
      if (o.data && o.data.length <= 16) { const v = parseInt(o.data, 16); if (dests.has(v) && !seen.has(v)) q.push(v); }
      names.add(o.name);
      const pv = ops[i - 1];
      if (o.name === 'SLOAD' && pv && (pv.name === 'PUSH1' || pv.name === 'PUSH2')) rd.add(parseInt(pv.data!, 16));
      if (o.name === 'SSTORE') for (const x of ops.slice(Math.max(0, i - 14), i).reverse().filter((y, k, w) => !w.slice(0, k).some(z => z.name === 'JUMPDEST' || TERMINATORS.has(z.name)))) if ((x.name === 'PUSH1' || x.name === 'PUSH2') && parseInt(x.data!, 16) <= 0x40 && !['00', '01', '20', '40', 'ff'].includes(x.data!)) wr.add(parseInt(x.data!, 16));
      if (TERMINATORS.has(o.name)) break;
      i++;
      if (ops[i]?.name === 'JUMPDEST') { if (seen.has(ops[i].pc)) break; seen.add(ops[i].pc); }
    }
  }
  return { names, rd, wr };
}

const STD_SELS = new Set([...'name() symbol() decimals() totalSupply() balanceOf(address) transfer(address,uint256) transferFrom(address,address,uint256) approve(address,uint256) allowance(address,address) increaseAllowance(address,uint256) decreaseAllowance(address,uint256) owner() renounceOwnership() transferOwnership(address) permit(address,address,uint256,uint256,uint8,bytes32,bytes32) nonces(address) DOMAIN_SEPARATOR() eip712Domain()'.split(' ')].map(s => keccakId(s).slice(0, 10)));
const SEL_OWNER = '0x8da5cb5b', SEL_TRANSFER = '0xa9059cbb', SEL_TRANSFER_FROM = '0x23b872dd', SEL_UNLOCK_CALLBACK = '0x91dd7346';
// removeLiquidity(), removeLiquidity(address,uint256), unlockCallback(bytes)
const SELF_LIQ_SELS = new Set(['0x67b9a286', '0xa201ccf6', SEL_UNLOCK_CALLBACK]);

function behaviourFlags(ops: Op[], byPc: Map<number, number>, dests: Set<number>, selectors: Selector[], privilegedSels: Set<string | null>): Flag[] {
  const out: Flag[] = []; const fn = (s: Selector): FlagFunction => ({ selector: s.selector, name: s.name });
  const hasOwner = selectors.some(s => s.selector === SEL_OWNER);
  const facts = new Map(selectors.map(s => [s.selector, reachFacts(ops, byPc, dests, s.entry)]));
  const nonstd = selectors.filter(s => !STD_SELS.has(s.selector));
  const xr = new Set<number>(); for (const t of [SEL_TRANSFER, SEL_TRANSFER_FROM]) for (const r of facts.get(t)?.rd ?? []) xr.add(r);
  if (hasOwner) {
    const hits = nonstd.map(s => ({ s, f: facts.get(s.selector)!, slots: [...facts.get(s.selector)!.wr].filter(w => xr.has(w)) }))
      .filter(h => h.f.names.has('CALLER') && h.f.names.has('SLOAD') && h.f.names.has('EQ') && h.f.wr.size > 0 && h.f.wr.size <= 3 && h.slots.length);
    if (hits.length) out.push({ tag: 'owner_switch', severity: 'medium', detail: `slot ${[...new Set(hits.flatMap(h => h.slots))].sort((a, b) => a - b).join(', ')} written by a CALLER-guarded function and read by transfer`, functions: hits.map(h => fn(h.s)) });
  } else {
    const hits = nonstd.filter(s => { const n = facts.get(s.selector)!.names; return ['CALLER', 'SLOAD', 'EQ', 'SSTORE'].every(x => n.has(x)) && !n.has('KECCAK256') && !privilegedSels.has(s.selector); });
    if (hits.length) out.push({ tag: 'hidden_admin', severity: 'medium', detail: 'CALLER-guarded state write with no owner() getter', functions: hits.map(fn) });
  }
  const liq = selectors.filter(s => SELF_LIQ_SELS.has(s.selector));
  if (liq.length) out.push({ tag: 'self_liquidity', severity: 'medium', detail: liq.map(s => s.name ?? s.selector).join(', '), functions: liq.map(fn) });
  return out;
}

// ---- flags ----
function detectFlags(ops: Op[], stripped: Buffer, strippedHash: string, live: Set<number>): { flag: Flag; sites: number[] }[] {
  const flags: { flag: Flag; sites: number[] }[] = [];
  const add = (tag: string, severity: 'high' | 'medium' | 'info', detail: string, sites: number[] = []): void => { flags.push({ flag: { tag, severity, detail, functions: [] }, sites }); };
  const names = new Set(ops.map(o => o.name));
  const addrs = new Map<string, number[]>(); const privileged = new Map<string, number[]>();
  ops.forEach((o, i) => {
    if (o.name !== 'PUSH20' || /^f+$/.test(o.data!) || !live.has(o.pc) || looksAscii(o.data!)) return; // data/string tails decode as fake PUSH20s
    const a = '0x' + o.data!; addrs.set(a, [...(addrs.get(a) ?? []), o.pc]);
    const w = ops.slice(Math.max(0, i - 6), i + 7);
    // PUSH20 const vs CALLER/ORIGIN through EQ, either operand order, DUP/SWAP between
    if (w.some(x => x.name === 'CALLER' || x.name === 'ORIGIN') && w.some(x => x.name === 'EQ')) privileged.set(a, [...(privileged.get(a) ?? []), o.pc, ...w.filter(x => x.name === 'CALLER' || x.name === 'ORIGIN').map(x => x.pc)]);
  });
  for (const [a, sites] of privileged) add('hardcoded_privileged_caller', 'high', a, sites);
  for (const [n, t] of [['SELFDESTRUCT', 'selfdestruct'], ['DELEGATECALL', 'delegatecall'], ['CALLCODE', 'callcode']] as const) if (names.has(n)) add(t, 'high', n, ops.filter(o => o.name === n).map(o => o.pc));
  if (sigs.codeHashes[strippedHash]) add('known_scam_codehash', 'high', sigs.codeHashes[strippedHash]);
  for (const [a, sites] of addrs) if (sigs.addresses[a]) add('known_scam_address', 'high', `${a} ${sigs.addresses[a]}`, sites);
  if (minimalProxyTarget(stripped)) add('minimal_proxy', 'info', `EIP-1167 -> ${minimalProxyTarget(stripped)}`);
  const slot = ops.find(o => o.name === 'PUSH32' && (o.data === EIP1967_IMPL_SLOT || o.data === EIP1967_BEACON_SLOT));
  if (slot) add('eip1967_proxy', 'info', slot.data === EIP1967_IMPL_SLOT ? 'implementation slot' : 'beacon slot');
  return flags;
}

export function scanBytecode(hex: string): ScanResult {
  const code = Buffer.from(norm(hex), 'hex');
  const stripped = stripMetadata(code);
  const strippedCodeHash = keccak256(stripped);
  const ops = disassemble(stripped);
  const byPc = new Map(ops.map((o, i) => [o.pc, i]));
  const dests = new Set(ops.filter(o => o.name === 'JUMPDEST').map(o => o.pc));
  const selectors = extractSelectors(ops);
  const walks = selectors.map(s => ({ ...s, ...listFunction(ops, byPc, dests, s.entry, stripped) }));
  const functions = walks.map(({ pcs: _p, ...f }) => f);
  const flags = detectFlags(ops, stripped, strippedCodeHash, livePcs(ops, byPc, dests)).map(({ flag, sites }) => {
    flag.functions = walks.filter(w => sites.some(p => w.pcs.has(p))).map(w => ({ selector: w.selector, name: w.name }));
    return { flag, sites };
  });
  if (selectors.length && flags.some(f => f.sites.length && !f.flag.functions.length)) {
    const fb = fallthroughPcs(ops, byPc, dests, stripped);
    for (const f of flags) if (f.sites.length && !f.flag.functions.length && f.sites.some(p => fb.has(p))) f.flag.functions = [{ selector: null, name: 'fallback/unknown' }];
  }
  // Uniswap v4 unlockCallback must check msg.sender == PoolManager: legitimate, not a hidden role
  const kept = flags.filter(f => !(f.flag.tag === 'hardcoded_privileged_caller' && f.flag.functions.length && f.flag.functions.every(x => x.selector === SEL_UNLOCK_CALLBACK)));
  const privileged = new Set(kept.filter(f => f.flag.tag === 'hardcoded_privileged_caller').flatMap(f => f.flag.functions.map(x => x.selector)));
  const out = kept.map(f => f.flag).concat(behaviourFlags(ops, byPc, dests, selectors, privileged));
  if (selectors.length && !selectors.some(s => s.selector === '0x8da5cb5b')) out.push({ tag: 'no_owner_getter', severity: 'info', detail: 'no owner() selector', functions: [] });
  return { size: code.length, strippedSize: stripped.length, codeHash: keccak256(code), strippedCodeHash, selectors, functions, flags: out };
}
