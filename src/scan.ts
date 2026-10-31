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
  privileged_balance_move: 'A function guarded by a CALLER check against stored state debits a balance-mapping entry for an account taken from calldata without consulting the allowance mapping: the guarded role can move or burn any holder\'s balance.',
  admin_role: 'Info: a CALLER-guarded state write exists with no owner() getter, but it does not reach balances, allowances, supply or a transfer gate.',
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
  'removeLiquidity(address,address,uint256,uint256,uint256,address,uint256)', 'removeLiquidity()', 'removeLiquidity(address,uint256)', 'unlockCallback(bytes)', 'execute(bytes,bytes[],uint256)', 'initialize()', 'upgradeTo(address)', 'implementation()',
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
function fallbackEntry(ops: Op[]): number | null {
  // ponytail: assumes a linear dispatcher; a binary-search dispatcher's tail may not be the true fallback
  for (let i = ops.length - 1; i >= 3; i--) {
    if (ops[i].name === 'JUMPI' && isPush(ops[i - 1]) && ops[i - 2].name === 'EQ' && ops.slice(Math.max(0, i - 6), i - 2).some(x => x.name === 'PUSH4') && ops[i + 1]) return ops[i + 1].pc;
  }
  return null;
}

// ---- reachability, stack simulation and per-function facts ----
/** Jump target from a PUSHn payload of any width (leading zeros stripped), or -1 if too large to be a pc. */
const jumpDest = (hex: string): number => { const t = hex.replace(/^0+/, ''); return t.length > 12 ? -1 : parseInt(t || '0', 16); };

type V = bigint | 'E' | 'C'; // constant | carried in from an earlier block | computed in this block
interface El { v: V; src?: bigint[]; caller?: boolean; ld?: boolean; deb?: boolean } // src = constant storage slots the value was SLOADed from; caller = derived from CALLER
interface Flow {
  jumps: Map<number, V>;              // operand of each JUMP/JUMPI
  rets: Map<number, number[]>;        // JUMP pc -> dest-sized constants pushed earlier in its block chain (callee targets and return labels)
  keys: Map<number, bigint>;          // constant storage key per SLOAD/SSTORE
  guards: Map<number, bigint[]>;      // EQ/SUB/XOR pc comparing CALLER with a value SLOADed from these constant slots (the owner/admin slot)
  maps: Map<number, bigint>;          // MSTORE(0x20, const) pc: the constant is a mapping slot about to be hashed
  debits: Set<number>;                // SSTORE pcs storing a value computed as (SLOADed value - x)
}
const EFFECT = new Map<number, [number, number]>();
for (const [list, p, q] of [
  [[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0a, 0x0b, 0x10, 0x11, 0x12, 0x13, 0x14, 0x16, 0x17, 0x18, 0x1a, 0x1b, 0x1c, 0x1d, 0x20], 2, 1],
  [[0x08, 0x09, 0xf0], 3, 1], [[0x15, 0x19, 0x31, 0x35, 0x3b, 0x3f, 0x40, 0x49, 0x51, 0x54, 0x5c], 1, 1],
  [[0x30, 0x32, 0x33, 0x34, 0x36, 0x38, 0x3a, 0x3d, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x4a, 0x58, 0x59, 0x5a], 0, 1],
  [[0x37, 0x39, 0x3e, 0x5e], 3, 0], [[0x3c], 4, 0], [[0x50, 0xff], 1, 0], [[0x52, 0x53, 0x55, 0x5d, 0xf3, 0xfd], 2, 0],
  [[0xf1, 0xf2], 7, 1], [[0xf4, 0xfa], 6, 1], [[0xf5], 4, 1],
] as [number[], number, number][]) for (const b of list) EFFECT.set(b, [p, q]);
const M256 = (1n << 256n) - 1n;
const FOLD: Record<number, (a: bigint, b: bigint) => bigint> = {
  0x01: (a, b) => (a + b) & M256, 0x02: (a, b) => (a * b) & M256, 0x03: (a, b) => (a - b) & M256, 0x16: (a, b) => a & b, 0x17: (a, b) => a | b, 0x18: (a, b) => a ^ b,
  0x1b: (a, b) => a >= 256n ? 0n : (b << a) & M256, 0x1c: (a, b) => a >= 256n ? 0n : b >> a,
};
/**
 * Per-basic-block constant-propagating stack simulation (stack empty at each JUMPDEST).
 * ponytail: intra-block only; values crossing blocks are 'E' (carried). Upgrade path: a real CFG with dataflow.
 */
function simulate(ops: Op[]): Flow {
  const jumps = new Map<number, V>(), rets = new Map<number, number[]>(), keys = new Map<number, bigint>(), guards = new Map<number, bigint[]>(), maps = new Map<number, bigint>(), debits = new Set<number>();
  const st: El[] = []; let pending: number[] = []; const small = (ops[ops.length - 1]?.pc ?? 0) < 256;
  const pop = (): El => st.pop() ?? { v: 'E' };
  for (const o of ops) {
    const b = o.op;
    if (b === 0x5b) { st.length = 0; continue; } // fallthrough keeps `pending`
    if (b >= 0x60 && b <= 0x7f) { st.push({ v: BigInt('0x' + (o.data || '0')) }); const d = jumpDest(o.data || '0'); if (d >= 0 && (b === 0x61 || b === 0x62 || (b === 0x60 && small))) pending.push(d); continue; } // code labels are PUSH2/3 in contracts over 255 bytes
    if (b === 0x5f) { st.push({ v: 0n }); continue; }
    if (b >= 0x80 && b <= 0x8f) { st.push(st[st.length - (b - 0x7f)] ?? { v: 'E' }); continue; }
    if (b >= 0x90 && b <= 0x9f) { const n = b - 0x8f; while (st.length <= n) st.unshift({ v: 'E' }); const t = st.length - 1; [st[t], st[t - n]] = [st[t - n], st[t]]; continue; }
    if (b === 0x56 || b === 0x57) {
      jumps.set(o.pc, pop().v);
      if (b === 0x57) pop(); else { rets.set(o.pc, pending); pending = []; st.length = 0; }
      continue;
    }
    if (b === 0x55 && st[st.length - 2]?.deb) debits.add(o.pc);
    if (b === 0x54 || b === 0x55) { const k = st[st.length - 1]?.v; if (typeof k === 'bigint') keys.set(o.pc, k); }
    if (b === 0x52 && st[st.length - 1]?.v === 0x20n && typeof st[st.length - 2]?.v === 'bigint') maps.set(o.pc, st[st.length - 2].v as bigint);
    if (b >= 0xa0 && b <= 0xa4) { for (let k = 0; k < 2 + b - 0xa0; k++) pop(); continue; }
    const [p, q] = EFFECT.get(b) ?? [0, 0];
    const args = Array.from({ length: p }, pop);
    const src = args.flatMap(a => a.src ?? []);
    if ((b === 0x14 || b === 0x03 || b === 0x18) && args.length === 2) for (const [x, y] of [[args[0], args[1]], [args[1], args[0]]]) if (x.caller && y.src?.length) guards.set(o.pc, y.src);
    const f = b in FOLD ? FOLD[b] : undefined;
    for (let k = 0; k < q; k++) {
      const v: V = f && typeof args[0].v === 'bigint' && typeof args[1].v === 'bigint' ? f(args[0].v, args[1].v) : 'C';
      const slot = b === 0x54 ? keys.get(o.pc) : undefined;
      st.push({ v, src: slot !== undefined ? [slot] : src, caller: b === 0x33 || args.some(a => a.caller), ld: b === 0x54 || args.some(a => a.ld), deb: (b === 0x03 && args.some(a => a.ld)) || args.some(a => a.deb) });
    }
    if (TERMINATORS.has(o.name)) { st.length = 0; pending = []; }
  }
  return { jumps, rets, keys, guards, maps, debits };
}
const jumpTarget = (flow: Flow, pc: number): number => { const v = flow.jumps.get(pc); return typeof v === 'bigint' && v < 1n << 40n ? Number(v) : -1; };
/** Static successors of a JUMP/JUMPI: its (folded) constant operand, plus for JUMP every dest-sized constant pushed in its block (callee + return labels). */
const jumpSuccessors = (flow: Flow, o: Op): number[] => [jumpTarget(flow, o.pc), ...(o.op === 0x56 ? flow.rets.get(o.pc) ?? [] : [])];

/**
 * Pcs of ops reachable from pc 0 via fallthrough and statically resolved JUMPDEST targets; the rest is data/string tail.
 * `computed` = a reachable jump target is computed in-block (unresolvable). Fail closed: then every JUMPDEST below `codeEnd`
 * (the code region, before the metadata tail) is treated as live.
 */
function livePcs(ops: Op[], byPc: Map<number, number>, dests: Set<number>, flow: Flow, codeEnd: number): { live: Set<number>; computed: boolean } {
  const live = new Set<number>(); const q = [0]; let computed = false, seeded = false;
  const hasLabels = [...flow.rets.values()].some(l => l.some(d => dests.has(d)));
  for (;;) {
    while (q.length) {
      const p = q.pop()!; if (!byPc.has(p)) continue;
      for (let i = byPc.get(p)!; i < ops.length && !live.has(ops[i].pc); i++) {
        const o = ops[i]; live.add(o.pc);
        if (o.op === 0x56 || o.op === 0x57) {
          for (const t of jumpSuccessors(flow, o)) if (dests.has(t) && !live.has(t)) q.push(t);
          const jv = flow.jumps.get(o.pc); // 'E' (carried) is a return jump only if some return label was pushed anywhere
          if (jv === 'C' || (jv === 'E' && !hasLabels)) computed = true;
        }
        if (TERMINATORS.has(o.name)) break;
      }
    }
    if (!computed || seeded) return { live, computed };
    seeded = true; for (const d of dests) if (d < codeEnd && !live.has(d)) q.push(d);
  }
}

type Slots = Set<bigint>;
interface Facts { names: Set<string>; rd: Slots; wr: Slots; guard: Slots; maps: Slots }
/** Op names, constant storage slots read/written, owner/admin guard slots and hashed mapping slots on the walk from `entry`. */
function reachFacts(ops: Op[], byPc: Map<number, number>, dests: Set<number>, flow: Flow, entry: number): Facts {
  // ponytail: slots come from intra-block constant propagation; unresolved keys fall back to a nearby-PUSH1/2 heuristic. Capped at 4000 ops.
  const names = new Set<string>(), rd: Slots = new Set(), wr: Slots = new Set(), guard: Slots = new Set(), maps: Slots = new Set(), seen = new Set<number>(); const q = [entry]; let n = 0;
  while (q.length && n < 4000) {
    const p = q.pop()!; if (seen.has(p) || !byPc.has(p)) continue;
    seen.add(p);
    for (let i = byPc.get(p)!; i < ops.length; n++) {
      const o = ops[i];
      if (o.op === 0x56 || o.op === 0x57) for (const t of jumpSuccessors(flow, o)) if (dests.has(t) && !seen.has(t)) q.push(t);
      names.add(o.name);
      const pv = ops[i - 1], k = flow.keys.get(o.pc);
      if (o.name === 'SLOAD') { if (k !== undefined) rd.add(k); else if (pv && (pv.name === 'PUSH1' || pv.name === 'PUSH2')) rd.add(BigInt('0x' + pv.data!)); }
      if (o.name === 'SSTORE') {
        if (k !== undefined) wr.add(k);
        else for (const x of ops.slice(Math.max(0, i - 14), i).reverse().filter((y, j, w) => !w.slice(0, j).some(z => z.name === 'JUMPDEST' || TERMINATORS.has(z.name)))) if ((x.name === 'PUSH1' || x.name === 'PUSH2') && parseInt(x.data!, 16) <= 0x40 && !['00', '01', '20', '40', 'ff'].includes(x.data!)) wr.add(BigInt('0x' + x.data!));
      }
      for (const g of flow.guards.get(o.pc) ?? []) guard.add(g);
      const m = flow.maps.get(o.pc); if (m !== undefined) maps.add(m);
      if (flow.debits.has(o.pc)) names.add('DEBIT');
      if (TERMINATORS.has(o.name)) break;
      i++;
      if (ops[i]?.name === 'JUMPDEST') { if (seen.has(ops[i].pc)) break; seen.add(ops[i].pc); }
    }
  }
  return { names, rd, wr, guard, maps };
}

const sel4 = (s: string): string => keccakId(s).slice(0, 10);
const SEL_OWNER = '0x8da5cb5b', SEL_TRANSFER = '0xa9059cbb', SEL_TRANSFER_FROM = '0x23b872dd', SEL_UNLOCK_CALLBACK = '0x91dd7346';
const SEL_BALANCE_OF = '0x70a08231', SEL_ALLOWANCE = '0xdd62ed3e', SEL_TOTAL_SUPPLY = '0x18160ddd', SEL_RENOUNCE = '0x715018a6';
/** Core ERC20 entry points: not admin setters, so not considered as guarded writers. */
const CORE_SELS = new Set(['transfer(address,uint256)', 'transferFrom(address,address,uint256)', 'approve(address,uint256)', 'increaseAllowance(address,uint256)', 'decreaseAllowance(address,uint256)', 'permit(address,address,uint256,uint256,uint8,bytes32,bytes32)'].map(sel4));
/** Official Uniswap v4 PoolManager deployments (mainnets, from the public deployments page). unlockCallback must check msg.sender == PoolManager. */
const POOL_MANAGERS = new Set(['0x000000000004444c5dc75cb358380d2e3de08a90', '0x1f98400000000000000000000000000000000004', '0x9a13f98cb987694c9f086b1f5eb990eea8264ec3',
  '0x498581ff718922c3f8e6a244956af099b2652b2b', '0x360e68faccca8ca495c1b759fd9eee466db9fb32', '0x67366782805870060151383f4bbff9dab53e5cd6', '0x0575338e4c17006ae181b47900a84404247ca30f',
  '0xb1860d529182ac3bc1f51fa2abd56662b7d13f33', '0x06380c0e0912312b5150364b9dc4542ba0dbbc85', '0x28e2ea090877bf75740558f6bfb36a5ffee9e9df', '0x288dc841a52fca2707c6947b3a777c5e56cd87bc',
  '0x188d586ddcf52439676ca21a244753fa19f9ea8e', '0xacb7e78fa05d562e0a5d3089ec896d57d057d38e', '0x33620f62c5b9b2086dd6b62f4a297a9f30347029', '0x8366a39cc670b4001a1121b8f6a443a643e40951',
  '0x12d4fd9c5dedd00ab8a0bce2cf0167bbf94b6b1f']);
// removeLiquidity(), removeLiquidity(address,uint256), unlockCallback(bytes)
const SELF_LIQ_SELS = new Set(['0x67b9a286', '0xa201ccf6', SEL_UNLOCK_CALLBACK]);

/** Comparison forms: EQ, or SUB/XOR followed by ISZERO. */
const hasCmp = (names: Set<string>): boolean => names.has('EQ') || (names.has('ISZERO') && (names.has('SUB') || names.has('XOR')));
const fmtSlot = (s: bigint): string => s < 1n << 32n ? String(s) : '0x' + s.toString(16);
const intersects = (a: Slots, b: Slots): boolean => [...a].some(x => b.has(x));

function behaviourFlags(ops: Op[], byPc: Map<number, number>, dests: Set<number>, flow: Flow, selectors: Selector[], privilegedSels: Set<string | null>, fallbackEntry: number | null): Flag[] {
  const out: Flag[] = []; const fn = (s: Selector): FlagFunction => ({ selector: s.selector, name: s.name });
  const hasOwner = selectors.some(s => s.selector === SEL_OWNER);
  const facts = new Map(selectors.map(s => [s.selector, reachFacts(ops, byPc, dests, flow, s.entry)]));
  const guarded = (f: Facts): boolean => f.guard.size > 0 && f.names.has('CALLER') && hasCmp(f.names); // CALLER compared with a constant-slot SLOAD
  const cands = selectors.filter(s => !CORE_SELS.has(s.selector));
  const xr: Slots = new Set(); for (const t of [SEL_TRANSFER, SEL_TRANSFER_FROM]) for (const r of facts.get(t)?.rd ?? []) xr.add(r);
  const bal = facts.get(SEL_BALANCE_OF)?.maps ?? new Set<bigint>(), allow = facts.get(SEL_ALLOWANCE)?.maps ?? new Set<bigint>();
  // privileged_balance_move: guarded non-ERC20 function debiting a holder-chosen balance without touching the allowance mapping
  const moves = cands.filter(s => { const f = facts.get(s.selector)!; return guarded(f) && f.names.has('SSTORE') && f.names.has('CALLDATALOAD') && f.names.has('DEBIT') && intersects(f.maps, bal) && !intersects(f.maps, allow); });
  if (moves.length) {
    const ren = facts.get(SEL_RENOUNCE);
    const survives = ren !== undefined && ren.wr.size > 0 && moves.some(s => !intersects(facts.get(s.selector)!.guard, ren.wr));
    out.push({ tag: 'privileged_balance_move', severity: 'high', detail: `CALLER-guarded function reaches a balance-mapping write for a calldata-chosen account without reading the allowance mapping${survives ? ' (survives renounceOwnership)' : ''}`, functions: moves.map(fn) });
  }
  if (hasOwner) {
    const hits = cands.map(s => { const f = facts.get(s.selector)!; return { s, f, slots: [...f.wr].filter(w => xr.has(w) && !f.guard.has(w)) }; })
      .filter(h => guarded(h.f) && h.slots.length);
    if (hits.length) out.push({ tag: 'owner_switch', severity: 'medium', detail: `slot ${[...new Set(hits.flatMap(h => h.slots))].sort((a, b) => (a < b ? -1 : 1)).map(fmtSlot).join(', ')} written by a CALLER-guarded function and read by transfer`, functions: hits.map(h => fn(h.s)) });
  } else {
    const adm = (f: Facts): boolean => guarded(f) && f.names.has('SSTORE') && !f.names.has('KECCAK256');
    const sensitiveSlots: Slots = new Set([...xr, ...(facts.get(SEL_TOTAL_SUPPLY)?.rd ?? [])]);
    const sensitive = (f: Facts): boolean => intersects(f.maps, bal) || intersects(f.maps, allow) || intersects(f.wr, sensitiveSlots);
    const hits: { fn: FlagFunction; f: Facts }[] = cands.filter(s => adm(facts.get(s.selector)!) && !privilegedSels.has(s.selector)).map(s => ({ fn: fn(s), f: facts.get(s.selector)! }));
    if (fallbackEntry !== null && !privilegedSels.has(null)) { const f = reachFacts(ops, byPc, dests, flow, fallbackEntry); if (adm(f)) hits.push({ fn: { selector: null, name: 'fallback/unknown' }, f }); }
    const hot = hits.filter(h => sensitive(h.f)), cold = hits.filter(h => !sensitive(h.f));
    if (hot.length) out.push({ tag: 'hidden_admin', severity: 'medium', detail: 'CALLER-guarded write to balances, allowances, supply or a transfer-gate slot with no owner() getter', functions: hot.map(h => h.fn) });
    if (cold.length) out.push({ tag: 'admin_role', severity: 'info', detail: 'CALLER-guarded state write with no owner() getter (does not reach balances, allowances, supply or a transfer gate)', functions: cold.map(h => h.fn) });
  }
  const liq = selectors.filter(s => SELF_LIQ_SELS.has(s.selector));
  if (liq.length) out.push({ tag: 'self_liquidity', severity: 'medium', detail: liq.map(s => s.name ?? s.selector).join(', '), functions: liq.map(fn) });
  return out;
}

// ---- flags ----
/** Address constant from PUSH20, or a wider PUSH (immutable-style zero-padded word) whose value fits 160 bits and is >= 12 bytes; '0x'+40 hex, or null. */
function addrConst(o: Op): string | null {
  if (o.op < 0x73 || !o.data) return null;
  const t = o.data.replace(/^0+/, '');
  if (o.op === 0x73) return /^f+$/.test(o.data) ? null : '0x' + o.data;
  return t.length < 24 || t.length > 40 || /^f+$/.test(t) ? null : '0x' + t.padStart(40, '0');
}

interface Raised { flag: Flag; sites: number[]; anyLive: boolean; allLive: boolean }
/**
 * HIGH-severity detectors run on a LINEAR floor: every op of the code region (before the metadata tail) plus any metadata-region op proven reachable.
 * Reachability only attributes functions and gates exemptions; it never decides whether a HIGH flag fires.
 */
function detectFlags(ops: Op[], byPc: Map<number, number>, stripped: Buffer, strippedHash: string, live: Set<number>): Raised[] {
  const flags: Raised[] = [];
  const add = (tag: string, severity: 'high' | 'medium' | 'info', detail: string, sites: number[] = []): void => {
    const anyLive = sites.some(p => live.has(p));
    flags.push({ flag: { tag, severity, detail: sites.length && !anyLive && !/^(hardcoded|known)/.test(tag) ? `${detail} (not proven reachable)` : detail, functions: [] }, sites, anyLive, allLive: sites.every(p => live.has(p)) });
  };
  const floor = ops.filter(o => o.pc < stripped.length || live.has(o.pc));
  const names = new Set(floor.map(o => o.name));
  const addrs = new Map<string, number[]>(); const privileged = new Map<string, number[]>();
  ops.forEach((o) => { // address patterns: floored over the FULL code, tail included
    const a = addrConst(o);
    if (!a) return;
    addrs.set(a, [...(addrs.get(a) ?? []), o.pc]);
    const i = byPc.get(o.pc)!, w = ops.slice(Math.max(0, i - 6), i + 7);
    // address const vs CALLER/ORIGIN through EQ (or SUB/XOR + ISZERO), either operand order, DUP/SWAP between
    if (w.some(x => x.name === 'CALLER' || x.name === 'ORIGIN') && hasCmp(new Set(w.map(x => x.name)))) privileged.set(a, [...(privileged.get(a) ?? []), o.pc, ...w.filter(x => x.name === 'CALLER' || x.name === 'ORIGIN').map(x => x.pc)]);
  });
  for (const [a, sites] of privileged) add('hardcoded_privileged_caller', 'high', a, sites);
  for (const [n, t] of [['SELFDESTRUCT', 'selfdestruct'], ['DELEGATECALL', 'delegatecall'], ['CALLCODE', 'callcode']] as const) if (names.has(n)) add(t, 'high', n, floor.filter(o => o.name === n).map(o => o.pc));
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
  // all detectors run on the FULL code: a fabricated metadata tail must not hide executable bytes. Stripping only feeds the hash and the metadata-tail floor boundary.
  const ops = disassemble(code);
  const byPc = new Map(ops.map((o, i) => [o.pc, i]));
  const dests = new Set(ops.filter(o => o.name === 'JUMPDEST').map(o => o.pc));
  const flow = simulate(ops);
  const { live, computed } = livePcs(ops, byPc, dests, flow, code.length);
  const selectors = extractSelectors(ops);
  const walks = selectors.map(s => ({ ...s, ...listFunction(ops, byPc, dests, s.entry, code) }));
  const functions = walks.map(({ pcs: _p, ...f }) => f);
  const fbEntry = selectors.length ? fallbackEntry(ops) : null;
  const flags = detectFlags(ops, byPc, stripped, strippedCodeHash, live);
  const fb = fbEntry !== null && flags.some(f => f.sites.length) ? listFunction(ops, byPc, dests, fbEntry, code).pcs : new Set<number>();
  for (const f of flags) {
    f.flag.functions = walks.filter(w => f.sites.some(p => w.pcs.has(p))).map(w => ({ selector: w.selector, name: w.name }));
    if (f.sites.some(p => fb.has(p))) f.flag.functions.push({ selector: null, name: 'fallback/unknown' });
    if (f.sites.length && !f.anyLive) f.flag.functions = [{ selector: null, name: 'unreachable/unknown' }]; // linear-floor hit in code not proven reachable
  }
  // Uniswap v4 unlockCallback must check msg.sender == the canonical PoolManager. Exempt ONLY if the hit is proven reachable, the walk has no unresolved
  // (computed) jumps, and unlockCallback is the sole reacher; otherwise the HIGH flag stays.
  const kept = flags.filter(f => !(f.flag.tag === 'hardcoded_privileged_caller' && POOL_MANAGERS.has(f.flag.detail) && f.allLive && !computed && f.flag.functions.length && f.flag.functions.every(x => x.selector === SEL_UNLOCK_CALLBACK)));
  const privileged = new Set(kept.filter(f => f.flag.tag === 'hardcoded_privileged_caller').flatMap(f => f.flag.functions.map(x => x.selector)));
  const out = kept.map(f => f.flag).concat(behaviourFlags(ops, byPc, dests, flow, selectors, privileged, fbEntry));
  if (selectors.length && !selectors.some(s => s.selector === '0x8da5cb5b')) out.push({ tag: 'no_owner_getter', severity: 'info', detail: 'no owner() selector', functions: [] });
  return { size: code.length, strippedSize: stripped.length, codeHash: keccak256(code), strippedCodeHash, selectors, functions, flags: out };
}
