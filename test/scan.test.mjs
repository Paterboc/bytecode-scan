// No network. All bytecode is synthetic, built in this file.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { execFileSync, spawnSync } from 'node:child_process';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
const require = createRequire(import.meta.url);
const { scanBytecode, disassemble, stripMetadata } = require('../dist/scan.js');
const tags = (hex) => scanBytecode(hex).flags.map(f => f.tag);
const ADDR = '11'.repeat(20);

// WHY: a privileged role hidden as a compile-time constant cannot be found by owner() probes.
test('hardcoded privileged caller is flagged (both operand orders)', () => {
  const a = scanBytecode('0x73' + ADDR + '33145b00'); // PUSH20 CALLER EQ JUMPDEST STOP
  assert.equal(a.flags.find(f => f.tag === 'hardcoded_privileged_caller')?.detail, '0x' + ADDR);
  assert.ok(tags('0x33' + '73' + ADDR + '1400').includes('hardcoded_privileged_caller')); // CALLER PUSH20 EQ
  assert.ok(tags('0x73' + ADDR + '3281145b00').includes('hardcoded_privileged_caller')); // ORIGIN DUP2 EQ
});

// WHY: a mask (PUSH20 ff..ff AND CALLER) is not a role; false positives make triage useless.
test('address mask is not a privileged constant', () => {
  assert.ok(!tags('0x73' + 'ff'.repeat(20) + '331600').includes('hardcoded_privileged_caller'));
});

test('selfdestruct, delegatecall, callcode, proxies', () => {
  assert.ok(tags('0x6000ff').includes('selfdestruct'));
  assert.ok(tags('0x60006000f4').includes('delegatecall'));
  assert.ok(tags('0x60006000f2').includes('callcode'));
  const mp = scanBytecode('0x363d3d373d3d3d363d73' + ADDR + '5af43d82803e903d91602b57fd5bf3');
  assert.equal(mp.flags.find(f => f.tag === 'minimal_proxy')?.detail, `EIP-1167 -> 0x${ADDR}`);
  assert.ok(tags('0x7f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc54').includes('eip1967_proxy'));
});

// WHY: PUSH data holding opcode bytes (JUMPDEST, CALL, SELFDESTRUCT, DELEGATECALL) must not be parsed as ops.
test('PUSH data is skipped, not misparsed', () => {
  const pushy = '0x7f' + '5bf1fff4'.repeat(8) + '600a56';
  const ops = disassemble(Buffer.from(pushy.slice(2), 'hex'));
  assert.deepEqual(ops.map(o => o.name), ['PUSH32', 'PUSH1', 'JUMP']);
  assert.ok(!tags(pushy).some(t => t === 'selfdestruct' || t === 'delegatecall'));
});

test('opcode table covers Cancun', () => {
  const names = disassemble(Buffer.from('5f5c5d5e494a', 'hex')).map(o => o.name);
  assert.deepEqual(names, ['PUSH0', 'TLOAD', 'TSTORE', 'MCOPY', 'BLOBHASH', 'BLOBBASEFEE']);
});

test('selector dispatch is extracted', () => {
  // PUSH4 transfer sel, EQ, PUSH2 0x0010, JUMPI
  const s = scanBytecode('0x63a9059cbb14610010' + '57');
  assert.equal(s.selectors[0]?.selector, '0xa9059cbb');
  assert.equal(s.selectors[0]?.name, 'transfer(address,uint256)');
});

// WHY: raw hashes differ by metadata tail; only the stripped hash is stable.
test('stripped hash is stable across metadata tails', () => {
  const body = '6001600055' + '00';
  const mk = (fill) => '0x' + body + 'a2' + fill.repeat(7) + '0008';
  const a = scanBytecode(mk('aa')), b = scanBytecode(mk('bb'));
  assert.notEqual(a.codeHash, b.codeHash);
  assert.equal(a.strippedCodeHash, b.strippedCodeHash);
  assert.equal(stripMetadata(Buffer.from(mk('aa').slice(2), 'hex')).toString('hex'), body);
});

// WHY: known_* flags must fire only when the user supplies data.
test('signatures file enables known_scam_* flags', () => {
  const hex = '0x73' + ADDR + '33145b00';
  const h = scanBytecode(hex).strippedCodeHash;
  assert.ok(!tags(hex).includes('known_scam_address') && !tags(hex).includes('known_scam_codehash'));
  const f = join(mkdtempSync(join(tmpdir(), 'sig-')), 'sigs.json');
  writeFileSync(f, JSON.stringify({ codeHashes: { [h]: 'synthetic' }, addresses: { ['0x' + ADDR]: 'synthetic' } }));
  const out = JSON.parse(execFileSync('node', ['dist/cli.js', '--hex', hex, '--json', '--signatures', f]));
  const t = out.flags.map(x => x.tag);
  assert.ok(t.includes('known_scam_address') && t.includes('known_scam_codehash'));
  const bad = join(tmpdir(), 'nope-does-not-exist.json');
  assert.equal(spawnSync('node', ['dist/cli.js', '--hex', hex, '--signatures', bad]).status, 2);
});

// ---- function attribution ----
// WHY: knowing WHICH function carries a hardcoded role is what makes the flag actionable.
test('flag sites are attributed to the dispatcher function that reaches them', () => {
  // 0x00-0x13: two PUSH4 EQ PUSH2 JUMPI dispatch entries; 0x14 STOP (fallthrough);
  // 0x15: A = JUMPDEST STOP; 0x17: B = JUMPDEST PUSH20 CALLER EQ POP STOP
  const full = '0x' + '63aaaaaaaa14' + '610015' + '57' + '63bbbbbbbb14' + '610017' + '57' + '00'
    + '5b00' + '5b73' + ADDR + '331450' + '00';
  const r = scanBytecode(full);
  const sel = r.selectors.map(s => [s.selector, s.entry]);
  assert.deepEqual(sel, [['0xaaaaaaaa', 0x15], ['0xbbbbbbbb', 0x17]]);
  const f = r.flags.find(x => x.tag === 'hardcoded_privileged_caller');
  assert.deepEqual(f.functions, [{ selector: '0xbbbbbbbb', name: null }]);
  assert.deepEqual(r.flags.find(x => x.tag === 'no_owner_getter').functions, []);
});

// WHY: a site outside every function but reachable from the dispatcher fallthrough must not be silently unattributed.
test('fallthrough-only site is attributed to fallback/unknown', () => {
  // PUSH4 sel EQ PUSH2 0x0010 JUMPI | SELFDESTRUCT (fallthrough) ... 0x10: JUMPDEST STOP
  const r = scanBytecode('0x63aaaaaaaa14' + '610010' + '57' + 'ff' + '00'.repeat(5) + '5b00');
  assert.equal(r.selectors[0].entry, 0x10);
  assert.deepEqual(r.flags.find(x => x.tag === 'selfdestruct').functions, [{ selector: null, name: 'fallback/unknown' }]);
});

// ---- behavioural flags (synthetic dispatcher: n x [PUSH4 sel EQ PUSH2 off JUMPI], STOP, bodies each starting JUMPDEST) ----
const contract = (fns) => {
  let off = fns.length * 10 + 1;
  const heads = fns.map(([s, b]) => { const h = '63' + s + '14' + '61' + off.toString(16).padStart(4, '0') + '57'; off += 1 + b.length / 2; return h; });
  return '0x' + heads.join('') + '00' + fns.map(([, b]) => '5b' + b).join('');
};
const OWNER = ['8da5cb5b', '00'];
const readsSlot = (n) => '60' + n + '5400'; // PUSH1 n SLOAD STOP
const SETTER = ['11223344', '33' + '600154' + '14' + '6001' + '6005' + '55' + '00']; // CALLER == SLOAD(1); SSTORE slot 5
const find = (hex, tag) => scanBytecode(hex).flags.find(f => f.tag === tag);

// WHY: an owner who can flip a slot that transfer reads can lock sells; a setter of an unrelated slot cannot.
test('owner_switch: guarded setter of a slot transfer reads', () => {
  const f = find(contract([OWNER, ['a9059cbb', readsSlot('05')], SETTER]), 'owner_switch');
  assert.equal(f.severity, 'medium');
  assert.match(f.detail, /slot 5/);
  assert.deepEqual(f.functions, [{ selector: '0x11223344', name: null }]);
});
test('owner_switch: not raised when transfer does not read the setter slot, or without owner()', () => {
  assert.ok(!tags(contract([OWNER, ['a9059cbb', readsSlot('06')], SETTER])).includes('owner_switch'));
  assert.ok(!tags(contract([['a9059cbb', readsSlot('05')], SETTER])).includes('owner_switch'));
});

// WHY: an admin role with no owner() getter is invisible to owner probes.
test('hidden_admin: CALLER-guarded state write without owner()', () => {
  const f = find(contract([['a9059cbb', readsSlot('06')], SETTER]), 'hidden_admin');
  assert.equal(f.severity, 'medium');
  assert.deepEqual(f.functions, [{ selector: '0x11223344', name: null }]);
  assert.ok(!tags(contract([OWNER, ['a9059cbb', readsSlot('06')], SETTER])).includes('hidden_admin'));
});

test('self_liquidity: removeLiquidity and unlockCallback selectors', () => {
  const f = find(contract([['67b9a286', '00'], ['91dd7346', '00']]), 'self_liquidity');
  assert.equal(f.severity, 'medium');
  assert.deepEqual(f.functions.map(x => x.selector), ['0x67b9a286', '0x91dd7346']);
});

// WHY: Uniswap v4 requires unlockCallback to check msg.sender == PoolManager; that is not a hidden role.
test('hardcoded caller inside unlockCallback only is suppressed', () => {
  const guard = '73' + ADDR + '331450' + '00';
  assert.ok(!tags(contract([['91dd7346', guard]])).includes('hardcoded_privileged_caller'));
  assert.ok(tags(contract([['91dd7346', guard], ['11223344', guard]])).includes('hardcoded_privileged_caller'));
  assert.ok(tags(contract([['11223344', guard]])).includes('hardcoded_privileged_caller'));
});

// WHY: string/data tails decode as fake PUSH20 constants.
test('PUSH20 in an ASCII string or unreachable tail is not an address', () => {
  const text = Buffer.from('insufficient balance.').subarray(0, 20).toString('hex');
  assert.ok(!tags('0x73' + text + '331400').includes('hardcoded_privileged_caller')); // reachable but ASCII
  assert.ok(!tags('0x00' + '73' + ADDR + '331400').includes('hardcoded_privileged_caller')); // after STOP, unreachable
});

// ---- auto chain ----
const { autoDetect } = require('../dist/auto.js');
const CH = { a: 'ua', b: 'ub', c: 'uc' };
const fake = (m) => async (url) => { const v = m[url]; if (v instanceof Error) throw v; return v; };
test('auto: code on one chain', async () => {
  const r = await autoDetect('0x' + ADDR, CH, fake({ ua: '0x', ub: '0x6000', uc: '0x' }));
  assert.deepEqual(r.found.map(f => f.chain), ['b']);
  assert.deepEqual(r.rpcErrors, {});
});
test('auto: code on two chains keeps chain order', async () => {
  const r = await autoDetect('0x' + ADDR, CH, fake({ ua: '0x6000', ub: '0x', uc: '0x6001' }));
  assert.deepEqual(r.found.map(f => f.chain), ['a', 'c']);
});
test('auto: no code anywhere throws', async () => {
  await assert.rejects(autoDetect('0x' + ADDR, CH, fake({ ua: '0x', ub: '0x', uc: '0x' })), /no contract code on any known chain/);
});
test('auto: all chains erroring throws', async () => {
  const e = new Error('boom');
  await assert.rejects(autoDetect('0x' + ADDR, CH, fake({ ua: e, ub: e, uc: e })), /all chains failed/);
});
test('auto: partial error still succeeds and records rpcErrors', async () => {
  const r = await autoDetect('0x' + ADDR, CH, fake({ ua: new Error('boom'), ub: '0x6000', uc: '0x' }));
  assert.deepEqual(r.found.map(f => f.chain), ['b']);
  assert.equal(r.rpcErrors.a, 'boom');
});
test('auto: a hung chain times out instead of blocking', async () => {
  const r = await autoDetect('0x' + ADDR, { a: 'ua', b: 'ub' }, (u) => u === 'ua' ? new Promise(() => {}) : Promise.resolve('0x6000'), 50);
  assert.deepEqual(r.found.map(f => f.chain), ['b']);
  assert.match(r.rpcErrors.a, /timeout/);
});
