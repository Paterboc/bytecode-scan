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

// WHY: Uniswap v4 requires unlockCallback to check msg.sender == PoolManager; only that public address is exempt.
const POOL_MANAGER = '000000000004444c5dc75cb358380d2e3de08a90'; // Uniswap's public Ethereum deployment
test('PoolManager guard inside unlockCallback is suppressed; any other constant is not', () => {
  const guard = (a) => '73' + a + '331450' + '00';
  assert.ok(!tags(contract([['91dd7346', guard(POOL_MANAGER)]])).includes('hardcoded_privileged_caller'));
  assert.ok(tags(contract([['91dd7346', guard(POOL_MANAGER)], ['11223344', guard(POOL_MANAGER)]])).includes('hardcoded_privileged_caller'));
  const f = find(contract([['91dd7346', guard(ADDR)]]), 'hardcoded_privileged_caller'); // backdoor named unlockCallback
  assert.equal(f.severity, 'high');
});

// WHY: string/data tails decode as fake ops; only reachable code counts. ASCII-looking constants are NOT exempt (vanity backdoors).
test('unreachable data tail is ignored; ASCII-looking reachable constant is flagged', () => {
  assert.ok(!tags('0x00' + '73' + ADDR + '331400').includes('hardcoded_privileged_caller'));
  assert.ok(!tags('0x00f2').includes('callcode'));
  const text = Buffer.from('backdoorAddrXYZ').toString('hex') + 'c3d4e5f601';
  assert.ok(tags('0x73' + text + '331400').includes('hardcoded_privileged_caller'));
});

// WHY: a jump target pushed as PUSH32 must not hide the code behind it.
test('PUSH32-dispatched body is still reachable', () => {
  const pre = '7f' + (35).toString(16).padStart(64, '0') + '56' + '00'; // PUSH32 35 JUMP STOP, JUMPDEST at 35
  assert.ok(tags('0x' + pre + '5b73' + ADDR + '331400').includes('hardcoded_privileged_caller'));
});

// WHY: a security scanner must fail closed -- unresolved control flow and equivalent encodings must not hide a backdoor.
const guardOf = (a) => '73' + a + '331450' + '00';
test('computed jump target does not hide a backdoor', () => {
  // PUSH1 4 PUSH1 4 ADD JUMP STOP STOP JUMPDEST <guard>: target 8 is computed, not pushed
  assert.ok(tags('0x6004600401' + '56' + '0000' + '5b' + guardOf(ADDR).slice(0)).includes('hardcoded_privileged_caller'));
});
test('equivalent caller checks: wide immutable-style push, SUB/XOR + ISZERO', () => {
  assert.ok(tags('0x74' + '00' + ADDR + '331450' + '00').includes('hardcoded_privileged_caller')); // PUSH21 0x00..addr
  assert.ok(tags('0x7f' + '00'.repeat(12) + ADDR + '331450' + '00').includes('hardcoded_privileged_caller')); // PUSH32
  assert.ok(tags('0x73' + ADDR + '33' + '03' + '15' + '00').includes('hardcoded_privileged_caller')); // CALLER SUB ISZERO
  assert.ok(tags('0x73' + ADDR + '33' + '18' + '15' + '00').includes('hardcoded_privileged_caller')); // CALLER XOR ISZERO
  assert.ok(!tags('0x7f' + '00'.repeat(31) + '01' + '331450' + '00').includes('hardcoded_privileged_caller')); // small number, not an address
});
test('fabricated metadata tail does not hide executable code', () => {
  const body = '600556' + 'a1' + '00' + '5b' + guardOf(ADDR); // PUSH1 5 JUMP, 0xa1 (fake CBOR map), STOP, JUMPDEST, guard
  const n = body.length / 2 + 2 - 5; // trailing length chosen so the stripped region is only the first 3 bytes
  const hex = '0x' + body + n.toString(16).padStart(4, '0');
  assert.equal(scanBytecode(hex).strippedSize, 3);
  assert.ok(tags(hex).includes('hardcoded_privileged_caller'));
});
// WHY: unlockCallback is exempt only as the SOLE reacher; a shared fallback path keeps the flag.
test('PoolManager guard shared with the fallback is still flagged', () => {
  const hex = '0x' + '6391dd7346' + '14' + '610025' + '57' + '5b73' + POOL_MANAGER + '33145000' + '5b' + '61000a' + '56';
  const f = find(hex, 'hardcoded_privileged_caller');
  assert.deepEqual(f.functions.map(x => x.selector), ['0x91dd7346', null]);
});
// WHY: transfer locks in ordinary slots (0, 1, 64) must be seen; only the owner slot itself is not a "switch".
test('owner_switch: any constant slot, but not the owner slot itself', () => {
  const setter = (guard, w) => ['11223344', '33' + '60' + guard + '54' + '14' + '6001' + '60' + w + '55' + '00'];
  for (const w of ['00', '01', '40']) {
    const f = find(contract([OWNER, ['a9059cbb', readsSlot(w)], setter('09', w)]), 'owner_switch');
    assert.ok(f, 'slot 0x' + w);
    assert.match(f.detail, new RegExp('slot ' + parseInt(w, 16) + ' '));
  }
  assert.ok(!tags(contract([OWNER, ['a9059cbb', readsSlot('09')], setter('09', '09')])).includes('owner_switch')); // transferOwnership-like
});
test('hidden_admin: guard in the fallback', () => {
  // dispatcher for transfer only; fallthrough: JUMPDEST CALLER == SLOAD(9) ; SSTORE slot 3
  const hex = '0x' + '63a9059cbb' + '14' + '61001b' + '57' + '5b' + '33' + '600954' + '14' + '6001' + '6003' + '55' + '00' + '5b00';
  const f = find(hex, 'hidden_admin');
  assert.deepEqual(f.functions, [{ selector: null, name: 'fallback/unknown' }]);
});

// WHY: a junk proxy slot (nonzero, pointing at an empty account) must not lose the token's own high-severity result.
test('--follow-proxy is best-effort: junk implementation slot keeps the main result', async () => {
  const { createServer } = await import('node:http');
  const { execFile } = await import('node:child_process');
  let junk = true;
  const token = '0x' + 'd2'.repeat(20);
  const code = contract([['23b872dd', '73' + 'd2'.repeat(20) + '331450' + '00']]);
  const srv = createServer((req, res) => {
    let b = ''; req.on('data', d => b += d); req.on('end', () => {
      const j = JSON.parse(b); let result = '0x';
      if (j.method === 'eth_getCode') result = j.params[0] === token ? code : '0x';
      if (j.method === 'eth_getStorageAt') result = junk ? '0x' + '00'.repeat(12) + 'ab'.repeat(20) : '0x' + '00'.repeat(32);
      res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ jsonrpc: '2.0', id: j.id, result }));
    });
  });
  await new Promise(r => srv.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${srv.address().port}`;
  const run = (extra) => new Promise(r => execFile('node', ['dist/cli.js', token, '--rpc', url, '--follow-proxy', '--json', '--no-listing', ...extra], (e, out, err) => r({ code: e ? e.code : 0, out, err })));
  try {
    const a = await run([]);
    assert.equal(a.code, 0);
    assert.match(a.err, /implementation unavailable/);
    const j = JSON.parse(a.out);
    assert.ok(j.flags.some(f => f.tag === 'hardcoded_privileged_caller'));
    assert.ok(j.incomplete.some(m => /implementation unavailable/.test(m))); // hans fails closed on this field
    junk = false;
    assert.equal(JSON.parse((await run([])).out).incomplete, undefined); // clean run: field absent
    assert.equal((await run(['--fail-on', 'high'])).code, 1);
  } finally { srv.close(); }
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
