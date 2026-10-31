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
