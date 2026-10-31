# bytecode-scan

A small command-line tool for static triage of EVM contract bytecode. Give it an address (or raw hex) and it prints the function selectors it can find, an annotated listing of each function, and plain-English red flags. It flags patterns such as a hardcoded privileged caller, which `owner()`-style probes cannot see.

## Install

Requires Node >= 18.

```sh
git clone <this-repo-url> bytecode-scan && cd bytecode-scan
npm install -g .        # or: npm link
bytecode --help
```

The `prepare` script builds `dist/` during install. `npx` works too: `npx github:<owner>/bytecode-scan --help`.

## Usage

```sh
bytecode 0xTOKEN                            # auto: find the chain(s) holding code, scan each
bytecode 0xTOKEN --chain base               # one chain only
bytecode 0xTOKEN --rpc https://my.node/rpc  # your own endpoint
bytecode 0xPROXY --follow-proxy             # also scan the implementation
bytecode 0xTOKEN --json --no-listing        # machine-readable, no per-function listings
bytecode 0xTOKEN --fail-on high || echo "high-severity flag"   # for scripts/CI
bytecode --hex 0x6080...                    # offline
bytecode --file code.hex
```

| Option | Meaning |
| --- | --- |
| `--chain <name>` | `auto` (default; also used when no `--chain`/`--rpc`/`BYTECODE_RPC` is given): queries every built-in chain concurrently (8 s timeout each) and scans each chain that has code, reporting `chain` per result (JSON array when several). Failed chains are noted on stderr and in JSON `rpcErrors` (these describe other chains and do not mark a result incomplete); exit 2 if no chain has code or all errored. Or `ethereum`, `base`, `arbitrum`, `optimism`, `bsc`, `polygon`, `avalanche`, `robinhood`. These are public endpoints and may rate-limit; use `--rpc` for your own. |
| `--rpc <url>` | JSON-RPC endpoint. Default override: env `BYTECODE_RPC`. |
| `--follow-proxy` | Detect an EIP-1167 minimal proxy (embedded address) or an EIP-1967 implementation/beacon slot or the legacy OpenZeppelin (zos) slot (`eth_getStorageAt`) and scan the implementation as well. |
| `--json` | JSON output (a result carries `incomplete: [string]` only when coverage of that same contract failed: `--follow-proxy` could not read a proxy slot, call the beacon or fetch the implementation; consumers should not treat such a result as clean) (an array when a proxy implementation or several chains are scanned). Each result has `chain`; each flag has `functions: [{selector, name}]` listing the dispatcher functions whose bounded walk reaches the flagged instruction (`{selector: null, name: "fallback/unknown"}` for the dispatcher fallthrough, empty for info flags). Text output prints `in: <function>` under each flag. |
| `--no-listing` | Skip annotated function listings. |
| `--signatures <file>` | Load a JSON file `{"codeHashes": {"0x<keccak of stripped code>": "label"}, "addresses": {"0x<addr>": "label"}}` merged over the shipped (empty) tables. Default: env `BYTECODE_SIGNATURES`. Invalid file: exit 2. |
| `--fail-on high` | Exit 1 if any high-severity flag is present. |

Exit codes: `0` analysed, `1` `--fail-on` tripped, `2` usage or fetch error.

## Red flags

| Tag | Severity | Meaning |
| --- | --- | --- |
| `hardcoded_privileged_caller` | high | A fixed address constant (in reachable code) is compared with `msg.sender`/`tx.origin`: a compile-time privileged role that `owner()`-style checks cannot see. Not raised when the only function reaching it is Uniswap v4 `unlockCallback(bytes)` and the constant is an official Uniswap v4 PoolManager address. |
| `selfdestruct` | high | Contains `SELFDESTRUCT`. |
| `delegatecall` | high | Contains `DELEGATECALL` (foreign code in this contract's storage). |
| `callcode` | high | Contains deprecated `CALLCODE`. |
| `known_scam_codehash` | high | Metadata-stripped code hash matches an entry in the loaded signatures file. |
| `known_scam_address` | high | A `PUSH20` constant matches an entry in the loaded signatures file. |
| `owner_switch` | medium | Has `owner()`, and a function (other than the core ERC20 entry points) guarded by a `CALLER` check against a stored value writes a constant storage slot, other than the guard's own owner slot, that `transfer`/`transferFrom` read: the owner can flip a setting transfers depend on (sell lock, trading switch, limits, blacklist toggle). `functions` lists the setters; `detail` names the slot. |
| `hidden_admin` | medium | No `owner()`, yet a function (or the dispatcher fallback) is guarded by `CALLER` == a stored constant-slot value and writes balances, allowances, supply or a slot that `transfer`/`transferFrom` read. |
| `admin_role` | info | Same guard with no `owner()`, but the write reaches none of those (for example a metadata-only role). |
| `privileged_balance_move` | high | A non-ERC20-standard function guarded by `CALLER` == a stored value debits a balance-mapping entry for an account taken from calldata without touching the allowance mapping: the guarded role can move or burn any holder's balance. Detail adds `(survives renounceOwnership)` when `renounceOwnership()` does not clear the guarding slot. |
| `self_liquidity` | medium | The token exposes `removeLiquidity`-style or Uniswap v4 `unlockCallback` selectors: it can manage or remove its own pool liquidity. |
| `minimal_proxy` | info | EIP-1167 clone; logic lives at the embedded address. |
| `eip1967_proxy` | info | Code references the EIP-1967 implementation/beacon slot. |
| `no_owner_getter` | info | No `owner()` selector. |

Severities are `high`, `medium` and `info`; `medium` flags are heuristics (leads to review). `--fail-on high` ignores them.

`delegatecall` and `selfdestruct` are legitimate in many contracts (proxies, factories); treat flags as leads, not verdicts.

## Tests

```sh
npm test    # builds, then runs node:test over synthetic bytecode; no network
```

## Limits

- HIGH flags (`hardcoded_privileged_caller`, `selfdestruct`, `delegatecall`, `callcode`, known-scam matches) use a whole-code floor: every op of the code region (before the metadata tail) is considered whether or not reachability analysis reaches it. Hits not proven reachable keep their severity and are attributed to `unreachable/unknown` (or noted in `detail`), so data tails can add false positives. Reachability only attributes functions and gates the PoolManager exemption.
- Pattern matching, not dataflow: a privileged address assembled at run time (loaded from code or memory, built with shifts/OR, or `CALLER` stashed in memory and compared far from the constant) is not recognised, and `owner_switch`/`hidden_admin`/`privileged_balance_move` follow storage slots and mappings only within a basic block, so switch logic split across blocks or helper functions can be missed. Unresolvable jump targets are handled conservatively (all JUMPDESTs count as reachable), which can add false positives.
- Known-hash matching is exact: appending or changing any byte defeats `known_scam_codehash`.
- EVM only. Not zkSync Era / EraVM, and not non-EVM chains.
- Static analysis cannot see storage-based backdoors (roles set at runtime with no getter).
- This is disassembly with a bounded block walk, not decompilation; listings are hints and can be incomplete.
- Metadata stripping targets the solc CBOR tail. Vyper contracts may use a different tail; stripping is best-effort there.
- Built-in public RPCs rate-limit. Behaviour that lives outside the contract's own bytecode is invisible to bytecode analysis.

## License

MIT
