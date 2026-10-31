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
bytecode 0xTOKEN --chain base               # fetch code via eth_getCode and scan it
bytecode 0xTOKEN --rpc https://my.node/rpc  # your own endpoint
bytecode 0xPROXY --follow-proxy             # also scan the implementation
bytecode 0xTOKEN --json --no-listing        # machine-readable, no per-function listings
bytecode 0xTOKEN --fail-on high || echo "high-severity flag"   # for scripts/CI
bytecode --hex 0x6080...                    # offline
bytecode --file code.hex
```

| Option | Meaning |
| --- | --- |
| `--chain <name>` | `ethereum` (default), `base`, `arbitrum`, `optimism`, `bsc`, `polygon`, `avalanche`, `robinhood`. These are public endpoints and may rate-limit; use `--rpc` for your own. |
| `--rpc <url>` | JSON-RPC endpoint. Default override: env `BYTECODE_RPC`. |
| `--follow-proxy` | Detect an EIP-1167 minimal proxy (embedded address) or an EIP-1967 implementation/beacon slot or the legacy OpenZeppelin (zos) slot (`eth_getStorageAt`) and scan the implementation as well. |
| `--json` | JSON output (an array when a proxy implementation is also scanned). |
| `--no-listing` | Skip annotated function listings. |
| `--signatures <file>` | Load a JSON file `{"codeHashes": {"0x<keccak of stripped code>": "label"}, "addresses": {"0x<addr>": "label"}}` merged over the shipped (empty) tables. Default: env `BYTECODE_SIGNATURES`. Invalid file: exit 2. |
| `--fail-on high` | Exit 1 if any high-severity flag is present. |

Exit codes: `0` analysed, `1` `--fail-on` tripped, `2` usage or fetch error.

## Red flags

| Tag | Severity | Meaning |
| --- | --- | --- |
| `hardcoded_privileged_caller` | high | A fixed address constant is compared with `msg.sender`/`tx.origin`: a compile-time privileged role that `owner()`-style checks cannot see. |
| `selfdestruct` | high | Contains `SELFDESTRUCT`. |
| `delegatecall` | high | Contains `DELEGATECALL` (foreign code in this contract's storage). |
| `callcode` | high | Contains deprecated `CALLCODE`. |
| `known_scam_codehash` | high | Metadata-stripped code hash matches an entry in the loaded signatures file. |
| `known_scam_address` | high | A `PUSH20` constant matches an entry in the loaded signatures file. |
| `minimal_proxy` | info | EIP-1167 clone; logic lives at the embedded address. |
| `eip1967_proxy` | info | Code references the EIP-1967 implementation/beacon slot. |
| `no_owner_getter` | info | No `owner()` selector. |

`delegatecall` and `selfdestruct` are legitimate in many contracts (proxies, factories); treat flags as leads, not verdicts.

## Tests

```sh
npm test    # builds, then runs node:test over synthetic bytecode; no network
```

## Limits

- EVM only. Not zkSync Era / EraVM, and not non-EVM chains.
- Static analysis cannot see storage-based backdoors (roles set at runtime with no getter).
- This is disassembly with a bounded block walk, not decompilation; listings are hints and can be incomplete.
- Metadata stripping targets the solc CBOR tail. Vyper contracts may use a different tail; stripping is best-effort there.
- Built-in public RPCs rate-limit. Behaviour that lives outside the contract's own bytecode is invisible to bytecode analysis.

## License

MIT
