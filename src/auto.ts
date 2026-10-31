/** Multi-chain code lookup. The fetch function is injected so tests need no network. */
export type GetCode = (url: string, address: string) => Promise<string>;
export interface ChainCode { chain: string; code: string }
export interface AutoResult { found: ChainCode[]; rpcErrors: Record<string, string> }

const hasCode = (c: string): boolean => /^(0x)?([0-9a-fA-F]{2})+$/.test(c);

/** Query eth_getCode on every chain concurrently. Throws when no chain has code (or every chain errored). */
export async function autoDetect(address: string, chains: Record<string, string>, getCode: GetCode, timeoutMs = 8000): Promise<AutoResult> {
  const found: ChainCode[] = []; const rpcErrors: Record<string, string> = {};
  await Promise.all(Object.entries(chains).map(async ([chain, url]) => {
    let timer: NodeJS.Timeout | undefined;
    try {
      const code = await Promise.race([
        getCode(url, address),
        new Promise<never>((_, rej) => { timer = setTimeout(() => rej(new Error(`timeout after ${timeoutMs} ms`)), timeoutMs); }),
      ]);
      if (hasCode(code)) found.push({ chain, code });
    } catch (e) { rpcErrors[chain] = (e as Error).message; }
    finally { clearTimeout(timer); }
  }));
  const order = Object.keys(chains);
  found.sort((a, b) => order.indexOf(a.chain) - order.indexOf(b.chain));
  if (!found.length) {
    if (Object.keys(rpcErrors).length === order.length) throw new Error(`all chains failed: ${Object.entries(rpcErrors).map(([c, m]) => `${c}: ${m}`).join('; ')}`);
    throw new Error('no contract code on any known chain' + (Object.keys(rpcErrors).length ? ` (rpc errors on: ${Object.keys(rpcErrors).join(', ')})` : ''));
  }
  return { found, rpcErrors };
}
