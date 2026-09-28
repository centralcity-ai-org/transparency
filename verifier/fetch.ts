// Reads the public log from a Central City origin. Only public, unauthenticated GET requests.
import type { Checkpoint } from './count-log.js';
import type { Jwk, Leaf, PublicLog } from './verify.js';

const PAGE = 10_000;
const MAX_BYTES = 64 * 1024 * 1024;

export class NotPublished extends Error {}

async function getJson<T>(url: URL, fetchImpl: typeof fetch): Promise<T> {
  const response = await fetchImpl(url, { redirect: 'error', headers: { accept: 'application/json' } });
  if (response.status === 404) throw new NotPublished(`${url.pathname}: not published (404)`);
  if (!response.ok) throw new Error(`${url.pathname}: HTTP ${response.status}`);
  const length = Number(response.headers.get('content-length') ?? 0);
  if (length > MAX_BYTES) throw new Error(`${url.pathname}: response too large`);
  return (await response.json()) as T;
}

export function checkOrigin(origin: string): URL {
  const url = new URL(origin);
  const loopback = ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback))
    throw new Error('Use an https origin (plain http only on loopback).');
  return new URL(url.origin);
}

export async function fetchCheckpoints(origin: string, fetchImpl: typeof fetch = fetch): Promise<Checkpoint[]> {
  const base = checkOrigin(origin);
  const body = await getJson<{ checkpoints: Checkpoint[] }>(
    new URL('/api/public/count-log/checkpoints', base),
    fetchImpl,
  );
  return body.checkpoints;
}

export async function fetchLog(origin: string, fetchImpl: typeof fetch = fetch): Promise<PublicLog> {
  const base = checkOrigin(origin);
  const checkpoints = await fetchCheckpoints(origin, fetchImpl);
  const jwks = await getJson<{ keys: Jwk[] }>(new URL('/.well-known/jwks.json', base), fetchImpl);
  const size = Math.max(0, ...checkpoints.map((cp) => cp.tree_size));
  const leaves: Leaf[] = [];
  for (let from = 0; from < size; from += PAGE) {
    const url = new URL('/api/public/count-log/leaves', base);
    url.searchParams.set('from', String(from));
    url.searchParams.set('to', String(Math.min(size, from + PAGE)));
    const page = await getJson<{ leaves: Leaf[] }>(url, fetchImpl);
    if (!page.leaves.length) break;
    leaves.push(...page.leaves);
  }
  const { withdrawn } = await getJson<{ withdrawn: PublicLog['withdrawn'] }>(
    new URL('/api/public/count-log/withdrawn', base),
    fetchImpl,
  );
  return { checkpoints, keys: jwks.keys, leaves, withdrawn };
}
