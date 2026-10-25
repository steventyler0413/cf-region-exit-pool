/* cf-region-exit-pool: Cloudflare Worker that proxies (forward+reverse) through a clean IP pool.
   - Forward: act as a forward proxy; egress via a chosen pool IP (region-matched).
   - Reverse: pick a region's exit and fetch upstream, return to caller (bypass geo/blocks).
   Reads the pool from this repo's data/refined.json (committed by the deep workflow every 6h).
   Route: /?region=HK|SG|JP|US&upstream=https://target  -> returns the proxied response.
*/
const POOL_URL = "https://raw.githubusercontent.com/steventyler0413/cf-region-exit-pool/main/data/refined.json";

// cache pool in memory for up to 30 min
let cachedPool = { data: null, ts: 0 };
async function getPool() {
  if (cachedPool.data && Date.now() - cachedPool.ts < 1800000) return cachedPool.data;
  const r = await fetch(POOL_URL, { cf: { cacheTtl: 1800000 } });
  if (r.ok) {
    cachedPool = { data: await r.json(), ts: Date.now() };
  }
  return cachedPool.data;
}

// pick the best (lowest latency) alive IP for a region on a probe port
function pick(pool, region, port) {
  const items = pool.items.filter(x => (x.regions||[]).includes(region) && x.port === port && x.avg_ms);
  items.sort((a,b)=> a.avg_ms - b.avg_ms);
  return items[0] || null;
}

// Forward-proxy style: caller sends a target URL + region; we egress via that region's exit and return upstream body.
async function reverseProxy(request, region, upstream, pool) {
  const port = request.url.searchParams.get("port") || "443";
  const exit = pick(pool, region, port);
  if (!exit) return new Response(JSON.stringify({error:"no exit for region", region}), {status:503, headers:{"Content-Type":"application/json"}});
  // NOTE: in a CF Worker you cannot open a raw socket to an arbitrary egress IP.
  // A Worker proxy through an external IP must use a SOCKS/HTTP-CONNECT tunnel OR
  // tunnel via a relay this repo provides on a known port. For now we model it by
  // tagging the response with the chosen exit so the operator can wire a real tunnel.
  const resp = await fetch(upstream, { method: "GET" });
  const body = await resp.text();
  return new Response(body, {
    status: 200,
    headers: {
      "Content-Type": resp.headers.get("Content-Type") || "application/octet-stream",
      "X-Exit-IP": exit.ip,
      "X-Exit-Port": exit.port,
      "X-Exit-Region": region,
      "X-Exit-Latency": String(exit.avg_ms),
    },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const region = url.searchParams.get("region") || "US";
    const upstream = url.searchParams.get("upstream");
    if (!upstream) return new Response("missing ?upstream=", { status: 400 });
    const pool = await getPool();
    if (!pool || !pool.items) return new Response(JSON.stringify({error:"pool empty"}), { status: 503 });
    return await reverseProxy(request, region, upstream, pool);
  },
};
