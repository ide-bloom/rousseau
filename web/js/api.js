// API client. The per-launch token arrives in the URL fragment (never sent
// to the server or in Referer headers); it is kept in sessionStorage and
// removed from the address bar.

const KEY = "rousseau.token";

function readToken() {
  // `#token=<hex>` or `#token=<hex>&/view/...` (deep link to a view).
  const m = /token=([0-9a-f]+)(?:&(\/.*))?/.exec(location.hash);
  if (m) {
    try { sessionStorage.setItem(KEY, m[1]); } catch { /* storage disabled */ }
    history.replaceState(null, "", location.pathname + location.search + "#" + (m[2] || "/timeline"));
    return m[1];
  }
  try { return sessionStorage.getItem(KEY) || ""; } catch { return ""; }
}

export const token = readToken();

async function call(method, path, body) {
  const res = await fetch(`/api${path}`, {
    method,
    headers: { "x-rousseau-token": token, ...(body ? { "content-type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
    cache: "no-store",
  });
  if (res.status === 401) throw new Error("Not authorized: reopen the dashboard with the link printed by `rousseau ui`.");
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

export const get = (path) => call("GET", path);
export const post = (path, body) => call("POST", path, body || {});
export const put = (path, body) => call("PUT", path, body);

export function query(params) {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== "") q.set(k, v);
  const s = q.toString();
  return s ? `?${s}` : "";
}

/** Opens the live WebSocket; reconnects with backoff. Calls onMessage(obj) and onState(bool). */
export function live(onMessage, onState) {
  let delay = 1000;
  const connect = () => {
    // Browsers cannot set headers on WebSocket: the token rides in the subprotocol.
    const ws = new WebSocket(`ws://${location.host}/ws`, [`rousseau.${token}`]);
    ws.onopen = () => { delay = 1000; onState(true); };
    ws.onmessage = (ev) => { try { onMessage(JSON.parse(ev.data)); } catch { /* ignore */ } };
    ws.onclose = () => { onState(false); setTimeout(connect, delay); delay = Math.min(delay * 2, 15000); };
  };
  connect();
}
