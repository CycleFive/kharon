// REQ-DEP-005 VM test, broker side: through the WireGuard tunnel, open
// a CDP session on the provisioned agent host's Chromium and read
// chrome://prefs-internals. The password manager and address autofill
// must be off *by managed policy*, not just off.
//
// Usage: node cdp-policy-check.mjs ws://10.66.0.2:9222/devtools/browser/<id>
// Needs Node 22+ (global WebSocket).

const url = process.argv[2];
if (!url) {
  console.error("usage: cdp-policy-check.mjs <browser websocket url>");
  process.exit(2);
}

const ws = new WebSocket(url);
let nextId = 1;
const pending = new Map();
ws.onmessage = (ev) => {
  const msg = JSON.parse(ev.data);
  if (msg.id && pending.has(msg.id)) {
    const { resolve, reject } = pending.get(msg.id);
    pending.delete(msg.id);
    msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result);
  }
};
const opened = new Promise((resolve, reject) => {
  ws.onopen = resolve;
  ws.onerror = () => reject(new Error(`cannot connect to ${url}`));
});
function send(method, params = {}, sessionId) {
  const id = nextId++;
  ws.send(JSON.stringify({ id, method, params, sessionId }));
  return new Promise((resolve, reject) => pending.set(id, { resolve, reject }));
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function prefAt(prefs, path) {
  let node = prefs;
  for (const part of path.split(".")) {
    if (node === undefined || node === null) return undefined;
    node = node[part];
  }
  return node;
}

const timer = setTimeout(() => {
  console.error("FAIL: timed out");
  process.exit(1);
}, 60_000);

await opened;
const version = await send("Browser.getVersion");
console.log(`connected: ${version.product}`);
// The default context: chrome://prefs-internals shows the profile's
// own prefs, which an off-the-record context does not have.
const { targetId } = await send("Target.createTarget", { url: "chrome://prefs-internals" });
const { sessionId } = await send("Target.attachToTarget", { targetId, flatten: true });

let prefs;
for (let i = 0; i < 50 && !prefs; i++) {
  const r = await send(
    "Runtime.evaluate",
    { expression: "document.body ? document.body.innerText : ''", returnByValue: true },
    sessionId,
  );
  try {
    prefs = JSON.parse(r.result.value);
  } catch {
    await sleep(200);
  }
}
if (!prefs) {
  const r = await send(
    "Runtime.evaluate",
    { expression: "location.href + ' ' + (document.body ? document.body.innerText.slice(0, 300) : '')", returnByValue: true },
    sessionId,
  );
  console.error(`FAIL: chrome://prefs-internals did not load: ${r.result.value}`);
  process.exit(1);
}

let failed = false;
for (const path of ["credentials_enable_service", "autofill.profile_enabled"]) {
  const pref = prefAt(prefs, path);
  const ok =
    pref && pref.value === false && Array.isArray(pref.metadata) && pref.metadata.includes("managed");
  console.log(`${ok ? "ok" : "FAIL"}: ${path} = ${JSON.stringify(pref)}`);
  failed ||= !ok;
}
await send("Target.closeTarget", { targetId });
clearTimeout(timer);
ws.close();
process.exit(failed ? 1 : 0);
