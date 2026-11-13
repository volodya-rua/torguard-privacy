const ROTATOR_API = 'http://127.0.0.1:8222';
const $ = (id) => document.getElementById(id);

const LEVEL_TEXT = {
  off: 'Tor is off for this site, so it sees your real IP.',
  low: 'Tor and leak protection only. Fewest blocks and broken pages.',
  medium: 'Also blends in: UTC clock, en-US, common hardware and GPU.',
  high: 'Also adds noise to canvas, WebGL and audio fingerprints. Most private.',
};
// firewall / bot protection block pages (cloudflare, akamai, imperva, perimeterx...)
const BLOCK_SIGNS = /sorry, you have been blocked|attention required! \| cloudflare|error 10(06|07|08|12|20)\b|access denied[\s\S]{0,200}(cloudflare|reference #)|you don't have permission to access|incapsula incident id|access to this page has been denied|blocked by network security/i;

const statePanel = $('state');
const statusText = $('statusText');
const statusDetail = $('statusDetail');
const stateError = $('stateError');
const fixBtn = $('fixBtn');
const toggleBtn = $('toggleBtn');
const blockedBox = $('blocked');
const blockedBody = $('blockedBody');
const blockedRotate = $('blockedRotate');
const blockedDirect = $('blockedDirect');
const ipBox = $('ipBox');
const ipLabel = $('ipLabel');
const ipValue = $('ipValue');
const ipMeta = $('ipMeta');
const ipHint = $('ipHint');
const reloadBtn = $('reloadBtn');
const retryBtn = $('retryBtn');
const rotateBtn = $('rotateBtn');
const pingBox = $('ping');
const pingMs = $('pingMs');
const pingLabel = $('pingLabel');
const spark = $('spark');
const siteRow = $('siteRow');
const siteName = $('siteName');
const siteHint = $('siteHint');
const siteReloadBtn = $('siteReloadBtn');
const useDefaultBtn = $('useDefaultBtn');
const incognitoBox = $('incognitoOnly');
const scopeHint = $('scopeHint');
const forgetBtn = $('forgetBtn');
const forceHttpsBox = $('forceHttps');
const exitSelect = $('exitCountry');
const exitHint = $('exitHint');
const autoSelect = $('autoRotate');
const autoHint = $('autoHint');
const rotateAllBtn = $('rotateAllBtn');

const S = {
  enabled: false, incognitoOnly: true, allowed: false, levels: {}, defaultLevel: 'high', ports: [], lastError: null,
  forceHttps: true, autoRotate: 0, exitCountry: 'any', autoRotateResult: null,
};
let tor = { geoip: null, exitCountry: null }; // what the rotator last said about tor itself
let tab = null;
let host = ''; // full hostname of the tab, like www.example.com
let site = ''; // its site key, like example.com (per site levels get saved under this)
let slot = 0;
let pageLevel = null; // the level the open page was loaded with
let usingTor = false; // is this tab actually going through tor right now
let ip = { state: 'loading' };
let note = null; // rotate result that stays until u do something else
let busy = false;
let blocked = false;
let pings = []; // last 20 pings in ms (null = no reply)
let pingError = null;
let localError = '';

const siteLevel = () => S.levels[site] ?? S.defaultLevel;

class RotatorError extends Error {
  constructor(code, message, detail) {
    super(message);
    this.code = code;
    this.detail = detail;
  }
}

async function getJSON(path, timeout) {
  const res = await fetch(`${ROTATOR_API}${path}`, { signal: AbortSignal.timeout(timeout) });
  let data;
  try {
    data = await res.json();
  } catch {
    throw new RotatorError('bad_json', 'The rotator sent something unexpected.');
  }
  if (!res.ok || data.status === 'error') throw new RotatorError(data.code || `http_${res.status}`, data.message || `HTTP ${res.status}`, data.detail);
  return data;
}

// every error becomes: a short title, what to do, and whether to retry by itself
function describe(e) {
  if (e instanceof TypeError) return { offline: true, title: 'Rotator offline', message: 'Start it with start_privacy.bat.' };
  if (e?.name === 'TimeoutError' || e?.code === 'timeout') return { title: 'Slow to answer', message: 'Tor is taking a while. Retrying…', auto: true };
  switch (e?.code) {
    case 'tor_starting': return { title: 'Tor is starting', message: `${e.message} Retrying…`, auto: true };
    case 'tor_control_unreachable':
    case 'tor_unreachable': return { title: 'Tor not reachable', message: e.message };
    case 'tor_auth_failed': return { title: 'Tor refused the rotator', message: 'Restart start_privacy.bat.' };
    case 'not_found':
    case 'http_404':
    case 'bad_request': return { title: 'Old rotator', message: 'Restart start_privacy.bat to load the new rotator.' };
    case 'no_geoip': return { title: 'No country data', message: 'Your Tor has no GeoIP file, so it can\'t choose exits by country.' };
    case 'exit_failed': return { title: 'Country unavailable', message: e.message };
    default: return { title: 'Unavailable', message: e?.message || 'Something went wrong.' };
  }
}

const ago = (t) => {
  const min = Math.round((Date.now() - t) / 60000);
  return min < 1 ? 'just now' : min < 60 ? `${min} min ago` : `${Math.round(min / 60)} h ago`;
};

async function load() {
  const session = await chrome.storage.session.get(['enabled', 'ports', 'lastError', 'autoRotateResult']);
  const local = await chrome.storage.local.get(['incognitoOnly', 'levels', 'defaultLevel', 'forceHttps', 'autoRotate', 'exitCountry']);
  S.enabled = session.enabled === true;
  S.ports = Array.isArray(session.ports) ? session.ports : [];
  S.lastError = session.lastError || null;
  S.autoRotateResult = session.autoRotateResult || null;
  S.incognitoOnly = local.incognitoOnly !== false;
  S.levels = local.levels && typeof local.levels === 'object' ? local.levels : {};
  S.defaultLevel = ['low', 'medium', 'high'].includes(local.defaultLevel) ? local.defaultLevel : 'high';
  S.forceHttps = local.forceHttps !== false;
  S.autoRotate = [0, 10, 30, 60].includes(local.autoRotate) ? local.autoRotate : 0;
  S.exitCountry = typeof local.exitCountry === 'string' ? local.exitCountry : 'any';
  S.allowed = await chrome.extension.isAllowedIncognitoAccess();
}

function paintSettings() {
  forceHttpsBox.checked = S.forceHttps;
  autoSelect.value = String(S.autoRotate);
  const r = S.autoRotateResult;
  autoHint.textContent = !S.autoRotate ? 'You may get logged out of sites.'
    : !r ? 'First change in a few minutes.'
    : r.ok ? `Last change ${ago(r.at)}.` : `Last try failed (${ago(r.at)}): ${r.message}`;
  autoHint.className = `hint${S.autoRotate && r && !r.ok ? ' err' : ''}`;
  if (document.activeElement !== exitSelect) exitSelect.value = S.exitCountry;
  if (tor.geoip === false) {
    exitHint.textContent = 'Your Tor is missing its country data (GeoIP file).';
    exitHint.className = 'hint warn';
  } else if (!exitHint.dataset.message) {
    exitHint.textContent = 'Fewer exits make you easier to single out.';
    exitHint.className = 'hint';
  }
  for (const option of exitSelect.options) option.disabled = tor.geoip === false && option.value !== 'any';
}

async function render() {
  try {
    await load();
  } catch (e) {
    stateError.textContent = `Couldn't read your settings: ${e.message}`;
    stateError.hidden = false;
    return;
  }

  let state = 'off';
  let title = 'Off';
  let detail = 'Browsing uses your normal connection.';
  let fix = false;
  if (S.enabled) {
    state = 'on';
    title = 'Protected';
    detail = `${S.incognitoOnly ? 'Incognito windows go' : 'All windows go'} through Tor, with a separate IP for each site.`;
    if (!S.allowed && S.incognitoOnly) {
      [state, title, fix] = ['warn', 'Not active', true];
      detail = '“Allow in Incognito” is off for this extension, so nothing goes through Tor.';
    } else if (!S.allowed) {
      fix = true;
      detail = 'Normal windows go through Tor. Incognito windows aren\'t covered until you allow it.';
    } else {
      try {
        const { levelOfControl } = await chrome.proxy.settings.get({ incognito: S.incognitoOnly });
        if (levelOfControl === 'controlled_by_other_extensions' || levelOfControl === 'not_controllable') {
          [state, title, fix] = ['warn', 'Not active', true];
          detail = 'Another extension or a policy controls the proxy, so Tor isn\'t being used.';
        }
      } catch {}
    }
  } else if (!S.allowed && S.incognitoOnly) {
    fix = true;
    detail = 'Turn on “Allow in Incognito” for this extension first, or nothing will go through Tor.';
  }
  // whether stuff goes through tor depends on the settings above, not on some error message
  usingTor = state === 'on' && (!S.incognitoOnly || !tab || tab.incognito) && !(site && siteLevel() === 'off');
  const error = localError || (S.enabled && S.lastError ? `Couldn't apply protection: ${S.lastError}` : '');
  if (error) state = 'warn';

  statePanel.dataset.state = state;
  statusText.textContent = error && title === 'Protected' ? 'Problem' : title;
  statusDetail.textContent = detail;
  stateError.textContent = error;
  stateError.hidden = !error;
  fixBtn.hidden = !fix;
  toggleBtn.textContent = S.enabled ? 'Turn off protection' : 'Turn on protection';
  toggleBtn.className = S.enabled ? 'btn btn-secondary' : 'btn btn-primary';

  siteRow.hidden = !site;
  if (site) {
    const level = siteLevel();
    const custom = site in S.levels;
    siteName.textContent = site;
    siteName.title = site;
    for (const r of document.querySelectorAll('input[name="siteLevel"]')) r.checked = r.value === level;
    siteHint.textContent = `${custom ? '' : 'Using the default. '}${LEVEL_TEXT[level]}`;
    siteHint.className = `hint${level === 'off' ? ' warn' : ''}`;
    useDefaultBtn.hidden = !custom;
    useDefaultBtn.textContent = `Use default (${S.defaultLevel[0].toUpperCase()}${S.defaultLevel.slice(1)})`;
    siteReloadBtn.hidden = !(S.enabled && tab?.id && pageLevel !== null && level !== pageLevel);
  }
  for (const r of document.querySelectorAll('input[name="defaultLevel"]')) r.checked = r.value === S.defaultLevel;
  incognitoBox.checked = S.incognitoOnly;
  scopeHint.textContent = S.incognitoOnly ? 'Normal windows keep your usual connection.' : 'Every window goes through Tor.';
  paintSettings();

  paintIP();
  paintPing();
  paintBlocked();
}

function paintIP() {
  ipLabel.textContent = site ? `IP seen by ${site}` : 'Tor exit IP';
  let view = ip.state === 'error' ? (ip.offline ? 'offline' : 'down') : ip.state;
  let value = '';
  let meta = '';
  let hint = '';
  let tone = '';
  let retry = false;

  if (!S.enabled) [view, value, hint] = ['idle', 'Not using Tor', 'Turn on protection to browse through Tor.'];
  else if (site && siteLevel() === 'off') [view, value, hint] = ['idle', 'Not using Tor', 'Tor is off for this site.'];
  else if (!usingTor && S.incognitoOnly && S.allowed && tab && !tab.incognito) {
    [view, value, hint] = ['idle', 'Not using Tor', 'This is a normal window. Open an incognito window to use Tor.'];
  } else if (!usingTor) [view, value] = ['idle', 'Not using Tor'];
  else if (ip.state === 'ok') [value, meta] = [ip.value, ip.location && ip.location !== '??' ? ip.location : ''];
  else if (ip.state === 'error') [value, hint, tone, retry] = [ip.title, ip.message, ip.offline ? '' : 'err', !ip.auto];
  if (note) [hint, tone] = [note.text, note.tone || ''];

  ipBox.dataset.state = view;
  ipValue.textContent = value;
  ipMeta.textContent = meta;
  ipHint.textContent = hint;
  ipHint.className = `hint ${tone}`;
  ipHint.hidden = !hint;
  ipHint.title = note?.detail || ip.detail || '';
  reloadBtn.hidden = !note?.reload;
  retryBtn.hidden = !retry || Boolean(note);
  rotateBtn.disabled = !S.enabled || busy || Boolean(ip.offline);
}

function paintPing() {
  pingBox.hidden = !usingTor || ip.offline;
  if (pingBox.hidden) return;
  const last = pings.at(-1);
  let quality = '';
  if (!pings.length) {
    pingMs.textContent = '…';
    pingLabel.textContent = 'Measuring';
  } else if (last == null) {
    const d = describe(pingError);
    pingMs.textContent = '—';
    pingLabel.textContent = d.title === 'Unavailable' ? 'No reply' : d.title;
    pingBox.title = d.message;
    quality = 'slow';
  } else {
    quality = last < 700 ? 'good' : last < 1500 ? 'ok' : 'slow'; // tor goes through 3 relays so ~300-700 ms is normal
    pingMs.textContent = `${last} ms`;
    pingLabel.textContent = { good: 'Good', ok: 'OK', slow: 'Slow' }[quality];
    pingBox.title = 'Round trip through this site\'s Tor circuit, measured every 2 seconds';
  }
  pingBox.dataset.quality = quality;
  const ok = pings.map((v, i) => [i, v]).filter(([, v]) => v != null);
  const max = Math.max(400, ...ok.map(([, v]) => v));
  const offset = 20 - pings.length;
  spark.setAttribute('points', ok.map(([i, v]) => `${((offset + i) * 72) / 19},${17 - (v / max) * 16}`).join(' '));
}

function paintBlocked() {
  blockedBox.hidden = !blocked;
  if (!blocked) return;
  const viaTor = usingTor;
  blockedBody.textContent = viaTor
    ? 'Many sites block all Tor IPs. A new IP or a lower level below can help. Off always works, but shows your real IP.'
    : 'This site isn\'t going through Tor right now, so this block isn\'t about Tor. Try reloading the page.';
  blockedRotate.hidden = !viaTor;
  blockedDirect.hidden = !viaTor;
}

// the rotator owns the per site tor ports, hand them to the background when they change
async function usePorts(ports) {
  if (!Array.isArray(ports)) return; // old rotator that doesnt give ports
  if (JSON.stringify(S.ports) !== JSON.stringify(ports)) await chrome.storage.session.set({ ports });
}

// wait till chrome's proxy script has `needle`. reloading before that still uses the old settings
// (the old ports are already closed so it falls back to the shared one = wrong ip, wtf moment)
async function proxyHas(needle) {
  for (let i = 0; i < 40; i++) {
    try {
      const { value } = await chrome.proxy.settings.get({ incognito: S.incognitoOnly });
      if (value.pacScript?.data?.includes(needle)) return;
    } catch {
      return; // no incognito access, nothing to wait for
    }
    await new Promise((r) => setTimeout(r, 150));
  }
}

let statusTries = 0;
async function refreshIP(quiet = false) {
  if (!quiet) {
    ip = { state: 'loading' };
    paintIP();
  }
  try {
    const data = await getJSON(`/status?slot=${slot}`, 45000); // first call also builds every site's circuit so it can take a bit
    ip = { state: 'ok', value: data.current_ip, location: data.location };
    tor = { geoip: data.geoip ?? null, exitCountry: data.exit_country ?? null };
    await usePorts(data.ports);
    // tor forgets the exit country when it restarts, put it back
    if (S.exitCountry !== 'any' && tor.geoip && tor.exitCountry !== S.exitCountry) setExit(S.exitCountry);
  } catch (e) {
    ip = { state: 'error', ...describe(e), detail: e.detail || e.message };
    if (ip.auto && ++statusTries < 10) setTimeout(() => refreshIP(true), 3000);
  }
  paintIP();
  paintPing();
  paintSettings();
}

async function setExit(country) {
  exitSelect.disabled = true;
  exitHint.dataset.message = '1';
  exitHint.textContent = country === 'any' ? 'Going back to any country…' : 'Switching exits…';
  exitHint.className = 'hint';
  try {
    const data = await getJSON(`/exit?country=${country}&slot=${slot}`, 90000);
    await usePorts(data.ports);
    await save('local', { exitCountry: country });
    ip = { state: 'ok', value: data.new_ip, location: data.location };
    tor.exitCountry = country;
    exitHint.textContent = country === 'any' ? 'Tor picks exits anywhere again.' : `Exits now in ${exitSelect.selectedOptions[0].text}. Reload pages to use them.`;
    exitHint.className = 'hint ok';
  } catch (e) {
    const d = describe(e);
    exitHint.textContent = d.message;
    exitHint.className = 'hint err';
    exitHint.title = e.detail || '';
    exitSelect.value = S.exitCountry; // nothing changed
  } finally {
    exitSelect.disabled = false;
    paintIP();
    paintSettings();
  }
}

// cookies (even the login ones scripts cant see) for the whole site + this page's storage.
// two clicks cuz it logs u out
let forgetArmed = false;
async function forgetSite() {
  if (!forgetArmed) {
    forgetArmed = true;
    forgetBtn.textContent = 'Click again to forget';
    setTimeout(() => { forgetArmed = false; forgetBtn.textContent = 'Forget this site'; }, 4000);
    return;
  }
  try {
    const store = (await chrome.cookies.getAllCookieStores()).find((s) => s.tabIds.includes(tab.id));
    const cookies = await chrome.cookies.getAll({ domain: site, ...(store && { storeId: store.id }) });
    await Promise.all(cookies.map((c) => chrome.cookies.remove({ url: `https://${c.domain.replace(/^\./, '')}${c.path}`, name: c.name, storeId: c.storeId })));
    await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: async () => {
        try { localStorage.clear(); sessionStorage.clear(); } catch {}
        try { for (const db of await indexedDB.databases()) indexedDB.deleteDatabase(db.name); } catch {}
        try { for (const key of await caches.keys()) await caches.delete(key); } catch {}
        try { for (const reg of await navigator.serviceWorker.getRegistrations()) await reg.unregister(); } catch {}
      },
    });
    await reloadTab();
  } catch (e) {
    localError = `Couldn't forget this site: ${e.message}`;
    render();
  }
}

let pinging = false;
async function pingOnce() {
  if (pinging || !usingTor || ip.offline) return;
  pinging = true;
  try {
    const port = S.ports.length ? S.ports[slot] : 9050;
    const target = host.includes('.') ? host : 'www.cloudflare.com';
    pings.push((await getJSON(`/ping?port=${port}&host=${encodeURIComponent(target)}`, 15000)).ms);
    pingError = null;
  } catch (e) {
    pings.push(null);
    pingError = e;
  } finally {
    pings = pings.slice(-20);
    pinging = false;
    paintPing();
  }
}

async function checkBlocked() {
  if (!tab?.id || !site) return;
  try {
    const [{ result }] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: (pattern) => new RegExp(pattern, 'i').test(`${document.title}\n${(document.body?.innerText || '').slice(0, 3000)}`),
      args: [BLOCK_SIGNS.source],
    });
    blocked = result === true;
  } catch {
    blocked = false; // chrome's own error pages cant be inspected
  }
  paintBlocked();
}

// scope 'site': only this site gets a new ip (others stay logged in). 'all': every site does
async function rotate({ reloadAfter = false, scope = site ? 'site' : 'all' } = {}) {
  if (busy) return;
  busy = true;
  rotateBtn.classList.add('busy');
  blockedRotate.disabled = true;
  rotateAllBtn.disabled = true;
  note = { text: scope === 'site' ? `Getting a new Tor circuit for ${site}…` : 'Getting new Tor circuits for every site…' };
  paintIP();
  try {
    const data = await getJSON(`/rotate?slot=${slot}&scope=${scope}`, 90000);
    ip = { state: 'ok', value: data.new_ip, location: data.location };
    await usePorts(data.ports);
    if (Array.isArray(data.ports)) await proxyHas(String(data.ports[slot]));
    pings = [];
    if (!data.changed) {
      note = { text: 'Tor picked the same exit 3 times in a row. Try again.', tone: 'err' };
    } else if (reloadAfter && tab?.id) {
      await chrome.tabs.reload(tab.id);
      window.close();
      return;
    } else {
      const who = data.scope === 'site' ? `${site} has a new IP` : 'Every site has a new IP';
      note = { text: `${who} (was ${data.old_ip}). Reload to use it.`, tone: 'ok', reload: Boolean(tab?.id) };
    }
  } catch (e) {
    const d = describe(e);
    if (d.offline) {
      ip = { state: 'error', ...d };
      note = null;
    } else {
      note = { text: `Couldn't get new circuits. ${d.message}`, tone: 'err', detail: e.detail || e.message };
    }
  } finally {
    busy = false;
    rotateBtn.classList.remove('busy');
    blockedRotate.disabled = false;
    rotateAllBtn.disabled = false;
    paintIP();
  }
}

async function save(area, values) {
  try {
    await chrome.storage[area].set(values);
    localError = '';
  } catch (e) {
    localError = `Couldn't save that change: ${e.message}`;
    render();
  }
}

async function reloadTab() {
  try {
    await chrome.tabs.reload(tab.id);
    window.close();
  } catch (e) {
    localError = `Couldn't reload the page: ${e.message}`;
    render();
  }
}

// the background applies every change when storage changes
toggleBtn.addEventListener('click', () => { note = null; save('session', { enabled: !S.enabled }); });
incognitoBox.addEventListener('change', () => save('local', { incognitoOnly: incognitoBox.checked }));
fixBtn.addEventListener('click', () => chrome.tabs.create({ url: `chrome://extensions/?id=${chrome.runtime.id}` }));
for (const r of document.querySelectorAll('input[name="siteLevel"]')) {
  r.addEventListener('change', () => { pings = []; save('local', { levels: { ...S.levels, [site]: r.value } }); });
}
for (const r of document.querySelectorAll('input[name="defaultLevel"]')) {
  r.addEventListener('change', () => save('local', { defaultLevel: r.value }));
}
useDefaultBtn.addEventListener('click', () => {
  const { [site]: _, ...rest } = S.levels;
  save('local', { levels: rest });
});
siteReloadBtn.addEventListener('click', reloadTab);
reloadBtn.addEventListener('click', reloadTab);
retryBtn.addEventListener('click', () => { statusTries = 0; refreshIP(); });
rotateBtn.addEventListener('click', () => rotate());
blockedRotate.addEventListener('click', () => rotate({ reloadAfter: true }));
blockedDirect.addEventListener('click', async () => {
  await save('local', { levels: { ...S.levels, [site]: 'off' } });
  await proxyHas(`"${site}":1`);
  reloadTab();
});
rotateAllBtn.addEventListener('click', () => rotate({ scope: 'all' }));
forgetBtn.addEventListener('click', forgetSite);
forceHttpsBox.addEventListener('change', () => save('local', { forceHttps: forceHttpsBox.checked }));
autoSelect.addEventListener('change', () => save('local', { autoRotate: Number(autoSelect.value) }));
exitSelect.addEventListener('change', () => setExit(exitSelect.value));

(async () => {
  try {
    [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const url = new URL(tab?.url || 'about:blank');
    if ((url.protocol === 'http:' || url.protocol === 'https:') && !url.hostname.startsWith('[')) {
      host = url.hostname;
      site = siteKey(host);
    }
  } catch {}
  slot = site ? siteSlot(site, TOR_SLOTS) : 0;
  const rotateLabel = site ? `New IP for ${site}` : 'New IPs for every site';
  rotateBtn.title = rotateLabel;
  rotateBtn.setAttribute('aria-label', rotateLabel);
  chrome.storage.onChanged.addListener(() => render());
  chrome.proxy.settings.onChange.addListener(() => render());
  await render();
  pageLevel = site ? siteLevel() : null;
  refreshIP();
  checkBlocked();
  pingOnce();
  setInterval(pingOnce, 2000);
})();
