const ROTATOR_API = 'http://127.0.0.1:8222';
const $ = (id) => document.getElementById(id);

const LEVEL_TEXT = {
  off: 'Tor is off for this site, so it sees your real IP.',
  low: 'Tor and leak protection only. Fewest blocks and broken pages.',
  medium: 'Also blends in: UTC clock, en-US, common hardware and GPU.',
  high: 'Also adds noise to canvas, WebGL and audio fingerprints. Most private.',
};
// firewall / bot protection block pages (cloudflare, akamai, imperva, perimeterx...)
const BLOCK_SIGNS = /sorry, you have been blocked|attention required! \| cloudflare|error 10(06|07|08|12|20)\b|access denied[\s\S]{0,200}(cloudflare|reference #)|you don't have permission to access[\s\S]{0,400}reference #|incapsula incident id|access to this page has been denied|blocked by network security/i;

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
const fastestBtn = $('fastestBtn');
const trackerHint = $('trackerHint');
const blockTrackersBox = $('blockTrackers');
const bridgesSelect = $('bridges');
const bridgesHint = $('bridgesHint');
const leakBtn = $('leakBtn');
const leakResults = $('leakResults');

const S = {
  enabled: false, incognitoOnly: true, allowed: false, levels: {}, defaultLevel: 'high', ports: [], lastError: null,
  forceHttps: true, autoRotate: 0, exitCountry: 'any', autoRotateResult: null, blockTrackers: true, hostStatus: null,
};
let tor = { geoip: null, exitCountry: null, bridges: null }; // what the rotator last said about tor itself
let tab = null;
let host = ''; // full hostname of the tab, like www.example.com
let site = ''; // its site key, like example.com (per site levels get saved under this)
let slot = 0;
let pageLevel = null; // the level the open page was loaded with
let usingTor = false; // does this tab go through tor with the settings as they are now
let pageRec = null; // what the open page was really loaded with (background records it per tab)
let pageTor = false; // did the open page really load through tor (and still does)
let stalePage = false; // page loaded with different settings than now, needs a reload
let ip = { state: 'loading' };
let note = null; // rotate result that stays until u do something else
// one port changing thing at a time (new ip, fastest, exit country, bridges). otherwise they
// overwrite each others ports, or "put the saved country back" runs in the middle of ur switch
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
  if (e instanceof TypeError) {
    // rotator not answering: is the native host starting it right now, did that fail, or is there no host?
    const h = S.hostStatus;
    if (S.enabled && h?.available && h.ok && h.cmd === 'start' && Date.now() - h.at < 120000) {
      return { title: 'Starting Tor…', message: 'Give it a few seconds.', auto: true };
    }
    if (h?.available && h.ok === false && h.cmd === 'start') return { offline: true, title: 'Couldn\'t start Tor', message: h.message };
    return { offline: true, title: 'Rotator offline',
      message: h?.available ? 'Turn protection off and on again to start it.' : 'Start it with start_privacy.bat, or run install_host.bat once so this button starts Tor for you.' };
  }
  // auto = worth retrying by itself. only refreshIP actually retries, it adds the "Retrying…"
  if (e?.name === 'TimeoutError' || e?.code === 'timeout') return { title: 'Slow to answer', message: 'Tor is taking a while.', auto: true };
  switch (e?.code) {
    case 'tor_starting': return { title: 'Tor is starting', message: e.message, auto: true };
    case 'tor_control_unreachable':
    case 'tor_unreachable': return { title: 'Tor not reachable', message: e.message };
    case 'tor_auth_failed': return { title: 'Tor refused the rotator', message: 'Restart start_privacy.bat.' };
    case 'not_found':
    case 'http_404':
    case 'bad_request': return { title: 'Old rotator', message: 'Restart start_privacy.bat to load the new rotator.' };
    case 'no_geoip': return { title: 'No country data', message: 'Your Tor has no GeoIP file, so it can\'t choose exits by country.' };
    case 'exit_failed': return { title: 'Country unavailable', message: e.message };
    case 'no_bridges':
    case 'bridges_failed': return { title: 'Bridges unavailable', message: e.message };
    case 'ping_failed': return { title: 'No reply', message: e.message };
    default: return { title: 'Unavailable', message: e?.message || 'Something went wrong.' };
  }
}

const ago = (t) => {
  const min = Math.round((Date.now() - t) / 60000);
  return min < 1 ? 'just now' : min < 60 ? `${min} min ago` : `${Math.round(min / 60)} h ago`;
};

async function load() {
  const session = await chrome.storage.session.get(['enabled', 'ports', 'lastError', 'autoRotateResult', 'hostStatus']);
  const local = await chrome.storage.local.get(['incognitoOnly', 'levels', 'defaultLevel', 'forceHttps', 'autoRotate', 'exitCountry', 'blockTrackers']);
  S.hostStatus = session.hostStatus || null;
  S.blockTrackers = local.blockTrackers !== false;
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
  const key = `page${tab?.id}`;
  const rec = tab?.id ? (await chrome.storage.session.get(key))[key] : null;
  pageRec = rec && rec.host === host ? rec : null; // other host = it navigated, record is old
}

function paintSettings() {
  forceHttpsBox.checked = S.forceHttps;
  blockTrackersBox.checked = S.blockTrackers;
  if (tor.bridges && document.activeElement !== bridgesSelect && !bridgesSelect.disabled) bridgesSelect.value = tor.bridges;
  autoSelect.value = String(S.autoRotate);
  const r = S.autoRotateResult;
  autoHint.textContent = !S.autoRotate ? 'You may get logged out of sites.'
    : !r ? 'First change in a few minutes.'
    : r.ok ? `Last change ${ago(r.at)}.` : `Last try failed (${ago(r.at)}): ${r.message}`;
  autoHint.className = `hint${S.autoRotate && r && !r.ok ? ' err' : ''}`;
  // while a switch runs the saved country is still the old one, dont snap the dropdown back to it
  // shows what tor actually uses (if a re-apply failed that can differ from the saved one)
  if (document.activeElement !== exitSelect && !busy) exitSelect.value = tor.exitCountry && tor.exitCountry !== 'custom' ? tor.exitCountry : S.exitCountry;
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
  let proxyOurs = false; // chrome is really using our proxy settings right now
  if (S.enabled) {
    state = 'on';
    title = 'Protected';
    detail = `${S.incognitoOnly ? 'Incognito windows go' : 'All windows go'} through Tor, with a separate IP for each site.`;
    if (!S.allowed && S.incognitoOnly) {
      [state, title, fix] = ['warn', 'Not active', true];
      detail = '“Allow in Incognito” is off for this extension, so nothing goes through Tor.';
    } else {
      if (!S.allowed) {
        fix = true;
        detail = 'Normal windows go through Tor. Incognito windows aren\'t covered until you allow it.';
      }
      try {
        const { levelOfControl } = await chrome.proxy.settings.get({ incognito: S.incognitoOnly });
        proxyOurs = levelOfControl === 'controlled_by_this_extension';
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
  usingTor = state === 'on' && proxyOurs && (!S.incognitoOnly || !tab || tab.incognito) && !(site && siteLevel() === 'off')
    && !(host && isLocal(host)); // the proxy script sends ur own network direct
  // no record (page was open before the extension started) = trust the settings
  pageTor = usingTor && (!pageRec || pageRec.tor);
  stalePage = Boolean(pageRec) && (pageRec.tor !== usingTor || (usingTor && pageRec.level !== siteLevel()));
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
    siteReloadBtn.hidden = !(tab?.id && (pageRec ? stalePage : S.enabled && pageLevel !== null && level !== pageLevel));
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
  if (usingTor && pageRec && !pageRec.tor) [hint, tone] = ['This page loaded without Tor. Reload it to use Tor.', 'err'];
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
  rotateBtn.disabled = !S.enabled || busy || Boolean(ip.offline) || Boolean(site && !usingTor); // a new ip does nothing for an Off site
  fastestBtn.disabled = !usingTor || busy || ip.state !== 'ok';
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
  const viaTor = pageTor; // about how the page (and its block) loaded
  blockedBody.textContent = viaTor
    ? 'Many sites block all Tor IPs. A new IP or a lower level below can help. Off always works, but shows your real IP.'
    : 'This site isn\'t going through Tor right now, so this block isn\'t about Tor. Try reloading the page.';
  blockedRotate.hidden = !viaTor;
  blockedDirect.hidden = !viaTor;
}

// the rotator owns the per site tor ports, hand them to the background when they change
async function usePorts(ports) {
  if (!Array.isArray(ports)) return; // rotator didnt send ports, nothing to hand over
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
    tor = { geoip: data.geoip ?? null, exitCountry: data.exit_country ?? null, bridges: data.bridges ?? null };
    await usePorts(data.ports);
    // tor forgets the exit country when it restarts (or a switch got cut off), make it match the setting
    // ('custom' = ExitNodes set in ur own torrc, leave that alone)
    if (tor.geoip && tor.exitCountry && tor.exitCountry !== 'custom' && tor.exitCountry !== S.exitCountry) setExit(S.exitCountry);
  } catch (e) {
    ip = { state: 'error', ...describe(e), detail: e.detail || e.message };
    if (ip.auto && ++statusTries < 40) {
      ip.message += ' Retrying…';
      setTimeout(() => refreshIP(true), 3000); // tor can take a minute (longer with bridges)
    } else {
      ip.auto = false; // gave up, show the try again button
    }
  }
  paintIP();
  paintPing();
  paintSettings();
}

// the controls the port changing stuff uses, all locked while one runs
const opControls = () => [exitSelect, bridgesSelect, blockedRotate, rotateAllBtn];
function startOp() {
  if (busy) return false;
  busy = true;
  for (const el of opControls()) el.disabled = true;
  paintIP();
  return true;
}
function endOp() {
  busy = false;
  for (const el of opControls()) el.disabled = false;
  paintIP();
  // worked or not, tor might have new ports now (a failed switch can still swap them), grab them
  getJSON('/ports', 10000).then((d) => usePorts(d.ports)).catch(() => {});
}

async function setExit(country) {
  if (!startOp()) return;
  const before = S.exitCountry;
  exitSelect.value = country;
  exitHint.dataset.message = '1';
  exitHint.textContent = country === 'any' ? 'Going back to any country…' : 'Switching exits…';
  exitHint.className = 'hint';
  try {
    // saved first: if the popup closes before tor answers, tor + the setting still end up the same
    await save('local', { exitCountry: country });
    S.exitCountry = country;
    const data = await getJSON(`/exit?country=${country}&slot=${slot}`, 90000);
    await usePorts(data.ports);
    pings = [];
    ip = { state: 'ok', value: data.new_ip, location: data.location };
    tor.exitCountry = country;
    const name = [...exitSelect.options].find((o) => o.value === country)?.text || country.toUpperCase();
    exitHint.textContent = country === 'any' ? 'Tor picks exits anywhere again.' : `Exits now in ${name}. Reload pages to use them.`;
    exitHint.className = 'hint ok';
  } catch (e) {
    const d = describe(e);
    exitHint.textContent = d.message;
    exitHint.className = 'hint err';
    exitHint.title = e.detail || '';
    if (country !== before) { // tor kept the old setting, so does the dropdown
      await save('local', { exitCountry: before });
      S.exitCountry = before;
    }
  } finally {
    endOp();
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
  if (pinging || busy || !usingTor || ip.offline) return; // mid switch the port is about to close
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
      // real block pages come back as 403 / 429 / 503. a normal page that just mentions "access denied"
      // or "you have been blocked" (articles, help pages, forums) loads fine, so those dont count
      func: (pattern) => {
        const status = performance.getEntriesByType('navigation')[0]?.responseStatus || 0;
        const text = (document.body?.innerText || '').slice(0, 3000);
        const errorPage = status ? status >= 400 : text.length < 2000; // no status = guess, block pages are tiny
        return errorPage && new RegExp(pattern, 'i').test(`${document.title}\n${text}`);
      },
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
  if (!startOp()) return;
  rotateBtn.classList.add('busy');
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
      note = { text: `${who}${data.old_ip ? ` (was ${data.old_ip})` : ''}. Reload to use it.`, tone: 'ok', reload: Boolean(tab?.id) };
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
    rotateBtn.classList.remove('busy');
    endOp();
  }
}

// try a few circuits for this site and keep the quickest (rotator does the measuring)
async function findFastest() {
  if (!startOp()) return;
  fastestBtn.classList.add('busy');
  note = { text: `Trying 4 circuits for ${site || 'this page'}…` };
  paintIP();
  try {
    const target = host.includes('.') ? host : 'www.cloudflare.com';
    const data = await getJSON(`/fastest?slot=${slot}&host=${encodeURIComponent(target)}`, 90000);
    ip = { state: 'ok', value: data.new_ip, location: data.location };
    await usePorts(data.ports);
    if (Array.isArray(data.ports)) await proxyHas(String(data.ports[slot]));
    pings = [];
    note = data.changed
      ? { text: `Switched to the fastest of ${data.tried.length} circuits (${data.tried.join(', ')} ms). Reload to use it.`, tone: 'ok', reload: Boolean(tab?.id) }
      : { text: `Already on the fastest circuit (${data.ms} ms).`, tone: 'ok' };
  } catch (e) {
    note = { text: `Couldn't test circuits. ${describe(e).message}`, tone: 'err', detail: e.detail || e.message };
  } finally {
    fastestBtn.classList.remove('busy');
    endOp();
  }
}

async function setBridges(mode) {
  if (!startOp()) return;
  bridgesHint.className = 'hint';
  bridgesHint.textContent = mode === 'off' ? 'Switching back to normal Tor relays…' : `Connecting through ${bridgesSelect.selectedOptions[0].text} bridges. This can take a minute…`;
  try {
    const data = await getJSON(`/bridges?mode=${mode}&slot=${slot}`, 150000);
    await usePorts(data.ports);
    pings = [];
    ip = { state: 'ok', value: data.new_ip, location: data.location };
    tor.bridges = mode;
    bridgesHint.textContent = mode === 'off' ? 'Back to normal Tor relays.' : 'On. Fully hidden from the next Tor start; old connections fade out in a few minutes.';
    bridgesHint.className = 'hint ok';
  } catch (e) {
    bridgesHint.textContent = describe(e).message;
    bridgesHint.className = 'hint err';
    bridgesHint.title = e.detail || '';
    bridgesSelect.value = tor.bridges || 'off';
  } finally {
    endOp();
  }
}

// how many trackers the block rules caught on this tab since it loaded
async function countTrackers() {
  trackerHint.hidden = true;
  if (!tab?.id || !S.blockTrackers || !pageTor) return 0;
  try {
    const { rulesMatchedInfo } = await chrome.declarativeNetRequest.getMatchedRules({ tabId: tab.id });
    const n = rulesMatchedInfo.filter((m) => m.rule.ruleId === 4 || m.rule.ruleId >= 10).length;
    trackerHint.textContent = n ? `${n} tracker${n === 1 ? '' : 's'} blocked on this page` : 'No trackers found on this page';
    trackerHint.hidden = false;
    return n;
  } catch {
    return null; // chrome limits how often this can be asked
  }
}

// runs inside the page (main world) so it sees exactly what the page's own scripts see
async function pageProbe() {
  const out = { tz: Intl.DateTimeFormat().resolvedOptions().timeZone, langs: navigator.languages.join(','), cores: navigator.hardwareConcurrency, rtcLeaks: [] };
  try {
    const gl = document.createElement('canvas').getContext('webgl');
    const dbg = gl.getExtension('WEBGL_debug_renderer_info');
    out.gpu = dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : '';
  } catch {}
  const c = document.createElement('canvas');
  c.width = 80;
  c.height = 20;
  const x = c.getContext('2d');
  x.fillStyle = '#f60'; x.fillRect(0, 0, 80, 20); x.fillStyle = '#069'; x.font = '14px Arial'; x.fillText('leak test', 2, 15);
  out.canvas = c.toDataURL();
  try {
    const pc = new RTCPeerConnection({ iceServers: [] });
    pc.createDataChannel('t');
    pc.onicecandidate = (e) => {
      const addr = e.candidate?.candidate.split(' ')[4];
      if (addr && !addr.endsWith('.local')) out.rtcLeaks.push(addr);
    };
    await pc.setLocalDescription(await pc.createOffer());
    await new Promise((r) => setTimeout(r, 1500));
    pc.close();
  } catch {
    out.rtcBlocked = true;
  }
  return out;
}

async function runLeakTest() {
  leakBtn.disabled = true;
  leakBtn.textContent = 'Testing…';
  const rows = [];
  const add = (state, label, detail) => rows.push({ state, label, detail });
  const level = pageRec?.level ?? (site ? siteLevel() : S.defaultLevel);

  add(pageTor && ip.state === 'ok' ? 'pass' : 'fail', 'Traffic goes through Tor',
    pageTor ? (ip.state === 'ok' ? `${site || 'This page'} sees ${ip.value}, not your IP` : 'Tor isn\'t answering')
      : usingTor ? 'This page loaded without Tor. Reload it, then test again' : 'This page uses your real connection');

  let proxied = false;
  let prediction = null;
  try {
    const { value, levelOfControl } = await chrome.proxy.settings.get({ incognito: S.incognitoOnly });
    proxied = levelOfControl === 'controlled_by_this_extension' && ['pac_script', 'fixed_servers'].includes(value.mode);
    prediction = (await chrome.privacy.network.networkPredictionEnabled.get({ incognito: S.incognitoOnly })).value;
  } catch {}
  // the proxy being on somewhere doesnt mean THIS page uses it (Off site, normal window in incognito only mode)
  if (!pageTor) add('fail', 'DNS goes through Tor', 'Names are looked up by your normal DNS, so your ISP sees which sites you visit');
  else add(proxied && prediction === false ? 'pass' : 'fail', 'DNS goes through Tor',
    !proxied ? 'The Tor proxy isn\'t active'
      : prediction === false ? 'Names are looked up by the Tor exit, nothing is prefetched outside Tor'
      : 'Chrome may look up names ahead of time outside Tor (preloading is on)');

  let page = null;
  try {
    [{ result: page }] = await chrome.scripting.executeScript({ target: { tabId: tab.id }, world: 'MAIN', func: pageProbe });
  } catch {}
  if (!page) {
    add('na', 'WebRTC and fingerprint', 'Can\'t test on this kind of page');
  } else {
    if (!pageTor) add('na', 'WebRTC', 'Doesn\'t matter here, the site already sees your real IP');
    else add(page.rtcLeaks.length ? 'fail' : 'pass', 'WebRTC can\'t leak your IP',
      page.rtcLeaks.length ? `Exposed: ${page.rtcLeaks.join(', ')}` : page.rtcBlocked ? 'WebRTC isn\'t available here' : 'No direct connections offered');
    if (level === 'low' || level === 'off') {
      add('na', 'Fingerprint', `Left alone on ${level === 'low' ? 'Low' : 'Off'}, on purpose`);
    } else {
      const real = await pageProbe(); // the popup isn't protected, so this is your real fingerprint
      const fakes = [];
      if (page.tz === 'UTC') fakes.push(`clock UTC (real ${real.tz})`);
      if (page.langs === 'en-US,en') fakes.push('language en-US');
      if (page.cores === 4) fakes.push(`4 cores (real ${real.cores})`);
      if (page.gpu && page.gpu !== real.gpu) fakes.push('common GPU');
      add(fakes.length >= 3 ? 'pass' : 'fail', 'Fingerprint blends in', fakes.length ? fakes.join(', ') : 'Nothing is being changed');
      if (level === 'high') {
        add(page.canvas !== real.canvas ? 'pass' : 'fail', 'Canvas fingerprint randomized',
          page.canvas !== real.canvas ? 'Changes on every page load' : 'Same as your real one');
      }
    }
  }

  const proto = tab?.url ? new URL(tab.url).protocol : '';
  if (proto === 'https:') add('pass', 'Page is encrypted (HTTPS)', pageTor ? 'Tor exit relays can\'t read or change it' : 'Your wifi and ISP can\'t read or change it, but they see the site name');
  else if (proto === 'http:' && host.endsWith('.onion')) add('pass', 'Page is encrypted (onion)', 'Tor encrypts .onion sites end to end');
  else if (proto === 'http:') {
    add('fail', 'Page is not encrypted', !S.forceHttps ? 'Turn on Force HTTPS'
      : isLocal(host) ? 'Pages on your own network are left alone'
      : pageTor ? 'This site has no HTTPS version' : 'Force HTTPS only works on pages that go through Tor');
  }
  else add('na', 'HTTPS', 'Not a website');

  const trackers = await countTrackers();
  if (!S.blockTrackers) add('na', 'Trackers', 'Tracker blocking is off');
  else if (!pageTor) add('fail', 'Trackers blocked', level === 'off' ? 'Nothing is blocked on Off sites, on purpose' : 'Only blocked on pages that go through Tor');
  else if (trackers === null) add('na', 'Trackers', 'Couldn\'t count right now');
  else add('pass', 'Trackers blocked', trackers ? `${trackers} blocked on this page` : 'None found on this page');

  leakResults.replaceChildren(...rows.map(({ state, label, detail }) => {
    const li = document.createElement('li');
    li.className = state;
    const mark = document.createElement('span');
    mark.className = 'mark';
    mark.textContent = { pass: '✓', fail: '✗', na: '–' }[state];
    const text = document.createElement('span');
    const b = document.createElement('b');
    b.textContent = label;
    const small = document.createElement('small');
    small.textContent = detail;
    text.append(b, small);
    li.append(mark, text);
    return li;
  }));
  leakResults.hidden = false;
  leakBtn.disabled = false;
  leakBtn.textContent = 'Run leak test again';
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
fastestBtn.addEventListener('click', findFastest);
blockTrackersBox.addEventListener('change', () => save('local', { blockTrackers: blockTrackersBox.checked }));
bridgesSelect.addEventListener('change', () => setBridges(bridgesSelect.value));
leakBtn.addEventListener('click', runLeakTest);
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
  chrome.storage.onChanged.addListener(async (changes) => {
    await render();
    // just turned on, or the native host just started tor: go look for the rotator again
    if (changes.enabled?.newValue || (changes.hostStatus?.newValue?.cmd === 'start' && changes.hostStatus.newValue.ok)) {
      statusTries = 0;
      refreshIP(true);
    }
  });
  chrome.proxy.settings.onChange.addListener(() => render());
  await render();
  pageLevel = site ? siteLevel() : null;
  refreshIP();
  checkBlocked();
  countTrackers();
  pingOnce();
  setInterval(pingOnce, 2000);
})();
