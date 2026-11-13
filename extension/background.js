// torguard background worker
// on/off + the rotator ports are in storage.session so it always starts OFF when chrome starts
// or when u re-enable the extension (it used to just turn itself on, annoying af)
// settings in storage.local:
//   incognitoOnly  - only touch incognito windows
//   defaultLevel   - low / medium / high for sites u havent set
//   levels         - { 'example.com': 'off' | 'low' | 'medium' | 'high' } per site
//   forceHttps     - http -> https (tor exits can read + mess with plain http)
//   autoRotate     - minutes between auto new ips (0 = off)
//   exitCountry    - the popup sends this to the rotator ('any' or a country code)
// low = tor + leak stuff. medium = also fake clock/lang/hardware. high = also canvas/webgl/audio
// noise + workers. off = that site goes direct, no tor
importScripts('site.js', 'trackers.js');

const ROTATOR_API = 'http://127.0.0.1:8222';
const LEVELS = ['off', 'low', 'medium', 'high'];
const AUTO_ROTATE_MINUTES = [0, 10, 30, 60];
const TOR_FALLBACK = { mode: 'fixed_servers', rules: { singleProxy: { scheme: 'socks5', host: '127.0.0.1', port: 9050 } } };
const PRIVATE_IP = '(10|127|192\\.168|172\\.(1[6-9]|2[0-9]|3[01]))\\.'; // local network ip ranges

// with the rotator ports every site gets its own tor circuit. 9050 is the fallback if a port
// died (like tor restarted). only Off sites + ur own network go DIRECT so if tor dies nothing leaks
function proxyConfig(ports, directSites) {
  if (!ports.length && !directSites.length) return TOR_FALLBACK;
  const tor = ports.length
    ? `'SOCKS5 127.0.0.1:' + PORTS[siteSlot(host, PORTS.length)] + '; SOCKS5 127.0.0.1:9050'`
    : `'SOCKS5 127.0.0.1:9050'`;
  const data = `${siteKey}\n${siteSlot}\nvar PORTS = ${JSON.stringify(ports)};
var DIRECT = ${JSON.stringify(Object.fromEntries(directSites.map((s) => [s, 1])))};
function FindProxyForURL(url, host) {
  if (host === 'localhost' || host === '::1' || host === '[::1]' || /^${PRIVATE_IP}/.test(host)) return 'DIRECT';
  if (DIRECT[siteKey(host)]) return 'DIRECT';
  return ${tor};
}`;
  return { mode: 'pac_script', pacScript: { data, mandatory: true } };
}

// [chrome setting, value when protected]. these are browser wide, chrome has no per site version.
// some only exist for the normal profile, incognito has those off anyway
const PRIVACY = [
  [chrome.privacy.network.webRTCIPHandlingPolicy, 'disable_non_proxied_udp'], // webrtc cant leak ur ip
  [chrome.privacy.network.networkPredictionEnabled, false], // no dns prefetch outside tor
  [chrome.privacy.websites.thirdPartyCookiesAllowed, false],
  [chrome.privacy.websites.hyperlinkAuditingEnabled, false], // <a ping> click tracking crap
  [chrome.privacy.websites.topicsEnabled, false],
  [chrome.privacy.websites.fledgeEnabled, false],
  [chrome.privacy.websites.adMeasurementEnabled, false],
  [chrome.privacy.websites.relatedWebsiteSetsEnabled, false],
].filter(([setting]) => setting);

const SCRIPT = { matches: ['<all_urls>'], runAt: 'document_start', allFrames: true, matchOriginAsFallback: true, persistAcrossSessions: false };

const ALL_TYPES = ['main_frame', 'sub_frame', 'stylesheet', 'script', 'image', 'font', 'object', 'xmlhttprequest',
  'ping', 'csp_report', 'media', 'websocket', 'webtransport', 'webbundle', 'other'];
const RULE = { HEADERS: 1, HTTPS: 2, LOCAL_HTTP: 3, TRACKERS: 4 };
const TRACKER_URL_RULES = TRACKER_URLS.map((urlFilter, i) => ({ id: 10 + i, urlFilter })); // ids 10+
// medium + high: everyone says en-US and no detailed device/os/version hints
const HEADER_ACTION = {
  type: 'modifyHeaders',
  requestHeaders: [
    { header: 'accept-language', operation: 'set', value: 'en-US,en;q=0.9' },
    ...['arch', 'bitness', 'full-version', 'full-version-list', 'model', 'platform-version', 'wow64', 'form-factors']
      .map((hint) => ({ header: `sec-ch-ua-${hint}`, operation: 'remove' })),
  ],
};

async function readState() {
  const { enabled = false, ports = [], lastError = null } = await chrome.storage.session.get(['enabled', 'ports', 'lastError']);
  const local = await chrome.storage.local.get(['incognitoOnly', 'defaultLevel', 'levels', 'forceHttps', 'autoRotate', 'blockTrackers']);
  const { incognitoOnly = true, defaultLevel = 'high', levels = {}, forceHttps = true, autoRotate = 0, blockTrackers = true } = local;
  return {
    enabled,
    lastError,
    ports: Array.isArray(ports) ? ports.filter(Number.isInteger) : [],
    incognitoOnly,
    incognitoAllowed: await chrome.extension.isAllowedIncognitoAccess(),
    defaultLevel: LEVELS.includes(defaultLevel) && defaultLevel !== 'off' ? defaultLevel : 'high',
    // skip anything broken instead of breaking protection for every site
    levels: Object.fromEntries(Object.entries(levels || {}).filter(([site, lvl]) => LEVELS.includes(lvl) && /^[a-z0-9-]+(\.[a-z0-9-]+)*$/i.test(site))),
    forceHttps: forceHttps !== false,
    blockTrackers: blockTrackers !== false,
    autoRotate: AUTO_ROTATE_MINUTES.includes(autoRotate) ? autoRotate : 0,
  };
}

const levelOf = (state, host) => state.levels[siteKey(host)] ?? state.defaultLevel;
const offSites = (state) => Object.keys(state.levels).filter((s) => state.levels[s] === 'off');

// which sites a level based thing applies to: all sites except some, or only some
function coverage({ levels, defaultLevel }, wanted) {
  const sites = Object.keys(levels);
  return wanted.includes(defaultLevel)
    ? { all: true, sites: sites.filter((s) => !wanted.includes(levels[s])) } // sites = exceptions
    : { all: false, sites: sites.filter((s) => wanted.includes(levels[s])) }; // sites = the only ones
}
const patterns = (sites) => sites.flatMap((s) => (/^[\d.]+$/.test(s) || !s.includes('.') ? [`*://${s}/*`] : [`*://${s}/*`, `*://*.${s}/*`]));

async function applySettings(state) {
  const { enabled, ports, incognitoOnly, incognitoAllowed } = state;
  // incognito inherits the regular scope so "all windows" = set regular only,
  // "incognito only" = set incognito only. everything else gets cleared
  const target = enabled && (incognitoOnly ? 'incognito_persistent' : 'regular');
  const scopes = incognitoAllowed ? ['regular', 'incognito_persistent'] : ['regular'];
  const proxy = proxyConfig(ports, offSites(state));
  for (const scope of scopes) {
    for (const [setting, value] of [[chrome.proxy.settings, proxy], ...PRIVACY]) {
      try {
        await (scope === target ? setting.set({ value, scope }) : setting.clear({ scope }));
      } catch (e) {
        if (setting === chrome.proxy.settings) throw new Error(`Couldn't change the proxy (${e.message})`);
      }
    }
  }
}

async function applyScripts(state) {
  await chrome.scripting.unregisterContentScripts();
  if (!state.enabled) return;
  const entry = (id, file, world, cover) => (cover.all
    ? { id, js: [file], world, ...SCRIPT, ...(cover.sites.length && { excludeMatches: patterns(cover.sites) }) }
    : cover.sites.length > 0 && { id, js: [file], world, ...SCRIPT, matches: patterns(cover.sites) });
  // chrome runs these in ID order not array order (that one was fun to find), so the "1-" ones
  // run first and tell fingerprint.js to back off (normal window) or go easy (medium)
  const scripts = [
    state.incognitoOnly && { id: '1-skip-normal', js: ['skip-normal.js'], world: 'ISOLATED', ...SCRIPT },
    entry('1-level-medium', 'level-medium.js', 'ISOLATED', coverage(state, ['medium'])),
    entry('1-workers-check', 'workers-check.js', 'ISOLATED', coverage(state, ['high'])),
    entry('2-fingerprint', 'fingerprint.js', 'MAIN', coverage(state, ['medium', 'high'])),
  ].filter(Boolean);
  if (scripts.length) await chrome.scripting.registerContentScripts(scripts);
}

// network rules: header cleanup (medium/high) + https upgrade (every level except off)
async function applyRules(state) {
  const addRules = [];
  if (state.enabled) {
    // rules cant target "incognito" so in incognito only mode just exclude every normal tab
    // (worst case a brand new normal tab gets the rules for a sec, which is fine)
    const tabScope = {};
    if (state.incognitoOnly) {
      const normalTabs = (await chrome.tabs.query({})).filter((t) => !t.incognito).map((t) => t.id);
      if (normalTabs.length) tabScope.excludedTabIds = normalTabs;
    }
    const cover = coverage(state, ['medium', 'high']);
    if (cover.all || cover.sites.length) {
      const condition = { resourceTypes: ALL_TYPES, ...tabScope };
      if (cover.all && cover.sites.length) condition.excludedRequestDomains = cover.sites;
      if (!cover.all) condition.requestDomains = cover.sites;
      // higher than LOCAL_HTTP's "allow" or that rule switches this one off too
      addRules.push({ id: RULE.HEADERS, priority: 3, action: HEADER_ACTION, condition });
    }
    if (state.forceHttps) {
      addRules.push({
        id: RULE.HTTPS, priority: 1, action: { type: 'upgradeScheme' },
        // .onion is already end to end encrypted by tor and most of them are plain http anyway
        condition: { urlFilter: '|http://', resourceTypes: ALL_TYPES, excludedRequestDomains: ['localhost', 'onion', ...offSites(state)], ...tabScope },
      });
      // router, nas etc on ur local network dont have https, leave them alone
      addRules.push({ id: RULE.LOCAL_HTTP, priority: 2, action: { type: 'allow' }, condition: { regexFilter: `^http://${PRIVATE_IP}`, resourceTypes: ALL_TYPES } });
    }
    if (state.blockTrackers) {
      // only when loaded on OTHER sites, and never on sites u set to Off
      const off = offSites(state);
      const condition = { domainType: 'thirdParty', resourceTypes: ALL_TYPES.filter((t) => t !== 'main_frame'), ...tabScope, ...(off.length && { excludedInitiatorDomains: off }) };
      addRules.push({ id: RULE.TRACKERS, priority: 1, action: { type: 'block' }, condition: { ...condition, requestDomains: TRACKER_DOMAINS } });
      for (const { id, urlFilter } of TRACKER_URL_RULES) addRules.push({ id, priority: 1, action: { type: 'block' }, condition: { ...condition, urlFilter } });
    }
  }
  await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: [...Object.values(RULE), ...TRACKER_URL_RULES.map((r) => r.id)], addRules });
}

async function applyAlarm({ enabled, autoRotate }) {
  const alarm = await chrome.alarms.get('rotate');
  if (!enabled || !autoRotate) {
    if (alarm) await chrome.alarms.clear('rotate');
  } else if (alarm?.periodInMinutes !== autoRotate) {
    await chrome.alarms.create('rotate', { delayInMinutes: autoRotate, periodInMinutes: autoRotate });
  }
}

// toolbar badge per tab: H / M / L / OFF, or ! when something broke
const BADGES = { high: ['H', '#1e7d45'], medium: ['M', '#1e7d45'], low: ['L', '#1e7d45'], off: ['OFF', '#a35f00'] };
async function paintBadges(onlyTab) {
  const state = await readState();
  for (const tab of onlyTab ? [onlyTab] : await chrome.tabs.query({})) {
    let text = '';
    let color = '#1e7d45';
    if (state.enabled && /^https?:/.test(tab.url || '')) {
      if (state.lastError || (state.incognitoOnly && !state.incognitoAllowed)) [text, color] = ['!', '#c5221f'];
      else if (!state.incognitoOnly || tab.incognito) [text, color] = BADGES[levelOf(state, new URL(tab.url).hostname)];
    }
    try {
      await chrome.action.setBadgeText({ tabId: tab.id, text });
      if (text) {
        await chrome.action.setBadgeBackgroundColor({ tabId: tab.id, color });
        await chrome.action.setBadgeTextColor?.({ tabId: tab.id, color: '#ffffff' });
      }
    } catch {} // tab got closed meanwhile
  }
}

// the popup shows lastError so nothing fails silently
async function setError(message) {
  const { lastError = null } = await chrome.storage.session.get('lastError');
  if (lastError !== message) await chrome.storage.session.set({ lastError: message });
}

// one at a time so spamming the toggle cant mix up set/clear calls. only a full sync that worked
// clears the error, a small rule update working doesnt mean the proxy is fine
let queue = Promise.resolve();
const run = (fn, clearsError) => (queue = queue.then(fn).then(
  () => clearsError && setError(null),
  (e) => { console.error('[TorGuard]', e); return setError(e?.message || String(e)); },
).catch((e) => console.error('[TorGuard] could not record error', e)));
const sync = () => run(async () => {
  const state = await readState();
  await applySettings(state);
  await applyScripts(state).catch((e) => { throw new Error(`Couldn't set up fingerprint protection (${e.message})`); });
  await applyRules(state).catch((e) => { throw new Error(`Couldn't set up HTTPS and header protection (${e.message})`); });
  await applyAlarm(state).catch((e) => { throw new Error(`Couldn't schedule auto-rotate (${e.message})`); });
}, true).then(() => paintBadges()).catch((e) => console.error('[TorGuard] badge', e));
const syncRules = () => run(async () => applyRules(await readState()), false);

// auto rotate: new circuits for every site on whatever schedule u picked
chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== 'rotate') return;
  let result;
  try {
    const res = await fetch(`${ROTATOR_API}/rotate?scope=all&slot=0`, { signal: AbortSignal.timeout(90000) });
    const data = await res.json();
    if (data.status !== 'success') throw new Error(data.message || `HTTP ${res.status}`);
    await chrome.storage.session.set({ ports: data.ports });
    result = { at: Date.now(), ok: true, ip: data.new_ip };
  } catch (e) {
    result = { at: Date.now(), ok: false, message: e instanceof TypeError ? 'Rotator offline' : e.message };
  }
  await chrome.storage.session.set({ autoRotateResult: result });
  run(async () => applyAlarm(await readState()), false); // make sure the schedule is still there
});

// high starts web workers from a blob: wrapper. if a page's CSP doesnt allow blob: workers they
// just die, so remember each frame's CSP and tell workers-check.js
const blobWorkers = new Map(); // "tabId/frameId" -> { url, ok }
function allowsBlobWorkers(headerValues) {
  for (const policy of headerValues.join(',').split(',')) {
    const directives = new Map(policy.split(';').map((d) => d.trim().toLowerCase().split(/\s+/)).filter(([name]) => name).map(([name, ...src]) => [name, src]));
    const sources = ['worker-src', 'child-src', 'script-src', 'default-src'].map((name) => directives.get(name)).find(Boolean);
    if (sources && !sources.includes('blob:')) return false;
  }
  return true;
}
chrome.webRequest.onHeadersReceived.addListener((d) => {
  const csp = (d.responseHeaders || []).filter((h) => h.name.toLowerCase() === 'content-security-policy').map((h) => h.value || '');
  blobWorkers.set(`${d.tabId}/${d.frameId}`, { url: d.url, ok: allowsBlobWorkers(csp) });
}, { urls: ['<all_urls>'], types: ['main_frame', 'sub_frame'] }, ['responseHeaders']);
chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (message !== 'blob-workers?') return;
  const known = blobWorkers.get(`${sender.tab?.id}/${sender.frameId}`);
  reply(known && known.url === sender.url ? known.ok : null); // null = no idea (like the worker restarted)
});
chrome.tabs.onRemoved.addListener((tabId) => {
  for (const key of blobWorkers.keys()) if (key.startsWith(`${tabId}/`)) blobWorkers.delete(key);
});

// native host (install_host.bat): turning protection on/off starts/stops tor + the rotator so u dont
// need the .bat window. if its not installed this just fails and u use start_privacy.bat like before
async function host(cmd) {
  let status;
  try {
    status = { available: true, cmd, ...(await chrome.runtime.sendNativeMessage('com.torguard.host', { cmd })) };
  } catch (e) {
    status = { available: false, cmd, ok: false, message: e?.message || String(e) };
  }
  await chrome.storage.session.set({ hostStatus: { ...status, at: Date.now() } });
}

const STATUS_KEYS = ['lastError', 'autoRotateResult', 'hostStatus']; // stuff this worker writes, not settings
chrome.storage.onChanged.addListener((changes) => {
  if (changes.enabled && changes.enabled.newValue !== changes.enabled.oldValue) host(changes.enabled.newValue ? 'start' : 'stop');
  if (Object.keys(changes).some((key) => !STATUS_KEYS.includes(key))) sync();
  else if ('lastError' in changes) paintBadges();
});
chrome.runtime.onStartup.addListener(() => {
  sync(); // chrome keeps proxy settings after a restart, reset them
  host('stop'); // protection starts off, so stop a tor the popup left running last time
});
chrome.tabs.onCreated.addListener(syncRules);
chrome.tabs.onRemoved.addListener(syncRules);
chrome.tabs.onUpdated.addListener((tabId, change, tab) => { if (change.url) paintBadges(tab); });
sync();
