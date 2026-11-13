// torguard anti fingerprinting. gets injected into every frame (main world) at document_start
// two things:
//  - blend in: say what most ppl say (UTC clock, en-US, 4 cores, 8 GB, a common gpu)
//  - noise: tiny noise on canvas / webgl / audio reads that changes every page load, so the
//    hashes trackers make from them cant follow u around
// everything we override keeps its native name, length and "[native code]" toString
//
// levels: only runs on medium + high sites. level-medium.js marks medium pages first, medium blends
// in but skips the noise (some sites bot checks hate it). high also covers web workers, otherwise
// they see the real clock, cpu count and canvas
(() => {
  const root = document.documentElement;
  const level = root?.getAttribute('data-tg-level');
  const nonce = root?.getAttribute('data-tg-nonce');
  root?.removeAttribute('data-tg-level');
  root?.removeAttribute('data-tg-nonce');
  if (root && root.hasAttribute('data-tg-skip')) { // normal window in "incognito only" mode
    root.removeAttribute('data-tg-skip');
    return;
  }
  const high = level !== 'medium';

  // high: can workers start from a blob: wrapper here? workers-check.js asks the background (it saw
  // this page's CSP). until the answer shows up (super early workers) just try the wrapper, and a
  // CSP violation for a blob: url turns it off for the rest of the page
  let blobWorkers = null;
  if (nonce) document.addEventListener(`tg-${nonce}`, (e) => { blobWorkers = e.detail; }, { once: true });
  document.addEventListener('securitypolicyviolation', (e) => { if (/^blob/.test(e.blockedURI)) blobWorkers = false; });

  // no outside variables so this whole thing can get copied into workers as text
  const torguard = function torguard(self, { high, workers, workerBase }) {
    const nativeToString = Function.prototype.toString;
    const SOURCE = nativeToString.call(torguard);
    const seed = crypto.getRandomValues(new Uint32Array(1))[0];
    // same input = same noise inside a page, so reading the same pixels twice matches
    const noise = (i) => {
      let h = Math.imul(seed ^ i, 0x9e3779b1);
      h = Math.imul(h ^ (h >>> 15), 0x85ebca77);
      return (h ^ (h >>> 13)) >>> 0;
    };
    // flip the lowest bit of one color channel in ~1 of 32 pixels (u cant see it but the hash changes)
    const farblePixels = (data, x0, y0, width) => {
      for (let p = 0, n = data.length >> 2; p < n; p++) {
        const h = noise(Math.imul(x0 + (p % width), 73856093) ^ Math.imul(y0 + ((p / width) | 0), 19349663));
        if ((h & 31) === 0) data[(p << 2) + ((h >>> 5) % 3)] ^= 1;
      }
    };

    const masked = new WeakMap(); // our fn -> the native source text it pretends to be
    const setMeta = (fn, orig) => {
      Object.defineProperty(fn, 'name', { value: orig.name });
      Object.defineProperty(fn, 'length', { value: orig.length });
      masked.set(fn, nativeToString.call(orig));
      return fn;
    };
    // swap a method: make(orig) returns the replacement (shorthand method so it has no .prototype,
    // same as real native ones)
    const wrap = (obj, name, make) => {
      const desc = obj && Object.getOwnPropertyDescriptor(obj, name);
      if (!desc || typeof desc.value !== 'function') return;
      Object.defineProperty(obj, name, { ...desc, value: setMeta(make(desc.value), desc.value) });
    };
    // swap a getter for one returning value (or value(origGetter, this) if its a function)
    const getter = (obj, name, value) => {
      const desc = obj && Object.getOwnPropertyDescriptor(obj, name);
      if (!desc || !desc.get) return;
      const get = { get() { return typeof value === 'function' ? value(desc.get, this) : value; } }.get;
      Object.defineProperty(obj, name, { ...desc, get: setMeta(get, desc.get) });
    };
    // swap a constructor (Date, Intl.*, Worker) so new X(), instanceof X and subclasses still work
    const replaceClass = (owner, name, Orig, Fake) => {
      setMeta(Fake, Orig);
      for (const key of Reflect.ownKeys(Orig)) {
        if (key !== 'name' && key !== 'length') Object.defineProperty(Fake, key, Object.getOwnPropertyDescriptor(Orig, key));
      }
      Object.defineProperty(Orig.prototype, 'constructor', { ...Object.getOwnPropertyDescriptor(Orig.prototype, 'constructor'), value: Fake });
      Object.defineProperty(owner, name, { ...Object.getOwnPropertyDescriptor(owner, name), value: Fake });
    };

    const done = new WeakSet();
    function protect(win) {
      if (done.has(win)) return;
      try { win.Function; } catch { return; } // cross origin frame, it gets its own copy of this script anyway
      done.add(win);

      // --- toString: hide all this shit ----------------------------------------------------
      const winToString = win.Function.prototype.toString;
      const toString = { toString() { return masked.has(this) ? masked.get(this) : winToString.call(this); } }.toString;
      win.Function.prototype.toString = setMeta(toString, winToString);

      // --- hardware, language, battery, client hints (pages + workers) ---------------------
      const nav = (win.Navigator || win.WorkerNavigator)?.prototype;
      const languages = win.Object.freeze(win.Array.of('en-US', 'en'));
      getter(nav, 'hardwareConcurrency', 4);
      getter(nav, 'deviceMemory', 8);
      getter(nav, 'language', 'en-US');
      getter(nav, 'languages', languages);
      const battery = high && win.BatteryManager?.prototype;
      getter(battery, 'charging', true);
      getter(battery, 'chargingTime', 0);
      getter(battery, 'dischargingTime', Infinity);
      getter(battery, 'level', 1);
      wrap(win.NavigatorUAData?.prototype, 'getHighEntropyValues', (orig) => ({
        getHighEntropyValues(hints) {
          const major = (v) => `${String(v).split('.')[0]}.0.0.0`;
          return orig.call(this, hints).then((v) => {
            if ('platformVersion' in v) v.platformVersion = '10.0.0';
            if ('architecture' in v) v.architecture = 'x86';
            if ('bitness' in v) v.bitness = '64';
            if ('model' in v) v.model = '';
            if ('wow64' in v) v.wow64 = false;
            if ('uaFullVersion' in v) v.uaFullVersion = major(v.uaFullVersion);
            if (v.fullVersionList) v.fullVersionList = v.fullVersionList.map((b) => ({ brand: b.brand, version: major(b.version) }));
            return v;
          });
        },
      }).getHighEntropyValues);

      // --- timezone -> UTC, default locale -> en-US ----------------------------------------
      const OrigDate = win.Date;
      const DP = OrigDate.prototype;
      const realOffset = DP.getTimezoneOffset;
      const U = {}; // original UTC getters
      for (const k of ['getUTCFullYear', 'getUTCMonth', 'getUTCDate', 'getUTCDay', 'getUTCHours', 'getUTCMinutes', 'getUTCSeconds']) U[k] = DP[k];
      const LOCAL_TO_UTC = {
        getFullYear: 'getUTCFullYear', getMonth: 'getUTCMonth', getDate: 'getUTCDate', getDay: 'getUTCDay',
        getHours: 'getUTCHours', getMinutes: 'getUTCMinutes', getSeconds: 'getUTCSeconds', getMilliseconds: 'getUTCMilliseconds',
        setFullYear: 'setUTCFullYear', setMonth: 'setUTCMonth', setDate: 'setUTCDate', setHours: 'setUTCHours',
        setMinutes: 'setUTCMinutes', setSeconds: 'setUTCSeconds', setMilliseconds: 'setUTCMilliseconds',
      };
      for (const [local, utc] of Object.entries(LOCAL_TO_UTC)) {
        const target = DP[utc];
        wrap(DP, local, () => ({ [local](...a) { return target.apply(this, a); } })[local]);
      }
      wrap(DP, 'getYear', () => ({ getYear() { return U.getUTCFullYear.call(this) - 1900; } }).getYear);
      wrap(DP, 'getTimezoneOffset', () => ({
        getTimezoneOffset() { const t = DP.getTime.call(this); return t === t ? 0 : NaN; },
      }).getTimezoneOffset);

      const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
      const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
      const pad = (n, w = 2) => String(n).padStart(w, '0');
      const year = (y) => (y < 0 ? `-${pad(-y, 6)}` : pad(y, 4));
      const datePart = (d) => `${DAYS[U.getUTCDay.call(d)]} ${MONTHS[U.getUTCMonth.call(d)]} ${pad(U.getUTCDate.call(d))} ${year(U.getUTCFullYear.call(d))}`;
      const timePart = (d) => `${pad(U.getUTCHours.call(d))}:${pad(U.getUTCMinutes.call(d))}:${pad(U.getUTCSeconds.call(d))} GMT+0000 (Coordinated Universal Time)`;
      const valid = (d) => { const t = DP.getTime.call(d); return t === t; };
      wrap(DP, 'toString', () => ({ toString() { return valid(this) ? `${datePart(this)} ${timePart(this)}` : 'Invalid Date'; } }).toString);
      wrap(DP, 'toDateString', () => ({ toDateString() { return valid(this) ? datePart(this) : 'Invalid Date'; } }).toDateString);
      wrap(DP, 'toTimeString', () => ({ toTimeString() { return valid(this) ? timePart(this) : 'Invalid Date'; } }).toTimeString);
      for (const name of ['toLocaleString', 'toLocaleDateString', 'toLocaleTimeString']) {
        wrap(DP, name, (orig) => ({ [name](locales, options) { return orig.call(this, locales ?? 'en-US', { timeZone: 'UTC', ...options }); } })[name]);
      }
      wrap(win.Number.prototype, 'toLocaleString', (orig) => ({ toLocaleString(locales, options) { return orig.call(this, locales ?? 'en-US', options); } }).toLocaleString);

      // strings with a zone ("Z", "+05:30", "GMT"...) keep it, local time strings become UTC
      const HAS_ZONE = /(?:Z|[+-]\d{2}(?::?\d{2})?|\b(?:UTC|GMT|UT)\b.*)$/i;
      const asUTC = (t) => t - realOffset.call(new OrigDate(t)) * 60000;
      const parse = setMeta({ parse(s) {
        const str = String(s);
        const t = OrigDate.parse(str);
        return t !== t || HAS_ZONE.test(str.trim()) ? t : asUTC(t);
      } }.parse, OrigDate.parse);
      const FakeDate = function Date(...args) {
        if (!new.target) return DP.toString.call(new OrigDate());
        let value = args;
        if (args.length >= 2) value = [OrigDate.UTC(...args)];
        else if (args.length === 1 && typeof args[0] === 'string') value = [parse(args[0])];
        return Reflect.construct(OrigDate, value, new.target === FakeDate ? OrigDate : new.target);
      };
      replaceClass(win, 'Date', OrigDate, FakeDate);
      Object.defineProperty(FakeDate, 'parse', { ...Object.getOwnPropertyDescriptor(OrigDate, 'parse'), value: parse });

      for (const name of ['DateTimeFormat', 'NumberFormat', 'Collator', 'PluralRules', 'RelativeTimeFormat', 'ListFormat', 'DisplayNames', 'Segmenter', 'DurationFormat']) {
        const Orig = win.Intl[name];
        if (!Orig) continue;
        const withTz = name === 'DateTimeFormat';
        const Fake = function (locales, options) {
          const args = [locales ?? 'en-US', withTz ? { timeZone: 'UTC', ...options } : options];
          return new.target ? Reflect.construct(Orig, args, new.target === Fake ? Orig : new.target) : Orig(...args);
        };
        replaceClass(win.Intl, name, Orig, Fake);
      }
      const now = win.Temporal?.Now;
      if (now) {
        wrap(now, 'timeZoneId', () => ({ timeZoneId() { return 'UTC'; } }).timeZoneId);
        for (const name of ['plainDateTimeISO', 'plainDateISO', 'plainTimeISO', 'zonedDateTimeISO']) {
          wrap(now, name, (orig) => ({ [name](tz = 'UTC') { return orig.call(this, tz); } })[name]);
        }
      }

      // --- canvas (high only, OffscreenCanvas in workers too) ------------------------------
      const C2D = win.CanvasRenderingContext2D?.prototype;
      const OC2D = win.OffscreenCanvasRenderingContext2D?.prototype;
      const ctx2d = C2D && { getImageData: C2D.getImageData, putImageData: C2D.putImageData, drawImage: C2D.drawImage };
      const octx2d = OC2D && { getImageData: OC2D.getImageData, putImageData: OC2D.putImageData, drawImage: OC2D.drawImage };
      for (const proto of high ? [C2D, OC2D] : []) {
        wrap(proto, 'getImageData', (orig) => ({
          getImageData(sx, sy, ...rest) {
            const img = orig.call(this, sx, sy, ...rest);
            farblePixels(img.data, sx | 0, sy | 0, img.width);
            return img;
          },
        }).getImageData);
      }
      // export a noisy copy, never touch whats on screen. null = let the original call run
      // (like a tainted canvas, so it throws its normal error)
      const farbledCopy = (source, makeCanvas, getCtx, api) => {
        try {
          const { width, height } = source;
          if (!width || !height) return null;
          const copy = makeCanvas(width, height);
          const ctx = getCtx(copy);
          api.drawImage.call(ctx, source, 0, 0);
          const img = api.getImageData.call(ctx, 0, 0, width, height);
          farblePixels(img.data, 0, 0, width);
          api.putImageData.call(ctx, img, 0, 0);
          return copy;
        } catch {
          return null;
        }
      };
      const HC = high && ctx2d && win.HTMLCanvasElement?.prototype;
      if (HC) {
        const getContext = HC.getContext;
        const createElement = win.Document.prototype.createElement;
        const copyOf = (canvas) => farbledCopy(canvas, (w, h) => {
          const c = createElement.call(canvas.ownerDocument, 'canvas');
          c.width = w;
          c.height = h;
          return c;
        }, (c) => getContext.call(c, '2d'), ctx2d);
        wrap(HC, 'toDataURL', (orig) => ({ toDataURL(...a) { return orig.apply(copyOf(this) || this, a); } }).toDataURL);
        wrap(HC, 'toBlob', (orig) => ({ toBlob(...a) { return orig.apply(copyOf(this) || this, a); } }).toBlob);
      }
      const OC = win.OffscreenCanvas;
      if (high && OC && octx2d) {
        const ocGetContext = OC.prototype.getContext;
        wrap(OC.prototype, 'convertToBlob', (orig) => ({
          convertToBlob(...a) {
            return orig.apply(farbledCopy(this, (w, h) => new OC(w, h), (c) => ocGetContext.call(c, '2d'), octx2d) || this, a);
          },
        }).convertToBlob);
      }

      // --- webgl: common gpu name, noisy pixel reads on high --------------------------------
      for (const proto of [win.WebGLRenderingContext?.prototype, win.WebGL2RenderingContext?.prototype]) {
        wrap(proto, 'getParameter', (orig) => ({
          getParameter(p) {
            const v = orig.call(this, p);
            if (typeof v !== 'string') return v;
            if (p === 0x9245) return 'Google Inc. (Intel)'; // UNMASKED_VENDOR_WEBGL
            if (p === 0x9246) return 'ANGLE (Intel, Intel(R) UHD Graphics 620 (0x00005917) Direct3D11 vs_5_0 ps_5_0, D3D11)';
            return v;
          },
        }).getParameter);
        wrap(high && proto, 'readPixels', (orig) => ({
          readPixels(...a) {
            const r = orig.apply(this, a);
            const px = a[6];
            if (px && px.BYTES_PER_ELEMENT === 1 && a[4] === 0x1908 /* RGBA */) farblePixels(px, a[0] | 0, a[1] | 0, a[2] | 0 || 1);
            return r;
          },
        }).readPixels);
      }

      // --- audio (high only): inaudible noise (~1e-7) so the AudioContext hash changes every load
      const AB = high && win.AudioBuffer?.prototype;
      if (AB) {
        const farbled = new WeakSet();
        const origGetChannelData = AB.getChannelData;
        const getChannelData = ({
          getChannelData(channel) {
            const data = origGetChannelData.call(this, channel);
            if (!farbled.has(data)) {
              farbled.add(data);
              for (let i = 0; i < data.length; i++) {
                const h = noise(Math.imul(i, 31) + channel);
                if ((h & 15) === 0) data[i] += ((h >>> 4) / 268435456 - 0.5) * 1e-7;
              }
            }
            return data;
          },
        }).getChannelData;
        wrap(AB, 'getChannelData', () => getChannelData);
        // noise the buffer in place first so both ways of reading it match
        wrap(AB, 'copyFromChannel', (orig) => ({ copyFromChannel(dest, channel, ...rest) { getChannelData.call(this, channel); return orig.call(this, dest, channel, ...rest); } }).copyFromChannel);
      }
      wrap(high && win.AnalyserNode?.prototype, 'getFloatFrequencyData', (orig) => ({
        getFloatFrequencyData(array) {
          orig.call(this, array);
          for (let i = 0; i < array.length; i++) array[i] += ((noise(i) & 255) / 255 - 0.5) * 0.1;
        },
      }).getFloatFrequencyData);

      // --- frames: trackers grab a fresh same origin iframe's window before scripts run in it --
      for (const el of [win.HTMLIFrameElement, win.HTMLFrameElement, win.HTMLObjectElement]) {
        getter(el?.prototype, 'contentWindow', (get, self) => { const w = get.call(self); if (w) protect(w); return w; });
        getter(el?.prototype, 'contentDocument', (get, self) => { const d = get.call(self); if (d?.defaultView) protect(d.defaultView); return d; });
      }

      // --- workers (high): start every same origin worker through a small blob: wrapper that runs
      // this same protection first and then loads the real script. if the page's CSP blocks blob:
      // workers (workers() says no) they just start normally without protection instead of breaking
      const OrigWorker = workers && win.Worker;
      if (OrigWorker) {
        const FakeWorker = function Worker(url, options) {
          if (!new.target) return OrigWorker(url, options); // throws, like the real one
          const target = new.target === FakeWorker ? OrigWorker : new.target;
          let wrapper = null;
          try {
            const script = new win.URL(url, win.document.baseURI);
            if (workers() && script.origin === win.location.origin && /^https?:$/.test(script.protocol)) {
              const load = options?.type === 'module' ? `await import(${JSON.stringify(script.href)});` : `importScripts(${JSON.stringify(script.href)});`;
              const code = `(${SOURCE})(self, { high: true, workers: false, workerBase: ${JSON.stringify(script.href)} });\n${load}`;
              wrapper = win.URL.createObjectURL(new win.Blob([code], { type: 'text/javascript' }));
              win.setTimeout(() => win.URL.revokeObjectURL(wrapper), 30000);
            }
          } catch {}
          if (wrapper) {
            try { return Reflect.construct(OrigWorker, [wrapper, options], target); } catch {}
          }
          return Reflect.construct(OrigWorker, [url, options], target);
        };
        replaceClass(win, 'Worker', OrigWorker, FakeWorker);
      }

      // --- inside a wrapped worker: relative urls have to resolve against the real script, not the
      // blob: wrapper, and self.location has to look like the real script's location
      const WGS = workerBase && win.WorkerGlobalScope?.prototype;
      if (WGS) {
        const base = new win.URL(workerBase);
        const resolve = (u) => (typeof u === 'string' && !/^[a-z][a-z0-9+.-]*:/i.test(u) ? new win.URL(u, base).href : u);
        wrap(WGS, 'importScripts', (orig) => ({ importScripts(...urls) { return orig.apply(this, urls.map(resolve)); } }).importScripts);
        wrap(WGS, 'fetch', (orig) => ({ fetch(input, init) { return orig.call(this, resolve(input), init); } }).fetch);
        wrap(win.XMLHttpRequest?.prototype, 'open', (orig) => ({ open(method, url, ...rest) { return orig.call(this, method, resolve(url), ...rest); } }).open);
        getter(WGS, 'location', base);
      }
    }

    protect(self);
  };

  torguard(window, { high, workers: high && (() => blobWorkers !== false) });
})();
