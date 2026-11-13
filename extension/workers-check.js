// registered for high sites, runs before fingerprint.js. high starts web workers from a blob:
// wrapper but pages whose CSP blocks blob: workers would break, so ask the background (it saw the
// CSP header) and pass the answer to fingerprint.js on a private event the page cant guess
const nonce = crypto.randomUUID();
document.documentElement?.setAttribute('data-tg-nonce', nonce);
chrome.runtime.sendMessage('blob-workers?')
  .then((ok) => document.dispatchEvent(new CustomEvent(`tg-${nonce}`, { detail: ok })))
  .catch(() => {});
