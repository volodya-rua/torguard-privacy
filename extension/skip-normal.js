// only registered in "incognito windows only" mode. runs right before fingerprint.js and tells it
// to back off in normal windows (the main world script cant tell if its incognito)
if (!chrome.extension.inIncognitoContext && document.documentElement) {
  document.documentElement.setAttribute('data-tg-skip', '');
}
