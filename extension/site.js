// used by background.js (gets pasted into the PAC script) and popup.js: which tor slot a site
// uses. a site + its subdomains share a slot so logins keep working, different sites get
// different circuits / exit ips. plain ES5 on purpose cuz chrome's PAC engine runs it too
var TOR_SLOTS = 16; // must match SLOTS in tor_rotator.py

function siteKey(host) {
  var parts = host.toLowerCase().replace(/\.$/, '').split('.');
  if (parts.length <= 2 || /^\d+$/.test(parts[parts.length - 1])) return parts.join('.'); // short host or an ipv4
  var twoPartSuffix = parts[parts.length - 1].length === 2 &&
    /^(co|com|net|org|gov|edu|ac|or|ne|go)$/.test(parts[parts.length - 2]); // like bbc.co.uk
  return parts.slice(twoPartSuffix ? -3 : -2).join('.');
}

// ur own pc / local network (router, nas...). these never go thru tor. full ipv4 only, so a real
// site like 10.tv or 127.net isnt mistaken for a local address
function isLocal(host) {
  return host === 'localhost' || /\.localhost$/.test(host) || host === '::1' || host === '[::1]' ||
    /^(10|127|192\.168|172\.(1[6-9]|2\d|3[01]))(\.\d{1,3}){2,3}$/.test(host);
}

function siteSlot(host, slots) {
  var key = siteKey(host), h = 2166136261; // FNV-1a
  for (var i = 0; i < key.length; i++) h = Math.imul(h ^ key.charCodeAt(i), 16777619);
  return (h >>> 0) % slots;
}
