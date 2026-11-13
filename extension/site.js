// used by background.js (gets pasted into the PAC script) and popup.js: which tor slot a site
// uses. a site + its subdomains share a slot so logins keep working, different sites get
// different circuits / exit ips. plain ES5 on purpose cuz chrome's PAC engine runs it too
var TOR_SLOTS = 16; // must match SLOTS in tor_rotator.py

function siteKey(host) {
  var parts = host.toLowerCase().replace(/\.$/, '').split('.');
  if (parts.length <= 2 || /^\d+$/.test(parts[parts.length - 1])) return host; // short host or an ipv4
  var twoPartSuffix = parts[parts.length - 1].length === 2 &&
    /^(co|com|net|org|gov|edu|ac|or|ne|go)$/.test(parts[parts.length - 2]); // like bbc.co.uk
  return parts.slice(twoPartSuffix ? -3 : -2).join('.');
}

function siteSlot(host, slots) {
  var key = siteKey(host), h = 2166136261; // FNV-1a
  for (var i = 0; i < key.length; i++) h = Math.imul(h ^ key.charCodeAt(i), 16777619);
  return (h >>> 0) % slots;
}
