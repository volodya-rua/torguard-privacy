// tracker + ad domains that get blocked when they load on OTHER sites (third party only, so going to
// facebook.com itself still works). picked by hand: the big analytics, ad, pixel and session replay
// stuff, but not things sites need to work (login sdks, captchas, payments, cdns)
var TRACKER_DOMAINS = [
  // google ads + analytics
  'google-analytics.com', 'analytics.google.com', 'doubleclick.net', 'googleadservices.com',
  'googlesyndication.com', 'googletagservices.com', 'adservice.google.com', 'app-measurement.com',
  // microsoft, tiktok, x, linkedin, pinterest, snap, reddit, yandex, baidu
  'bat.bing.com', 'clarity.ms', 'analytics.tiktok.com', 'ads-twitter.com', 'analytics.twitter.com',
  'px.ads.linkedin.com', 'snap.licdn.com', 'ct.pinterest.com', 'tr.snapchat.com', 'sc-static.net',
  'events.redditmedia.com', 'mc.yandex.ru', 'mc.yandex.com', 'hm.baidu.com',
  // session replay + product analytics
  'hotjar.com', 'hotjar.io', 'mouseflow.com', 'fullstory.com', 'crazyegg.com', 'luckyorange.com',
  'luckyorange.net', 'smartlook.com', 'inspectlet.com', 'heapanalytics.com', 'mixpanel.com',
  'amplitude.com', 'segment.io', 'cdn.segment.com', 'kissmetrics.io', 'quantserve.com', 'quantcount.com',
  'scorecardresearch.com', 'chartbeat.com', 'chartbeat.net', 'parsely.com', 'hs-analytics.net',
  'omtrdc.net', '2o7.net', 'demdex.net', 'everesttech.net',
  // ad exchanges + data brokers
  'adnxs.com', 'rubiconproject.com', 'pubmatic.com', 'openx.net', 'casalemedia.com', 'indexww.com',
  'criteo.com', 'criteo.net', 'taboola.com', 'outbrain.com', 'amazon-adsystem.com', 'adsrvr.org',
  'krxd.net', 'bluekai.com', 'exelator.com', 'rlcdn.com', 'adform.net', 'smartadserver.com',
  'sharethrough.com', 'teads.tv', 'moatads.com', 'doubleverify.com', 'adsafeprotected.com', 'media.net',
  'tapad.com', 'bidswitch.net', '3lift.com', 'contextweb.com', 'spotxchange.com', 'lijit.com',
  'gumgum.com', 'sovrn.com', 'mathtag.com', 'agkn.com', 'crwdcntrl.net', 'addthis.com', 'sharethis.com',
  'zemanta.com', 'yieldmo.com', 'adroll.com', 'quantcast.com', 'id5-sync.com', 'liadm.com',
];

// pixels that live on domains sites DO need (facebook login etc), so only the tracking path is blocked
var TRACKER_URLS = ['||facebook.com/tr', '||connect.facebook.net/*/fbevents.js', '||google.com/pagead/'];
