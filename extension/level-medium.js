// registered for medium sites. runs right before fingerprint.js and tells it to blend in
// (clock, language, hardware) but skip the canvas/webgl/audio noise
document.documentElement?.setAttribute('data-tg-level', 'medium');
