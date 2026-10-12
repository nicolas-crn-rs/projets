/*
 * Barrière de mot de passe partagée par toutes les pages du site.
 * Une fois le mot de passe saisi, le navigateur s'en souvient (localStorage)
 * et la demande ne revient plus sur aucune page.
 * Attention : filtre côté navigateur, pas une protection forte.
 */
(function () {
  var HASH = "4de506b0a50bc9b0b69132226b1cdff18f4fd0ee7210a7cc61bc80a1223f9ef7";
  var KEY = "rs_projets_auth";
  var SALT = "rs-projets|";

  function isStored() {
    try { return localStorage.getItem(KEY) === HASH; } catch (e) { return false; }
  }
  function store() {
    try { localStorage.setItem(KEY, HASH); } catch (e) {}
  }
  if (isStored()) return;

  /* Masque la page tant que le mot de passe n'est pas validé */
  var hide = document.createElement("style");
  hide.textContent = "body{visibility:hidden!important}";
  document.head.appendChild(hide);

  /* SHA-256 de secours si crypto.subtle est indisponible */
  function sha256(ascii) {
    function rr(v, a) { return (v >>> a) | (v << (32 - a)); }
    var mathPow = Math.pow, maxWord = mathPow(2, 32), i, j, result = "";
    var words = [], bitLength = ascii.length * 8;
    var hash = [], k = [], primeCounter = 0, isComposite = {};
    for (var candidate = 2; primeCounter < 64; candidate++) {
      if (!isComposite[candidate]) {
        for (i = 0; i < 313; i += candidate) isComposite[i] = candidate;
        hash[primeCounter] = (mathPow(candidate, 0.5) * maxWord) | 0;
        k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
      }
    }
    ascii += "\x80";
    while (ascii.length % 64 - 56) ascii += "\x00";
    for (i = 0; i < ascii.length; i++) {
      j = ascii.charCodeAt(i);
      words[i >> 2] |= j << ((3 - i) % 4) * 8;
    }
    words[words.length] = (bitLength / maxWord) | 0;
    words[words.length] = bitLength;
    for (j = 0; j < words.length;) {
      var w = words.slice(j, j += 16);
      var oldHash = hash;
      hash = hash.slice(0, 8);
      for (i = 0; i < 64; i++) {
        var w15 = w[i - 15], w2 = w[i - 2];
        var a = hash[0], e = hash[4];
        var temp1 = hash[7] + (rr(e, 6) ^ rr(e, 11) ^ rr(e, 25)) + ((e & hash[5]) ^ ((~e) & hash[6])) + k[i] +
          (w[i] = (i < 16) ? w[i] : (w[i - 16] + (rr(w15, 7) ^ rr(w15, 18) ^ (w15 >>> 3)) + w[i - 7] +
            (rr(w2, 17) ^ rr(w2, 19) ^ (w2 >>> 10))) | 0);
        var temp2 = (rr(a, 2) ^ rr(a, 13) ^ rr(a, 22)) + ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2]));
        hash = [(temp1 + temp2) | 0].concat(hash);
        hash[4] = (hash[4] + temp1) | 0;
      }
      for (i = 0; i < 8; i++) hash[i] = (hash[i] + oldHash[i]) | 0;
    }
    for (i = 0; i < 8; i++) {
      for (j = 3; j + 1; j--) {
        var b = (hash[i] >> (j * 8)) & 255;
        result += ((b < 16) ? 0 : "") + b.toString(16);
      }
    }
    return result;
  }

  function hashPassword(pw) {
    var s = SALT + pw;
    if (window.crypto && crypto.subtle && window.TextEncoder) {
      return crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)).then(function (buf) {
        return Array.prototype.map.call(new Uint8Array(buf), function (b) {
          return ("0" + b.toString(16)).slice(-2);
        }).join("");
      });
    }
    return Promise.resolve(sha256(unescape(encodeURIComponent(s))));
  }

  var css = document.createElement("style");
  css.textContent =
    "#rs-gate{position:fixed;inset:0;z-index:2147483647;display:flex;align-items:center;justify-content:center;" +
    "background:#f5f7fa;padding:16px;font-family:Wotfard,Arial,sans-serif;color:#1D096E;visibility:visible}" +
    "#rs-gate .box{background:#fff;border-top:6px solid #3CD200;border-radius:12px;padding:32px 28px;" +
    "max-width:380px;width:100%;box-shadow:0 4px 24px rgba(29,9,110,.12);text-align:center}" +
    "#rs-gate h1{margin:0 0 6px;font-size:1.5rem}" +
    "#rs-gate p{margin:0 0 18px;color:#5b5675;font-size:.95rem}" +
    "#rs-gate input{width:100%;padding:12px;border:2px solid #1D096E;border-radius:8px;font-family:inherit;" +
    "font-size:1rem;color:#1D096E;margin-bottom:12px}" +
    "#rs-gate button{width:100%;background:#3CD200;color:#1D096E;border:0;border-radius:8px;padding:12px;" +
    "font-family:inherit;font-size:1rem;font-weight:700;cursor:pointer}" +
    "#rs-gate button:hover{background:#1D096E;color:#fff}" +
    "#rs-gate input:focus-visible,#rs-gate button:focus-visible{outline:3px solid #3CD200;outline-offset:2px}" +
    "#rs-gate .err{min-height:1.2rem;margin:10px 0 0;color:#b3261e;font-size:.9rem}";
  document.head.appendChild(css);

  var gate = document.createElement("div");
  gate.id = "rs-gate";
  gate.innerHTML =
    '<div class="box" role="dialog" aria-labelledby="rs-gate-title">' +
    '<h1 id="rs-gate-title">Accès protégé</h1>' +
    "<p>Saisissez le mot de passe pour accéder aux projets.</p>" +
    '<input id="rs-gate-pw" type="password" placeholder="Mot de passe" aria-label="Mot de passe" autocomplete="current-password">' +
    '<button id="rs-gate-ok" type="button">Entrer</button>' +
    '<p class="err" id="rs-gate-err" role="alert"></p>' +
    "</div>";
  document.documentElement.appendChild(gate);

  var input = gate.querySelector("#rs-gate-pw");
  var err = gate.querySelector("#rs-gate-err");

  function unlock() {
    store();
    if (gate.parentNode) gate.parentNode.removeChild(gate);
    if (css.parentNode) css.parentNode.removeChild(css);
    if (hide.parentNode) hide.parentNode.removeChild(hide);
  }

  function submit() {
    err.textContent = "";
    hashPassword(input.value).then(function (h) {
      if (h === HASH) { unlock(); }
      else { err.textContent = "Mot de passe incorrect."; input.select(); }
    });
  }

  gate.querySelector("#rs-gate-ok").addEventListener("click", submit);
  /* Empêche les jeux d'intercepter les touches saisies dans le champ */
  input.addEventListener("keydown", function (e) {
    e.stopPropagation();
    if (e.key === "Enter") { e.preventDefault(); submit(); }
  });
  input.addEventListener("keyup", function (e) { e.stopPropagation(); });
  setTimeout(function () { input.focus(); }, 0);
})();
