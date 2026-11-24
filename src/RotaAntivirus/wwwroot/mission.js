// Radar de mission. Le decor bouge seul, mais chaque cible affichee vient d'une vraie detection du moteur.
(function () {
  'use strict';
  const cv = document.getElementById('mission'); const g = cv.getContext('2d');
  const reduit = window.matchMedia('(prefers-reduced-motion: reduce)');
  const COUL = { veille: [85, 230, 255], scan: [85, 230, 255], alerte: [255, 169, 77], ok: [98, 245, 181] };
  const NOMS = { REPARER: 'À RÉPARER', REMPLACER: 'À REMPLACER', GRENAM: 'FAUX PROGRAMME', ISOLER: 'À ISOLER', RETELECHARGER: 'À RETÉLÉCHARGER', A_VERIFIER: 'À VÉRIFIER' };
  const POLICE = '"Cascadia Mono",Consolas,monospace';
  let mode = 'veille', pct = 0, W = 0, H = 0, cx = 0, cy = 0, R = 0, t = 0, avant = 0, rot = 0, balai = -Math.PI / 2, numero = 0;
  let c = COUL.veille.slice();
  const paquets = [], ondes = [], cibles = new Map();

  const points = [];
  const NB = 560, OR = Math.PI * (3 - Math.sqrt(5));
  for (let i = 0; i < NB; i++) { const y = 1 - (i / (NB - 1)) * 2, r = Math.sqrt(1 - y * y), a = i * OR; points.push([Math.cos(a) * r, y, Math.sin(a) * r]); }

  function teinte(a) { return 'rgba(' + Math.round(c[0]) + ',' + Math.round(c[1]) + ',' + Math.round(c[2]) + ',' + a + ')'; }
  function hache(s) { let h = 2166136261; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return h >>> 0; }
  function surSphere(cle) { const h = hache(cle), lon = (h % 6283) / 1000, y = (((h >>> 13) % 1500) / 1000) - .75, r = Math.sqrt(1 - y * y); return [Math.cos(lon) * r, y, Math.sin(lon) * r]; }
  function projette(p, S) {
    const co = Math.cos(rot), si = Math.sin(rot), x = p[0] * co + p[2] * si, z0 = -p[0] * si + p[2] * co;
    const ti = .36, ct = Math.cos(ti), st = Math.sin(ti), y = p[1] * ct - z0 * st, z = p[1] * st + z0 * ct;
    return { x: cx + x * S, y: cy + y * S, z: z };
  }

  function taille() {
    const r = cv.getBoundingClientRect(), d = Math.min(window.devicePixelRatio || 1, 2);
    W = r.width; H = r.height; if (!W || !H) return; cv.width = Math.round(W * d); cv.height = Math.round(H * d); g.setTransform(d, 0, 0, d, 0, 0);
    cx = W / 2; cy = H / 2; R = Math.max(90, Math.min(H / 2 - 18, W / 2 - 18, 300));
  }

  function cadran() {
    g.lineWidth = 1;
    [1, .84, .62].forEach((k, i) => { g.strokeStyle = teinte(i === 0 ? .42 : .16); g.beginPath(); g.arc(cx, cy, R * k, 0, Math.PI * 2); g.stroke(); });
    for (let d = 0; d < 360; d += 5) {
      const a = (d - 90) * Math.PI / 180, long = d % 30 === 0, r1 = R * (long ? .955 : .98), co = Math.cos(a), si = Math.sin(a);
      g.strokeStyle = teinte(long ? .75 : .26); g.beginPath(); g.moveTo(cx + co * r1, cy + si * r1); g.lineTo(cx + co * R, cy + si * R); g.stroke();
      if (long && R > 150) { g.fillStyle = teinte(.62); g.font = '9px ' + POLICE; g.textAlign = 'center'; g.textBaseline = 'middle'; g.fillText(String(d).padStart(3, '0'), cx + co * R * .91, cy + si * R * .91); }
    }
    g.setLineDash([3, 7]); g.strokeStyle = teinte(.16); g.beginPath(); g.moveTo(cx - R, cy); g.lineTo(cx + R, cy); g.moveTo(cx, cy - R); g.lineTo(cx, cy + R); g.stroke(); g.setLineDash([]);
    g.lineWidth = 3; g.strokeStyle = teinte(.8);
    for (let i = 0; i < 3; i++) { const a = t * (i % 2 ? -.22 : .3) + i * 2.1; g.beginPath(); g.arc(cx, cy, R * (1.025 + i * .012), a, a + .5 + i * .16); g.stroke(); }
    g.lineWidth = 1;
    if (mode === 'scan') {
      g.strokeStyle = 'rgba(190,220,250,.16)'; g.lineWidth = 4; g.beginPath(); g.arc(cx, cy, R * .78, 0, Math.PI * 2); g.stroke();
      g.strokeStyle = teinte(1); g.shadowColor = teinte(.9); g.shadowBlur = 12; g.beginPath(); g.arc(cx, cy, R * .78, -Math.PI / 2, -Math.PI / 2 + Math.PI * 2 * pct); g.stroke(); g.shadowBlur = 0; g.lineWidth = 1;
    }
  }

  function faisceau() {
    if (mode !== 'scan' && mode !== 'veille') return;
    const fort = mode === 'scan' ? .34 : .12, l = 1.15;
    g.save(); g.beginPath(); g.arc(cx, cy, R * .985, 0, Math.PI * 2); g.clip();
    const q = g.createConicGradient(balai - l, cx, cy), f = l / (Math.PI * 2);
    q.addColorStop(0, teinte(0)); q.addColorStop(f, teinte(fort)); q.addColorStop(f + .0005, teinte(0)); q.addColorStop(1, teinte(0));
    g.fillStyle = q; g.fillRect(cx - R, cy - R, R * 2, R * 2);
    g.strokeStyle = teinte(mode === 'scan' ? .95 : .35); g.shadowColor = teinte(.9); g.shadowBlur = mode === 'scan' ? 10 : 0; g.beginPath(); g.moveTo(cx, cy); g.lineTo(cx + Math.cos(balai) * R, cy + Math.sin(balai) * R); g.stroke();
    g.restore();
  }

  function sphere() {
    const S = R * .56;
    const halo = g.createRadialGradient(cx, cy, S * .2, cx, cy, S * 1.2); halo.addColorStop(0, teinte(.13)); halo.addColorStop(1, teinte(0)); g.fillStyle = halo; g.beginPath(); g.arc(cx, cy, S * 1.2, 0, Math.PI * 2); g.fill();
    g.fillStyle = 'rgba(7,13,23,.74)'; g.beginPath(); g.arc(cx, cy, S, 0, Math.PI * 2); g.fill();
    for (const p of points) { const q = projette(p, S); const a = q.z > 0 ? .25 + q.z * .7 : .04 + (1 + q.z) * .07, s = q.z > 0 ? 1.7 : 1; g.fillStyle = teinte(a.toFixed(3)); g.fillRect(q.x - s / 2, q.y - s / 2, s, s); }
    for (let o = 0; o < 3; o++) {
      const inc = .55 + o * .62, b = o * 1.2 + t * .05, r1 = R * (.67 + o * .035), r2 = r1 * Math.abs(Math.cos(inc)) + 12;
      g.strokeStyle = teinte(.2); g.beginPath(); g.ellipse(cx, cy, r1, r2, b, 0, Math.PI * 2); g.stroke();
      const a = t * (.55 - o * .12) + o * 2, ca = Math.cos(a) * r1, sa = Math.sin(a) * r2, x = cx + ca * Math.cos(b) - sa * Math.sin(b), y = cy + ca * Math.sin(b) + sa * Math.cos(b);
      g.fillStyle = teinte(1); g.shadowColor = teinte(1); g.shadowBlur = 8; g.beginPath(); g.arc(x, y, 2.4, 0, Math.PI * 2); g.fill(); g.shadowBlur = 0;
    }
  }

  function flux(dt) {
    for (let i = paquets.length - 1; i >= 0; i--) {
      const p = paquets[i]; p.v += dt * p.k; if (p.v >= 1) { paquets.splice(i, 1); continue; }
      const r1 = R * (.98 - p.v * .42), r2 = r1 + R * .07, co = Math.cos(p.a), si = Math.sin(p.a);
      g.strokeStyle = teinte((1 - p.v).toFixed(3)); g.lineWidth = 1.4; g.beginPath(); g.moveTo(cx + co * r1, cy + si * r1); g.lineTo(cx + co * r2, cy + si * r2); g.stroke(); g.lineWidth = 1;
    }
    for (let i = ondes.length - 1; i >= 0; i--) {
      const o = ondes[i]; o.v += dt * .8; if (o.v >= 1) { ondes.splice(i, 1); continue; }
      g.strokeStyle = teinte(((1 - o.v) * .9).toFixed(3)); g.lineWidth = 2; g.beginPath(); g.arc(cx, cy, R * (.3 + o.v * .75), 0, Math.PI * 2); g.stroke(); g.lineWidth = 1;
    }
  }

  function viseur(x, y, s, a, couleur) {
    const k = s * .42; g.strokeStyle = couleur; g.lineWidth = 1.6; g.globalAlpha = a;
    [[-1, -1], [1, -1], [1, 1], [-1, 1]].forEach(([u, w]) => { g.beginPath(); g.moveTo(x + u * s, y + w * (s - k)); g.lineTo(x + u * s, y + w * s); g.lineTo(x + u * (s - k), y + w * s); g.stroke(); });
    g.fillStyle = couleur; g.beginPath(); g.arc(x, y, 2.2, 0, Math.PI * 2); g.fill(); g.lineWidth = 1; g.globalAlpha = 1;
  }

  function coupe(s, n) { return s.length > n ? '…' + s.slice(-(n - 1)) : s; }

  function etiquettes(liste) {
    const place = W - (cx + R), large = Math.min(236, Math.max(150, place + 58)), haut = 46;
    liste.slice(0, 5).forEach((e, i) => {
      const gauche = i % 2 === 1, col = gauche ? 8 : W - large - 8, rang = Math.floor(i / 2), y = gauche ? H - 16 - haut - rang * (haut + 10) : 12 + rang * (haut + 10);
      const entree = Math.min(1, e.age * 3); g.globalAlpha = entree;
      const ax = gauche ? col + large : col, ay = y + haut / 2, cou = gauche ? ax + 16 : ax - 16;
      g.strokeStyle = 'rgba(255,169,77,.75)'; g.beginPath(); g.moveTo(e.x, e.y); g.lineTo(cou, ay); g.lineTo(ax, ay); g.stroke();
      g.fillStyle = 'rgba(14,18,26,.9)'; g.fillRect(col, y, large, haut); g.strokeStyle = 'rgba(255,169,77,.7)'; g.strokeRect(col + .5, y + .5, large - 1, haut - 1); g.fillStyle = '#FFA94D'; g.fillRect(gauche ? col + large - 3 : col, y, 3, haut);
      g.textAlign = 'left'; g.textBaseline = 'top'; g.font = '600 10px ' + POLICE; g.fillStyle = '#FFC285'; g.fillText('CIBLE ' + String(e.n).padStart(2, '0') + ' · ' + (e.age < 1.2 && Math.floor(e.age * 7) % 2 ? 'VERROUILLAGE' : e.nom), col + 10, y + 8);
      g.font = '11px ' + POLICE; g.fillStyle = '#EEF4FF'; g.fillText(coupe(e.fichier, Math.floor((large - 18) / 6.7)), col + 10, y + 26);
      g.globalAlpha = 1;
    });
  }

  function dessinerCibles(dt) {
    const S = R * .56, vue = [];
    for (const e of cibles.values()) {
      e.age += dt; const q = projette(e.pos, S); e.x = q.x; e.y = q.y; const lock = Math.min(1, e.age / .7), s = 34 - 23 * (1 - Math.pow(1 - lock, 3)), a = q.z > -.15 ? 1 : .35;
      viseur(q.x, q.y, s + (lock >= 1 ? Math.sin(t * 4 + e.n) * 1.4 : 0), a, '#FFA94D');
      if (lock >= 1) { const v = (t * .8 + e.n * .17) % 1; g.strokeStyle = 'rgba(255,169,77,' + ((1 - v) * .55 * a).toFixed(3) + ')'; g.beginPath(); g.arc(q.x, q.y, 8 + v * 22, 0, Math.PI * 2); g.stroke(); }
      vue.push(e);
    }
    vue.sort((u, w) => w.n - u.n); etiquettes(vue);
  }

  function image(ms) {
    const dt = Math.min(.05, (ms - avant) / 1000 || 0); avant = ms; const fixe = reduit.matches, pas = fixe ? 0 : dt;
    t += pas; rot += pas * (mode === 'scan' ? .55 : .16); balai += pas * (mode === 'scan' ? 2.7 : .55);
    const but = COUL[mode]; for (let i = 0; i < 3; i++) c[i] += (but[i] - c[i]) * Math.min(1, (fixe ? 1 : dt * 4));
    if (W && H) { g.clearRect(0, 0, W, H); cadran(); faisceau(); sphere(); flux(pas); dessinerCibles(fixe ? 1 : pas); }
    if (fixe) setTimeout(() => requestAnimationFrame(image), 500); else requestAnimationFrame(image);
  }

  window.Mission = {
    mode(m) { if (m === 'ok' && mode !== 'ok') ondes.push({ v: 0 }, { v: -.25 }); mode = m; },
    progres(p) { pct = Math.max(0, Math.min(1, p)); },
    fichier() { if (reduit.matches || paquets.length > 46) return; for (let i = 0; i < 3; i++) paquets.push({ a: Math.random() * Math.PI * 2, v: 0, k: 1.2 + Math.random() * 1.3 }); },
    cible(type, fichier) {
      const cle = type + '|' + fichier; if (cibles.has(cle)) return;
      numero++; cibles.set(cle, { n: numero, nom: NOMS[type] || type, fichier: fichier, pos: surSphere(fichier), age: reduit.matches ? 2 : 0, x: cx, y: cy });
    },
    vider() { cibles.clear(); paquets.length = 0; pct = 0; numero = 0; }
  };
  if (window.ResizeObserver) new ResizeObserver(taille).observe(cv); window.addEventListener('resize', taille); taille();
  requestAnimationFrame(image);
})();
