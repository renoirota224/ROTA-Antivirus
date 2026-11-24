(function () {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const hote = window.chrome && window.chrome.webview;
  const envoyer = (cmd) => { if (hote) hote.postMessage({ cmd: cmd, disque: etat.disque }); };
  const etat = { disques: [], disque: '', occupe: false, resultat: null };
  const ecrans = ['ecranAccueil', 'ecranAnalyse', 'ecranResultat'];

  function montrer(id) { ecrans.forEach((e) => { $(e).hidden = e !== id; }); }
  function ambiance(c) { $('app').className = 'app' + (c ? ' ' + c : ''); }
  function coeur(haut, valeur, bas) { $('coeurHaut').textContent = haut; $('coeurValeur').textContent = valeur; $('coeurBas').textContent = bas; }
  function nomDisque() { const d = etat.disques.find((x) => x.racine === etat.disque); return d ? d.nom : '--'; }
  function occuper(v) { etat.occupe = v; document.querySelectorAll('.disque').forEach((b) => { b.disabled = v; }); }

  function dessinerDisques() {
    const zone = $('disques'); zone.replaceChildren();
    etat.disques.forEach((d) => {
      const b = document.createElement('button');
      b.className = 'disque' + (d.racine === etat.disque ? ' actif' : '');
      b.textContent = d.nom; b.title = d.label + ' (' + d.go + ' Go)' + (d.systeme ? ' - Windows' : '');
      b.setAttribute('aria-pressed', d.racine === etat.disque ? 'true' : 'false'); b.disabled = etat.occupe;
      b.addEventListener('click', () => { etat.disque = d.racine; etat.resultat = null; dessinerDisques(); accueil(); });
      zone.appendChild(b);
    });
  }

  function accueil() {
    ambiance(''); $('noyau').className = 'noyau'; coeur('SYSTÈME', nomDisque(), 'En attente');
    $('nomDisque').textContent = nomDisque(); $('bLancer').disabled = !etat.disque; montrer('ecranAccueil');
  }

  function debutTravail(titre) {
    occuper(true); ambiance(''); $('noyau').className = 'noyau scan'; $('titreAnalyse').textContent = titre;
    $('piste').classList.add('indetermine'); $('jauge').style.width = '0'; $('lus').textContent = '0'; $('trouves').textContent = '0'; $('courant').textContent = '';
    coeur('EN COURS', '...', 'Préparation'); montrer('ecranAnalyse');
  }

  function avancement(m) {
    const pct = m.total > 0 ? Math.min(100, Math.floor(100 * m.fait / m.total)) : 0;
    $('piste').classList.toggle('indetermine', m.total === 0); $('jauge').style.width = pct + '%'; $('piste').setAttribute('aria-valuenow', String(pct));
    $('lus').textContent = Number(m.fait).toLocaleString('fr-FR'); $('trouves').textContent = String(m.trouves); $('courant').textContent = m.courant || m.phase;
    coeur(m.phase.toUpperCase(), m.total > 0 ? pct + '%' : '...', m.total > 0 ? m.fait + ' / ' + m.total : 'Préparation');
  }

  function ligne(e) {
    const l = document.createElement('div'); l.className = 'ligne' + (e.type === 'RESTE' ? ' discret' : '');
    const g = document.createElement('div'); const f = document.createElement('div'); f.className = 'fichier mono'; f.textContent = e.relatif;
    const d = document.createElement('div'); d.className = 'detail'; d.textContent = e.detail; g.append(f, d);
    const s = document.createElement('span'); s.className = 'etat'; s.textContent = e.libelle; l.append(g, s); return l;
  }

  function resultat(m) {
    occuper(false); etat.resultat = m; const pret = m.niveau === 'PRET';
    ambiance(pret ? 'ok' : 'alerte'); $('noyau').className = 'noyau';
    coeur(pret ? 'CONTRÔLE' : 'ALERTE', pret ? 'OK' : String(m.bloquants.length), pret ? 'Aucun problème connu' : 'point(s) à régler');
    $('titreResultat').textContent = m.titre; $('message').hidden = !m.message; $('message').textContent = m.message || '';
    const pts = $('points'); pts.replaceChildren();
    (pret ? m.reserves : m.bloquants).forEach((t) => { const li = document.createElement('li'); li.textContent = t; pts.appendChild(li); });
    const zone = $('liste'); zone.replaceChildren(); zone.hidden = m.elements.length === 0;
    m.elements.forEach((e, i) => { const l = ligne(e); if (i < 12) l.style.animationDelay = (i * 35) + 'ms'; else l.style.animation = 'none'; zone.appendChild(l); });
    $('bReparer').hidden = m.systeme || m.aTraiter === 0; $('bRanger').hidden = m.systeme || !m.recycler; $('bAnnuler').hidden = m.systeme;
    $('infos').textContent = Number(m.total).toLocaleString('fr-FR') + ' fichiers, ' + Number(m.examines).toLocaleString('fr-FR') + ' examinés' + (m.tronque ? ', ' + m.nbElements + ' à voir dans le rapport' : '');
    montrer('ecranResultat');
  }

  function erreur(t) {
    occuper(false); ambiance('alerte'); $('noyau').className = 'noyau'; coeur('ERREUR', '!', 'Opération arrêtée');
    $('titreResultat').textContent = 'Opération impossible'; $('message').hidden = false; $('message').textContent = t;
    $('points').replaceChildren(); $('liste').replaceChildren(); $('liste').hidden = true;
    ['bReparer', 'bRanger', 'bAnnuler'].forEach((b) => { $(b).hidden = true; }); montrer('ecranResultat');
  }

  function recevoir(m) {
    switch (m.type) {
      case 'disques':
        etat.disques = m.disques;
        if (!etat.disques.some((d) => d.racine === etat.disque)) { const x = etat.disques.find((d) => !d.systeme) || etat.disques[0]; etat.disque = x ? x.racine : ''; }
        dessinerDisques(); if (!etat.occupe && !etat.resultat) accueil(); break;
      case 'debut': debutTravail('Analyse en cours'); break;
      case 'action': debutTravail(m.titre); $('bArreter').hidden = true; break;
      case 'avancement': avancement(m); break;
      case 'resultat': $('bArreter').hidden = false; resultat(m); break;
      case 'arrete': $('bArreter').hidden = false; occuper(false); accueil(); break;
      case 'erreur': $('bArreter').hidden = false; erreur(m.message); break;
    }
  }

  $('bLancer').addEventListener('click', () => envoyer('analyser'));
  $('bNouvelle').addEventListener('click', () => envoyer('analyser'));
  $('bArreter').addEventListener('click', () => envoyer('arreter'));
  $('bReparer').addEventListener('click', () => envoyer('reparer'));
  $('bRanger').addEventListener('click', () => envoyer('ranger'));
  $('bAnnuler').addEventListener('click', () => envoyer('annuler'));
  $('bRapport').addEventListener('click', () => envoyer('rapport'));
  if (hote) { hote.addEventListener('message', (e) => recevoir(e.data)); envoyer('pret'); }
  window.addEventListener('focus', () => { if (!etat.occupe) envoyer('pret'); });
})();
