(function () {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const hote = window.chrome && window.chrome.webview;
  const etat = { disques: [], disque: '', occupe: false, resultat: null, vue: 'controle', ecranControle: 'ecranAccueil', filtre: 'tous', recherche: '' };
  const envoyer = (cmd, valeur) => { if (hote) hote.postMessage({ cmd: cmd, disque: etat.disque, valeur: valeur === undefined ? '' : String(valeur) }); };
  const ecrans = ['ecranAccueil', 'ecranAnalyse', 'ecranResultat', 'ecranQuarantaine', 'ecranBibliotheque', 'ecranHistorique', 'ecranAide'];
  const FILTRES = [['tous', 'Tous'], ['traiter', 'À traiter'], ['verifier', 'À vérifier'], ['inerte', 'Inertes']];
  const TRAITER = ['REPARER', 'REMPLACER', 'RESTAURER', 'GRENAM', 'ISOLER', 'RETELECHARGER'];
  let minuteur = null, debut = 0, chrono = null, refFait = 0, refTemps = 0, dernierCourant = '';
  const mission = window.Mission;

  function afficherChrono() { const s = Math.max(0, Math.floor((Date.now() - debut) / 1000)); $('tTemps').textContent = 'T+' + String(Math.floor(s / 60)).padStart(2, '0') + ':' + String(s % 60).padStart(2, '0'); }
  function demarrerChrono() { debut = Date.now(); refFait = 0; refTemps = debut; afficherChrono(); clearInterval(chrono); chrono = setInterval(afficherChrono, 500); }
  function arreterChrono() { clearInterval(chrono); chrono = null; }
  function telemetrie(phase, lus, cibles) { $('tPhase').textContent = phase; $('tLus').textContent = nombre(lus); $('tCibles').textContent = String(cibles); $('tDisque').textContent = nomDisque(); }
  function ajouterFlux(texte, alerte) {
    const z = $('fluxDirect'), l = document.createElement('div'); l.textContent = (alerte ? '[CIBLE] ' : '> ') + texte; if (alerte) l.className = 'alerte-flux';
    z.appendChild(l); while (z.children.length > 4) z.removeChild(z.firstChild);
  }

  function montrer(id) { ecrans.forEach((e) => { $(e).hidden = e !== id; }); }
  function ambiance(c) { $('app').className = 'app' + (c ? ' ' + c : ''); }
  function coeur(haut, valeur, bas) { $('coeurHaut').textContent = haut; $('coeurValeur').textContent = valeur; $('coeurBas').textContent = bas; }
  function nomDisque() { const d = etat.disques.find((x) => x.racine === etat.disque); return d ? d.nom : '--'; }
  function nombre(n) { return Number(n).toLocaleString('fr-FR'); }
  function bouton(texte, classe, action, aide) { const b = document.createElement('button'); b.className = classe; b.textContent = texte; if (aide) b.setAttribute('aria-label', aide); b.addEventListener('click', action); return b; }
  function notifier(t) { $('notif').textContent = t; clearTimeout(minuteur); minuteur = setTimeout(() => { $('notif').textContent = ''; }, 3000); }

  function occuper(v) {
    etat.occupe = v;
    document.querySelectorAll('.disque').forEach((b) => { b.disabled = v; });
    document.querySelectorAll('.onglet').forEach((b) => { b.disabled = v; });
  }

  function choisirVue(v) {
    etat.vue = v;
    document.querySelectorAll('.onglet').forEach((b) => { const a = b.dataset.vue === v; b.classList.toggle('actif', a); if (a) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current'); });
    if (v === 'controle') montrer(etat.ecranControle);
    if (v === 'quarantaine') { $('nomDisqueQ').textContent = nomDisque(); montrer('ecranQuarantaine'); envoyer('quarantaine'); }
    if (v === 'historique') { montrer('ecranHistorique'); envoyer('historique'); }
    if (v === 'bibliotheque') { montrer('ecranBibliotheque'); envoyer('bibliotheque'); }
    if (v === 'aide') montrer('ecranAide');
  }

  function controle(id) { etat.ecranControle = id; if (etat.vue !== 'controle') choisirVue('controle'); else montrer(id); }

  function dessinerDisques() {
    const zone = $('disques'); zone.replaceChildren();
    etat.disques.forEach((d) => {
      const b = document.createElement('button');
      b.className = 'disque' + (d.racine === etat.disque ? ' actif' : '');
      b.textContent = d.nom; b.title = d.label + ' (' + d.go + ' Go)' + (d.systeme ? ' - Windows' : '');
      b.setAttribute('aria-pressed', d.racine === etat.disque ? 'true' : 'false'); b.disabled = etat.occupe;
      b.addEventListener('click', () => { etat.disque = d.racine; etat.resultat = null; dessinerDisques(); accueil(); if (etat.vue === 'quarantaine') choisirVue('quarantaine'); });
      zone.appendChild(b);
    });
  }

  function accueil() {
    ambiance(''); $('noyau').className = 'noyau'; coeur('SYSTÈME', nomDisque(), 'En attente');
    $('nomDisque').textContent = nomDisque(); $('bLancer').disabled = !etat.disque; $('infos').textContent = "Aucun programme du disque n'est lancé";
    etat.ecranControle = 'ecranAccueil'; if (etat.vue === 'controle') montrer('ecranAccueil');
    arreterChrono(); mission.vider(); mission.mode('veille'); $('fluxDirect').replaceChildren(); $('tTemps').textContent = 'T+00:00'; $('tDebit').textContent = '0 /s'; telemetrie('EN VEILLE', 0, 0);
  }

  function debutTravail(titre) {
    occuper(true); ambiance(''); $('noyau').className = 'noyau scan'; $('titreAnalyse').textContent = titre;
    $('piste').classList.add('indetermine'); $('jauge').style.width = '0'; $('lus').textContent = '0'; $('trouves').textContent = '0'; $('courant').textContent = '';
    coeur('EN COURS', '...', 'Préparation'); controle('ecranAnalyse');
    mission.vider(); mission.mode('scan'); $('fluxDirect').replaceChildren(); dernierCourant = ''; $('tDebit').textContent = '0 /s'; telemetrie(titre.toUpperCase(), 0, 0); demarrerChrono();
  }

  function avancement(m) {
    const pct = m.total > 0 ? Math.min(100, Math.floor(100 * m.fait / m.total)) : 0;
    $('piste').classList.toggle('indetermine', m.total === 0); $('jauge').style.width = pct + '%'; $('piste').setAttribute('aria-valuenow', String(pct));
    $('lus').textContent = nombre(m.fait); $('trouves').textContent = String(m.trouves); $('courant').textContent = m.courant || m.phase;
    coeur(m.phase.toUpperCase(), m.total > 0 ? pct + '%' : '...', m.total > 0 ? m.fait + ' / ' + m.total : 'Préparation');
    mission.progres(m.total > 0 ? m.fait / m.total : 0);
    if (m.courant && m.courant !== dernierCourant) { dernierCourant = m.courant; mission.fichier(); ajouterFlux(m.courant, false); }
    (m.cibles || []).slice().reverse().forEach((c) => { const i = c.indexOf('|'), type = c.slice(0, i), f = c.slice(i + 1); const cle = 'vu:' + c; if (!etat[cle]) { etat[cle] = true; ajouterFlux(f, true); } mission.cible(type, f); });
    const now = Date.now(); if (now - refTemps >= 700) { $('tDebit').textContent = nombre(Math.max(0, Math.round((m.fait - refFait) * 1000 / (now - refTemps)))) + ' /s'; refFait = m.fait; refTemps = now; }
    telemetrie(m.phase.toUpperCase(), m.fait, m.trouves);
  }

  function ligneFichier(e, i) {
    const l = document.createElement('div'); l.className = 'ligne' + (e.type === 'RESTE' ? ' discret' : '');
    if (i < 12) l.style.animationDelay = (i * 30) + 'ms'; else l.style.animation = 'none';
    const g = document.createElement('div'); const f = document.createElement('div'); f.className = 'fichier mono'; f.textContent = e.relatif;
    const d = document.createElement('div'); d.className = 'detail'; d.textContent = e.detail; g.append(f, d);
    const dr = document.createElement('div'); dr.className = 'droite';
    const s = document.createElement('span'); s.className = 'etat'; s.textContent = e.libelle;
    const m = document.createElement('div'); m.className = 'mini-actions';
    m.append(bouton('Emplacement', 'mini', () => envoyer('emplacement', e.index), 'Montrer ' + e.relatif + ' dans l’Explorateur'), bouton('Copier', 'mini', () => envoyer('copier', e.index), 'Copier le chemin de ' + e.relatif));
    dr.append(s, m); l.append(g, dr); return l;
  }

  function garder(e) {
    const q = etat.recherche.toLowerCase();
    if (q && !e.relatif.toLowerCase().includes(q)) return false;
    if (etat.filtre === 'traiter') return TRAITER.includes(e.type);
    if (etat.filtre === 'verifier') return e.type === 'A_VERIFIER';
    if (etat.filtre === 'inerte') return e.type === 'RESTE';
    return true;
  }

  function dessinerListe() {
    const m = etat.resultat; if (!m) return;
    const z = $('filtres'); z.replaceChildren();
    const compte = { tous: m.elements.length, traiter: m.elements.filter((x) => TRAITER.includes(x.type)).length, verifier: m.elements.filter((x) => x.type === 'A_VERIFIER').length, inerte: m.elements.filter((x) => x.type === 'RESTE').length };
    FILTRES.forEach(([id, nom]) => { const b = bouton(nom + ' (' + compte[id] + ')', 'filtre' + (etat.filtre === id ? ' actif' : ''), () => { etat.filtre = id; dessinerListe(); }); b.setAttribute('aria-pressed', etat.filtre === id ? 'true' : 'false'); z.appendChild(b); });
    const zone = $('liste'); zone.replaceChildren(); const vus = m.elements.filter(garder);
    vus.forEach((e, i) => zone.appendChild(ligneFichier(e, i)));
    if (vus.length === 0) { const v = document.createElement('div'); v.className = 'vide'; v.textContent = 'Aucun fichier pour ce filtre.'; zone.appendChild(v); }
  }

  function resultat(m) {
    occuper(false); etat.resultat = m; etat.filtre = 'tous'; etat.recherche = ''; $('recherche').value = ''; const pret = m.niveau === 'PRET';
    ambiance(pret ? 'ok' : 'alerte'); $('noyau').className = 'noyau';
    coeur(pret ? 'CONTRÔLE' : 'ALERTE', pret ? 'OK' : String(m.bloquants.length), pret ? 'Aucun problème connu' : 'point(s) à régler');
    $('titreResultat').textContent = m.titre; $('message').hidden = !m.message; $('message').textContent = m.message || '';
    const pts = $('points'); pts.replaceChildren();
    (pret ? m.reserves : m.bloquants).forEach((t) => { const li = document.createElement('li'); li.textContent = t; pts.appendChild(li); });
    const aListe = m.elements.length > 0; $('outilsListe').hidden = !aListe; $('liste').hidden = !aListe; dessinerListe();
    const ext = !m.systeme;
    $('bReparer').hidden = !(m.aReparer > 0); $('bReparer').textContent = 'Réparer (' + m.aReparer + ')';
    $('bIsoler').hidden = !(m.aIsoler > 0); $('bIsoler').textContent = 'Isoler (' + m.aIsoler + ')';
    $('bRanger').hidden = !(ext && m.recycler);
    $('bBlocage').hidden = !(ext && !m.recycler && !m.blocage);
    $('bSortir').hidden = !(ext && m.quarantaine);
    $('bCaches').hidden = !(ext && m.caches > 0);
    $('bTout').hidden = !(m.aTraiter > 0 || (ext && (m.caches > 0 || m.recycler || !m.blocage)));
    $('bRemettre').hidden = !(ext && m.archive && !m.quarantaine);
    $('bAnnuler').hidden = !m.annulable;
    $('bRapport').hidden = false; $('bNouvelle').hidden = false;
    $('bDefender').hidden = !!m.defenderFait; $('bComparer').hidden = !(m.references > 0) || !!m.bibliothequeFaite;
    $('zoneCertificat').hidden = !(pret && ext);
    $('infos').textContent = nombre(m.total) + ' fichiers, ' + nombre(m.examines) + ' examinés' + (m.tronque ? ', ' + m.nbElements + ' à voir dans le rapport' : '');
    arreterChrono(); Object.keys(etat).forEach((k) => { if (k.startsWith('vu:')) delete etat[k]; });
    const vraies = m.elements.filter((e) => e.type !== 'RESTE'); mission.vider(); vraies.forEach((e) => mission.cible(e.type, e.relatif)); mission.progres(1); mission.mode(pret ? 'ok' : 'alerte');
    $('tDebit').textContent = '0 /s'; telemetrie(pret ? 'CONTRÔLE OK' : 'ALERTE', m.examines, vraies.length);
    controle('ecranResultat');
  }

  function erreur(t) {
    occuper(false); etat.resultat = null; ambiance('alerte'); $('noyau').className = 'noyau'; coeur('ERREUR', '!', 'Opération arrêtée');
    $('titreResultat').textContent = 'Opération impossible'; $('message').hidden = false; $('message').textContent = t;
    $('points').replaceChildren(); $('liste').replaceChildren(); $('liste').hidden = true; $('outilsListe').hidden = true;
    ['bTout', 'bReparer', 'bIsoler', 'bCaches', 'bRanger', 'bBlocage', 'bSortir', 'bRemettre', 'bAnnuler', 'bRapport', 'bDefender', 'bComparer', 'zoneCertificat'].forEach((b) => { $(b).hidden = true; }); $('bNouvelle').hidden = false;
    arreterChrono(); mission.vider(); mission.mode('alerte'); telemetrie('ERREUR', 0, 0);
    controle('ecranResultat');
  }

  function ligneSimple(titre, detail, droite, classe) {
    const l = document.createElement('div'); l.className = 'ligne ' + (classe || 'neutre'); l.style.animation = 'none';
    const g = document.createElement('div'); const f = document.createElement('div'); f.className = 'fichier mono'; f.textContent = titre;
    const d = document.createElement('div'); d.className = 'detail'; d.textContent = detail; g.append(f, d); l.appendChild(g);
    if (droite) l.appendChild(droite); return l;
  }

  function quarantaine(m) {
    if (m.disque !== etat.disque) return;
    const z = $('listeQuarantaine'); z.replaceChildren();
    const total = m.sessions.reduce((a, s) => a + s.fichiers, 0);
    $('texteQuarantaine').textContent = m.sessions.length ? total + ' fichier(s) gardés sur ce disque. Ils sont inactifs, mais ce dossier ne doit jamais partir chez un client.' : (m.archive ? 'Rien sur ce disque. Une archive de sa quarantaine est gardée sur ce PC.' : 'Aucune quarantaine sur ce disque.');
    m.sessions.forEach((s) => { const e = document.createElement('span'); e.className = 'etat'; e.textContent = s.fichiers + ' fichier(s), ' + s.mo + ' Mo'; z.appendChild(ligneSimple(s.genre, s.date + ' • ' + s.nom, e)); });
    z.hidden = m.sessions.length === 0;
  }

  function historique(m) {
    const z = $('listeHistorique'); z.replaceChildren();
    if (!m.rapports.length) { const v = document.createElement('div'); v.className = 'vide'; v.textContent = 'Aucun contrôle enregistré.'; z.appendChild(v); return; }
    m.rapports.forEach((r) => {
      const dr = document.createElement('div'); dr.className = 'droite';
      const e = document.createElement('span'); e.className = 'etat'; e.textContent = r.verdict.startsWith('Prêt') ? 'Prêt' : (r.verdict.startsWith('Aucun') ? 'Aucun problème' : 'À régler');
      dr.append(e, bouton('Ouvrir', 'mini', () => envoyer('ouvrirRapport', r.nom), 'Ouvrir le rapport du ' + r.date));
      z.appendChild(ligneSimple((r.disque || 'Disque') + '  ' + r.date, r.verdict, dr, e.textContent === 'À régler' ? '' : 'ok-ligne'));
    });
  }

  function bibliotheque(m) {
    const z = $('listeBibliotheque'); z.replaceChildren();
    if (!m.references.length) { const v = document.createElement('div'); v.className = 'vide'; v.textContent = 'Aucune copie maître pour l’instant. Ajoute le dossier propre de ton premier jeu.'; z.appendChild(v); return; }
    m.references.forEach((r) => {
      const dr = document.createElement('div'); dr.className = 'droite';
      const e = document.createElement('span'); e.className = 'etat'; e.textContent = r.fichiers + ' programme(s)';
      dr.append(e, bouton('Retirer', 'mini', () => envoyer('supprimerReference', r.nom), 'Retirer ' + r.nom + ' de la bibliothèque'));
      z.appendChild(ligneSimple(r.nom, (r.date ? r.date + ' • ' : '') + r.source, dr, 'ok-ligne'));
    });
  }

  function recevoir(m) {
    switch (m.type) {
      case 'disques':
        etat.disques = m.disques;
        if (!etat.disques.some((d) => d.racine === etat.disque)) { const x = etat.disques.find((d) => !d.systeme) || etat.disques[0]; etat.disque = x ? x.racine : ''; etat.resultat = null; if (!etat.occupe) accueil(); }
        dessinerDisques(); if (!etat.occupe && !etat.resultat && etat.ecranControle === 'ecranAccueil') accueil(); break;
      case 'debut': $('bArreter').hidden = false; debutTravail('Analyse en cours'); break;
      case 'action': debutTravail(m.titre); $('bArreter').hidden = true; break;
      case 'avancement': avancement(m); break;
      case 'resultat': $('bArreter').hidden = false; resultat(m); break;
      case 'arrete': $('bArreter').hidden = false; occuper(false); accueil(); break;
      case 'erreur': $('bArreter').hidden = false; erreur(m.message); break;
      case 'quarantaine': quarantaine(m); break;
      case 'historique': historique(m); break;
      case 'info': notifier(m.message); break;
      case 'analyse2': $('bArreter').hidden = false; debutTravail(m.titre); break;
      case 'retour': occuper(false); if (etat.resultat) resultat(etat.resultat); else accueil(); choisirVue(m.vue || 'controle'); if (m.message) notifier(m.message); break;
      case 'bibliotheque': bibliotheque(m); break;
    }
  }

  document.querySelectorAll('.onglet').forEach((b) => b.addEventListener('click', () => choisirVue(b.dataset.vue)));
  [['bTout', 'tout'], ['bLancer', 'analyser'], ['bNouvelle', 'analyser'], ['bArreter', 'arreter'], ['bReparer', 'reparer'], ['bIsoler', 'isoler'], ['bCaches', 'caches'], ['bRanger', 'ranger'], ['bBlocage', 'blocage'], ['bSortir', 'sortir'], ['bRemettre', 'remettre'], ['bAnnuler', 'annuler'], ['bRapport', 'rapport'], ['bActuQ', 'quarantaine'], ['bDossierRapports', 'dossierRapports']].forEach(([id, cmd]) => $(id).addEventListener('click', () => envoyer(cmd)));
  $('bVersControle').addEventListener('click', () => choisirVue('controle'));
  [['bDefender', 'defender'], ['bComparer', 'comparer'], ['bAjouterRef', 'ajouterReference']].forEach(([id, cmd]) => $(id).addEventListener('click', () => envoyer(cmd)));
  $('bCertificat').addEventListener('click', () => envoyer('certificat', $('clientNom').value));
  $('recherche').addEventListener('input', (e) => { etat.recherche = e.target.value; dessinerListe(); });
  if (hote) { hote.addEventListener('message', (e) => recevoir(e.data)); envoyer('pret'); }
  window.addEventListener('focus', () => { if (!etat.occupe) envoyer('pret'); });
})();
