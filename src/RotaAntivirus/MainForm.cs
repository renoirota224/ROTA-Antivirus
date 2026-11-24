using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

namespace RotaAntivirus
{
    public class MainForm : Form
    {
        const string Hote = "app.rota.invalid";
        const string Origine = "https://app.rota.invalid/";
        const int MaxLignes = 500;
        readonly WebView2 web = new WebView2();
        readonly string donnees = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RotaAntivirus");
        CancellationTokenSource arret;
        PlanDisque plan;
        VerdictDisque verdict;
        List<ElementPlan> vue = new List<ElementPlan>();
        string disqueAnalyse = "", rapport = "";
        bool occupe, ecriture;

        string DossierRapports { get { return Path.Combine(donnees, "Rapports"); } }

        public MainForm()
        {
            Text = "ROTA Antivirus";
            ClientSize = new Size(1280, 820);
            MinimumSize = new Size(1000, 700);
            StartPosition = FormStartPosition.CenterScreen;
            BackColor = Color.FromArgb(6, 10, 18);
            try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }
            web.Dock = DockStyle.Fill;
            web.DefaultBackgroundColor = Color.FromArgb(6, 10, 18);
            Controls.Add(web);
            Load += async (s, e) => await Demarrer();
            FormClosing += Fermeture;
        }

        async Task Demarrer()
        {
            try
            {
                Directory.CreateDirectory(donnees);
                var env = await CoreWebView2Environment.CreateAsync(null, Path.Combine(donnees, "Interface"));
                await web.EnsureCoreWebView2Async(env);
                var c = web.CoreWebView2;
                c.Settings.AreDevToolsEnabled = false;
                c.Settings.AreDefaultContextMenusEnabled = false;
                c.Settings.AreBrowserAcceleratorKeysEnabled = false;
                c.Settings.IsStatusBarEnabled = false;
                c.Settings.IsZoomControlEnabled = false;
                c.Settings.AreHostObjectsAllowed = false;
                c.SetVirtualHostNameToFolderMapping(Hote, Path.Combine(AppContext.BaseDirectory, "wwwroot"), CoreWebView2HostResourceAccessKind.Deny);
                c.NavigationStarting += (s, e) => { if (!e.Uri.StartsWith(Origine, StringComparison.OrdinalIgnoreCase)) e.Cancel = true; };
                c.NewWindowRequested += (s, e) => { e.Handled = true; };
                c.WebMessageReceived += Recevoir;
                c.Navigate(Origine + "index.html");
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "L'interface n'a pas pu démarrer. Réinstalle ROTA Antivirus.\n\n" + ex.Message, "ROTA Antivirus", MessageBoxButtons.OK, MessageBoxIcon.Error);
                Close();
            }
        }

        void Fermeture(object sender, FormClosingEventArgs e)
        {
            if (!occupe) return;
            e.Cancel = true;
            MessageBox.Show(this, ecriture ? "Une opération est en cours sur le disque. Attends sa fin et ne le débranche pas." : "Une analyse est en cours. Clique sur Arrêter avant de fermer.", "ROTA Antivirus", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }

        void Envoyer(object message)
        {
            var json = JsonSerializer.Serialize(message);
            Action a = () => { if (!IsDisposed && web.CoreWebView2 != null) web.CoreWebView2.PostWebMessageAsJson(json); };
            if (InvokeRequired) { try { BeginInvoke(a); } catch (InvalidOperationException) { } } else a();
        }

        void Recevoir(object sender, CoreWebView2WebMessageReceivedEventArgs e)
        {
            if (!e.Source.StartsWith(Origine, StringComparison.OrdinalIgnoreCase)) return;
            string cmd = "", disque = "", valeur = "";
            try
            {
                using (var d = JsonDocument.Parse(e.WebMessageAsJson))
                {
                    JsonElement x;
                    if (d.RootElement.TryGetProperty("cmd", out x)) cmd = x.GetString() ?? "";
                    if (d.RootElement.TryGetProperty("disque", out x)) disque = x.GetString() ?? "";
                    if (d.RootElement.TryGetProperty("valeur", out x)) valeur = x.GetString() ?? "";
                }
            }
            catch { return; }
            switch (cmd)
            {
                case "pret": EnvoyerDisques(); break;
                case "analyser": if (!occupe && DisqueConnu(disque)) Analyse(disque); break;
                case "arreter": if (arret != null) arret.Cancel(); break;
                case "reparer": if (!occupe && DisqueConnu(disque) && plan != null && string.Equals(disqueAnalyse, disque, StringComparison.OrdinalIgnoreCase)) Reparer(disque); break;
                case "isoler": if (!occupe && DisqueConnu(disque) && plan != null && string.Equals(disqueAnalyse, disque, StringComparison.OrdinalIgnoreCase)) Isoler(disque); break;
                case "ranger": if (!occupe && PeutEcrire(disque)) Ranger(disque); break;
                case "blocage": if (!occupe && PeutEcrire(disque)) Blocage(disque); break;
                case "sortir": if (!occupe && PeutEcrire(disque)) Sortir(disque); break;
                case "remettre": if (!occupe && Externe(disque)) Remettre(disque); break;
                case "annuler": if (!occupe && DisqueConnu(disque)) AnnulerReparation(disque); break;
                case "rapport": OuvrirFichierRapport(rapport); break;
                case "quarantaine": if (DisqueConnu(disque)) EnvoyerQuarantaine(disque); break;
                case "historique": EnvoyerHistorique(); break;
                case "ouvrirRapport": OuvrirRapportNomme(valeur); break;
                case "dossierRapports": OuvrirDossierRapports(); break;
                case "emplacement": OuvrirEmplacement(valeur); break;
                case "copier": CopierChemin(valeur); break;
            }
        }

        static List<DriveInfo> Disques()
        {
            return DriveInfo.GetDrives().Where(d => (d.DriveType == DriveType.Fixed || d.DriveType == DriveType.Removable) && d.IsReady).ToList();
        }

        static bool DisqueConnu(string disque) { return Disques().Any(d => string.Equals(d.Name, disque, StringComparison.OrdinalIgnoreCase)); }
        static bool Externe(string disque) { return DisqueConnu(disque) && !Moteur.EstDisqueSysteme(disque); }

        bool PeutEcrire(string disque)
        {
            return Externe(disque) && plan != null && string.Equals(disqueAnalyse, disque, StringComparison.OrdinalIgnoreCase);
        }

        void EnvoyerDisques()
        {
            var l = Disques().Select(d => new
            {
                racine = d.Name,
                nom = d.Name.TrimEnd('\\'),
                label = string.IsNullOrEmpty(d.VolumeLabel) ? "Sans nom" : d.VolumeLabel,
                go = (long)Math.Round(d.TotalSize / 1073741824.0),
                systeme = Moteur.EstDisqueSysteme(d.Name)
            }).ToList();
            Envoyer(new { type = "disques", disques = l });
        }

        void Tache(bool ecrit, Action travail)
        {
            occupe = true; ecriture = ecrit;
            Task.Run(() =>
            {
                try { travail(); }
                catch (OperationCanceledException) { Fin(); Envoyer(new { type = "arrete" }); }
                catch (Exception ex) { Fin(); Envoyer(new { type = "erreur", message = ex.Message }); }
            });
        }

        void Fin() { occupe = false; ecriture = false; }

        void Suivi(Avancement a)
        {
            Envoyer(new { type = "avancement", phase = a.Phase, fait = a.Fait, total = a.Total, trouves = a.Trouves, courant = a.Courant, cibles = a.Cibles });
        }

        void Analyse(string disque, string messageAvant = "")
        {
            arret = new CancellationTokenSource(); var jeton = arret.Token;
            plan = null; verdict = null; disqueAnalyse = ""; vue = new List<ElementPlan>();
            Envoyer(new { type = "debut", disque = disque, message = messageAvant });
            Tache(false, () =>
            {
                var p = Moteur.Analyser(disque, Suivi, jeton);
                bool systeme = Moteur.EstDisqueSysteme(disque); var etat = Moteur.Etat(disque); var v = Moteur.Verdict(p, etat, systeme);
                rapport = Moteur.EcrireRapport(DossierRapports, disque, v, p);
                var lignes = p.Elements.OrderBy(x => x.Type == "RESTE" ? 1 : 0).Take(MaxLignes).ToList();
                bool archive = !systeme && Moteur.ArchiveExiste(disque);
                plan = p; verdict = v; disqueAnalyse = disque; vue = lignes; Fin();
                Envoyer(new
                {
                    type = "resultat", disque = disque, niveau = v.Niveau, titre = v.Titre, bloquants = v.Bloquants, reserves = v.Reserves, aTraiter = v.ATraiter, aReparer = v.AReparer, aIsoler = v.AIsoler,
                    total = p.Total, examines = p.Examines, systeme = systeme, recycler = etat.RecyclerDossier, blocage = etat.Blocage, quarantaine = etat.Quarantaine, archive = archive, annulable = Moteur.PeutAnnuler(disque),
                    message = messageAvant, tronque = p.Elements.Count > MaxLignes, nbElements = p.Elements.Count,
                    elements = lignes.Select((x, i) => new { index = i.ToString(), type = x.Type, libelle = Moteur.Libelle(x.Type), relatif = x.Relatif, detail = x.Detail }).ToList()
                });
            });
        }

        bool Confirmer(string texte)
        {
            return MessageBox.Show(this, texte, "ROTA Antivirus", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) == DialogResult.Yes;
        }

        static string Bilan(ResultatAction r, string action)
        {
            var t = action + " : " + r.Ok + " fichier(s), " + r.Echecs + " échec(s).";
            return r.Messages.Count > 0 ? t + " " + string.Join(" ", r.Messages.Take(3)) : t;
        }

        void Action2(string titre, string bilan, string disque, Func<ResultatAction> travail)
        {
            Envoyer(new { type = "action", titre = titre });
            Tache(true, () => { var r = travail(); Fin(); Relancer(disque, Bilan(r, bilan)); });
        }

        void Reparer(string disque)
        {
            if (verdict == null || verdict.AReparer == 0) return;
            if (!Confirmer(verdict.AReparer + " fichier(s) vont être réparés ou remplacés sur " + disque + " et resteront à leur place.\n\nLes originaux sont gardés dans _QUARANTAINE_ROTA." + TexteZone(disque) + "\n\nContinuer ?")) return;
            var p = plan; Action2("Réparation en cours", "Réparation", disque, () => Moteur.Appliquer(p, disque, Suivi, false, "reparer"));
        }

        void Isoler(string disque)
        {
            if (verdict == null || verdict.AIsoler == 0) return;
            if (!Confirmer(verdict.AIsoler + " fichier(s) impossibles à réparer vont être retirés de leur place sur " + disque + " et mis en quarantaine.\n\nRien n'est supprimé, mais un programme isolé ne pourra plus démarrer. Il faudra le retélécharger." + TexteZone(disque) + "\n\nContinuer ?")) return;
            var p = plan; Action2("Isolement en cours", "Isolement", disque, () => Moteur.Appliquer(p, disque, Suivi, false, "isoler"));
        }

        static string TexteZone(string disque)
        {
            return Moteur.EstDisqueSysteme(disque) ? "\n\nSur le disque de Windows, seuls tes dossiers personnels sont touchés. Windows et Program Files restent intacts." : "\nNe débranche pas le disque.";
        }

        void Ranger(string disque)
        {
            int n;
            try { n = Moteur.CompterRecycler(disque); } catch (Exception ex) { Envoyer(new { type = "erreur", message = ex.Message }); return; }
            if (!Confirmer(n + " fichier(s) de RECYCLER.BIN vont être rangés dans _QUARANTAINE_ROTA, sans suppression.\nEnsuite, un fichier vide bloquera le retour de PlugX.\n\nContinuer ?")) return;
            Action2("Rangement en cours", "Rangement", disque, () => Moteur.RangerRecycler(disque, n));
        }

        void Blocage(string disque)
        {
            if (!Confirmer("Poser le blocage PlugX sur " + disque + " ?\n\nUn petit fichier vide et protégé nommé RECYCLER.BIN sera créé à la racine.")) return;
            Action2("Pose du blocage", "Blocage", disque, () => Moteur.PoserBlocageDisque(disque));
        }

        void Sortir(string disque)
        {
            if (!Confirmer("Sortir _QUARANTAINE_ROTA de " + disque + " ?\n\nChaque fichier est copié et vérifié sur ce PC, puis seulement retiré du disque.\nLe disque ne contiendra plus les fichiers infectés isolés.\n\nContinuer ?")) return;
            Action2("Sortie de la quarantaine", "Quarantaine sortie", disque, () => Moteur.SortirQuarantaine(disque));
        }

        void Remettre(string disque)
        {
            if (!Confirmer("Remettre sur " + disque + " la dernière quarantaine gardée sur ce PC ?\n\nATTENTION : elle contient des fichiers infectés. Ne livre pas ce disque ensuite.")) return;
            Action2("Remise de la quarantaine", "Quarantaine remise", disque, () => Moteur.RemettreQuarantaine(disque));
        }

        void AnnulerReparation(string disque)
        {
            if (!Confirmer("Remettre les fichiers de la dernière réparation sur " + disque + " ?\n\nATTENTION : cela remet aussi les fichiers infectés à leur place.")) return;
            Action2("Annulation en cours", "Annulation", disque, () => Moteur.Annuler(disque));
        }

        void Relancer(string disque, string message)
        {
            Action a = () => Analyse(disque, message);
            try { BeginInvoke(a); } catch (InvalidOperationException) { }
        }

        void EnvoyerQuarantaine(string disque)
        {
            Task.Run(() =>
            {
                try
                {
                    var l = Moteur.ListerQuarantaine(disque).Select(q => new { nom = q.Nom, genre = q.Genre, date = q.Date, fichiers = q.Fichiers, mo = Math.Round(q.Octets / 1048576.0, 1) }).ToList();
                    Envoyer(new { type = "quarantaine", disque = disque, sessions = l, archive = !Moteur.EstDisqueSysteme(disque) && Moteur.ArchiveExiste(disque) });
                }
                catch (Exception ex) { Envoyer(new { type = "erreur", message = ex.Message }); }
            });
        }

        void EnvoyerHistorique()
        {
            try
            {
                Directory.CreateDirectory(DossierRapports);
                var l = new DirectoryInfo(DossierRapports).GetFiles("rapport-*.txt").OrderByDescending(f => f.LastWriteTimeUtc).Take(40)
                    .Select(f => new { nom = f.Name, date = f.LastWriteTime.ToString("dd/MM/yyyy HH:mm"), verdict = LireVerdict(f.FullName), disque = LireDisque(f.FullName) }).ToList();
                Envoyer(new { type = "historique", rapports = l });
            }
            catch (Exception ex) { Envoyer(new { type = "erreur", message = ex.Message }); }
        }

        static string LigneRapport(string chemin, string debut)
        {
            try { return File.ReadLines(chemin).Take(6).Where(x => x.StartsWith(debut)).Select(x => x.Substring(debut.Length)).FirstOrDefault() ?? ""; } catch { return ""; }
        }
        static string LireVerdict(string chemin) { return LigneRapport(chemin, "Verdict : "); }
        static string LireDisque(string chemin) { return LigneRapport(chemin, "Disque : "); }

        void OuvrirRapportNomme(string nom)
        {
            if (string.IsNullOrEmpty(nom) || nom != Path.GetFileName(nom) || !nom.StartsWith("rapport-") || !nom.EndsWith(".txt")) return;
            OuvrirFichierRapport(Path.Combine(DossierRapports, nom));
        }

        void OuvrirFichierRapport(string chemin)
        {
            if (string.IsNullOrEmpty(chemin) || !File.Exists(chemin)) return;
            Demarrer(Path.Combine(Environment.SystemDirectory, "notepad.exe"), "\"" + chemin + "\"");
        }

        void OuvrirDossierRapports()
        {
            Directory.CreateDirectory(DossierRapports);
            Demarrer(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"), "\"" + DossierRapports + "\"");
        }

        ElementPlan ElementVue(string valeur)
        {
            int i; return int.TryParse(valeur, out i) && i >= 0 && i < vue.Count ? vue[i] : null;
        }

        // Montre le fichier dans l'Explorateur sans jamais le lancer.
        void OuvrirEmplacement(string valeur)
        {
            var e = ElementVue(valeur); if (e == null) return;
            Demarrer(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"), File.Exists(e.Chemin) ? "/select,\"" + e.Chemin + "\"" : "\"" + Path.GetDirectoryName(e.Chemin) + "\"");
        }

        void CopierChemin(string valeur)
        {
            var e = ElementVue(valeur); if (e == null) return;
            try { Clipboard.SetText(e.Chemin); Envoyer(new { type = "info", message = "Chemin copié." }); } catch (Exception ex) { Envoyer(new { type = "info", message = "Copie impossible : " + ex.Message }); }
        }

        void Demarrer(string programme, string arguments)
        {
            try { Process.Start(new ProcessStartInfo(programme, arguments) { UseShellExecute = false }); }
            catch (Exception ex) { Envoyer(new { type = "erreur", message = ex.Message }); }
        }
    }
}
