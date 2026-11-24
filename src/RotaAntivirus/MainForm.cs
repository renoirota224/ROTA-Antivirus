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
        string disqueAnalyse = "", rapport = "";
        bool occupe, ecriture;

        public MainForm()
        {
            Text = "ROTA Antivirus";
            ClientSize = new Size(1240, 780);
            MinimumSize = new Size(960, 680);
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
            MessageBox.Show(this, ecriture ? "Une réparation est en cours. Attends sa fin et ne débranche pas le disque." : "Une analyse est en cours. Clique sur Arrêter avant de fermer.", "ROTA Antivirus", MessageBoxButtons.OK, MessageBoxIcon.Warning);
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
            string cmd = "", disque = "";
            try
            {
                using (var d = JsonDocument.Parse(e.WebMessageAsJson))
                {
                    JsonElement x;
                    if (d.RootElement.TryGetProperty("cmd", out x)) cmd = x.GetString() ?? "";
                    if (d.RootElement.TryGetProperty("disque", out x)) disque = x.GetString() ?? "";
                }
            }
            catch { return; }
            switch (cmd)
            {
                case "pret": EnvoyerDisques(); break;
                case "analyser": if (!occupe && DisqueConnu(disque)) Analyse(disque); break;
                case "arreter": if (arret != null) arret.Cancel(); break;
                case "reparer": if (!occupe && PeutEcrire(disque)) Reparer(disque); break;
                case "ranger": if (!occupe && PeutEcrire(disque)) Ranger(disque); break;
                case "annuler": if (!occupe && DisqueConnu(disque) && !Moteur.EstDisqueSysteme(disque)) AnnulerReparation(disque); break;
                case "rapport": OuvrirRapport(); break;
            }
        }

        static List<DriveInfo> Disques()
        {
            return DriveInfo.GetDrives().Where(d => (d.DriveType == DriveType.Fixed || d.DriveType == DriveType.Removable) && d.IsReady).ToList();
        }

        static bool DisqueConnu(string disque)
        {
            return Disques().Any(d => string.Equals(d.Name, disque, StringComparison.OrdinalIgnoreCase));
        }

        bool PeutEcrire(string disque)
        {
            return DisqueConnu(disque) && !Moteur.EstDisqueSysteme(disque) && plan != null && string.Equals(disqueAnalyse, disque, StringComparison.OrdinalIgnoreCase);
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
            Envoyer(new { type = "avancement", phase = a.Phase, fait = a.Fait, total = a.Total, trouves = a.Trouves, courant = a.Courant });
        }

        void Analyse(string disque, string messageAvant = "")
        {
            arret = new CancellationTokenSource(); var jeton = arret.Token;
            plan = null; verdict = null; disqueAnalyse = "";
            Envoyer(new { type = "debut", disque = disque, message = messageAvant });
            Tache(false, () =>
            {
                var p = Moteur.Analyser(disque, Suivi, jeton);
                bool systeme = Moteur.EstDisqueSysteme(disque); var etat = Moteur.Etat(disque); var v = Moteur.Verdict(p, etat, systeme);
                rapport = Moteur.EcrireRapport(Path.Combine(donnees, "Rapports"), disque, v, p);
                plan = p; verdict = v; disqueAnalyse = disque; Fin();
                Envoyer(new
                {
                    type = "resultat", disque = disque, niveau = v.Niveau, titre = v.Titre, bloquants = v.Bloquants, reserves = v.Reserves, aTraiter = v.ATraiter,
                    total = p.Total, examines = p.Examines, systeme = systeme, recycler = etat.RecyclerDossier, message = messageAvant, tronque = p.Elements.Count > MaxLignes, nbElements = p.Elements.Count,
                    elements = p.Elements.OrderBy(x => x.Type == "RESTE" ? 1 : 0).Take(MaxLignes).Select(x => new { type = x.Type, libelle = Moteur.Libelle(x.Type), relatif = x.Relatif, detail = x.Detail }).ToList()
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

        void Reparer(string disque)
        {
            if (verdict == null || verdict.ATraiter == 0) return;
            if (!Confirmer(verdict.ATraiter + " fichier(s) vont être réparés, remplacés ou isolés sur " + disque + ".\n\nRien n'est supprimé : les originaux vont dans _QUARANTAINE_ROTA.\nNe débranche pas le disque.\n\nContinuer ?")) return;
            var p = plan; Envoyer(new { type = "action", titre = "Réparation en cours" });
            Tache(true, () => { var r = Moteur.Appliquer(p, disque, Suivi); Fin(); Relancer(disque, Bilan(r, "Réparation")); });
        }

        void Ranger(string disque)
        {
            int n;
            try { n = Moteur.CompterRecycler(disque); } catch (Exception ex) { Envoyer(new { type = "erreur", message = ex.Message }); return; }
            if (!Confirmer(n + " fichier(s) de RECYCLER.BIN vont être rangés dans _QUARANTAINE_ROTA, sans suppression.\nEnsuite, un fichier vide bloquera le retour de PlugX.\n\nContinuer ?")) return;
            Envoyer(new { type = "action", titre = "Rangement en cours" });
            Tache(true, () => { var r = Moteur.RangerRecycler(disque, n); Fin(); Relancer(disque, Bilan(r, "Rangement")); });
        }

        void AnnulerReparation(string disque)
        {
            if (!Confirmer("Remettre les fichiers de la dernière réparation sur " + disque + " ?\n\nATTENTION : cela remet aussi les fichiers infectés à leur place.")) return;
            Envoyer(new { type = "action", titre = "Annulation en cours" });
            Tache(true, () => { var r = Moteur.Annuler(disque); Fin(); Relancer(disque, Bilan(r, "Annulation")); });
        }

        void Relancer(string disque, string message)
        {
            Action a = () => Analyse(disque, message);
            try { BeginInvoke(a); } catch (InvalidOperationException) { }
        }

        void OuvrirRapport()
        {
            if (string.IsNullOrEmpty(rapport) || !File.Exists(rapport)) return;
            var psi = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "notepad.exe"), "\"" + rapport + "\"") { UseShellExecute = false };
            try { Process.Start(psi); } catch (Exception ex) { Envoyer(new { type = "erreur", message = ex.Message }); }
        }
    }
}
