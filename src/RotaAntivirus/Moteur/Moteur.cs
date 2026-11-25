// ROTA Antivirus - analyse, reparation et isolement d'un disque.
// Ce code lit et deplace des fichiers. Il ne lance jamais un programme du disque et ne supprime rien.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

public class ElementPlan
{
    public string Type = "", Chemin = "", Relatif = "", Detail = "", CheminG = "", RelatifG = "", Source = "", Empreinte = "";
    public int Attr, AttrG;
}

public class InfoReference { public string Nom = "", Source = "", Date = ""; public int Fichiers; }
public class DetectionDefender { public string Menace = "", Fichier = ""; }

public class PlanDisque
{
    public long Total; public int Examines, Illisibles, MenacesDefender, DifferencesBibliotheque; public bool PcInfecte, DefenderFait, BibliothequeFaite;
    public List<ElementPlan> Elements = new List<ElementPlan>();
}

public class Avancement { public int Fait, Total, Trouves; public string Courant = "", Phase = ""; public List<string> Cibles = new List<string>(); }
public class EtatDisque { public bool RecyclerDossier, Blocage, Quarantaine; public int DossiersCaches; public long Libre = long.MaxValue; }
public class VerdictDisque { public string Niveau = "", Titre = ""; public List<string> Bloquants = new List<string>(), Reserves = new List<string>(); public int ATraiter, AReparer, AIsoler; }
public class ResultatAction { public int Ok, Echecs; public string Session = ""; public List<string> Messages = new List<string>(); }
public class InfoQuarantaine { public string Nom = "", Genre = "", Date = ""; public int Fichiers; public long Octets; }

public static class Moteur
{
    public const string DossierQuarantaine = "_QUARANTAINE_ROTA";
    const long TailleMax = 1L << 30;
    static readonly string[] ExtensionsPe = { ".exe", ".dll", ".scr", ".ocx", ".cpl", ".sys" };
    static readonly string[] NomsPlugX = { "cefhelper.exe", "wsc.dll", "avastauth.dat" };
    static readonly string[] TypesAction = { "REPARER", "REMPLACER", "RESTAURER", "GRENAM", "ISOLER" };
    static readonly string[] ExtensionsSurveillees = { ".exe", ".dll", ".scr", ".ocx", ".cpl", ".sys", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".msi", ".lnk" };
    static readonly string[] MenacesLegeres = { "HackTool", "PUA", "PUADlEnablement", "PUAMiner", "Program", "Misleading", "Adware", "SoftwareBundler", "BrowserModifier", "App", "Tool" };
    static readonly string[] FichiersMemoire = { "pagefile.sys", "swapfile.sys", "hiberfil.sys" };
    const long PlaceMinimum = 300L * 1024 * 1024;

    // PlugX cache les fichiers du disque dans un dossier dont le nom est fait d'espaces invisibles.
    static bool NomInvisible(string nom)
    {
        return nom.Length > 0 && nom.All(c => char.IsWhiteSpace(c) || c == ' ' || c == '​' || c == '﻿' || c == 'ㅤ');
    }

    public static List<string> DossiersCaches(string racineBrute)
    {
        var racine = Normaliser(racineBrute);
        return Directory.GetDirectories(Long(racine)).Select(Court).Where(d => NomInvisible(Path.GetFileName(d))).ToList();
    }

    public static ResultatAction RemettreFichiersCaches(string racineBrute, bool essai = false)
    {
        string racine = Normaliser(racineBrute); Refuser(racine, essai); var r = new ResultatAction();
        var caches = DossiersCaches(racine); if (caches.Count == 0) { r.Messages.Add("Aucun dossier caché sur ce disque."); return r; }
        var dir = Path.Combine(racine, DossierQuarantaine, "caches-" + DateTime.Now.ToString("yyyyMMdd-HHmmss")); Directory.CreateDirectory(dir); r.Session = dir;
        var journal = Path.Combine(dir, "deplacements.tsv");
        foreach (var c in caches)
        {
            foreach (var x in Directory.GetFileSystemEntries(Long(c)).Select(Court))
            {
                var nom = Path.GetFileName(x); if (string.Equals(nom, "desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
                var cible = Path.Combine(racine, nom);
                for (int k = 2; File.Exists(Long(cible)) || Directory.Exists(Long(cible)); k++) cible = Path.Combine(racine, Path.GetFileNameWithoutExtension(nom) + " (récupéré " + k + ")" + Path.GetExtension(nom));
                try
                {
                    if (Directory.Exists(Long(x))) Directory.Move(Long(x), Long(cible)); else File.Move(Long(x), Long(cible));
                    File.AppendAllText(journal, Relatif(x, racine) + "\t" + Relatif(cible, racine) + "\r\n", new UTF8Encoding(false)); r.Ok++;
                }
                catch (Exception ex) { r.Echecs++; r.Messages.Add("Échec : " + nom + " : " + ex.Message); }
            }
            try
            {
                if (Directory.GetFileSystemEntries(Long(c)).All(x => string.Equals(Path.GetFileName(x), "desktop.ini", StringComparison.OrdinalIgnoreCase)))
                {
                    foreach (var f in Directory.GetFiles(Long(c))) { File.SetAttributes(f, FileAttributes.Normal); File.Move(f, Long(Path.Combine(dir, "desktop.ini"))); }
                    File.SetAttributes(Long(c), FileAttributes.Directory); Directory.Delete(Long(c));
                }
            }
            catch (Exception ex) { r.Messages.Add("Le dossier caché vide est resté : " + ex.Message); }
        }
        r.Messages.Add("Tes fichiers sont de nouveau visibles à la racine.");
        return r;
    }

    // Sur le disque de Windows, seuls les dossiers personnels peuvent etre repares pendant que Windows tourne.
    public static bool ReparableSurSysteme(string relatif)
    {
        return relatif.StartsWith("Users\\", StringComparison.OrdinalIgnoreCase) && relatif.IndexOf("\\AppData\\Local\\Microsoft\\WindowsApps\\", StringComparison.OrdinalIgnoreCase) < 0;
    }

    class Fichier { public string Chemin, Nom, Ext, Dossier; public long Taille; public int Attr; }
    class InfoPe { public string Derniere = ""; public uint Droits, Taille, Cert; public bool Upx0, Upx1; }

    public static string Libelle(string type)
    {
        switch (type)
        {
            case "REPARER": return "À réparer";
            case "REMPLACER": return "À remplacer (copie officielle)";
            case "RESTAURER": return "À restaurer (copie maître)";
            case "GRENAM": return "Faux programme à remplacer";
            case "ISOLER": return "À isoler";
            case "RETELECHARGER": return "À retélécharger";
            case "A_VERIFIER": return "À vérifier";
            case "RESTE": return "Marque inerte";
            default: return type;
        }
    }

    static string Long(string p)
    {
        if (p.StartsWith(@"\\?\")) return p;
        if (p.StartsWith(@"\\")) return @"\\?\UNC\" + p.Substring(2);
        return @"\\?\" + p;
    }
    static string Court(string p) { return p.StartsWith(@"\\?\") ? p.Substring(4) : p; }
    public static string Normaliser(string r) { return Path.GetFullPath(r).TrimEnd('\\') + "\\"; }
    static string Relatif(string chemin, string racine) { return chemin.Substring(racine.TrimEnd('\\').Length).TrimStart('\\'); }

    // ---------- Lecture des programmes ----------
    static InfoPe LirePe(string chemin)
    {
        using (var fs = new FileStream(Long(chemin), FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
        {
            if (fs.Length < 512) return null;
            var h = new byte[64]; if (fs.Read(h, 0, 64) != 64 || h[0] != 0x4D || h[1] != 0x5A) return null;
            int e = BitConverter.ToInt32(h, 60); if (e <= 0 || e > fs.Length - 256) return null;
            fs.Seek(e, SeekOrigin.Begin);
            var c = new byte[24]; if (fs.Read(c, 0, 24) != 24 || c[0] != 0x50 || c[1] != 0x45 || c[2] != 0 || c[3] != 0) return null;
            int ns = BitConverter.ToUInt16(c, 6), os = BitConverter.ToUInt16(c, 20); if (ns == 0 || ns > 96 || os > 1024) return null;
            int taille = os + 40 * ns; var b = new byte[taille]; if (fs.Read(b, 0, taille) != taille) return null;
            int certOff = os >= 2 && BitConverter.ToUInt16(b, 0) == 0x20B ? 148 : 132;
            var r = new InfoPe(); if (certOff + 4 <= os) r.Cert = BitConverter.ToUInt32(b, certOff);
            for (int i = 0; i < ns; i++)
            {
                int o = os + 40 * i; r.Derniere = Encoding.ASCII.GetString(b, o, 8).Split('\0')[0];
                r.Taille = BitConverter.ToUInt32(b, o + 16); r.Droits = BitConverter.ToUInt32(b, o + 36);
                if (r.Derniere == "UPX0") r.Upx0 = true; if (r.Derniere == "UPX1") r.Upx1 = true;
            }
            return r;
        }
    }

    static string Marque(InfoPe p)
    {
        if (p == null) return null;
        bool rwx = (p.Droits & 0xA0000000) == 0xA0000000;
        if (rwx && p.Taille >= 256 * 1024 && (p.Derniere == ".reloc" || p.Derniere == ".rsrc" || p.Derniere == ".debug")) return "CONFIRME";
        if (p.Upx1 && !p.Upx0) return "CONFIRME";
        if (rwx && p.Cert == 0) return "A_VERIFIER";
        return null;
    }

    static bool FauxGrenam(byte[] o)
    {
        try
        {
            int pe; bool x; var s = Reparateur.Sections(o, out pe, out x);
            return !x && s.Count > 0 && s[0].Raw == 0x70200 && BitConverter.ToUInt32(o, pe + 40) == 0x72814;
        }
        catch { return false; }
    }

    // Ver Ground : un faux programme qui prend la place du vrai fichier, renomme en « g... » et cache.
    // Il se camoufle souvent derriere un nom comme Jeu.exe.cat, Jeu.exe.cfg ou Jeu.exe.lnk.
    static readonly System.Text.RegularExpressions.Regex NomCamoufle = new System.Text.RegularExpressions.Regex(@"\.(exe|scr|com|dll)\.[a-z0-9_-]{1,12}$", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
    static bool Camoufle(string nom) { return NomCamoufle.IsMatch(nom); }

    static int Chercher(byte[] b, byte[] m)
    {
        for (int i = 0; i + m.Length <= b.Length; i++)
        {
            int k = 0; while (k < m.Length && (b[i + k] | 0x20) == (m[k] | 0x20)) k++;
            if (k == m.Length) return i;
        }
        return -1;
    }

    static readonly byte[] MarqueGroundA = Encoding.ASCII.GetBytes(@"\Windows\Ground"), MarqueGroundU = Encoding.Unicode.GetBytes(@"\Windows\Ground");
    public static bool EstGround(byte[] b)
    {
        if (b == null || b.Length < 1024 || b[0] != 0x4D || b[1] != 0x5A) return false;
        return Chercher(b, MarqueGroundA) >= 0 || Chercher(b, MarqueGroundU) >= 0;
    }

    static string Probleme(byte[] o, byte[] infecte)
    {
        try
        {
            if (Reparateur.EstForme2(o)) return "forme 2 du virus encore présente";
            if (Reparateur.AppelsPendants(o, infecte) > 0) return "un appel du programme reste détourné vers le virus disparu";
            int pe; bool x; var s = Reparateur.Sections(o, out pe, out x);
            long ep = BitConverter.ToUInt32(o, pe + 40); bool code = false;
            foreach (var q in s)
            {
                if ((q.Ch & 0xA0000000) == 0xA0000000) return "section " + q.Nom + " encore inscriptible et exécutable";
                if (q.Nom == "UPX1" || q.Nom == "UPX0") return "bloc UPX1 inconnu restant";
                if (q.Raw > 0 && (long)q.Ptr + q.Raw > o.Length) return "section " + q.Nom + " hors du fichier";
                if (ep >= q.VA && ep < (long)q.VA + Math.Max(q.VS, q.Raw) && (q.Ch & 0x20000000) != 0) code = true;
            }
            if (!code) return "entrée du programme hors du code";
            string etat; if (Reparateur.Nettoyer(o, out etat) != null) return "encore des traces du virus";
            return "";
        }
        catch { return "structure illisible"; }
    }

    static bool LnkPiege(Fichier f)
    {
        if (f.Taille > 1024 * 1024) return false;
        var b = File.ReadAllBytes(Long(f.Chemin));
        string t = (Encoding.GetEncoding(28591).GetString(b) + Encoding.Unicode.GetString(b)).ToLowerInvariant();
        return t.Contains("cmd.exe") || t.Contains("recycler") || t.Contains("powershell");
    }

    // ---------- Signature Windows ----------
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    class InfoFichierConfiance { public uint Taille; [MarshalAs(UnmanagedType.LPWStr)] public string Chemin; public IntPtr Handle, Sujet; }
    [StructLayout(LayoutKind.Sequential)]
    class DonneesConfiance { public uint Taille; public IntPtr Politique, Sip; public uint Ui, Revocation, Choix; public IntPtr Fichier; public uint Etat; public IntPtr HEtat, Url; public uint Fournisseur, Contexte; public IntPtr Parametres; }
    [DllImport("wintrust.dll", CharSet = CharSet.Unicode)] static extern int WinVerifyTrust(IntPtr fenetre, ref Guid action, IntPtr donnees);

    public static bool SignatureValide(string chemin)
    {
        var action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
        var fi = new InfoFichierConfiance { Chemin = Court(chemin) }; fi.Taille = (uint)Marshal.SizeOf(typeof(InfoFichierConfiance));
        IntPtr pf = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(InfoFichierConfiance))), pd = IntPtr.Zero;
        try
        {
            Marshal.StructureToPtr(fi, pf, false);
            var d = new DonneesConfiance { Ui = 2, Revocation = 0, Choix = 1, Fichier = pf, Etat = 0, Fournisseur = 0x10 };
            d.Taille = (uint)Marshal.SizeOf(typeof(DonneesConfiance)); pd = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(DonneesConfiance))); Marshal.StructureToPtr(d, pd, false);
            return WinVerifyTrust(new IntPtr(-1), ref action, pd) == 0;
        }
        catch { return false; }
        finally { Marshal.DestroyStructure(pf, typeof(InfoFichierConfiance)); Marshal.FreeHGlobal(pf); if (pd != IntPtr.Zero) Marshal.FreeHGlobal(pd); }
    }

    // ---------- Copies officielles ----------
    static Dictionary<string, List<string>> IndexOfficiel()
    {
        var idx = new Dictionary<string, List<string>>();
        var racines = new[] {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Package Cache"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RotaAntivirus", "Copies-officielles")
        };
        foreach (var r in racines)
        {
            if (!Directory.Exists(r)) continue;
            var pile = new Stack<string>(); pile.Push(r);
            while (pile.Count > 0)
            {
                var d = pile.Pop();
                try { foreach (var s in Directory.GetDirectories(d)) { if ((File.GetAttributes(s) & FileAttributes.ReparsePoint) == 0) pile.Push(s); } } catch { }
                try
                {
                    foreach (var x in Directory.GetFiles(d, "*.exe"))
                    {
                        var c = Reparateur.CleFichier(x); if (c == null) continue;
                        List<string> l; if (!idx.TryGetValue(c, out l)) { l = new List<string>(); idx[c] = l; }
                        l.Add(x);
                    }
                }
                catch { }
            }
        }
        return idx;
    }

    static string CopieOfficielle(byte[] infecte, string chemin, Dictionary<string, List<string>> idx)
    {
        var k = Reparateur.CleFichier(Long(chemin)); List<string> l;
        if (k == null || !idx.TryGetValue(k, out l)) return "";
        foreach (var q in l)
        {
            if (string.Equals(q, chemin, StringComparison.OrdinalIgnoreCase)) continue;
            try { if (Reparateur.MemeProgramme(infecte, File.ReadAllBytes(q)) && SignatureValide(q)) return q; } catch { }
        }
        return "";
    }

    // ---------- Analyse ----------
    static List<Fichier> Lister(string racine, PlanDisque plan, CancellationToken stop)
    {
        var l = new List<Fichier>(); var pile = new Stack<string>(); pile.Push(racine);
        while (pile.Count > 0)
        {
            stop.ThrowIfCancellationRequested();
            var d = pile.Pop(); FileSystemInfo[] items;
            try { items = new DirectoryInfo(Long(d)).GetFileSystemInfos(); } catch { plan.Illisibles++; continue; }
            foreach (var i in items)
            {
                var p = Court(i.FullName);
                if ((i.Attributes & FileAttributes.Directory) != 0)
                {
                    if ((i.Attributes & FileAttributes.ReparsePoint) != 0 || i.Name == DossierQuarantaine || i.Name == "System Volume Information") continue;
                    pile.Push(p);
                }
                else
                {
                    plan.Total++; var ext = i.Extension.ToLowerInvariant();
                    // Les raccourcis d'applications Windows et les fichiers de memoire ne sont pas de vrais programmes a lire.
                    if ((i.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                    if (string.Equals(Path.GetDirectoryName(p).TrimEnd('\\'), racine.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase) && FichiersMemoire.Contains(i.Name.ToLowerInvariant())) continue;
                    if (ExtensionsPe.Contains(ext) || ext == ".lnk" || ext == ".dat" || Camoufle(i.Name))
                        l.Add(new Fichier { Chemin = p, Nom = i.Name, Ext = ext, Taille = ((FileInfo)i).Length, Attr = (int)i.Attributes & 0x3FFFF, Dossier = Path.GetDirectoryName(p) });
                }
            }
        }
        return l;
    }

    static void AjouterGround(Fichier f, string racine, Dictionary<string, Fichier> parChemin, List<ElementPlan> brut, HashSet<string> sourcesG)
    {
        var cheminG = Path.Combine(f.Dossier, "g" + f.Nom);
        if (parChemin.ContainsKey(cheminG)) { sourcesG.Add(cheminG); brut.Add(Element("GRENAM", f, racine, "Ver Ground : remplacé par le vrai fichier caché " + Path.GetFileName(cheminG), parChemin[cheminG])); }
        else brut.Add(Element("ISOLER", f, racine, "Ver Ground sans vrai fichier caché : à recopier depuis une copie saine", null));
    }

    static ElementPlan Element(string type, Fichier f, string racine, string detail, Fichier g)
    {
        var e = new ElementPlan { Type = type, Chemin = f.Chemin, Relatif = Relatif(f.Chemin, racine), Attr = f.Attr, Detail = detail };
        if (g != null) { e.CheminG = g.Chemin; e.RelatifG = Relatif(g.Chemin, racine); e.AttrG = g.Attr; }
        return e;
    }

    public static int PcInfecte()
    {
        int n = 0;
        try { foreach (var f in Directory.GetFiles(Environment.SystemDirectory, "*.exe")) { try { if (Marque(LirePe(f)) == "CONFIRME") n++; } catch { } } } catch { }
        return n;
    }

    public static PlanDisque Analyser(string racineBrute, Action<Avancement> suivi, CancellationToken stop)
    {
        string racine = Normaliser(racineBrute); var plan = new PlanDisque();
        if (suivi != null) suivi(new Avancement { Phase = "Contrôle de Windows" });
        plan.PcInfecte = PcInfecte() > 0;
        if (suivi != null) suivi(new Avancement { Phase = "Inventaire du disque" });
        var liste = Lister(racine, plan, stop); plan.Examines = liste.Count;
        var parChemin = new Dictionary<string, Fichier>(StringComparer.OrdinalIgnoreCase); foreach (var f in liste) parChemin[f.Chemin] = f;
        var brut = new List<ElementPlan>(); var sourcesG = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        Dictionary<string, List<string>> index = null; int n = 0; var dernier = DateTime.MinValue;
        foreach (var f in liste)
        {
            stop.ThrowIfCancellationRequested(); n++;
            if (suivi != null && (DateTime.UtcNow - dernier).TotalMilliseconds > 150) { dernier = DateTime.UtcNow; suivi(new Avancement { Phase = "Analyse", Fait = n, Total = liste.Count, Trouves = brut.Count(x => x.Type != "RESTE"), Courant = Relatif(f.Chemin, racine), Cibles = brut.Where(x => x.Type != "RESTE").Reverse().Take(8).Select(x => x.Type + "|" + x.Relatif).ToList() }); }
            var rel = Relatif(f.Chemin, racine);
            if ((rel.StartsWith("RECYCLER.BIN\\", StringComparison.OrdinalIgnoreCase) || rel.IndexOf("\\RECYCLER.BIN\\", StringComparison.OrdinalIgnoreCase) >= 0) && NomsPlugX.Contains(f.Nom.ToLowerInvariant())) { brut.Add(Element("ISOLER", f, racine, "Fichier PlugX", null)); continue; }
            if (Camoufle(f.Nom))
            {
                if (f.Taille < 1024 || f.Taille > 64L * 1024 * 1024) continue;
                try { if (EstGround(File.ReadAllBytes(Long(f.Chemin)))) AjouterGround(f, racine, parChemin, brut, sourcesG); }
                catch (Exception ex) { if (ex.Message.IndexOf("virus", StringComparison.OrdinalIgnoreCase) >= 0) brut.Add(Element("A_VERIFIER", f, racine, "Faux fichier bloqué par Windows Defender : ne l'ouvre pas, laisse Defender le supprimer", null)); }
                continue;
            }
            if (f.Ext == ".lnk")
            {
                if (string.Equals(f.Dossier.TrimEnd('\\'), racine.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
                {
                    try { if (LnkPiege(f)) brut.Add(Element("ISOLER", f, racine, "Faux raccourci du virus", null)); }
                    catch (Exception ex) { if (ex.Message.IndexOf("virus", StringComparison.OrdinalIgnoreCase) >= 0) brut.Add(Element("A_VERIFIER", f, racine, "Faux raccourci bloqué par Windows Defender : ne l'ouvre pas, laisse Defender le supprimer", null)); }
                }
                continue;
            }
            if (!ExtensionsPe.Contains(f.Ext) || f.Taille > TailleMax) continue;
            try
            {
                var info = LirePe(f.Chemin); if (info == null) continue;
                bool marque = Marque(info) != null || info.Upx1 || Reparateur.FichierForme2(Long(f.Chemin));
                var cheminG = Path.Combine(f.Dossier, "g" + f.Nom); bool aG = f.Ext == ".exe" && parChemin.ContainsKey(cheminG);
                if (!marque && !aG && !(f.Ext == ".exe" && f.Taille <= 2 * 1024 * 1024)) continue;
                var b = File.ReadAllBytes(Long(f.Chemin));
                if (EstGround(b)) { AjouterGround(f, racine, parChemin, brut, sourcesG); continue; }
                string etat; var o = Reparateur.Nettoyer(b, out etat); var courant = o ?? b;
                if (etat.Contains("forme 2"))
                {
                    if (index == null) index = IndexOfficiel();
                    var q = CopieOfficielle(b, f.Chemin, index);
                    if (q != "") { var e = Element("REMPLACER", f, racine, "Forme 2 : remplacé par une copie officielle signée", null); e.Source = q; brut.Add(e); }
                    else brut.Add(Element("ISOLER", f, racine, "Forme 2 : données écrasées par le virus, à retélécharger", null));
                    continue;
                }
                if (f.Ext == ".exe" && FauxGrenam(courant))
                {
                    if (aG) { sourcesG.Add(cheminG); brut.Add(Element("GRENAM", f, racine, "Remplacé par l'original " + Path.GetFileName(cheminG), parChemin[cheminG])); }
                    else brut.Add(Element("ISOLER", f, racine, "Faux programme Grenam sans original : à retélécharger", null));
                    continue;
                }
                if (o == null && info.Upx1 && !info.Upx0)
                {
                    if (Reparateur.ResteUpx1Inerte(b)) brut.Add(Element("RESTE", f, racine, "Section UPX1 inerte : simple table renommée", null));
                    else brut.Add(Element("A_VERIFIER", f, racine, "Section UPX1 non prouvée inerte", null));
                    continue;
                }
                if (o == null) { if (etat.StartsWith("non repare")) brut.Add(Element("A_VERIFIER", f, racine, etat, null)); continue; }
                var pb = Probleme(o, b);
                brut.Add(pb != "" ? Element("RETELECHARGER", f, racine, pb, null) : Element("REPARER", f, racine, etat, null));
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { brut.Add(Element("A_VERIFIER", f, racine, ex.Message.IndexOf("virus", StringComparison.OrdinalIgnoreCase) >= 0 ? "Bloqué par Windows Defender : ne l'ouvre pas, laisse Defender le supprimer" : "Illisible : " + ex.GetType().Name, null)); }
        }
        foreach (var e in brut.Where(x => x.Type == "GRENAM"))
        {
            string pb = "";
            try
            {
                var bg = File.ReadAllBytes(Long(e.CheminG)); string etat; var og = Reparateur.Nettoyer(bg, out etat);
                if (og != null) pb = Probleme(og, bg); else if (etat.StartsWith("non repare")) pb = etat;
                if (pb == "" && FauxGrenam(og ?? bg)) pb = "original lui-même faux";
                if (pb == "" && EstGround(bg)) pb = "original lui-même infecté par le ver Ground";
            }
            catch (Exception ex) { pb = ex.Message.IndexOf("virus", StringComparison.OrdinalIgnoreCase) >= 0 ? "original bloqué par l'antivirus" : "original illisible"; }
            if (pb != "") { sourcesG.Remove(e.CheminG); e.Type = "ISOLER"; e.Detail = "Faux programme isolé, à retélécharger (original inutilisable : " + pb + ")"; e.CheminG = ""; e.RelatifG = ""; e.AttrG = 0; }
        }
        plan.Elements = brut.Where(e => e.Type == "GRENAM" || !sourcesG.Contains(e.Chemin)).ToList();
        if (suivi != null) suivi(new Avancement { Phase = "Terminé", Fait = liste.Count, Total = liste.Count, Trouves = plan.Elements.Count(x => x.Type != "RESTE") });
        return plan;
    }

    // ---------- Verdict ----------
    public static EtatDisque Etat(string racineBrute)
    {
        string racine = Normaliser(racineBrute), r = Path.Combine(racine, "RECYCLER.BIN"); var e = new EtatDisque();
        e.RecyclerDossier = Directory.Exists(r); if (File.Exists(r)) e.Blocage = new FileInfo(r).Length == 0;
        e.Quarantaine = Directory.Exists(Path.Combine(racine, DossierQuarantaine));
        try { e.DossiersCaches = DossiersCaches(racine).Count; } catch { }
        try { e.Libre = new DriveInfo(Path.GetPathRoot(racine)).AvailableFreeSpace; } catch { }
        return e;
    }

    public static bool EstDisqueSysteme(string racine)
    {
        return string.Equals(Normaliser(racine).Substring(0, 2), Path.GetPathRoot(Environment.SystemDirectory).Substring(0, 2), StringComparison.OrdinalIgnoreCase);
    }

    public static VerdictDisque Verdict(PlanDisque p, EtatDisque e, bool systeme)
    {
        var v = new VerdictDisque();
        if (p.PcInfecte) v.Bloquants.Add("Ce PC porte la marque du virus : il pourrait réinfecter le disque.");
        if (p.Illisibles > 0 && !systeme) v.Bloquants.Add(p.Illisibles + " dossier(s) illisible(s) : contrôle incomplet.");
        if (p.Illisibles > 0 && systeme) v.Reserves.Add(p.Illisibles + " dossier(s) protégé(s) par Windows n'ont pas été lus.");
        foreach (var k in new[] { "REPARER", "REMPLACER", "RESTAURER", "GRENAM", "ISOLER", "RETELECHARGER", "A_VERIFIER" })
        { int n = p.Elements.Count(x => x.Type == k); if (n > 0) v.Bloquants.Add(n + " fichier(s) : " + Libelle(k)); }
        if (e.RecyclerDossier) v.Bloquants.Add("Dossier RECYCLER.BIN présent (PlugX) : à ranger.");
        if (e.DossiersCaches > 0) v.Bloquants.Add(e.DossiersCaches + " dossier(s) caché(s) par PlugX : tes fichiers sont dedans, clique sur Remettre les fichiers cachés.");
        if (!systeme && e.Libre < PlaceMinimum) v.Bloquants.Add("Disque presque plein (" + (e.Libre / 1048576) + " Mo libres) : sors la quarantaine pour libérer de la place, puis répare.");
        if (!systeme)
        {
            if (e.Quarantaine) v.Bloquants.Add("Dossier _QUARANTAINE_ROTA présent : il ne doit jamais partir chez un client.");
            if (!e.RecyclerDossier && !e.Blocage) v.Bloquants.Add("Blocage PlugX absent.");
        }
        int inerte = p.Elements.Count(x => x.Type == "RESTE");
        if (inerte > 0) v.Reserves.Add(inerte + " fichier(s) avec une marque inerte : teste ces jeux.");
        v.Reserves.Add("Ce contrôle reconnaît Expiro, Grenam, Ground, PlugX et UPX1, pas tous les virus.");
        v.Reserves.Add("Lance quelques jeux avant de livrer.");
        v.ATraiter = p.Elements.Count(x => TypesAction.Contains(x.Type) && (!systeme || ReparableSurSysteme(x.Relatif)));
        v.AIsoler = p.Elements.Count(x => x.Type == "ISOLER" && (!systeme || ReparableSurSysteme(x.Relatif)));
        v.AReparer = v.ATraiter - v.AIsoler;
        int horsZone = p.Elements.Count(x => TypesAction.Contains(x.Type)) - v.ATraiter;
        if (horsZone > 0) v.Reserves.Insert(0, horsZone + " fichier(s) dans Windows ou Program Files ne peuvent pas être réparés pendant que Windows tourne.");
        v.Niveau = v.Bloquants.Count == 0 ? "PRET" : "PAS_PRET";
        v.Titre = systeme ? (v.Niveau == "PRET" ? "Aucun problème connu sur ce disque Windows" : "Problèmes trouvés sur ce disque Windows") : (v.Niveau == "PRET" ? "Prêt pour la livraison" : "Pas prêt pour la livraison");
        return v;
    }

    public static string EcrireRapport(string dossier, string disque, VerdictDisque v, PlanDisque p)
    {
        Directory.CreateDirectory(dossier);
        var nom = new string(disque.Where(char.IsLetterOrDigit).Take(8).ToArray());
        var c = Path.Combine(dossier, "rapport-" + nom + "-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".txt");
        var t = new List<string> { "ROTA Antivirus - rapport du " + DateTime.Now.ToString("dd/MM/yyyy HH:mm"), "Disque : " + disque, "Verdict : " + v.Titre, "Fichiers sur le disque : " + p.Total + "   Examinés : " + p.Examines, "" };
        if (v.Bloquants.Count > 0) { t.Add("À régler :"); t.AddRange(v.Bloquants.Select(x => "  - " + x)); t.Add(""); }
        t.Add("À savoir :"); t.AddRange(v.Reserves.Select(x => "  - " + x)); t.Add("");
        if (p.Elements.Count > 0) { t.Add("Fichiers :"); t.AddRange(p.Elements.Select(e => "  [" + Libelle(e.Type) + "] " + e.Relatif + " : " + e.Detail)); }
        File.WriteAllLines(c, t, new UTF8Encoding(true)); return c;
    }

    // ---------- Actions (toujours reversibles) ----------
    static string Empreinte(byte[] b) { using (var s = SHA256.Create()) return BitConverter.ToString(s.ComputeHash(b)).Replace("-", ""); }
    static string EmpreinteFichier(string p) { using (var s = SHA256.Create()) using (var f = new FileStream(Long(p), FileMode.Open, FileAccess.Read, FileShare.Read)) return BitConverter.ToString(s.ComputeHash(f)).Replace("-", ""); }

    static void Refuser(string racine, bool essai)
    {
        if (essai) return;
        if (EstDisqueSysteme(racine)) throw new InvalidOperationException("Cette action ne travaille que sur un disque externe.");
        if (PcInfecte() > 0) throw new InvalidOperationException("Ce PC porte la marque du virus : il réinfecterait le disque.");
    }

    static void EcrireVerifie(string tmp, byte[] o)
    {
        File.WriteAllBytes(Long(tmp), o);
        if (Empreinte(File.ReadAllBytes(Long(tmp))) != Empreinte(o)) throw new IOException("relecture différente");
    }

    static string Champ(string s) { return (s ?? "").Replace("\t", " ").Replace("\r", " ").Replace("\n", " "); }

    static void TraiterElement(ElementPlan e, string dir, string id, string manifeste)
    {
        string a = Path.Combine(dir, id + "-a.origine"), bb = Path.Combine(dir, id + "-b.origine"), tmp = e.Chemin + ".rota-tmp", hAvant, hApres = "";
        if (e.Type == "ISOLER") hAvant = EmpreinteFichier(e.Chemin);
        else
        {
            byte[] brut, o;
            if (e.Type == "REMPLACER")
            {
                brut = File.ReadAllBytes(Long(e.Chemin)); o = File.ReadAllBytes(e.Source);
                if (!Reparateur.MemeProgramme(brut, o) || !SignatureValide(e.Source)) throw new IOException("copie officielle non prouvée");
            }
            else if (e.Type == "RESTAURER")
            {
                brut = File.ReadAllBytes(Long(e.Chemin)); o = File.ReadAllBytes(Long(e.Source));
                if (e.Empreinte == "" || Empreinte(o) != e.Empreinte) throw new IOException("la copie maître a changé depuis sa référence");
            }
            else
            {
                brut = File.ReadAllBytes(Long(e.Type == "GRENAM" ? e.CheminG : e.Chemin)); string etat; o = Reparateur.Nettoyer(brut, out etat);
                if (o == null) { if (e.Type == "GRENAM") o = brut; else throw new IOException("plus rien à corriger"); }
                if (e.Type == "REPARER") { var pb = Probleme(o, brut); if (pb != "") throw new IOException(pb); }
            }
            hAvant = Empreinte(brut); hApres = Empreinte(o);
            long libre = new DriveInfo(Path.GetPathRoot(Path.GetFullPath(e.Chemin))).AvailableFreeSpace;
            if (libre < o.Length + 64L * 1024 * 1024) throw new IOException("pas assez de place sur le disque (" + (libre / 1048576) + " Mo libres) : sors la quarantaine, puis recommence");
            EcrireVerifie(tmp, o);
        }
        File.AppendAllText(manifeste, string.Join("\t", new[] { id, e.Type, Champ(e.Relatif), e.Attr.ToString(), Champ(e.RelatifG), e.AttrG.ToString(), hAvant, hApres }) + "\r\n", new UTF8Encoding(false));
        bool b1 = false, b2 = false;
        try
        {
            File.SetAttributes(Long(e.Chemin), FileAttributes.Normal); File.Move(Long(e.Chemin), Long(a)); b1 = true;
            if (e.Type == "GRENAM") { File.SetAttributes(Long(e.CheminG), FileAttributes.Normal); File.Move(Long(e.CheminG), Long(bb)); b2 = true; }
            if (e.Type != "ISOLER") { File.Move(Long(tmp), Long(e.Chemin)); try { File.SetAttributes(Long(e.Chemin), (FileAttributes)e.Attr); } catch { } }
        }
        catch
        {
            if (b2) { File.Move(Long(bb), Long(e.CheminG)); File.SetAttributes(Long(e.CheminG), (FileAttributes)e.AttrG); }
            else if (e.Type == "GRENAM") { try { File.SetAttributes(Long(e.CheminG), (FileAttributes)e.AttrG); } catch { } }
            if (b1) File.Move(Long(a), Long(e.Chemin));
            try { File.SetAttributes(Long(e.Chemin), (FileAttributes)e.Attr); } catch { }
            if (File.Exists(Long(tmp))) File.Move(Long(tmp), Long(Path.Combine(dir, id + ".echec")));
            throw;
        }
    }

    static void PoserBlocage(string racine, ResultatAction r)
    {
        var v = Path.Combine(racine, "RECYCLER.BIN");
        if (File.Exists(v)) { r.Messages.Add("Blocage PlugX déjà en place."); return; }
        if (Directory.Exists(v)) { r.Messages.Add("Blocage PlugX non posé : le dossier RECYCLER.BIN est à ranger."); return; }
        File.WriteAllBytes(v, new byte[0]); File.SetAttributes(v, FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.System);
        r.Messages.Add("Blocage PlugX posé.");
    }

    static bool Correspond(string type, string filtre)
    {
        if (filtre == "isoler") return type == "ISOLER";
        if (filtre == "reparer") return type != "ISOLER";
        return true;
    }

    // filtre : "reparer", "isoler", ou null pour tout traiter.
    public static ResultatAction Appliquer(PlanDisque plan, string racineBrute, Action<Avancement> suivi, bool essai = false, string filtre = null)
    {
        string racine = Normaliser(racineBrute); bool systeme = !essai && EstDisqueSysteme(racine);
        if (!essai && PcInfecte() > 0) throw new InvalidOperationException("Ce PC porte la marque du virus : il réinfecterait le disque.");
        var liste = plan.Elements.Where(e => TypesAction.Contains(e.Type) && Correspond(e.Type, filtre) && (!systeme || ReparableSurSysteme(e.Relatif))).ToList(); var r = new ResultatAction();
        if ((systeme || filtre != null) && liste.Count == 0) { r.Messages.Add("Aucun fichier à traiter pour cette action."); return r; }
        // Chaque action a sa propre session : deux actions rapprochees ne doivent jamais se melanger.
        string baseDir = Path.Combine(racine, DossierQuarantaine, "antivirus-" + DateTime.Now.ToString("yyyyMMdd-HHmmss")), dir = baseDir;
        for (int k = 2; Directory.Exists(dir); k++) dir = baseDir + "-" + k;
        Directory.CreateDirectory(dir);
        r.Session = dir; string man = Path.Combine(dir, "manifeste.tsv"); int i = 0;
        foreach (var e in liste)
        {
            i++; if (suivi != null) suivi(new Avancement { Phase = filtre == "isoler" ? "Isolement" : "Réparation", Fait = i, Total = liste.Count, Courant = e.Relatif });
            try { TraiterElement(e, dir, i.ToString("D6"), man); r.Ok++; }
            catch (Exception ex) { r.Echecs++; r.Messages.Add("Échec : " + e.Relatif + " : " + ex.Message); }
        }
        if (!systeme && filtre == null) { try { PoserBlocage(racine, r); } catch (Exception ex) { r.Echecs++; r.Messages.Add("Blocage non posé : " + ex.Message); } }
        return r;
    }

    // ---------- Windows Defender (deuxieme moteur, lecture seule) ----------
    public static List<DetectionDefender> AnalyseDefender(string racineBrute, Action<Avancement> suivi, CancellationToken stop)
    {
        var mp = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender", "MpCmdRun.exe");
        if (!File.Exists(mp)) throw new InvalidOperationException("Windows Defender n'est pas disponible sur ce PC.");
        var cible = Normaliser(racineBrute).TrimEnd('\\');
        var arg = cible.Length == 2 ? cible + "\\" : "\"" + cible + "\"";
        var psi = new System.Diagnostics.ProcessStartInfo(mp, "-Scan -ScanType 3 -File " + arg + " -DisableRemediation") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        var lignes = new List<string>(); var verrou = new object(); var debut = DateTime.UtcNow;
        using (var p = new System.Diagnostics.Process { StartInfo = psi })
        {
            p.OutputDataReceived += (s, e) => { if (e.Data != null) lock (verrou) lignes.Add(e.Data); };
            p.Start(); p.BeginOutputReadLine();
            while (!p.WaitForExit(1000))
            {
                if (stop.IsCancellationRequested) { try { p.Kill(); } catch { } stop.ThrowIfCancellationRequested(); }
                if (suivi != null) { var t = DateTime.UtcNow - debut; suivi(new Avancement { Phase = "Windows Defender analyse le disque", Courant = "Temps écoulé : " + (int)t.TotalMinutes + " min " + t.Seconds.ToString("D2") + " s. Cela peut durer longtemps sur un gros disque." }); }
            }
            p.WaitForExit();
            if (p.ExitCode != 0 && p.ExitCode != 2) { string fin; lock (verrou) fin = string.Join(" ", lignes.Skip(Math.Max(0, lignes.Count - 3))); throw new InvalidOperationException("Windows Defender n'a pas pu analyser (code " + p.ExitCode + ") : " + fin); }
        }
        var r = new List<DetectionDefender>(); string menace = "";
        lock (verrou)
        {
            foreach (var brute in lignes)
            {
                var l = brute.Trim(); int i = l.IndexOf(" : "); if (i < 0) continue;
                var cle = l.Substring(0, i).Trim().ToLowerInvariant(); var val = l.Substring(i + 3).Trim();
                if (cle == "threat") menace = val;
                else if ((cle == "file" || cle == "containerfile") && menace != "") r.Add(new DetectionDefender { Menace = menace, Fichier = val });
            }
        }
        return r;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern uint GetLongPathNameW(string court, StringBuilder longue, uint taille);

    // Developpe un chemin abrege (ex. RUNNER~1) ; si le fichier n'existe plus, developpe au moins son dossier.
    static string NomLong(string p)
    {
        try
        {
            p = Path.GetFullPath(p); if (p.IndexOf('~') < 0) return p;
            var sb = new StringBuilder(32768);
            if (GetLongPathNameW(p, sb, (uint)sb.Capacity) > 0) return sb.ToString();
            var dossier = Path.GetDirectoryName(p);
            if (dossier != null && GetLongPathNameW(dossier, sb, (uint)sb.Capacity) > 0) return Path.Combine(sb.ToString(), Path.GetFileName(p));
        }
        catch { }
        return p;
    }

    static bool MenaceLegere(string menace)
    {
        int i = menace.IndexOf(':'); var famille = i > 0 ? menace.Substring(0, i) : menace;
        return MenacesLegeres.Any(x => string.Equals(x, famille, StringComparison.OrdinalIgnoreCase));
    }

    public static int FusionnerDefender(PlanDisque plan, string racineBrute, List<DetectionDefender> detections)
    {
        string racine = Normaliser(racineBrute); int ajouts = 0;
        var parChemin = new Dictionary<string, ElementPlan>(StringComparer.OrdinalIgnoreCase); foreach (var e in plan.Elements) parChemin[e.Chemin] = e;
        foreach (var d in detections)
        {
            int fl = d.Fichier.IndexOf("->"); bool archive = fl >= 0; var p = archive ? d.Fichier.Substring(0, fl) : d.Fichier;
            // Meme forme de chemin que la racine (un nom court comme RUNNER~1 devient son nom long).
            p = NomLong(p);
            if (!p.StartsWith(racine, StringComparison.OrdinalIgnoreCase) || p.IndexOf("\\" + DossierQuarantaine + "\\", StringComparison.OrdinalIgnoreCase) >= 0) continue;
            bool legere = MenaceLegere(d.Menace); var note = "Windows Defender : " + d.Menace;
            ElementPlan e;
            if (parChemin.TryGetValue(p, out e))
            {
                if (e.Detail.IndexOf(note, StringComparison.Ordinal) < 0) e.Detail += " | " + note;
                if (!legere && !archive && (e.Type == "RESTE" || e.Type == "A_VERIFIER")) e.Type = "ISOLER";
                continue;
            }
            int attr = 0; try { attr = (int)File.GetAttributes(Long(p)) & 0x3FFFF; } catch { }
            var type = (legere || archive) ? "A_VERIFIER" : "ISOLER";
            var detail = archive ? "Dans une archive : " + note : (legere ? note + " (souvent un outil ou un crack de jeu)" : "Détecté par " + note);
            e = new ElementPlan { Type = type, Chemin = p, Relatif = Relatif(p, racine), Attr = attr, Detail = detail };
            plan.Elements.Add(e); parChemin[p] = e; ajouts++;
        }
        plan.DefenderFait = true; plan.MenacesDefender = detections.Count;
        return ajouts;
    }

    // ---------- Bibliotheque d'empreintes des copies maitres ----------
    public static string DossierBibliotheque() { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "RotaAntivirus", "Bibliotheque"); }

    static string NomFichierReference(string nom) { foreach (var c in Path.GetInvalidFileNameChars()) nom = nom.Replace(c, '_'); return nom + ".ref"; }

    public static List<InfoReference> ListerReferences(string baseBib = null)
    {
        var b = baseBib ?? DossierBibliotheque(); var r = new List<InfoReference>(); if (!Directory.Exists(b)) return r;
        foreach (var f in Directory.GetFiles(b, "*.ref").OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
        {
            var i = new InfoReference { Nom = Path.GetFileNameWithoutExtension(f) };
            foreach (var l in File.ReadLines(f, Encoding.UTF8))
            {
                if (l.StartsWith("#source\t")) i.Source = l.Substring(8); else if (l.StartsWith("#nom\t")) i.Nom = l.Substring(5); else if (l.StartsWith("#date\t")) i.Date = l.Substring(6); else if (!l.StartsWith("#")) i.Fichiers++;
            }
            r.Add(i);
        }
        return r;
    }

    public static void SupprimerReference(string nom, string baseBib = null)
    {
        var f = Path.Combine(baseBib ?? DossierBibliotheque(), NomFichierReference(nom)); if (File.Exists(f)) File.Delete(f);
    }

    // Enregistre l'empreinte de chaque programme d'une copie maitre. Refuse une copie qui porte un virus connu.
    public static int CreerReference(string dossierBrut, Action<Avancement> suivi, CancellationToken stop, string baseBib = null)
    {
        var d = Path.GetFullPath(dossierBrut).TrimEnd('\\'); var nom = Path.GetFileName(d);
        if (string.IsNullOrEmpty(nom)) throw new InvalidOperationException("Choisis le dossier d'un jeu, pas la racine d'un disque.");
        var fichiers = Directory.GetFiles(Long(d), "*", SearchOption.AllDirectories).Select(Court).Where(x => ExtensionsSurveillees.Contains(Path.GetExtension(x).ToLowerInvariant())).ToList();
        var lignes = new List<string> { "#nom\t" + nom, "#source\t" + d, "#date\t" + DateTime.Now.ToString("dd/MM/yyyy HH:mm") };
        var infectes = new List<string>(); int n = 0;
        foreach (var f in fichiers)
        {
            stop.ThrowIfCancellationRequested(); n++;
            if (suivi != null && n % 10 == 1) suivi(new Avancement { Phase = "Création de la référence", Fait = n, Total = fichiers.Count, Courant = f.Substring(d.Length + 1) });
            var info = new FileInfo(Long(f)); string empreinte;
            if (info.Length <= 256L * 1024 * 1024 && ExtensionsPe.Contains(Path.GetExtension(f).ToLowerInvariant()))
            {
                var b = File.ReadAllBytes(Long(f)); string etat;
                if (Reparateur.Nettoyer(b, out etat) != null || Reparateur.EstForme2(b) || FauxGrenam(b) || EstGround(b)) { infectes.Add(f.Substring(d.Length + 1)); continue; }
                empreinte = Empreinte(b);
            }
            else empreinte = EmpreinteFichier(f);
            lignes.Add(f.Substring(d.Length + 1) + "\t" + info.Length + "\t" + empreinte);
        }
        if (infectes.Count > 0) throw new InvalidOperationException("Cette copie maître porte un virus (" + infectes.Count + " fichier(s), dont " + infectes[0] + "). Nettoie-la d'abord : aucune référence n'a été créée.");
        var bas = baseBib ?? DossierBibliotheque(); Directory.CreateDirectory(bas);
        File.WriteAllLines(Path.Combine(bas, NomFichierReference(nom)), lignes, new UTF8Encoding(false));
        return lignes.Count - 3;
    }

    // Compare les jeux du disque a leurs copies maitres : tout programme modifie est signale, meme par un virus inconnu.
    public static int ComparerBibliotheque(string racineBrute, PlanDisque plan, Action<Avancement> suivi, CancellationToken stop, string baseBib = null)
    {
        string racine = Normaliser(racineBrute), b = baseBib ?? DossierBibliotheque(); int diffs = 0;
        if (!Directory.Exists(b)) return 0;
        var parChemin = new Dictionary<string, ElementPlan>(StringComparer.OrdinalIgnoreCase); foreach (var e in plan.Elements) parChemin[e.Chemin] = e;
        foreach (var fr in Directory.GetFiles(b, "*.ref"))
        {
            string nom = Path.GetFileNameWithoutExtension(fr), source = ""; var refs = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
            foreach (var l in File.ReadLines(fr, Encoding.UTF8))
            {
                if (l.StartsWith("#nom\t")) nom = l.Substring(5); else if (l.StartsWith("#source\t")) source = l.Substring(8);
                else if (!l.StartsWith("#")) { var c = l.Split('\t'); if (c.Length == 3) refs[c[0]] = c; }
            }
            var candidats = new List<string>(); var pile = new Stack<KeyValuePair<string, int>>(); pile.Push(new KeyValuePair<string, int>(racine.TrimEnd('\\'), 0));
            while (pile.Count > 0)
            {
                var x = pile.Pop(); if (x.Value >= 3) continue; string[] sous;
                try { sous = Directory.GetDirectories(Long(x.Key)).Select(Court).ToArray(); } catch { continue; }
                foreach (var s in sous)
                {
                    var n = Path.GetFileName(s); if (n == DossierQuarantaine || n.StartsWith("$") || n == "System Volume Information") continue;
                    if (string.Equals(n, nom, StringComparison.OrdinalIgnoreCase)) candidats.Add(s); else pile.Push(new KeyValuePair<string, int>(s, x.Value + 1));
                }
            }
            foreach (var cand in candidats)
            {
                if (string.Equals(cand.TrimEnd('\\'), source.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)) continue;
                var fichiers = Directory.GetFiles(Long(cand), "*", SearchOption.AllDirectories).Select(Court).Where(x => ExtensionsSurveillees.Contains(Path.GetExtension(x).ToLowerInvariant())).ToList(); int k = 0;
                foreach (var f in fichiers)
                {
                    stop.ThrowIfCancellationRequested(); k++;
                    var rel = f.Substring(cand.TrimEnd('\\').Length + 1);
                    if (suivi != null && k % 10 == 1) suivi(new Avancement { Phase = "Comparaison avec « " + nom + " »", Fait = k, Total = fichiers.Count, Courant = rel });
                    string[] attendu; long taille = new FileInfo(Long(f)).Length; string detail = null, type = "A_VERIFIER", src = "", emp = "";
                    if (!refs.TryGetValue(rel, out attendu)) detail = "Programme absent de ta copie maître « " + nom + " »";
                    else if (taille.ToString() != attendu[1] || EmpreinteFichier(f) != attendu[2])
                    {
                        var maitre = Path.Combine(source, rel);
                        if (File.Exists(Long(maitre)) && new FileInfo(Long(maitre)).Length.ToString() == attendu[1] && EmpreinteFichier(maitre) == attendu[2]) { type = "RESTAURER"; src = maitre; emp = attendu[2]; detail = "Modifié : remis depuis ta copie maître « " + nom + " »"; }
                        else detail = "Différent de ta copie maître « " + nom + " » : branche le disque maître pour le remettre";
                    }
                    if (detail == null) continue;
                    diffs++; ElementPlan e;
                    if (parChemin.TryGetValue(f, out e))
                    {
                        if (type == "RESTAURER" && e.Type != "REPARER") { e.Type = type; e.Source = src; e.Empreinte = emp; e.CheminG = ""; e.RelatifG = ""; }
                        e.Detail += " | " + detail; continue;
                    }
                    int attr = 0; try { attr = (int)File.GetAttributes(Long(f)) & 0x3FFFF; } catch { }
                    e = new ElementPlan { Type = type, Chemin = f, Relatif = Relatif(f, racine), Attr = attr, Detail = detail, Source = src, Empreinte = emp };
                    plan.Elements.Add(e); parChemin[f] = e;
                }
            }
        }
        plan.BibliothequeFaite = true; plan.DifferencesBibliotheque = diffs;
        return diffs;
    }

    // ---------- Certificat de livraison ----------
    static string Html(string s) { return System.Net.WebUtility.HtmlEncode(s ?? ""); }

    public static string EcrireCertificat(string dossier, string disque, string client, VerdictDisque v, PlanDisque p, string logoBase64, string version)
    {
        if (v.Niveau != "PRET") throw new InvalidOperationException("Le certificat n'est possible qu'avec le verdict Prêt.");
        Directory.CreateDirectory(dossier); string racine = Normaliser(disque), nomVol = "", taille = "";
        try { var di = new DriveInfo(racine); nomVol = di.VolumeLabel; taille = (di.TotalSize / 1073741824) + " Go"; } catch { }
        var date = DateTime.Now; var serie = SerieDisque(racine);
        var controles = new List<string> { "Moteur ROTA : Expiro, Grenam, Ground, PlugX et UPX1" };
        if (p.DefenderFait) controles.Add("Windows Defender : analyse complète du disque");
        if (p.BibliothequeFaite) controles.Add("Bibliothèque RotaGaming : programmes comparés aux copies maîtres");
        string id; using (var s = SHA256.Create()) id = BitConverter.ToString(s.ComputeHash(Encoding.UTF8.GetBytes(serie + "|" + client + "|" + date.ToString("o") + "|" + p.Examines))).Replace("-", "").Substring(0, 12);
        var t = new StringBuilder();
        t.Append("<!doctype html><html lang=\"fr\"><head><meta charset=\"utf-8\"><title>Certificat ROTA ").Append(id).Append("</title><style>");
        t.Append("body{margin:0;background:#eef1f5;font-family:'Segoe UI',system-ui,sans-serif;color:#141922}.page{max-width:760px;margin:24px auto;background:#fff;border-radius:10px;padding:44px 52px;box-shadow:0 6px 30px rgba(0,0,0,.12)}");
        t.Append(".tete{display:flex;justify-content:space-between;align-items:center;background:#0a1018;margin:-44px -52px 30px;padding:22px 52px;border-radius:10px 10px 0 0}.tete img{height:30px}.tete span{color:#ffb07a;font:600 12px Consolas,monospace;letter-spacing:.16em}");
        t.Append("h1{font-size:28px;margin:0 0 6px}.ok{display:inline-block;background:#e3f8ee;color:#0d6b43;border:1px solid #8fd9b4;border-radius:6px;padding:6px 12px;font-weight:700;margin:10px 0 22px}");
        t.Append("table{width:100%;border-collapse:collapse;margin:10px 0 20px}td{padding:9px 6px;border-bottom:1px solid #e3e7ee;font-size:15px}td:first-child{color:#5a6474;width:38%}");
        t.Append("ul{margin:6px 0 20px;padding-left:20px;line-height:1.6}.note{font-size:12.5px;color:#5a6474;border-top:1px solid #e3e7ee;padding-top:14px}.id{font:600 13px Consolas,monospace}");
        t.Append("button{margin:18px 0 0;padding:10px 18px;font-size:15px;border:0;border-radius:6px;background:#0a1018;color:#fff;cursor:pointer}@media print{body{background:#fff}.page{box-shadow:none;margin:0}button{display:none}}");
        t.Append("</style></head><body><div class=\"page\"><div class=\"tete\">");
        if (!string.IsNullOrEmpty(logoBase64)) t.Append("<img alt=\"RotaGaming\" src=\"data:image/png;base64,").Append(logoBase64).Append("\">"); else t.Append("<strong style=\"color:#fff\">ROTAGAMING</strong>");
        t.Append("<span>CERTIFICAT DE CONTRÔLE</span></div><h1>Disque contrôlé avant livraison</h1><div class=\"ok\">Verdict : prêt pour la livraison</div><table>");
        t.Append("<tr><td>Client</td><td>").Append(Html(string.IsNullOrWhiteSpace(client) ? "Non précisé" : client.Trim())).Append("</td></tr>");
        t.Append("<tr><td>Disque</td><td>").Append(Html((nomVol == "" ? "Sans nom" : nomVol) + (taille == "" ? "" : " (" + taille + ")"))).Append(" — n° ").Append(Html(serie)).Append("</td></tr>");
        t.Append("<tr><td>Date du contrôle</td><td>").Append(date.ToString("dd/MM/yyyy à HH:mm")).Append("</td></tr>");
        t.Append("<tr><td>Fichiers sur le disque</td><td>").Append(p.Total.ToString("N0")).Append(" dont ").Append(p.Examines.ToString("N0")).Append(" programmes examinés</td></tr>");
        t.Append("<tr><td>Numéro du certificat</td><td class=\"id\">").Append(id).Append("</td></tr></table><strong>Contrôles effectués</strong><ul>");
        foreach (var c in controles) t.Append("<li>").Append(Html(c)).Append("</li>");
        t.Append("</ul><p class=\"note\">Ce certificat atteste qu'aucun virus connu n'a été trouvé sur ce disque à la date indiquée, avec ROTA Antivirus ").Append(Html(version)).Append(". Il ne garantit pas l'absence de tout virus, ni la sécurité de l'ordinateur sur lequel le disque sera branché.</p>");
        t.Append("<button onclick=\"window.print()\">Imprimer ou enregistrer en PDF</button></div></body></html>");
        var c2 = Path.Combine(dossier, "certificat-" + date.ToString("yyyyMMdd-HHmmss") + "-" + id + ".html");
        File.WriteAllText(c2, t.ToString(), new UTF8Encoding(true)); return c2;
    }

    // Fait toutes les etapes dans le bon ordre. S'arrete et explique si une etape est impossible.
    public static ResultatAction ToutNettoyer(string racineBrute, Action<Avancement> suivi, bool essai = false, string baseArchives = null, List<ElementPlan> extras = null)
    {
        string racine = Normaliser(racineBrute); bool systeme = !essai && EstDisqueSysteme(racine); var r = new ResultatAction(); int etape = 0, total = systeme ? 2 : 6;
        Action<string> annonce = t => { etape++; if (suivi != null) suivi(new Avancement { Phase = "Étape " + etape + "/" + total + " : " + t }); };
        Func<string, Func<ResultatAction>, bool> faire = (nom, travail) =>
        {
            try
            {
                var x = travail(); r.Ok += x.Ok; r.Echecs += x.Echecs;
                r.Messages.Add(nom + " : " + x.Ok + " fichier(s)" + (x.Echecs > 0 ? ", " + x.Echecs + " échec(s)" : "") + ".");
                r.Messages.AddRange(x.Messages.Where(m => m.StartsWith("Échec")).Take(3));
                return true;
            }
            catch (Exception ex) { r.Echecs++; r.Messages.Add("ARRÊT à l'étape « " + nom + " » : " + ex.Message); return false; }
        };
        if (!systeme)
        {
            annonce("place sur le disque");
            var e0 = Etat(racine);
            if (e0.Quarantaine && e0.Libre < 1024L * 1024 * 1024) { if (!faire("Sortie de la quarantaine", () => SortirQuarantaine(racine, baseArchives, essai))) return r; }
            else r.Messages.Add("Place sur le disque : suffisante.");
        }
        annonce("réparation des programmes");
        var plan = Analyser(racine, null, CancellationToken.None);
        // Les decouvertes de Windows Defender et de la bibliotheque ne sont pas refaites : on les reprend telles quelles.
        if (extras != null) foreach (var x in extras) { if (!plan.Elements.Any(e => string.Equals(e.Chemin, x.Chemin, StringComparison.OrdinalIgnoreCase)) && File.Exists(Long(x.Chemin))) plan.Elements.Add(x); }
        if (!faire("Réparation", () => Appliquer(plan, racine, suivi, essai, "reparer"))) return r;
        annonce("isolement des fichiers irréparables");
        if (!faire("Isolement", () => Appliquer(plan, racine, suivi, essai, "isoler"))) return r;
        if (systeme) return r;
        annonce("fichiers cachés par PlugX");
        if (DossiersCaches(racine).Count > 0) { if (!faire("Fichiers cachés remis", () => RemettreFichiersCaches(racine, essai))) return r; }
        else r.Messages.Add("Fichiers cachés : aucun.");
        annonce("dossier RECYCLER.BIN");
        if (Directory.Exists(Path.Combine(racine, "RECYCLER.BIN"))) { if (!faire("RECYCLER.BIN rangé", () => RangerRecycler(racine, CompterRecycler(racine), essai))) return r; }
        annonce("blocage PlugX");
        if (!Etat(racine).Blocage) faire("Blocage PlugX", () => PoserBlocageDisque(racine, essai));
        return r;
    }

    public static bool PeutAnnuler(string racineBrute)
    {
        var bas = Path.Combine(Normaliser(racineBrute), DossierQuarantaine); if (!Directory.Exists(bas)) return false;
        return Directory.GetDirectories(bas, "antivirus-*").Any(x => File.Exists(Path.Combine(x, "manifeste.tsv")) && Directory.GetFiles(x, "*.origine").Length > 0)
            || Directory.GetDirectories(bas, "recycler-*").Any(x => Directory.Exists(Path.Combine(x, "RECYCLER.BIN")));
    }

    static string DateSession(string d) { var n = Path.GetFileName(d); return n.Substring(n.IndexOf('-') + 1); }

    static void RemettreRecycler(string racine, string session, ResultatAction r)
    {
        string v = Path.Combine(racine, "RECYCLER.BIN"), src = Path.Combine(session, "RECYCLER.BIN"), bloc = Path.Combine(session, "blocage-retire.bin"), inv = Path.Combine(session, "inventaire.tsv");
        if (Directory.Exists(v)) { r.Echecs++; r.Messages.Add("Échec : un dossier RECYCLER.BIN existe déjà."); return; }
        bool retire = false;
        if (File.Exists(v))
        {
            if (new FileInfo(v).Length != 0) { r.Echecs++; r.Messages.Add("Échec : le fichier RECYCLER.BIN n'est pas le blocage attendu."); return; }
            if (File.Exists(bloc)) File.Delete(bloc);
            File.SetAttributes(v, FileAttributes.Normal); File.Move(v, bloc); retire = true;
        }
        try { Directory.Move(src, v); }
        catch (Exception ex)
        {
            if (retire) { File.Move(bloc, v); File.SetAttributes(v, FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.System); }
            r.Echecs++; r.Messages.Add("Échec : RECYCLER.BIN : " + ex.Message); return;
        }
        var apres = Inventaire(v);
        if (File.Exists(inv) && !File.ReadAllLines(inv, Encoding.UTF8).SequenceEqual(apres)) { r.Echecs++; r.Messages.Add("Échec : RECYCLER.BIN différent après sa remise."); return; }
        r.Ok += apres.Count;
    }

    public static ResultatAction Annuler(string racineBrute, bool essai = false)
    {
        string racine = Normaliser(racineBrute);
        var r = new ResultatAction(); var bas = Path.Combine(racine, DossierQuarantaine);
        if (!Directory.Exists(bas)) { r.Messages.Add("Aucune réparation sur ce disque."); return r; }
        var dir = Directory.GetDirectories(bas, "antivirus-*").OrderByDescending(x => x, StringComparer.Ordinal).FirstOrDefault(x => File.Exists(Path.Combine(x, "manifeste.tsv")) && Directory.GetFiles(x, "*.origine").Length > 0);
        var rec = Directory.GetDirectories(bas, "recycler-*").OrderByDescending(x => x, StringComparer.Ordinal).FirstOrDefault(x => Directory.Exists(Path.Combine(x, "RECYCLER.BIN")));
        var lignes = dir == null ? new string[0] : File.ReadAllLines(Path.Combine(dir, "manifeste.tsv"), Encoding.UTF8);
        bool besoinRecycler = lignes.Any(x => { var c = x.Split('\t'); return c.Length > 2 && c[2].StartsWith("RECYCLER.BIN\\", StringComparison.OrdinalIgnoreCase); });
        bool remettreRec = rec != null && (dir == null || besoinRecycler || string.CompareOrdinal(DateSession(rec), DateSession(dir)) >= 0);
        if (dir == null && !remettreRec) { r.Messages.Add("Rien à annuler."); return r; }
        r.Session = dir ?? rec;
        // Le dossier RECYCLER.BIN revient d'abord : les fichiers isoles peuvent y retourner.
        if (remettreRec) RemettreRecycler(racine, rec, r);
        foreach (var l in lignes.AsEnumerable().Reverse())
        {
            var c = l.Split('\t'); if (c.Length < 8) continue;
            string a = Path.Combine(dir, c[0] + "-a.origine"), bb = Path.Combine(dir, c[0] + "-b.origine"), dst = Path.Combine(racine, c[2]);
            if (!File.Exists(Long(a))) continue;
            try
            {
                if (c[1] != "ISOLER" && File.Exists(Long(dst))) { File.SetAttributes(Long(dst), FileAttributes.Normal); File.Move(Long(dst), Long(Path.Combine(dir, c[0] + ".repare"))); }
                Directory.CreateDirectory(Long(Path.GetDirectoryName(dst)));
                File.Move(Long(a), Long(dst)); File.SetAttributes(Long(dst), (FileAttributes)(int.Parse(c[3]) & 0x3FFFF));
                if (c[1] == "GRENAM" && File.Exists(Long(bb))) { var g = Path.Combine(racine, c[4]); File.Move(Long(bb), Long(g)); File.SetAttributes(Long(g), (FileAttributes)(int.Parse(c[5]) & 0x3FFFF)); }
                r.Ok++;
            }
            catch (Exception ex) { r.Echecs++; r.Messages.Add("Échec : " + c[2] + " : " + ex.Message); }
        }
        return r;
    }

    // ---------- Quarantaine et blocage ----------
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool GetVolumeInformationW(string racine, StringBuilder nom, int tailleNom, out uint serie, out uint maxComposant, out uint options, StringBuilder systeme, int tailleSysteme);

    static string SerieDisque(string racine)
    {
        uint s, a, b; return GetVolumeInformationW(Path.GetPathRoot(Normaliser(racine)), null, 0, out s, out a, out b, null, 0) ? s.ToString("X8") : "INCONNU";
    }

    static string DossierArchives() { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "RotaAntivirus", "Archives"); }

    public static ResultatAction PoserBlocageDisque(string racineBrute, bool essai = false)
    {
        string racine = Normaliser(racineBrute); Refuser(racine, essai); var r = new ResultatAction(); PoserBlocage(racine, r); return r;
    }

    public static List<InfoQuarantaine> ListerQuarantaine(string racineBrute)
    {
        var l = new List<InfoQuarantaine>(); var bas = Path.Combine(Normaliser(racineBrute), DossierQuarantaine);
        if (!Directory.Exists(bas)) return l;
        foreach (var d in Directory.GetDirectories(bas).OrderByDescending(x => x, StringComparer.Ordinal))
        {
            var n = Path.GetFileName(d); var q = new InfoQuarantaine { Nom = n, Date = Directory.GetLastWriteTime(d).ToString("dd/MM/yyyy HH:mm") };
            q.Genre = n.StartsWith("recycler") ? "Documents RECYCLER.BIN" : n.StartsWith("demarrage") ? "Réparation au démarrage" : "Fichiers isolés";
            try { foreach (var f in Directory.GetFiles(Long(d), "*", SearchOption.AllDirectories)) { q.Fichiers++; q.Octets += new FileInfo(f).Length; } } catch { }
            l.Add(q);
        }
        return l;
    }

    static int CopierVerifie(string source, string cible)
    {
        var s = Court(source).TrimEnd('\\'); int n = 0;
        foreach (var f in Directory.GetFiles(Long(s), "*", SearchOption.AllDirectories).Select(Court))
        {
            var c = Path.Combine(cible, f.Substring(s.Length + 1)); Directory.CreateDirectory(Long(Path.GetDirectoryName(c)));
            File.Copy(Long(f), Long(c), false); File.SetAttributes(Long(c), FileAttributes.Normal);
            if (EmpreinteFichier(f) != EmpreinteFichier(c)) throw new IOException("copie différente : " + Path.GetFileName(f));
            n++;
        }
        return n;
    }

    static void RetirerDossier(string d)
    {
        foreach (var x in Directory.GetFileSystemEntries(Long(d), "*", SearchOption.AllDirectories)) { try { File.SetAttributes(x, FileAttributes.Normal); } catch { } }
        try { File.SetAttributes(Long(d), FileAttributes.Directory); } catch { }
        Directory.Delete(Long(d), true);
    }

    public static bool ArchiveExiste(string racineBrute, string baseArchives = null)
    {
        var b = baseArchives ?? DossierArchives(); return Directory.Exists(b) && Directory.GetDirectories(b, SerieDisque(racineBrute) + "-*").Length > 0;
    }

    // Copie la quarantaine sur le PC, verifie chaque fichier, puis seulement la retire du disque.
    public static ResultatAction SortirQuarantaine(string racineBrute, string baseArchives = null, bool essai = false)
    {
        string racine = Normaliser(racineBrute), src = Path.Combine(racine, DossierQuarantaine), b = baseArchives ?? DossierArchives(); var r = new ResultatAction();
        if (!essai && EstDisqueSysteme(racine)) throw new InvalidOperationException("Cette action ne travaille que sur un disque externe.");
        if (!Directory.Exists(src)) { r.Messages.Add("Aucune quarantaine sur ce disque."); return r; }
        if (!essai && string.Equals(Path.GetPathRoot(b), Path.GetPathRoot(racine), StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("L'archive doit être sur un autre disque.");
        long total = Directory.GetFiles(Long(src), "*", SearchOption.AllDirectories).Sum(f => new FileInfo(f).Length);
        if (new DriveInfo(Path.GetPathRoot(Path.GetFullPath(b))).AvailableFreeSpace < total + 100L * 1024 * 1024) throw new IOException("Pas assez de place sur le PC : rien n'a été retiré du disque.");
        var archive = Path.Combine(b, SerieDisque(racine) + "-" + DateTime.Now.ToString("yyyyMMdd-HHmmss")); var dst = Path.Combine(archive, DossierQuarantaine);
        try { Directory.CreateDirectory(dst); r.Ok = CopierVerifie(src, dst); }
        catch (Exception ex) { try { if (Directory.Exists(archive)) RetirerDossier(archive); } catch { } throw new IOException("Copie impossible, rien n'a été retiré du disque : " + ex.Message); }
        RetirerDossier(src); r.Session = archive; r.Messages.Add("Quarantaine gardée sur le PC."); return r;
    }

    public static ResultatAction RemettreQuarantaine(string racineBrute, string baseArchives = null, bool essai = false)
    {
        string racine = Normaliser(racineBrute), dst = Path.Combine(racine, DossierQuarantaine), b = baseArchives ?? DossierArchives(); var r = new ResultatAction();
        if (!essai && EstDisqueSysteme(racine)) throw new InvalidOperationException("Cette action ne travaille que sur un disque externe.");
        if (Directory.Exists(dst)) throw new InvalidOperationException("Une quarantaine existe déjà sur ce disque.");
        var archive = Directory.Exists(b) ? Directory.GetDirectories(b, SerieDisque(racine) + "-*").OrderByDescending(x => x, StringComparer.Ordinal).FirstOrDefault() : null;
        if (archive == null) { r.Messages.Add("Aucune archive pour ce disque."); return r; }
        try { r.Ok = CopierVerifie(Path.Combine(archive, DossierQuarantaine), dst); }
        catch (Exception ex) { try { if (Directory.Exists(dst)) RetirerDossier(dst); } catch { } throw new IOException("Copie impossible, l'archive reste sur le PC : " + ex.Message); }
        RetirerDossier(archive); r.Session = dst; r.Messages.Add("Quarantaine remise sur le disque."); return r;
    }

    static List<string> Inventaire(string dossier)
    {
        var d = dossier.TrimEnd('\\');
        return Directory.GetFiles(Long(d), "*", SearchOption.AllDirectories).Select(Court).OrderBy(x => x, StringComparer.Ordinal).Select(x => x.Substring(d.Length + 1) + "\t" + new FileInfo(Long(x)).Length + "\t" + EmpreinteFichier(x)).ToList();
    }

    public static int CompterRecycler(string racineBrute) { return Directory.GetFiles(Long(Path.Combine(Normaliser(racineBrute), "RECYCLER.BIN")), "*", SearchOption.AllDirectories).Length; }

    public static ResultatAction RangerRecycler(string racineBrute, int attendus, bool essai = false)
    {
        string racine = Normaliser(racineBrute); Refuser(racine, essai);
        string src = Path.Combine(racine, "RECYCLER.BIN"); var r = new ResultatAction();
        if (!Directory.Exists(src)) { r.Messages.Add("Aucun dossier RECYCLER.BIN."); return r; }
        if ((File.GetAttributes(src) & FileAttributes.ReparsePoint) != 0) throw new InvalidOperationException("RECYCLER.BIN est un lien.");
        var avant = Inventaire(src); if (avant.Count != attendus) throw new InvalidOperationException("Le nombre de fichiers a changé : rien n'a été modifié.");
        var dir = Path.Combine(racine, DossierQuarantaine, "recycler-" + DateTime.Now.ToString("yyyyMMdd-HHmmss")); Directory.CreateDirectory(dir);
        File.WriteAllLines(Path.Combine(dir, "inventaire.tsv"), avant, new UTF8Encoding(false));
        var dst = Path.Combine(dir, "RECYCLER.BIN"); Directory.Move(src, dst); r.Session = dir;
        if (!avant.SequenceEqual(Inventaire(dst))) throw new IOException("Différence après le déplacement : blocage non posé. Documents dans " + dst);
        r.Ok = avant.Count; PoserBlocage(racine, r); return r;
    }
}
