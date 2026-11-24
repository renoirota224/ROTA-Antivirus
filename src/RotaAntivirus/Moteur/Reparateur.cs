// ROTAGAMING - reparation des programmes infectes par Expiro.
// Ce code lit et corrige des octets. Il n'execute jamais le programme analyse.
using System;
using System.Collections.Generic;
using System.Numerics;

public class SectionPe { public string Nom; public uint VS, VA, Raw, Ptr, Ch; public int Entete; }

public class ResultatReparation
{
    public bool Infecte, Repare, Is64;
    public string Raison = "";
    public byte[] Sortie;
    public uint Cible, Entree, Appel, TailleGardee;
}

public static class Reparateur
{
    // Cle publique du virus, necessaire pour relire ce qu'il a cache dans chaque fichier.
    static readonly byte[] ClePublique = Hex("66E34B34F63BE6588AEC2200594E41B6941FF4A4FA82D8CD57223F6F62AC8B11");
    static readonly byte[] Debut64 = Hex("505152535556574150415141524153415441554156415755488BEC4883EC204883E4F0488D05");
    static readonly byte[] Debut32 = Hex("50515253555657E8000000005881E8");
    static readonly BigInteger P = BigInteger.Pow(2, 255) - 19;

    static byte[] Hex(string h) { var r = new byte[h.Length / 2]; for (int i = 0; i < r.Length; i++) r[i] = Convert.ToByte(h.Substring(2 * i, 2), 16); return r; }
    static BigInteger M(BigInteger a) { a %= P; return a.Sign < 0 ? a + P : a; }
    static BigInteger Inv(BigInteger a) { return BigInteger.ModPow(M(a), P - 2, P); }

    static byte[] Echange(byte[] pub, byte[] priv, int so)
    {
        var e = new byte[32]; Array.Copy(priv, so, e, 0, 32); e[0] &= 248; e[31] &= 63; e[31] |= 64;
        var t0 = new byte[33]; Array.Copy(pub, t0, 32); t0[31] &= 0x7F; var y = new BigInteger(t0);
        var x1 = M((y + 1) * Inv(1 - y)); BigInteger x2 = 1, z2 = 0, x3 = x1, z3 = 1; int sw = 0;
        for (int pos = 254; pos >= 0; pos--)
        {
            int b = (e[pos / 8] >> (pos & 7)) & 1; sw ^= b;
            if (sw == 1) { var t = x2; x2 = x3; x3 = t; t = z2; z2 = z3; z3 = t; }
            sw = b;
            var A = M(x2 + z2); var AA = M(A * A); var B = M(x2 - z2); var BB = M(B * B); var E = M(AA - BB);
            var C = M(x3 + z3); var D = M(x3 - z3); var DA = M(D * A); var CB = M(C * B);
            var s = M(DA + CB); x3 = M(s * s); var d = M(DA - CB); z3 = M(x1 * M(d * d));
            x2 = M(AA * BB); z2 = M(E * M(AA + 121665 * E));
        }
        if (sw == 1) { var t = x2; x2 = x3; x3 = t; t = z2; z2 = z3; z3 = t; }
        var o = M(x2 * Inv(z2)).ToByteArray(); var res = new byte[32]; Array.Copy(o, res, Math.Min(32, o.Length)); return res;
    }

    static uint Rot(uint x, int n) { return (x << n) | (x >> (32 - n)); }
    static void Q(uint[] s, int a, int b, int c, int d) { s[a] += s[b]; s[d] = Rot(s[d] ^ s[a], 16); s[c] += s[d]; s[b] = Rot(s[b] ^ s[c], 12); s[a] += s[b]; s[d] = Rot(s[d] ^ s[a], 8); s[c] += s[d]; s[b] = Rot(s[b] ^ s[c], 7); }

    static byte[] Chacha8(byte[] cle, byte[] data, int o, int n)
    {
        var st = new uint[16]; st[0] = 0x61707865; st[1] = 0x3320646e; st[2] = 0x79622d32; st[3] = 0x6b206574;
        for (int i = 0; i < 8; i++) st[4 + i] = BitConverter.ToUInt32(cle, 4 * i);
        st[14] = 0x34333231; st[15] = 0x38373635;
        var x = (uint[])st.Clone();
        for (int i = 0; i < 4; i++) { Q(x, 0, 4, 8, 12); Q(x, 1, 5, 9, 13); Q(x, 2, 6, 10, 14); Q(x, 3, 7, 11, 15); Q(x, 0, 5, 10, 15); Q(x, 1, 6, 11, 12); Q(x, 2, 7, 8, 13); Q(x, 3, 4, 9, 14); }
        var ks = new byte[64]; for (int i = 0; i < 16; i++) BitConverter.GetBytes(x[i] + st[i]).CopyTo(ks, 4 * i);
        var r = new byte[n]; for (int i = 0; i < n; i++) r[i] = (byte)(data[o + i] ^ ks[i]); return r;
    }

    public static List<SectionPe> Sections(byte[] f, out int pe, out bool is64)
    {
        pe = BitConverter.ToInt32(f, 60); is64 = BitConverter.ToUInt16(f, pe + 24) == 0x20B;
        int ns = BitConverter.ToUInt16(f, pe + 6), os = BitConverter.ToUInt16(f, pe + 20), t = pe + 24 + os;
        var l = new List<SectionPe>();
        for (int i = 0; i < ns; i++)
        {
            int o = t + 40 * i;
            l.Add(new SectionPe { Nom = System.Text.Encoding.ASCII.GetString(f, o, 8).Split('\0')[0], VS = BitConverter.ToUInt32(f, o + 8), VA = BitConverter.ToUInt32(f, o + 12), Raw = BitConverter.ToUInt32(f, o + 16), Ptr = BitConverter.ToUInt32(f, o + 20), Ch = BitConverter.ToUInt32(f, o + 36), Entete = o });
        }
        return l;
    }

    static bool Egal(byte[] f, int o, byte[] m) { if (o < 0 || o + m.Length > f.Length) return false; for (int i = 0; i < m.Length; i++) if (f[o + i] != m[i]) return false; return true; }

    // Passe les instructions add/sub/xor/not de la boucle du virus, sans les executer.
    static int FinBoucle(byte[] f, int p)
    {
        for (int garde = 0; garde < 2000; garde++)
        {
            byte c = f[p];
            if (c == 0x48 || (c == 0x81 && f[p + 1] == 0xC6)) return p;
            if (c != 0x81 && c != 0xF7) return -1;
            byte m = f[p + 1]; int mod = m >> 6; if ((m & 7) != 0 || mod == 3) return -1;
            p += 2; if (mod == 1) p += 1; else if (mod == 2) p += 4;
            if (c == 0x81) p += 4;
        }
        return -1;
    }

    static uint Somme(byte[] f, int champ)
    {
        ulong s = 0; int n = f.Length;
        for (int i = 0; i + 1 < n; i += 2) { if (i == champ || i == champ + 2) continue; s += BitConverter.ToUInt16(f, i); s = (s & 0xFFFF) + (s >> 16); }
        if ((n & 1) != 0) { s += f[n - 1]; s = (s & 0xFFFF) + (s >> 16); }
        s = (s & 0xFFFF) + (s >> 16);
        return (uint)s + (uint)n;
    }

    // Forme 2 : son corps ecrase les donnees qui suivent la derniere section, sans en garder de copie.
    // Un fichier qui la porte ne peut donc jamais etre declare repare : seule une copie officielle le remplace.
    static readonly byte[] SigForme2 = Hex("E80B000000C3CCCCCCCCCCCCCCCCCCCC");

    public static bool EstForme2(byte[] f)
    {
        if (f == null || f.Length < 1024 || f[0] != 0x4D || f[1] != 0x5A) return false;
        try
        {
            int pe; bool is64; var sec = Sections(f, out pe, out is64); if (sec.Count == 0) return false;
            var L = sec[sec.Count - 1]; if (L.Raw < 0x200 || (long)L.Ptr + L.Raw > f.Length) return false;
            if (Egal(f, (int)(L.Ptr + L.Raw - 0x200), SigForme2)) return true;
            foreach (var s in sec) if (s.Nom == "UPX0") return false;
            return L.Nom == "UPX1" && TailleVariante(L.Raw) && Entropie(f, (int)(L.Ptr + L.Raw - 0x10000), 0x10000) >= 7.5;
        }
        catch { return false; }
    }

    // Variante sans signature : derniere section UPX1 sans UPX0, de la taille du corps du virus, remplie de donnees chiffrees.
    static bool TailleVariante(uint raw) { return raw >= 0xBD000 && raw <= 0xD0000; }

    static double Entropie(byte[] f, int o, int n)
    {
        var c = new int[256]; for (int i = 0; i < n; i++) c[f[o + i]]++;
        double e = 0; foreach (var x in c) if (x > 0) { double p = (double)x / n; e -= p * Math.Log(p, 2); }
        return e;
    }

    // Vrai seulement si la section UPX1 n'est qu'une table de relocations renommee : non executable,
    // entierement valide, sans donnees cachees et sans aucun saut du code vers elle.
    public static bool ResteUpx1Inerte(byte[] f)
    {
        try
        {
            int pe; bool is64; var sec = Sections(f, out pe, out is64); if (sec.Count == 0) return false;
            foreach (var s in sec) if (s.Nom == "UPX0") return false;
            var u = sec[sec.Count - 1];
            if (u.Nom != "UPX1" || (u.Ch & 0xA0000000) != 0 || u.Raw == 0 || u.Raw > 0x1000000 || (long)u.Ptr + u.Raw > f.Length) return false;
            int dd = pe + 24 + (is64 ? 112 : 96); uint rva = BitConverter.ToUInt32(f, dd + 40), taille = BitConverter.ToUInt32(f, dd + 44), image = BitConverter.ToUInt32(f, pe + 80);
            // Le virus a pu effacer le repertoire des relocations : la table se relit alors dans la section.
            bool sansRep = rva == 0;
            if (!sansRep && (rva != u.VA || taille < 8 || taille > u.Raw)) return false;
            uint limite = sansRep ? u.Raw : taille, lu = 0; int blocs = 0;
            while (lu + 8 <= limite)
            {
                uint page = BitConverter.ToUInt32(f, (int)(u.Ptr + lu)), bloc = BitConverter.ToUInt32(f, (int)(u.Ptr + lu + 4));
                if (sansRep && page == 0 && bloc == 0) break;
                if (bloc < 8 || (bloc & 1) != 0 || lu + bloc > limite || page >= image || (page & 0xFFF) != 0) return false;
                for (uint k = 8; k < bloc; k += 2) { int t = BitConverter.ToUInt16(f, (int)(u.Ptr + lu + k)) >> 12; if (t != 0 && t != 3 && t != 10) return false; }
                lu += bloc; blocs++;
            }
            if (blocs == 0 || (!sansRep && lu != taille)) return false;
            for (uint i = lu; i < u.Raw; i++) if (f[u.Ptr + i] != 0) return false;
            foreach (var s in sec)
            {
                // En 64 bits, Windows interdit toujours d'executer une section non executable : un saut vers elle planterait.
                if (is64 || s == u || (s.Ch & 0x20000000) == 0) continue;
                long max = Math.Min((long)s.Raw, f.Length - (long)s.Ptr) - 5;
                for (long i = 0; i < max; i++)
                {
                    byte b = f[s.Ptr + i]; if (b != 0xE8 && b != 0xE9) continue;
                    uint c = unchecked(s.VA + (uint)i + 5 + (uint)BitConverter.ToInt32(f, (int)(s.Ptr + i + 1)));
                    if (c >= u.VA && c < u.VA + Math.Max(u.VS, u.Raw)) return false;
                }
            }
            return true;
        }
        catch { return false; }
    }

    // Lecture rapide : seulement l'en-tete et les 16 octets de la signature.
    public static bool FichierForme2(string chemin)
    {
        try
        {
            using (var fs = new System.IO.FileStream(chemin, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.ReadWrite | System.IO.FileShare.Delete))
            {
                var h = new byte[4096]; int n = fs.Read(h, 0, h.Length); if (n < 512 || h[0] != 0x4D || h[1] != 0x5A) return false;
                int pe = BitConverter.ToInt32(h, 60); if (pe <= 0 || pe > n - 256 || BitConverter.ToUInt32(h, pe) != 0x4550) return false;
                int ns = BitConverter.ToUInt16(h, pe + 6), t = pe + 24 + BitConverter.ToUInt16(h, pe + 20); if (ns == 0 || ns > 96 || t + 40 * ns > n) return false;
                int l = t + 40 * (ns - 1); uint raw = BitConverter.ToUInt32(h, l + 16), ptr = BitConverter.ToUInt32(h, l + 20);
                if (raw < 0x200 || (long)ptr + raw > fs.Length) return false;
                var b = new byte[16]; fs.Seek((long)ptr + raw - 0x200, System.IO.SeekOrigin.Begin); if (fs.Read(b, 0, 16) != 16) return false;
                if (Egal(b, 0, SigForme2)) return true;
                if (!TailleVariante(raw) || System.Text.Encoding.ASCII.GetString(h, l, 8).Split('\0')[0] != "UPX1") return false;
                for (int k = 0; k < ns; k++) if (System.Text.Encoding.ASCII.GetString(h, t + 40 * k, 8).Split('\0')[0] == "UPX0") return false;
                var q = new byte[0x10000]; fs.Seek((long)ptr + raw - 0x10000, System.IO.SeekOrigin.Begin); int lu = 0, c; while (lu < q.Length && (c = fs.Read(q, lu, q.Length - lu)) > 0) lu += c;
                return lu == q.Length && Entropie(q, 0, q.Length) >= 7.5;
            }
        }
        catch { return false; }
    }

    // Identite d'un programme : date de compilation, point d'entree et taille.
    public static string CleFichier(string chemin)
    {
        try
        {
            using (var fs = new System.IO.FileStream(chemin, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.ReadWrite | System.IO.FileShare.Delete))
            {
                var h = new byte[4096]; int n = fs.Read(h, 0, h.Length); if (n < 256 || h[0] != 0x4D || h[1] != 0x5A) return null;
                int pe = BitConverter.ToInt32(h, 60); if (pe <= 0 || pe + 44 > n || BitConverter.ToUInt32(h, pe) != 0x4550) return null;
                return BitConverter.ToUInt32(h, pe + 8).ToString("X8") + ":" + BitConverter.ToUInt32(h, pe + 40).ToString("X8") + ":" + fs.Length;
            }
        }
        catch { return null; }
    }

    // Vrai seulement si "off" est bien l'original de "inf" : meme code au detournement pres (une zone de 5 octets
    // au plus), et memes donnees apres la zone ecrasee par le virus.
    public static bool MemeProgramme(byte[] inf, byte[] off)
    {
        if (inf == null || off == null || inf.Length != off.Length || !EstForme2(inf) || EstForme2(off)) return false;
        try
        {
            int pi, po; bool xi, xo; var si = Sections(inf, out pi, out xi); var so = Sections(off, out po, out xo);
            if (pi != po || xi != xo || si.Count != so.Count) return false;
            if (BitConverter.ToUInt32(inf, pi + 8) != BitConverter.ToUInt32(off, po + 8) || BitConverter.ToUInt32(inf, pi + 40) != BitConverter.ToUInt32(off, po + 40)) return false;
            int debut = (int)BitConverter.ToUInt32(off, po + 84), fin = (int)so[so.Count - 1].Ptr, zones = 0, deb = -1;
            if (debut <= 0 || fin <= debut || fin > off.Length) return false;
            for (int i = debut; i <= fin; i++)
            {
                bool d = i < fin && inf[i] != off[i];
                if (d && deb < 0) deb = i;
                else if (!d && deb >= 0) { if (++zones > 1 || i - deb > 5) return false; deb = -1; }
            }
            var L = si[si.Count - 1]; long finVirus = (long)L.Ptr + L.Raw;
            if (finVirus > off.Length) return false;
            for (long i = finVirus; i < off.Length; i++) if (inf[i] != off[i]) return false;
            return true;
        }
        catch { return false; }
    }

    // La forme UPX1 a ecrit "UPX1\0" sur le debut du nom ".reloc" : il reste "UPX1\0c". Si la section est
    // toujours une table de relocations valide et inerte, on remet exactement le nom et le repertoire d'origine.
    static readonly byte[] NomUpx1Reloc = { 0x55, 0x50, 0x58, 0x31, 0, 0x63, 0, 0 };

    public static byte[] RemettreReloc(byte[] f)
    {
        if (f == null || f.Length < 4096 || f[0] != 0x4D || f[1] != 0x5A) return null;
        try
        {
            int pe; bool is64; var sec = Sections(f, out pe, out is64); if (sec.Count == 0) return null;
            var u = sec[sec.Count - 1];
            if (!Egal(f, u.Entete, NomUpx1Reloc) || !ResteUpx1Inerte(f)) return null;
            int dd = pe + 24 + (is64 ? 112 : 96); uint rva = BitConverter.ToUInt32(f, dd + 40), lu = 0;
            if (rva == 0)
            {
                while (lu + 8 <= u.Raw)
                {
                    uint page = BitConverter.ToUInt32(f, (int)(u.Ptr + lu)), bloc = BitConverter.ToUInt32(f, (int)(u.Ptr + lu + 4));
                    if (page == 0 && bloc == 0) break;
                    lu += bloc;
                }
            }
            var o = (byte[])f.Clone();
            var nom = new byte[8]; System.Text.Encoding.ASCII.GetBytes(".reloc").CopyTo(nom, 0); nom.CopyTo(o, u.Entete);
            BitConverter.GetBytes((uint)0x42000040).CopyTo(o, u.Entete + 36);
            if (rva == 0 && lu > 0)
            {
                BitConverter.GetBytes(u.VA).CopyTo(o, dd + 40); BitConverter.GetBytes(lu).CopyTo(o, dd + 44);
                // Taille d'origine de la section, taille de l'image et chargement a adresse variable, comme avant l'infection.
                BitConverter.GetBytes(lu).CopyTo(o, u.Entete + 8);
                uint al = BitConverter.ToUInt32(f, pe + 56), img = u.VA + lu; if (al > 0 && img % al != 0) img += al - img % al;
                BitConverter.GetBytes(img).CopyTo(o, pe + 80);
                ushort dc = BitConverter.ToUInt16(f, pe + 94); if ((dc & 0x0100) != 0) BitConverter.GetBytes((ushort)(dc | 0x0040)).CopyTo(o, pe + 94);
            }
            if (BitConverter.ToUInt32(f, pe + 88) != 0) BitConverter.GetBytes(Somme(o, pe + 88)).CopyTo(o, pe + 88);
            return o;
        }
        catch { return null; }
    }

    // Appels du fichier repare qui sortent du programme et menaient, dans le fichier infecte, au code de la forme 2
    // (fin de la derniere section moins 0x200, ou sa signature exacte). Un tel fichier planterait : il n'est jamais declare repare.
    public static int AppelsPendants(byte[] f, byte[] infecte)
    {
        try
        {
            int pe, pi; bool is64, xi; var s = Sections(f, out pe, out is64); var si = Sections(infecte, out pi, out xi); var Li = si[si.Count - 1];
            uint img = BitConverter.ToUInt32(f, pe + 80), fin = Li.VA + Li.Raw - 0x200; int n = 0;
            foreach (var q in s)
            {
                if ((q.Ch & 0x20000000) == 0) continue; long max = Math.Min((long)q.Raw, f.Length - (long)q.Ptr) - 5;
                for (long i = 0; i < max; i++)
                {
                    byte b = f[q.Ptr + i]; if (b != 0xE8 && b != 0xE9) continue;
                    uint c = unchecked(q.VA + (uint)i + 5 + (uint)BitConverter.ToInt32(f, (int)(q.Ptr + i + 1)));
                    if (c < img) continue;
                    if (c == fin) { n++; continue; }
                    foreach (var w in si) if (c >= w.VA && c - w.VA + 16 <= w.Raw && Egal(infecte, (int)(w.Ptr + c - w.VA), SigForme2)) { n++; break; }
                }
            }
            return n;
        }
        catch { return 0; }
    }

    // Fonction de securite standard de Visual C++, reconnue a sa constante : BB40E64E (32 bits) ou 2B992DDFA232 (64 bits).
    static List<uint> FonctionsSecurite(byte[] f, List<SectionPe> s, bool is64)
    {
        var r = new List<uint>(); byte[] m = is64 ? new byte[] { 0x32, 0xA2, 0xDF, 0x2D, 0x99, 0x2B, 0, 0 } : new byte[] { 0x4E, 0xE6, 0x40, 0xBB };
        foreach (var q in s)
        {
            if ((q.Ch & 0x20000000) == 0) continue; long max = Math.Min((long)q.Raw, f.Length - (long)q.Ptr) - m.Length;
            for (long i = 0; i < max; i++)
            {
                if (!Egal(f, (int)(q.Ptr + i), m)) continue;
                long j = i; while (j > 0 && i - j < 96) { byte p = f[q.Ptr + j - 1]; if (p == 0xCC || p == 0x90 || p == 0xC3) break; j--; }
                uint debut = q.VA + (uint)j; if (!r.Contains(debut)) r.Add(debut);
            }
        }
        return r;
    }

    // La forme 2 detourne souvent l'appel du demarrage Visual C++ vers son code. Si cet appel pointe hors du
    // programme et qu'une seule fonction de securite existe, l'appel d'origine est certain : on le remet.
    public static byte[] RemettreAppelDemarrage(byte[] f)
    {
        try
        {
            int pe; bool is64; var s = Sections(f, out pe, out is64); uint ep = BitConverter.ToUInt32(f, pe + 40), img = BitConverter.ToUInt32(f, pe + 80);
            SectionPe t = null; foreach (var q in s) if (ep >= q.VA && ep < q.VA + q.Raw && (q.Ch & 0x20000000) != 0) t = q;
            if (t == null) return null;
            int off = (int)(t.Ptr + ep - t.VA), site = -1;
            if (!is64 && off + 10 <= f.Length && f[off] == 0xE8 && f[off + 5] == 0xE9) site = off;
            if (is64 && off + 14 <= f.Length && Egal(f, off, new byte[] { 0x48, 0x83, 0xEC, 0x28, 0xE8 }) && Egal(f, off + 9, new byte[] { 0x48, 0x83, 0xC4, 0x28, 0xE9 })) site = off + 4;
            if (site < 0) return null;
            uint rvaSite = t.VA + (uint)(site - t.Ptr), cible = unchecked(rvaSite + 5 + (uint)BitConverter.ToInt32(f, site + 1));
            if (cible < img) return null;
            var c = FonctionsSecurite(f, s, is64); if (c.Count != 1) return null;
            var o = (byte[])f.Clone();
            BitConverter.GetBytes(unchecked((int)(c[0] - (rvaSite + 5)))).CopyTo(o, site + 1);
            if (BitConverter.ToUInt32(f, pe + 88) != 0) BitConverter.GetBytes(Somme(o, pe + 88)).CopyTo(o, pe + 88);
            return o;
        }
        catch { return null; }
    }

    // Le ver renomme la section de ressources en UPX1 et la rend executable : on remet .rsrc.
    public static byte[] RemettreRessources(byte[] f)
    {
        if (f.Length < 4096 || f[0] != 0x4D || f[1] != 0x5A || EstForme2(f)) return null;
        int pe; bool is64; List<SectionPe> sec;
        try { sec = Sections(f, out pe, out is64); } catch { return null; }
        SectionPe u = null; foreach (var s in sec) { if (s.Nom == "UPX0") return null; if (s.Nom == "UPX1") u = s; }
        if (u == null) return null;
        int dd = pe + 24 + (is64 ? 112 : 96);
        if (BitConverter.ToUInt32(f, dd + 16) != u.VA) return null;
        var o = (byte[])f.Clone();
        var nom = new byte[8]; System.Text.Encoding.ASCII.GetBytes(".rsrc").CopyTo(nom, 0); nom.CopyTo(o, u.Entete);
        BitConverter.GetBytes((uint)0x40000040).CopyTo(o, u.Entete + 36);
        if (BitConverter.ToUInt32(f, pe + 88) != 0) BitConverter.GetBytes(Somme(o, pe + 88)).CopyTo(o, pe + 88);
        return o;
    }

    // Enleve toutes les couches connues. Renvoie null si le fichier n'a rien a corriger.
    public static byte[] Nettoyer(byte[] f, out string etat)
    {
        byte[] courant = f; int expiro = 0; etat = "sain";
        for (int i = 0; i < 4; i++)
        {
            var r = Reparer(courant);
            if (r.Repare) { courant = r.Sortie; expiro++; continue; }
            if (r.Infecte && expiro == 0) etat = "non repare : " + r.Raison;
            break;
        }
        if (EstForme2(courant)) { etat = "non repare : forme 2, donnees ecrasees par le virus"; return null; }
        var u = RemettreRessources(courant); bool res = u != null; if (res) courant = u;
        var rl = RemettreReloc(courant); bool rel = rl != null; if (rel) courant = rl;
        var ad = RemettreAppelDemarrage(courant); bool app = ad != null; if (app) courant = ad;
        if (expiro == 0 && !res && !rel && !app) return null;
        var parts = new List<string>();
        if (expiro > 0) parts.Add("Expiro retire"); if (res) parts.Add("ressources remises"); if (rel) parts.Add("nom .reloc remis"); if (app) parts.Add("appel de demarrage remis");
        etat = string.Join(" + ", parts.ToArray());
        return courant;
    }

    public static ResultatReparation Reparer(byte[] f)
    {
        var r = new ResultatReparation();
        if (f.Length < 4096 || f[0] != 0x4D || f[1] != 0x5A) { r.Raison = "pas un programme"; return r; }
        int pe; bool is64; List<SectionPe> sec;
        try { sec = Sections(f, out pe, out is64); } catch { r.Raison = "en-tete illisible"; return r; }
        r.Is64 = is64; if (sec.Count == 0) { r.Raison = "aucune section"; return r; }
        var L = sec[sec.Count - 1];
        if ((L.Ch & 0xA0000000) != 0xA0000000 || L.Raw < 0x8D000) { r.Raison = "pas la marque Expiro"; return r; }
        r.Infecte = true;
        var signature = is64 ? Debut64 : Debut32;
        int ep = -1;
        for (long k = (L.Raw / 0x1000); k >= 0; k--) { long o = L.Ptr + k * 0x1000; if (o + signature.Length < f.Length && Egal(f, (int)o, signature)) { ep = (int)o; break; } }
        if (ep < 0) { r.Raison = "entree du virus introuvable"; return r; }
        uint entree = L.VA + (uint)(ep - L.Ptr);
        int depart, fin, total;
        if (is64)
        {
            depart = ep + 0x2A + BitConverter.ToInt32(f, ep + 0x26);
            fin = FinBoucle(f, ep + 0x35);
            if (fin < 0 || f[fin + 1] != 0x81 || f[fin + 2] != 0xC6) { r.Raison = "boucle du virus inconnue"; return r; }
            total = BitConverter.ToInt32(f, fin + 17);
        }
        else
        {
            depart = ep + 12 - BitConverter.ToInt32(f, ep + 15);
            fin = FinBoucle(f, ep + 25);
            if (fin < 0 || f[fin] != 0x81 || f[fin + 1] != 0xC6 || f[fin + 6] != 0x81 || f[fin + 7] != 0xC0 || f[fin + 12] != 0x81 || f[fin + 13] != 0xFE) { r.Raison = "boucle du virus inconnue"; return r; }
            total = BitConverter.ToInt32(f, fin + 14);
        }
        if (depart < L.Ptr || total <= 0 || depart + total + 76 > f.Length) { r.Raison = "corps du virus incoherent"; return r; }
        int bloc = depart + total;

        var partage = Echange(ClePublique, f, bloc);
        var clair = Chacha8(partage, f, bloc + 64, 12);
        uint cible = BitConverter.ToUInt32(clair, 0);
        uint retour = BitConverter.ToUInt32(clair, 8);
        if (BitConverter.ToUInt32(clair, 4) != entree || retour <= entree || retour >= entree + 0x1000) { r.Raison = "bloc du virus non reconnu"; return r; }
        r.Cible = cible; r.Entree = entree;

        int appel = -1; uint rvaAppel = 0; int trouves = 0;
        foreach (var s in sec)
        {
            if (s == L || (s.Ch & 0x20000000) == 0) continue;
            int max = (int)Math.Min(s.Raw, (uint)(f.Length - s.Ptr)) - 5;
            for (int i = 0; i < max; i++)
            {
                byte b = f[s.Ptr + i]; if (b != 0xE8 && b != 0xE9) continue;
                uint rva = s.VA + (uint)i;
                if (unchecked(rva + 5 + (uint)BitConverter.ToInt32(f, (int)s.Ptr + i + 1)) == entree) { appel = (int)s.Ptr + i; rvaAppel = rva; trouves++; }
            }
        }
        if (trouves != 1) { r.Raison = "appel detourne introuvable (" + trouves + ")"; return r; }
        r.Appel = rvaAppel;

        uint garde = (uint)(depart - L.Ptr); r.TailleGardee = garde;
        int finSection = (int)Math.Min((long)L.Ptr + L.Raw, f.Length);
        int surplus = f.Length - finSection;
        var o2 = new byte[garde + L.Ptr + surplus];
        Array.Copy(f, o2, L.Ptr + garde);
        if (surplus > 0) Array.Copy(f, finSection, o2, L.Ptr + garde, surplus);

        BitConverter.GetBytes(unchecked(cible - (rvaAppel + 5))).CopyTo(o2, appel + 1);

        int dd = pe + 24 + (is64 ? 112 : 96);
        uint vs = garde;
        uint dirRs = BitConverter.ToUInt32(f, dd + 16), dirRz = BitConverter.ToUInt32(f, dd + 20);
        if (dirRs >= L.VA && dirRs < L.VA + garde && dirRz > 0) vs = dirRs - L.VA + dirRz;

        // Le virus efface la table de relocations : elle se relit dans sa section.
        SectionPe sr = null; foreach (var s in sec) if (s.Nom == ".reloc") sr = s;
        bool relocRemise = false;
        if (sr != null && BitConverter.ToUInt32(f, dd + 40) == 0)
        {
            uint maxR = sr == L ? garde : Math.Min(sr.Raw, sr.VS), lu = 0;
            while (lu + 8 <= maxR)
            {
                uint page = BitConverter.ToUInt32(f, (int)(sr.Ptr + lu)), bz = BitConverter.ToUInt32(f, (int)(sr.Ptr + lu + 4));
                if (page == 0 || bz < 8 || (bz & 1) != 0 || lu + bz > maxR) break;
                lu += bz;
            }
            if (lu > 0)
            {
                BitConverter.GetBytes(sr.VA).CopyTo(o2, dd + 40); BitConverter.GetBytes(lu).CopyTo(o2, dd + 44); relocRemise = true;
                if (sr == L) vs = lu;
            }
        }
        ushort dc = BitConverter.ToUInt16(f, pe + 94);
        if (relocRemise && (dc & 0x0100) != 0)
        {
            dc |= 0x0040;
            uint lcR = BitConverter.ToUInt32(f, dd + 80), lcZ = BitConverter.ToUInt32(f, dd + 84); int gf = is64 ? 0x90 : 0x58;
            foreach (var s in sec)
                if (lcZ > (uint)gf + 3 && lcR >= s.VA && lcR < s.VA + s.Raw)
                { int lo = (int)(lcR - s.VA + s.Ptr); if (BitConverter.ToUInt32(f, lo) > (uint)gf + 3 && (BitConverter.ToUInt32(f, lo + gf) & 0x100) != 0) dc |= 0x4000; }
            BitConverter.GetBytes(dc).CopyTo(o2, pe + 94);
        }
        BitConverter.GetBytes(vs).CopyTo(o2, L.Entete + 8);
        BitConverter.GetBytes(garde).CopyTo(o2, L.Entete + 16);
        BitConverter.GetBytes(L.Ch & 0x5FFFFFFF).CopyTo(o2, L.Entete + 36);
        uint al = BitConverter.ToUInt32(f, pe + 56);
        uint img = L.VA + vs; if (al > 0 && img % al != 0) img += al - img % al;
        BitConverter.GetBytes(img).CopyTo(o2, pe + 80);
        if (BitConverter.ToUInt32(f, pe + 88) != 0) BitConverter.GetBytes(Somme(o2, pe + 88)).CopyTo(o2, pe + 88);

        r.Sortie = o2; r.Repare = true; r.Raison = "repare";
        return r;
    }
}
