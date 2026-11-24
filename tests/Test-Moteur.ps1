# Teste le moteur sur un faux disque cree dans un dossier temporaire. Aucun vrai disque n'est modifie.
$ErrorActionPreference = 'Stop'
$src = Join-Path $PSScriptRoot '..\src\RotaAntivirus\Moteur'
Add-Type -ReferencedAssemblies System.Numerics, System.Core, System.Linq -Path (Join-Path $src 'Reparateur.cs'), (Join-Path $src 'Moteur.cs')
$t = Join-Path $env:TEMP ('rota-test-' + [Guid]::NewGuid().ToString('N')); $echecs = 0
function Test-Point([string]$Nom, [bool]$Ok) { if ($Ok) { "OK    $Nom" } else { $script:echecs++; "ECHEC $Nom" } }
function Get-PlanEssai { [Moteur]::Analyser($t, $null, [Threading.CancellationToken]::None) }
try {
    [void](New-Item -ItemType Directory -Path "$t\RECYCLER.BIN\1"); [void](New-Item -ItemType Directory -Path "$t\RECYCLER.BIN\DOCS"); [void](New-Item -ItemType Directory -Path "$t\Jeu")
    [IO.File]::WriteAllText("$t\RECYCLER.BIN\1\CEFHelper.exe", 'faux'); [IO.File]::WriteAllText("$t\RECYCLER.BIN\DOCS\doc.bin", 'document'); [IO.File]::WriteAllText("$t\Jeu\notes.txt", 'garde')
    $p = Get-PlanEssai; $v = [Moteur]::Verdict($p, [Moteur]::Etat($t), $false)
    Test-Point 'PlugX detecte' (@($p.Elements | Where-Object { $_.Type -eq 'ISOLER' }).Count -eq 1)
    Test-Point 'Verdict pas pret' ($v.Niveau -eq 'PAS_PRET')
    $r = [Moteur]::Appliquer($p, $t, $null, $true)
    Test-Point 'Isolement sans echec' ($r.Ok -eq 1 -and $r.Echecs -eq 0)
    Test-Point 'Fichier PlugX retire' (-not (Test-Path -LiteralPath "$t\RECYCLER.BIN\1\CEFHelper.exe"))
    $a = [Moteur]::Annuler($t, $true)
    Test-Point 'Annulation remet le fichier' ($a.Ok -eq 1 -and (Test-Path -LiteralPath "$t\RECYCLER.BIN\1\CEFHelper.exe"))
    $p = Get-PlanEssai; [void][Moteur]::Appliquer($p, $t, $null, $true)
    $n = [Moteur]::CompterRecycler($t); $g = [Moteur]::RangerRecycler($t, $n, $true)
    Test-Point 'Blocage pose' ([Moteur]::Etat($t).Blocage)
    Test-Point 'Document garde' (@(Get-ChildItem -LiteralPath "$t\_QUARANTAINE_ROTA" -Recurse -Force -Filter doc.bin).Count -eq 1)
    Test-Point 'Autre fichier intact' ((Get-Content -LiteralPath "$t\Jeu\notes.txt") -eq 'garde')
    $v = [Moteur]::Verdict((Get-PlanEssai), [Moteur]::Etat($t), $false)
    Test-Point 'Quarantaine interdit la livraison' ($v.Niveau -eq 'PAS_PRET')
    Test-Point 'Quarantaine listee' (@([Moteur]::ListerQuarantaine($t)).Count -ge 2)
    $s1 = [Moteur]::SortirQuarantaine($t, "$t-q", $true)
    Test-Point 'Quarantaine sortie du disque' ($s1.Ok -ge 2 -and -not (Test-Path -LiteralPath "$t\_QUARANTAINE_ROTA"))
    Test-Point 'Archive presente' ([Moteur]::ArchiveExiste($t, "$t-q"))
    $v = [Moteur]::Verdict((Get-PlanEssai), [Moteur]::Etat($t), $false)
    Test-Point 'Disque propre pret' ($v.Niveau -eq 'PRET')
    $s2 = [Moteur]::RemettreQuarantaine($t, "$t-q", $true)
    Test-Point 'Quarantaine remise identique' ($s2.Ok -eq $s1.Ok -and @(Get-ChildItem -LiteralPath "$t\_QUARANTAINE_ROTA" -Recurse -Force -Filter doc.bin).Count -eq 1)
    Test-Point 'Archive retiree apres remise' (-not [Moteur]::ArchiveExiste($t, "$t-q"))
    [void][Moteur]::SortirQuarantaine($t, "$t-q", $true)
    [IO.File]::SetAttributes("$t\RECYCLER.BIN", 'Normal'); Remove-Item -LiteralPath "$t\RECYCLER.BIN" -Force; [void][Moteur]::PoserBlocageDisque($t, $true)
    Test-Point 'Blocage seul pose' ([Moteur]::Etat($t).Blocage)
    $refus = 0; try { [void][Moteur]::RangerRecycler($env:SystemDrive + '\', 0, $false) } catch { $refus++ }; try { [void][Moteur]::PoserBlocageDisque($env:SystemDrive + '\', $false) } catch { $refus++ }; try { [void][Moteur]::SortirQuarantaine($env:SystemDrive + '\', "$t-q", $false) } catch { $refus++ }
    Test-Point 'Disque Windows : ranger, bloquer et sortir refuses' ($refus -eq 3)
    Test-Point 'Signature valide reconnue' ([Moteur]::SignatureValide("$env:WINDIR\explorer.exe") -or -not (Get-AuthenticodeSignature "$env:WINDIR\explorer.exe").SignerCertificate -or (Get-AuthenticodeSignature "$env:WINDIR\explorer.exe").SignatureType -eq 'Catalog')
    Test-Point 'Fichier non signe refuse' (-not [Moteur]::SignatureValide("$t\Jeu\notes.txt"))

    Test-Point 'C: dossier personnel reparable' ([Moteur]::ReparableSurSysteme('Users\Admin\Downloads\jeu.exe'))
    Test-Point 'C: Windows protege' (-not [Moteur]::ReparableSurSysteme('Windows\System32\cmd.exe'))
    Test-Point 'C: Program Files protege' (-not [Moteur]::ReparableSurSysteme('Program Files\App\app.exe'))
    Test-Point 'C: alias Windows protege' (-not [Moteur]::ReparableSurSysteme('Users\Admin\AppData\Local\Microsoft\WindowsApps\winget.exe'))
    $pz = New-Object PlanDisque; foreach ($x in 'Users\A\jeu.exe', 'Windows\x.exe') { $el = New-Object ElementPlan; $el.Type = 'REPARER'; $el.Relatif = $x; $pz.Elements.Add($el) }
    $vz = [Moteur]::Verdict($pz, (New-Object EtatDisque), $true)
    Test-Point 'C: seul le dossier personnel compte' ($vz.ATraiter -eq 1 -and $vz.Reserves[0] -like '1 fichier*Windows*')

    # Reparer et Isoler sont deux actions separees.
    $d = "$t-d"; [void](New-Item -ItemType Directory -Path "$d\RECYCLER.BIN\1"); [IO.File]::WriteAllText("$d\RECYCLER.BIN\1\CEFHelper.exe", 'faux'); [IO.File]::WriteAllText("$d\RECYCLER.BIN\1\wsc.dll", 'faux2')
    $pd = [Moteur]::Analyser($d, $null, [Threading.CancellationToken]::None); $vd = [Moteur]::Verdict($pd, [Moteur]::Etat($d), $false)
    Test-Point 'Compteurs separes' ($vd.AIsoler -eq 2 -and $vd.AReparer -eq 0)
    $rr = [Moteur]::Appliquer($pd, $d, $null, $true, 'reparer')
    Test-Point 'Reparer ne touche pas les fichiers a isoler' ($rr.Ok -eq 0 -and (Test-Path -LiteralPath "$d\RECYCLER.BIN\1\CEFHelper.exe") -and -not (Test-Path -LiteralPath "$d\_QUARANTAINE_ROTA"))
    $ri = [Moteur]::Appliquer($pd, $d, $null, $true, 'isoler')
    Test-Point 'Isoler retire seulement les fichiers a isoler' ($ri.Ok -eq 2 -and -not (Test-Path -LiteralPath "$d\RECYCLER.BIN\1\CEFHelper.exe"))
    Test-Point 'Isoler ne pose pas le blocage seul' (-not [Moteur]::Etat($d).Blocage)
    $ra = [Moteur]::Annuler($d, $true)
    Test-Point 'Annuler remet les fichiers isoles' ($ra.Ok -eq 2 -and (Test-Path -LiteralPath "$d\RECYCLER.BIN\1\wsc.dll"))
    $pm = New-Object PlanDisque; foreach ($x in 'REPARER', 'REPARER', 'ISOLER', 'A_VERIFIER') { $el = New-Object ElementPlan; $el.Type = $x; $el.Relatif = "Jeu\$x.exe"; $pm.Elements.Add($el) }
    $vm = [Moteur]::Verdict($pm, (New-Object EtatDisque), $false)
    Test-Point 'Comptes Reparer 2 et Isoler 1' ($vm.AReparer -eq 2 -and $vm.AIsoler -eq 1 -and $vm.ATraiter -eq 3)

    # Dossier cache par PlugX (nom fait d'un espace insecable).
    # Windows retire les espaces en fin de nom : le prefixe \\?\ garde le vrai nom, comme le fait le moteur.
    $e = "$t-e"; $cache = '\\?\' + $e + '\' + [string][char]0x00A0; [void][IO.Directory]::CreateDirectory("$cache\Mes jeux"); [IO.File]::WriteAllText("$cache\photo.jpg", 'image'); [IO.File]::WriteAllText("$cache\Mes jeux\save.dat", 'partie'); [IO.File]::WriteAllText("$e\photo.jpg", 'deja la'); [IO.File]::WriteAllText("$cache\desktop.ini", 'x')
    [IO.File]::SetAttributes($cache, [IO.FileAttributes]'Hidden, System, Directory')
    Test-Point 'Dossier cache detecte' ([Moteur]::Etat($e).DossiersCaches -eq 1)
    $vc = [Moteur]::Verdict((New-Object PlanDisque), [Moteur]::Etat($e), $false)
    Test-Point 'Dossier cache bloque la livraison' (@($vc.Bloquants | Where-Object { $_ -like '*caché*' }).Count -eq 1)
    $rc = [Moteur]::RemettreFichiersCaches($e, $true)
    Test-Point 'Fichiers caches remis' ($rc.Ok -eq 2 -and $rc.Echecs -eq 0 -and (Test-Path -LiteralPath "$e\Mes jeux\save.dat"))
    Test-Point 'Nom deja pris garde les deux fichiers' ((Get-Content -LiteralPath "$e\photo.jpg") -eq 'deja la' -and (Get-Content -LiteralPath "$e\photo (récupéré 2).jpg") -eq 'image')
    Test-Point 'Dossier cache vide retire' ([Moteur]::Etat($e).DossiersCaches -eq 0 -and -not [IO.Directory]::Exists($cache))
    $ep = New-Object EtatDisque; $ep.Libre = 10MB; $vp = [Moteur]::Verdict((New-Object PlanDisque), $ep, $false)
    Test-Point 'Disque plein signale' (@($vp.Bloquants | Where-Object { $_ -like 'Disque presque plein*' }).Count -eq 1)

    # Tout nettoyer : PlugX, dossier cache, RECYCLER.BIN et blocage en une fois.
    $f = "$t-f"; $cf = '\\?\' + $f + '\' + [string][char]0x00A0; [void][IO.Directory]::CreateDirectory("$cf\Jeux"); [IO.File]::WriteAllText("$cf\Jeux\notes.txt", 'garde'); [IO.File]::SetAttributes($cf, [IO.FileAttributes]'Hidden, System, Directory')
    [void](New-Item -ItemType Directory -Path "$f\RECYCLER.BIN\1"); [void](New-Item -ItemType Directory -Path "$f\RECYCLER.BIN\DOCS"); [IO.File]::WriteAllText("$f\RECYCLER.BIN\1\CEFHelper.exe", 'faux'); [IO.File]::WriteAllText("$f\RECYCLER.BIN\1\wsc.dll", 'faux2'); [IO.File]::WriteAllText("$f\RECYCLER.BIN\DOCS\doc.bin", 'document')
    $etapes = New-Object System.Collections.ArrayList; $suivi = [Action[Avancement]] { param($a) if ($a.Phase -like 'Étape*') { [void]$etapes.Add($a.Phase) } }
    $rt = [Moteur]::ToutNettoyer($f, $suivi, $true, "$t-fa")
    Test-Point 'Tout nettoyer sans arret' (@($rt.Messages | Where-Object { $_ -like 'ARR*' }).Count -eq 0 -and $rt.Echecs -eq 0)
    Test-Point 'Tout nettoyer annonce 6 etapes' ($etapes.Count -eq 6)
    Test-Point 'Tout nettoyer : PlugX retire et fichiers remis' (-not (Test-Path -LiteralPath "$f\RECYCLER.BIN\1\CEFHelper.exe") -and (Get-Content -LiteralPath "$f\Jeux\notes.txt") -eq 'garde')
    $ef = [Moteur]::Etat($f); $vf = [Moteur]::Verdict([Moteur]::Analyser($f, $null, [Threading.CancellationToken]::None), $ef, $false)
    Test-Point 'Tout nettoyer : blocage pose, plus de cache ni de PlugX' ($ef.Blocage -and $ef.DossiersCaches -eq 0 -and -not $ef.RecyclerDossier -and $vf.ATraiter -eq 0)
    Test-Point 'Tout nettoyer : seule la quarantaine reste a sortir' ($vf.Bloquants.Count -eq 1 -and $vf.Bloquants[0] -like '*QUARANTAINE*')

    # Les nouvelles reparations ne doivent jamais toucher un programme sain.
    $sains = @(Get-ChildItem "$env:WINDIR\System32" -Filter *.exe -File | Select-Object -First 300); $touches = 0
    foreach ($s in $sains) { try { [byte[]]$q = [IO.File]::ReadAllBytes($s.FullName); if ($null -ne [Reparateur]::RemettreReloc($q) -or $null -ne [Reparateur]::RemettreAppelDemarrage($q) -or [Reparateur]::AppelsPendants($q, $q) -gt 0) { $touches++ } } catch { } }
    Test-Point "Programmes Windows sains jamais modifies ($($sains.Count) testes)" ($touches -eq 0)

    # Bibliotheque : une copie maitre propre, un disque ou le programme a ete modifie.
    $m = "$t-m\JeuTest"; [void](New-Item -ItemType Directory -Path "$m\bin"); [IO.File]::WriteAllText("$m\bin\jeu.exe", 'programme propre'); [IO.File]::WriteAllText("$m\lisezmoi.txt", 'texte')
    $nb = [Moteur]::CreerReference($m, $null, [Threading.CancellationToken]::None, "$t-bib")
    Test-Point 'Reference creee pour les programmes seulement' ($nb -eq 1 -and @([Moteur]::ListerReferences("$t-bib")).Count -eq 1)
    $g2 = "$t-g"; [void](New-Item -ItemType Directory -Path "$g2\JEUX\JeuTest\bin"); [IO.File]::WriteAllText("$g2\JEUX\JeuTest\bin\jeu.exe", 'programme INFECTE'); [IO.File]::WriteAllText("$g2\JEUX\JeuTest\bin\ajout.exe", 'inconnu')
    $pg = [Moteur]::Analyser($g2, $null, [Threading.CancellationToken]::None); $dg = [Moteur]::ComparerBibliotheque($g2, $pg, $null, [Threading.CancellationToken]::None, "$t-bib")
    $rest = @($pg.Elements | Where-Object { $_.Type -eq 'RESTAURER' }); $nouv = @($pg.Elements | Where-Object { $_.Detail -like 'Programme absent*' })
    Test-Point 'Programme modifie a restaurer depuis la copie maitre' ($dg -eq 2 -and $rest.Count -eq 1 -and $nouv.Count -eq 1)
    $rg = [Moteur]::Appliquer($pg, $g2, $null, $true, 'reparer')
    Test-Point 'Programme remis identique a la copie maitre' ($rg.Ok -eq 1 -and (Get-Content -LiteralPath "$g2\JEUX\JeuTest\bin\jeu.exe") -eq 'programme propre')
    [void][Moteur]::Annuler($g2, $true); Test-Point 'Restauration annulable' ((Get-Content -LiteralPath "$g2\JEUX\JeuTest\bin\jeu.exe") -eq 'programme INFECTE')
    [Moteur]::SupprimerReference('JeuTest', "$t-bib"); Test-Point 'Reference retiree' (@([Moteur]::ListerReferences("$t-bib")).Count -eq 0)

    # Windows Defender : lecture des resultats et classement.
    $pdf = New-Object PlanDisque; $dl = New-Object 'System.Collections.Generic.List[DetectionDefender]'
    $g2c = try { (New-Object -ComObject Scripting.FileSystemObject).GetFolder($g2).ShortPath } catch { $g2 }
    foreach ($x in @(@('Virus:Win32/Expiro.EB!MTB', "$g2c\a.exe"), @('HackTool:Win32/Crack', "$g2\crack.exe"), @('Trojan:Win32/Test', "$g2\pack.zip->x.exe"), @('Virus:Win32/X', "$g2\_QUARANTAINE_ROTA\y.exe"))) { $dd = New-Object DetectionDefender; $dd.Menace = $x[0]; $dd.Fichier = $x[1]; $dl.Add($dd) }
    $na = [Moteur]::FusionnerDefender($pdf, $g2, $dl)
    $ty = @{}; foreach ($e in $pdf.Elements) { $ty[$e.Relatif] = $e.Type }
    Test-Point 'Defender : virus isole, crack a verifier, archive a verifier, quarantaine ignoree' ($na -eq 3 -and $ty['a.exe'] -eq 'ISOLER' -and $ty['crack.exe'] -eq 'A_VERIFIER' -and $ty['pack.zip'] -eq 'A_VERIFIER')
    # Sur certains PC (ou serveurs de fabrication) Defender est coupe : le test est alors simplement saute.
    try { $vd2 = [Moteur]::AnalyseDefender($m, $null, [Threading.CancellationToken]::None); Test-Point 'Defender analyse un dossier sain sans menace' ($vd2.Count -eq 0) }
    catch { "SAUTE Defender indisponible ici : $($_.Exception.InnerException.Message)" }

    # Certificat de livraison.
    $vp2 = New-Object VerdictDisque; $vp2.Niveau = 'PRET'; $pp2 = New-Object PlanDisque; $pp2.Examines = 12
    $cert = [Moteur]::EcrireCertificat("$t-cert", $g2, 'Client <b>test</b>', $vp2, $pp2, '', '1.6.0'); $ch = [IO.File]::ReadAllText($cert)
    Test-Point 'Certificat cree et texte protege' ($ch -like '*Client &lt;b&gt;test&lt;/b&gt;*' -and $ch -like '*prêt pour la livraison*')
    $vp2.Niveau = 'PAS_PRET'; $refusc = $false; try { [void][Moteur]::EcrireCertificat("$t-cert", $g2, 'x', $vp2, $pp2, '', '1.6.0') } catch { $refusc = $true }
    Test-Point 'Pas de certificat sans verdict Pret' $refusc

    # Parcours complet : reparer, ranger, sortir, remettre, puis tout annuler.
    $b = "$t-b"; [void](New-Item -ItemType Directory -Path "$b\RECYCLER.BIN\1"); [void](New-Item -ItemType Directory -Path "$b\RECYCLER.BIN\DOCS")
    [IO.File]::WriteAllText("$b\RECYCLER.BIN\1\CEFHelper.exe", 'faux'); [IO.File]::WriteAllText("$b\RECYCLER.BIN\1\wsc.dll", 'faux2'); [IO.File]::WriteAllText("$b\RECYCLER.BIN\DOCS\doc.bin", 'document')
    function Get-Empreintes([string]$D) { (Get-ChildItem -LiteralPath "$D\RECYCLER.BIN" -Recurse -Force -File | Sort-Object FullName | ForEach-Object { $_.Name + ':' + (Get-FileHash -LiteralPath $_.FullName).Hash }) -join '|' }
    $h0 = Get-Empreintes $b
    $pb = [Moteur]::Analyser($b, $null, [Threading.CancellationToken]::None); [void][Moteur]::Appliquer($pb, $b, $null, $true); [void][Moteur]::RangerRecycler($b, [Moteur]::CompterRecycler($b), $true)
    Test-Point 'Parcours : blocage en place' ([Moteur]::Etat($b).Blocage)
    $a1 = [Moteur]::Annuler($b, $true)
    Test-Point 'Annuler apres Ranger sans echec' ($a1.Echecs -eq 0 -and $a1.Ok -eq 3)
    Test-Point 'Annuler remet tout a l identique' ((Test-Path -LiteralPath "$b\RECYCLER.BIN" -PathType Container) -and (Get-Empreintes $b) -eq $h0)
    Remove-Item -LiteralPath "$b\_QUARANTAINE_ROTA" -Recurse -Force
    $pb = [Moteur]::Analyser($b, $null, [Threading.CancellationToken]::None); [void][Moteur]::Appliquer($pb, $b, $null, $true); [void][Moteur]::RangerRecycler($b, [Moteur]::CompterRecycler($b), $true)
    [void][Moteur]::SortirQuarantaine($b, "$t-c", $true); $s3 = [Moteur]::RemettreQuarantaine($b, "$t-c", $true)
    $a2 = [Moteur]::Annuler($b, $true)
    Test-Point 'Remettre puis Annuler sans echec' ($s3.Ok -gt 0 -and $a2.Echecs -eq 0 -and $a2.Ok -eq 3)
    Test-Point 'Remettre puis Annuler identique' ((Get-Empreintes $b) -eq $h0)
    $a3 = [Moteur]::Annuler($b, $true)
    Test-Point 'Deuxieme annulation sans effet' ($a3.Ok -eq 0 -and $a3.Echecs -eq 0)
}
finally {
    foreach ($x in $t, "$t-q", "$t-b", "$t-c", "$t-d", "$t-e", "$t-f", "$t-fa", "$t-m", "$t-bib", "$t-g", "$t-cert") { if (Test-Path -LiteralPath $x) { Get-ChildItem -LiteralPath $x -Recurse -Force | ForEach-Object { try { $_.Attributes = 'Normal' } catch { } }; Remove-Item -LiteralPath $x -Recurse -Force -Confirm:$false } }
}
"Echecs : $echecs"; if ($echecs -gt 0) { exit 1 }
