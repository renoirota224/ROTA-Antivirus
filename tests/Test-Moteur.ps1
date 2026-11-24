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
    foreach ($x in $t, "$t-q", "$t-b", "$t-c") { if (Test-Path -LiteralPath $x) { Get-ChildItem -LiteralPath $x -Recurse -Force | ForEach-Object { try { $_.Attributes = 'Normal' } catch { } }; Remove-Item -LiteralPath $x -Recurse -Force -Confirm:$false } }
}
"Echecs : $echecs"; if ($echecs -gt 0) { exit 1 }
