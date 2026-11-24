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
    $refus = $false; try { [void][Moteur]::Appliquer((Get-PlanEssai), $env:SystemDrive + '\', $null, $false) } catch { $refus = $true }
    Test-Point 'Disque Windows refuse' $refus
    Test-Point 'Signature valide reconnue' ([Moteur]::SignatureValide("$env:WINDIR\explorer.exe") -or -not (Get-AuthenticodeSignature "$env:WINDIR\explorer.exe").SignerCertificate -or (Get-AuthenticodeSignature "$env:WINDIR\explorer.exe").SignatureType -eq 'Catalog')
    Test-Point 'Fichier non signe refuse' (-not [Moteur]::SignatureValide("$t\Jeu\notes.txt"))
}
finally {
    foreach ($x in $t, "$t-q") { if (Test-Path -LiteralPath $x) { Get-ChildItem -LiteralPath $x -Recurse -Force | ForEach-Object { try { $_.Attributes = 'Normal' } catch { } }; Remove-Item -LiteralPath $x -Recurse -Force -Confirm:$false } }
}
"Echecs : $echecs"; if ($echecs -gt 0) { exit 1 }
