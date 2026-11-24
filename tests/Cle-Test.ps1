# Prepare ou nettoie une cle USB d'essai pour ROTA Antivirus.
# Les fichiers crees sont de simples textes inoffensifs qui imitent seulement les noms utilises par PlugX.
param([ValidateSet('Preparer', 'Nettoyer')][string]$Action = 'Preparer', [string]$Lettre, [switch]$Oui)

if (-not $Lettre) { $Lettre = [string](Read-Host 'Lettre de la cle USB (exemple : G)') }
$Lettre = $Lettre.Trim().TrimEnd(':', '\').ToUpper()
if ($Lettre -notmatch '^[A-Z]$') { Write-Host 'Lettre invalide.'; exit 1 }
$racine = "${Lettre}:\"
$d = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='${Lettre}:'"
if (-not $d) { Write-Host "Disque $Lettre introuvable."; exit 1 }
if ($d.DriveType -ne 2) { Write-Host 'Refuse : ce disque n est pas une cle USB amovible.'; exit 1 }
$marque = Join-Path $racine 'ROTA-TEST.txt'

if ($Action -eq 'Nettoyer') {
    if (-not (Test-Path -LiteralPath $marque)) { Write-Host 'Refuse : cette cle n a pas ete preparee pour le test.'; exit 1 }
    if (-not $Oui -and ([string](Read-Host "Effacer les fichiers du test sur ${Lettre}: ? Ecris OUI")).Trim().ToUpper() -ne 'OUI') { Write-Host 'Annule.'; exit 0 }
    foreach ($n in 'RECYCLER.BIN', '_QUARANTAINE_ROTA', 'Jeu-Test', 'Removable Disk.lnk', 'ROTA-TEST.txt') {
        $p = Join-Path $racine $n
        if (Test-Path -LiteralPath $p) {
            Get-ChildItem -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object { try { $_.Attributes = 'Normal' } catch { } }
            (Get-Item -LiteralPath $p -Force).Attributes = 'Normal'; Remove-Item -LiteralPath $p -Recurse -Force -Confirm:$false
        }
    }
    Write-Host 'Cle nettoyee.'; exit 0
}

$autres = @(Get-ChildItem -LiteralPath $racine -Force | Where-Object { $_.Name -ne 'System Volume Information' })
if ($autres.Count -gt 0) { Write-Host 'Refuse : la cle doit etre vide pour ne toucher a aucun de tes fichiers.'; exit 1 }
foreach ($x in 'RECYCLER.BIN\1', 'RECYCLER.BIN\DOCS', 'Jeu-Test') { [void](New-Item -ItemType Directory -Force -Path (Join-Path $racine $x)) }
$texte = 'FAUX FICHIER DE TEST ROTA ANTIVIRUS - INOFFENSIF'
foreach ($x in 'RECYCLER.BIN\1\CEFHelper.exe', 'RECYCLER.BIN\1\wsc.dll', 'RECYCLER.BIN\1\AvastAuth.dat', 'RECYCLER.BIN\DOCS\document-test.bin') { [IO.File]::WriteAllText((Join-Path $racine $x), $texte) }
[IO.File]::WriteAllText((Join-Path $racine 'Removable Disk.lnk'), "$texte - cmd.exe RECYCLER")
[IO.File]::WriteAllText((Join-Path $racine 'Jeu-Test\notes.txt'), 'Ce fichier doit rester intact.')
[IO.File]::WriteAllText($marque, 'Cle preparee pour tester ROTA Antivirus.')
Write-Host 'Cle prete. Ouvre ROTA Antivirus, choisis cette cle, puis lance l analyse.'
