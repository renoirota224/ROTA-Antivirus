# Cree ou retire un petit disque virtuel d'essai pour ROTA Antivirus (aucune cle USB necessaire).
# Le disque est un simple fichier de 128 Mo maximum. Ses faux fichiers sont des textes inoffensifs.
param([ValidateSet('Creer', 'Retirer')][string]$Action = 'Creer')

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Fais un clic droit sur ce fichier, puis Executer en tant qu administrateur.'; exit 1
}
$dir = Join-Path $env:ProgramData 'RotaAntivirus\Test'
$vhd = Join-Path $dir 'disque-test.vhdx'
$fichierLettre = Join-Path $dir 'lettre.txt'
$nomVolume = 'ROTATEST'

function Invoke-Diskpart([string[]]$Lignes) {
    $s = Join-Path $env:TEMP ('rota-diskpart-' + [Guid]::NewGuid().ToString('N') + '.txt')
    try { [IO.File]::WriteAllLines($s, $Lignes, [Text.Encoding]::ASCII); $o = & diskpart.exe /s $s; return [pscustomobject]@{ Code = $LASTEXITCODE; Sortie = ($o -join "`n") } }
    finally { Remove-Item -LiteralPath $s -Force -ErrorAction SilentlyContinue }
}

function Remove-DisqueVirtuel {
    [void](Invoke-Diskpart @("select vdisk file=`"$vhd`"", 'detach vdisk'))
    Start-Sleep -Seconds 1
    if (Test-Path -LiteralPath $vhd) { Remove-Item -LiteralPath $vhd -Force }
    if (Test-Path -LiteralPath $fichierLettre) { Remove-Item -LiteralPath $fichierLettre -Force }
}

if ($Action -eq 'Retirer') {
    if (-not (Test-Path -LiteralPath $vhd)) { Write-Host 'Aucun disque de test a retirer.'; exit 0 }
    if (Test-Path -LiteralPath $fichierLettre) {
        $l = ([IO.File]::ReadAllText($fichierLettre)).Trim()
        $v = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='${l}:'"
        if ($v -and $v.VolumeName -eq $nomVolume -and $v.VolumeSerialNumber) {
            $arch = Join-Path $env:ProgramData 'RotaAntivirus\Archives'
            if (Test-Path -LiteralPath $arch) { Get-ChildItem -LiteralPath $arch -Directory -Filter ($v.VolumeSerialNumber + '-*') | ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force -Confirm:$false } }
        }
    }
    try { Remove-DisqueVirtuel } catch { Write-Host "Retrait impossible : ferme ROTA Antivirus, puis recommence. ($($_.Exception.Message))"; exit 1 }
    if (Test-Path -LiteralPath $vhd) { Write-Host 'Retrait impossible : ferme ROTA Antivirus, puis recommence.'; exit 1 }
    Write-Host 'Disque de test retire.'; exit 0
}

if (Test-Path -LiteralPath $vhd) { Write-Host 'Un disque de test existe deja. Lance d abord Retirer-Disque-Test.bat.'; exit 1 }
$prises = @(Get-CimInstance Win32_LogicalDisk | ForEach-Object { $_.DeviceID.Substring(0, 1).ToUpper() }) + @(Get-PSDrive -PSProvider FileSystem | ForEach-Object { $_.Name.ToUpper() })
$lettre = 'Z', 'Y', 'X', 'W', 'V', 'U', 'T', 'S', 'R', 'Q' | Where-Object { $prises -notcontains $_ } | Select-Object -First 1
if (-not $lettre) { Write-Host 'Aucune lettre de disque libre.'; exit 1 }
[void](New-Item -ItemType Directory -Force -Path $dir)
Write-Host 'Creation du disque de test, patiente...'
$r = Invoke-Diskpart @("create vdisk file=`"$vhd`" maximum=128 type=expandable", "select vdisk file=`"$vhd`"", 'attach vdisk', 'create partition primary', "format fs=ntfs quick label=$nomVolume", "assign letter=$lettre")
Start-Sleep -Seconds 2
$racine = "${lettre}:\"
$v = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='${lettre}:'"
if ($r.Code -ne 0 -or -not $v -or $v.VolumeName -ne $nomVolume) {
    Write-Host 'Creation impossible :'; Write-Host $r.Sortie
    try { Remove-DisqueVirtuel } catch { }
    exit 1
}
[IO.File]::WriteAllText($fichierLettre, $lettre)
foreach ($x in 'RECYCLER.BIN\1', 'RECYCLER.BIN\DOCS', 'Jeu-Test') { [void](New-Item -ItemType Directory -Force -Path (Join-Path $racine $x)) }
$texte = 'FAUX FICHIER DE TEST ROTA ANTIVIRUS - INOFFENSIF'
foreach ($x in 'RECYCLER.BIN\1\CEFHelper.exe', 'RECYCLER.BIN\1\wsc.dll', 'RECYCLER.BIN\1\AvastAuth.dat', 'RECYCLER.BIN\DOCS\document-test.bin') { [IO.File]::WriteAllText((Join-Path $racine $x), $texte) }
[IO.File]::WriteAllText((Join-Path $racine 'Removable Disk.lnk'), "$texte - cmd.exe RECYCLER")
[IO.File]::WriteAllText((Join-Path $racine 'Jeu-Test\notes.txt'), 'Ce fichier doit rester intact.')
[IO.File]::WriteAllText((Join-Path $racine 'ROTA-TEST.txt'), 'Disque virtuel prepare pour tester ROTA Antivirus.')
Write-Host ''
Write-Host "=== DISQUE DE TEST PRET : ${lettre}: ==="
Write-Host "Dans ROTA Antivirus, clique sur le disque ${lettre}: puis lance l analyse."
