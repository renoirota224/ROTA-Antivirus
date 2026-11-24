; Installateur de ROTA Antivirus (Inno Setup 6).
#ifndef MyVersion
  #define MyVersion "1.0.0"
#endif

[Setup]
AppId={{7C4E2B19-5D3A-4F86-9B21-6E0A8D13F7C2}
AppName=ROTA Antivirus
AppVersion={#MyVersion}
AppVerName=ROTA Antivirus {#MyVersion}
AppPublisher=RotaGaming
DefaultDirName={autopf}\ROTA Antivirus
DefaultGroupName=ROTA Antivirus
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
OutputDir=..\dist
OutputBaseFilename=ROTA-Antivirus-Setup-{#MyVersion}
SetupIconFile=..\assets\rota.ico
UninstallDisplayIcon={app}\RotaAntivirus.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes

[Languages]
Name: "fr"; MessagesFile: "compiler:Languages\French.isl"

[Tasks]
Name: "bureau"; Description: "Créer une icône sur le Bureau"; GroupDescription: "Raccourcis :"

[Files]
Source: "..\publish\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\redist\MicrosoftEdgeWebview2Setup.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall; Check: not WebView2Present

[Icons]
Name: "{group}\ROTA Antivirus"; Filename: "{app}\RotaAntivirus.exe"
Name: "{group}\Désinstaller ROTA Antivirus"; Filename: "{uninstallexe}"
Name: "{autodesktop}\ROTA Antivirus"; Filename: "{app}\RotaAntivirus.exe"; Tasks: bureau

[Run]
Filename: "{tmp}\MicrosoftEdgeWebview2Setup.exe"; Parameters: "/silent /install"; StatusMsg: "Installation du composant d'affichage Microsoft..."; Check: not WebView2Present
Filename: "{app}\RotaAntivirus.exe"; Description: "Lancer ROTA Antivirus"; Flags: nowait postinstall skipifsilent shellexec

[Code]
function ValeurWebView2(Racine: Integer; Chemin: String): Boolean;
var
  Version: String;
begin
  Result := RegQueryStringValue(Racine, Chemin, 'pv', Version) and (Version <> '') and (Version <> '0.0.0.0');
end;

function WebView2Present: Boolean;
begin
  Result := ValeurWebView2(HKLM, 'SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}')
    or ValeurWebView2(HKCU, 'Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}');
end;
