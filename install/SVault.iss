#ifndef AppVersion
  #error Use install/Build-Installer.ps1 para definir a versao do pacote.
#endif

[Setup]
AppId={{C67452F4-F175-40BC-A5C5-22103F70C691}
AppName=SVault
AppVersion={#AppVersion}
AppPublisher=SVault
DefaultDirName={autopf}\SVault Setup
DisableDirPage=yes
DefaultGroupName=SVault
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
WizardStyle=modern
SetupIconFile=..\src\svault-manager\ui\icons\app.ico
UninstallDisplayIcon=C:\SVault\SVaultManager.exe
OutputDir=..\artifacts\installer
OutputBaseFilename=SVault-Setup-{#AppVersion}-x64
Compression=lzma2
SolidCompression=yes
CloseApplications=no

[Languages]
Name: "brazilianportuguese"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"

[Tasks]
Name: "desktopicon"; Description: "Criar atalho na área de trabalho"; Flags: unchecked

[Files]
Source: "Install-SVault.ps1"; DestDir: "{tmp}\svault-package\install"; Flags: deleteafterinstall
Source: "Run-Install.ps1"; DestDir: "{tmp}\svault-package\install"; Flags: deleteafterinstall
Source: "SVaultRollback.ps1"; DestDir: "{tmp}\svault-package\install"; Flags: deleteafterinstall
Source: "..\tests\mcp-smoke.mjs"; DestDir: "{tmp}\svault-package\tests"; Flags: deleteafterinstall
Source: "Uninstall-SVault.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\artifacts\publish\*"; DestDir: "{tmp}\svault-package\artifacts\publish"; Flags: recursesubdirs createallsubdirs deleteafterinstall
Source: "..\src\svault-mcp\index.mjs"; DestDir: "{tmp}\svault-package\src\svault-mcp"; Flags: deleteafterinstall
Source: "..\src\svault-mcp\package.json"; DestDir: "{tmp}\svault-package\src\svault-mcp"; Flags: deleteafterinstall
Source: "..\src\svault-mcp\package-lock.json"; DestDir: "{tmp}\svault-package\src\svault-mcp"; Flags: deleteafterinstall

[Icons]
Name: "{group}\SVault"; Filename: "C:\SVault\SVaultManager.exe"
Name: "{autodesktop}\SVault"; Filename: "C:\SVault\SVaultManager.exe"; Tasks: desktopicon

[Run]
Filename: "C:\SVault\SVaultManager.exe"; Description: "Abrir o SVault"; Flags: postinstall nowait skipifsilent runasoriginaluser

[Code]
function PrepareToInstall(var NeedsRestart: Boolean): String;
var Code: Integer;
begin
  Result := '';
  if not Exec(ExpandConstant('{sys}\cmd.exe'), '/C "node --version && npm --version"', '', SW_HIDE, ewWaitUntilTerminated, Code) or (Code <> 0) then
    Result := 'Instale o Node.js LTS com npm e conexão à internet para preparar o servidor MCP.';
end;

procedure CurStepChanged(CurStep: TSetupStep);
var Code: Integer;
begin
  if CurStep = ssPostInstall then begin
    if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
      ExpandConstant('-NoProfile -ExecutionPolicy Bypass -File "{tmp}\svault-package\install\Run-Install.ps1" -LogPath "{app}\install-last.log"'),
      '', SW_SHOW, ewWaitUntilTerminated, Code) or (Code <> 0) then
      RaiseException(ExpandConstant('A instalação do serviço falhou. Consulte o diagnóstico em {app}\install-last.log.'));
  end;
end;

function InitializeUninstall: Boolean;
var Code: Integer;
begin
  Result := Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    ExpandConstant('-NoProfile -ExecutionPolicy Bypass -File "{app}\Uninstall-SVault.ps1"'),
    '', SW_SHOW, ewWaitUntilTerminated, Code) and (Code = 0);
end;
