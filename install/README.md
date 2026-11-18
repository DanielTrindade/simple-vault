# Instalador do SVault para Windows

## Download e requisitos para instalar

As versões publicadas ficam em
[Releases](https://github.com/DanielTrindade/simple-vault/releases).
Em **Assets**, baixe `SVault-Setup-X.Y.Z-x64.exe`. O arquivo `.sha256` ao lado
contém o checksum para conferir a integridade do download.

O computador precisa apenas de **Windows 10/11 x64** e **permissão de administrador**.
Todos os binários (`svault-broker.exe`, `svaultctl.exe`, `svault-mcp.exe` e
`SVaultManager.exe`) são compilados em Rust com runtime C/C++ estático: **não são
necessários .NET, Node.js, npm, internet, Visual Studio, Rust nem Git** na máquina
de destino.

Para uma atualização, feche o SVault Manager e execute o instalador novo.
Cofres já inicializados em versões anteriores são preservados integralmente.

## Gerar localmente

Gere o instalador em uma máquina Windows x64 com Rust e
[Inno Setup 6](https://jrsoftware.org/isdl.php). O Rust exige o workload C++ do
Visual Studio ou o toolchain GNU com MinGW de 64 bits no PATH.

```powershell
.\install\Build-Installer.ps1
```

Com GNU ou compilador Inno em outro diretório:

```powershell
$env:PATH = 'C:\msys64\mingw64\bin;' + $env:PATH
.\install\Build-Installer.ps1 -CargoToolchain stable-x86_64-pc-windows-gnu -IsccPath 'C:\Ferramentas\Inno Setup 6\ISCC.exe'
```

Ajuste o caminho do MinGW conforme sua instalação. `windres` e `ar` devem ser
de 64 bits; uma instalação antiga de MinGW de 32 bits no PATH impede a
incorporação do ícone.

Saída: `artifacts\installer\SVault-Setup-0.1.0-x64.exe`.
O comando apenas compila e empacota; não instala nem acessa o cofre.
A versão vem de `src/svault-manager/Cargo.toml` (sincronizada com o workspace).
Um arquivo `.exe.sha256` é gerado junto ao executável. `-ReleaseTag v0.1.0`
valida se a tag corresponde à versão antes de iniciar o build.

O assistente em português solicita elevação, instala os binários em `C:\SVault`,
registra o serviço `SVaultBroker` e oferece atalhos no menu Iniciar e na área de
trabalho. Também instala `C:\SVault\svault-mcp.cmd` e o shim `C:\SVault\mcp\index.mjs`
para preservar compatibilidade com configurações MCP já registradas nos agentes.

Feche o SVault Manager antes de atualizar. Execute o instalador com o mesmo
usuário administrador autorizado pelo broker; a instalação usa o SID da
identidade elevada para definir o proprietário autorizado.

A release anterior é restaurada automaticamente pelo rollback se a validação pós-ativação
(`svaultctl health` + `Mcp.SmokeTest.ps1`) falhar. O diagnóstico da última tentativa fica
em `Program Files\SVault Setup\install-last.log`.

A desinstalação em Aplicativos do Windows remove o serviço e os binários,
preservando os dados do cofre em `C:\ProgramData\SVault`.

## GitHub Actions e publicação

O workflow `build-and-test` usa o runner `windows-2022` (com Visual Studio C++,
Windows SDK e Inno Setup pré-instalados). Ele instala apenas o toolchain Rust,
executa os testes unitários e de fumaça do workspace, gera o `.exe` com CRT
estático (`+crt-static`) e salva o instalador e seu checksum no artefato
`SVault-installer-windows-x64`.

Após integrar o PR na `main`, publique uma versão com:

```powershell
git switch main
git pull --ff-only
git tag v0.1.0
git push origin v0.1.0
```
