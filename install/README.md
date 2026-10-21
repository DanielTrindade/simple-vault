# Instalador do SVault para Windows

## Download e requisitos para instalar

As versões publicadas ficam em
[Releases](https://github.com/DanielTrindade/simple-vault/releases).
Em **Assets**, baixe `SVault-Setup-X.Y.Z-x64.exe`. O arquivo `.sha256` ao lado
contém o checksum para conferir a integridade do download.

O computador precisa de Windows 10/11 x64, permissão de administrador e
[Node.js LTS](https://nodejs.org/) com npm no PATH. A instalação usa internet
para baixar as dependências do servidor MCP. Broker e CLI incluem o runtime
.NET; o gerenciador distribuído pelo Actions inclui o runtime C/C++ estático.
Não são necessários .NET, Visual Studio, Rust, Git ou o código-fonte.

Para uma atualização, feche o SVault Manager e execute o instalador novo.
Depois de instalar, abra o SVault e inicialize o cofre pela interface se for
o primeiro uso. Não inicialize novamente um cofre que já está em uso.

## Gerar localmente

Gere o instalador em uma máquina Windows x64 com .NET SDK 8, Rust e
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
A versão vem de `src/svault-manager/Cargo.toml`. Um arquivo `.exe.sha256`
é gerado junto ao executável. `-ReleaseTag v0.1.0` valida se a tag corresponde
à versão antes de iniciar o build.

O assistente em português solicita elevação, instala os binários em `C:\SVault`,
registra o serviço pelo script existente e oferece atalhos no menu Iniciar e na
área de trabalho. Broker e CLI incluem o runtime .NET. O computador de destino
precisa de Node.js LTS com npm no PATH e internet para instalar as dependências
do MCP. Não são necessários Rust, SDK .NET ou fontes no computador de destino.

Feche o SVault Manager antes de atualizar. Execute o instalador com o mesmo
usuário administrador autorizado pelo broker; a instalação existente usa o SID
da identidade elevada para definir o proprietário autorizado.

Execute o mesmo instalador para atualizar uma versão existente, sem desinstalar
antes. A release anterior é restaurada pelo rollback se a validação falhar.
O diagnóstico da última tentativa fica em `Program Files\SVault Setup\install-last.log`.
O pacote inclui o teste isolado do MCP executado durante a validação.

A desinstalação em Aplicativos do Windows remove o serviço e os binários,
preservando os dados do cofre. Os metadados do instalador ficam separados em
`Program Files\SVault Setup`, pois o instalador existente troca a pasta dos
binários durante o rollback.

O ícone vetorial está em `src/svault-manager/ui/icons/app.svg`; a versão Windows
`app.ico` contém tamanhos de 16 a 256 pixels e é incorporada ao executável e ao
instalador. Ao alterar o SVG, regenere também o ICO.

Antes de distribuir, valide instalação, atualização e desinstalação em uma VM
Windows e consulte `docs/PENDENCIAS-VALIDACAO.md` para as pendências do produto.

## GitHub Actions e publicação

O workflow `build-and-test` usa o runner `windows-2022`, que já inclui Visual
Studio C++/SDK Windows e Inno Setup. Ele instala os SDKs .NET, Node e Rust,
executa os testes, gera o `.exe` e seu checksum e salva ambos no artefato
`SVault-installer-windows-x64`, disponível por 14 dias.

Para testar um PR, abra **Actions → build-and-test → execução → Artifacts** e
baixe esse artefato. O download de artefatos do Actions exige login no GitHub;
as Releases do repositório público permitem download sem login. **Run workflow**
gera apenas o artefato, sem publicar Release.

Após integrar o PR na `main`, publique uma versão com:

```powershell
git switch main
git pull --ff-only
git tag v0.1.0
git push origin v0.1.0
```

Use uma tag ainda não publicada. Para versões seguintes, atualize `version`
em `src/svault-manager/Cargo.toml` e o pacote correspondente no `Cargo.lock`,
integre a mudança e crie a tag com a mesma versão (`v0.1.1`, por exemplo).
Tags divergentes são recusadas antes do empacotamento.

O push de uma tag `v*` executa os mesmos testes e builds. Somente depois que
ambos os jobs passam, o job `release` confere o SHA-256 e cria uma Release
com notas automáticas, instalador e checksum. Se uma Release já existir para
a tag, a publicação falha sem substituir os arquivos existentes.

O workflow usa o `GITHUB_TOKEN` automático do GitHub; não é necessário cadastrar
PAT ou outro segredo. A permissão `contents: write` fica restrita ao job que
publica Releases. Em **Settings → Actions → General**, mantenha Actions habilitado
e permita as ações usadas pelo workflow, caso exista uma política restritiva.
