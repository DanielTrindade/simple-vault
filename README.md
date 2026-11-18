# SVault — cofre de credenciais para agentes de IA (Full Rust)

Cofre de dados sensíveis (CPF, senhas, tokens) para uso por agentes como Claude Code,
Codex e OpenCode **sem que os valores entrem no contexto do modelo**.

O agente conhece apenas **identificadores** (`CPF_PESSOAL`, `SENHA_PORTAL_A`). Para usar um
segredo, ele pede a execução de uma **operação previamente autorizada** por você. O broker
executa a operação com o segredo e devolve apenas um **resultado sanitizado**.

Todo o ecossistema do SVault — núcleo criptográfico, broker Windows Service, cliente do pipe,
CLI (`svaultctl`), servidor MCP (`svault-mcp`) e interface gráfica (`SVaultManager`) — é
implementado **100% em Rust**, sem dependência de runtime .NET ou Node.js.

---

## Arquitetura

```
   ┌──────────────────────┐        ┌──────────────────────┐        ┌────────────────────────┐
   │  Claude Code / Codex │        │      OpenCode        │        │  SVault Manager / CLI  │
   │  (sessão do agente)  │        │  (sessão do agente)  │        │      (você)            │
   └──────────┬───────────┘        └──────────┬───────────┘        └───────────┬────────────┘
              │                               │                            │      │
              │  MCP (stdio, sem segredos)    │                            │      │ senha do cofre
              └───────────────┬───────────────┘                            │      │ (+ TOTP)
                              ▼                                            │      ▼
                   ┌──────────────────────┐                                │  ┌────────────┐
                   │   svault-mcp (Rust)  │  cliente fino do pipe          │  │  aprovação │
                   │  NÃO guarda segredos │                                │  └─────┬──────┘
                   └──────────┬───────────┘                                │        │
                              │  \\.\pipe\svault.broker.v1                 │        │
                              │  (DACL: SYSTEM, Admins, seu SID)           │        │
                              ▼                                            │        │
                   ┌──────────────────────────────────────────────┐        │        │
                   │  SVaultBroker (Rust, Windows Service/SYSTEM) │◄───────┘────────┘
                   │  • guarda os segredos (memória + CredMan)    │
                   │  • executa só operações pré-autorizadas      │
                   │  • redige o segredo de toda saída            │
                   └───────────────┬──────────────────────────────┘
                                   │
              ┌────────────────────┴─────────────────────┐
              ▼                                          ▼
   ┌────────────────────────┐              ┌──────────────────────────┐
   │ Windows Credential Mgr │              │  Alvo autorizado         │
   │ (perfil do SYSTEM) +   │              │  (portal, API)           │
   │ AES-256-GCM com a sua  │              │  recebe o segredo real   │
   │ senha do cofre         │              │  nunca o modelo          │
   └────────────────────────┘              └──────────────────────────┘
```

### Quem é forte e onde

| Camada | Proteção | Contra quem |
|---|---|---|
| Serviço como LocalSystem | processo em contexto de sistema, não do seu usuário | agente no seu terminal, sem elevação |
| CredMan + DPAPI | valores atrelados ao perfil do SYSTEM | leitura direta do cofre pelo agente |
| AES-256-GCM + PBKDF2 | valores ainda cifrados pela sua senha do cofre | administrador local / dump de LSA |
| Aprovação por operação | cada uso do segredo exige a sua senha do cofre | automação descontrolada do agente |
| TOTP (opcional) | segundo fator do seu celular | roubo da senha do cofre |
| Redação | o valor é substituído por `***REDACTED***` em toda saída | vazamento em logs, erros e respostas |
| allowlist de alvos | o agente não escolhe o destino | exfiltração para servidor arbitrário |

---

## Instalador para Windows

Baixe o arquivo `SVault-Setup-X.Y.Z-x64.exe` em
[Releases](https://github.com/DanielTrindade/simple-vault/releases).
Requisitos: Windows 10/11 x64 e permissão de administrador. Não é preciso instalar .NET,
Node.js, Rust, internet nem ferramentas de desenvolvimento. Para atualizar, feche o
gerenciador e execute o instalador novo, sem desinstalar antes (cofres existentes são
100% compatíveis em formato binário e JSON).

O instalador gráfico é gerado com `install\Build-Installer.ps1` e salvo em
`artifacts\installer\`. Veja os detalhes em [install/README.md](install/README.md).

## Componentes (Workspace Cargo)

| Caminho | Papel |
|---|---|
| `src/svault-core` | criptografia (`PBKDF2`, `HKDF`, `AES-256-GCM`, `TOTP`), Credential Manager, LSA, store, redação, motor de operações |
| `src/svault-broker` | `svault-broker.exe` — Windows Service `SVaultBroker` + named pipe com DACL + fluxo de aprovação |
| `src/svault-client` | cliente do pipe com buffers `Zeroizing` + leitura segura de console (`SecureInput`) |
| `src/svault-cli` | `svaultctl.exe` — administração e automação via linha de comando |
| `src/svault-mcp` | `svault-mcp.exe` — servidor MCP nativo (stdio JSON-RPC) para os agentes (+ shim `index.mjs` para caminhos legados) |
| `src/svault-manager` | `SVaultManager.exe` — interface gráfica em Rust/Slint |
| `install/` | instalador e desinstalador elevados com rollback atômico |
| `tests/svault-smoke` | suíte completa de regressão, broker isolado e servidor MCP nativo |
| `tests/svault-demo` | demonstração ponta a ponta com dados fictícios |

Instalação final:

- `C:\SVault\svault-broker.exe` — broker (Windows Service `SVaultBroker`)
- `C:\SVault\svaultctl.exe` — CLI
- `C:\SVault\svault-mcp.exe` — servidor MCP nativo (`svault-mcp.cmd` e `mcp\index.mjs` mantidos por compatibilidade)
- `C:\SVault\SVaultManager.exe` — interface gráfica
- `C:\ProgramData\SVault\` — estado, log e configuração (ACL restrita)

### Compilação manual

Com Build Tools do Visual Studio (workload C++):

```powershell
cargo build --workspace --release
cargo test --workspace
```

Sem MSVC, use o toolchain GNU (`rustup toolchain install stable-x86_64-pc-windows-gnu`) com um
MinGW de 64 bits no `PATH`:

```powershell
$env:PATH = "C:\msys64\mingw64\bin;$env:PATH"
cargo +stable-x86_64-pc-windows-gnu build --workspace --release
cargo +stable-x86_64-pc-windows-gnu test --workspace
```

`SVAULT_PIPE` aponta a CLI, o servidor MCP e o gerenciador para outro pipe. Para testar com dados
fictícios, suba um broker isolado e abra o gerenciador apontando para ele:

```powershell
.\target\release\svault-broker.exe --console --home $env:TEMP\svault-demo --pipe svault.demo --in-memory-credentials
$env:SVAULT_PIPE = "svault.demo"; .\target\release\svault-manager.exe
```

---

## Uso

### 1. Inicializar o cofre (uma vez)

```powershell
& "C:\SVault\svaultctl.exe" init --totp
```

Escolha uma **senha do cofre** (≠ a senha do Windows). Com `--totp`, o comando imprime um URI
`otpauth://` para você importar no seu autenticador. Guarde o URI com cuidado: ele só é
exibido nesta etapa.

### 2. Cadastrar um segredo

```powershell
& "C:\SVault\svaultctl.exe" add --id CPF_PESSOAL --kind cpf --target https://servico.exemplo.com
& "C:\SVault\svaultctl.exe" add --id SENHA_PORTAL_A --kind password --target https://portal-a.exemplo.com
```

O valor é lido **sem eco**, sem arquivo temporário e sem área de transferência.
`--target` é a **allowlist**: o segredo só pode ser usado em alvos cobertos por ela.

Ou use a interface gráfica:

```powershell
& "C:\SVault\SVaultManager.exe"
```

### 3. Autorizar uma operação (uma vez por uso)

```powershell
& "C:\SVault\svaultctl.exe" authorize `
  --id login_portal_a --entry SENHA_PORTAL_A --action http.request `
  --target https://portal-a.exemplo.com/api/login `
  --body "usuario={{param:usuario}},senha={{secret}}" `
  --param usuario
```

- `--action http.request` → faz requisição HTTP no alvo fixo, injetando o segredo no corpo/cabeçalhos.
- `process.stdin` está desabilitado no broker até existir execução sob identidade restrita com validação de executável, dependências e destino. Operações `process.stdin` já cadastradas também são recusadas.
- `--action noop.echo` → diagnóstico: devolve o segredo mascarado, sem tocar na rede.

Placeholders aceitos nos templates:

| Placeholder | Resolve para |
|---|---|
| `{{secret}}` | o segredo do registro ligado à operação |
| `{{secret:IDENTIFICADOR}}` | o segredo de **outro** registro (ex.: CPF + senha no mesmo login) |
| `{{param:NOME}}` | um valor que **o agente** preenche (declarado em `--param`) |

Cada registro referenciado precisa existir e ter o **mesmo alvo** autorizado — o broker
recusa a operação se algum deles não cobrir o alvo da requisição.

O broker **recusa** templates que contenham literalmente o valor de um segredo cadastrado.

### 4. Agente usa o segredo

```
vault_request_operation { operationId: "login_portal_a", params: { "usuario": "..." } }
  → { requestId: "...", status: "pending_approval", requires: "passphrase+totp" }

(você aprova no SVault Manager ou com `svaultctl approve --request <id>`)

vault_operation_status { requestId: "..." }
  → { status: "completed", result: { body: "{\"status\":\"ok\",\"echo\":\"***REDACTED***\"}" } }
```

O agente **nunca** recebe o valor: nem no `body`, nem em log, nem em mensagem de erro.

### 5. Operação pela CLI

```powershell
& "C:\SVault\svaultctl.exe" request --op login_portal_a --param-value "usuario=meu-usuario"
& "C:\SVault\svaultctl.exe" pending
& "C:\SVault\svaultctl.exe" approve --request <requestId>
& "C:\SVault\svaultctl.exe" status --request <requestId>
```

---

## Ferramentas MCP expostas

| Ferramenta | Devolve |
|---|---|
| `vault_health` | situação do broker, contagens |
| `vault_list_entries` | identificadores + tipo + alvos + data (nunca valores) |
| `vault_list_operations` | operações autorizadas, alvo fixo, parâmetros aceitos |
| `vault_request_operation` | `requestId` + status (`pending_approval`/`completed`) |
| `vault_operation_status` | status + resultado sanitizado |

Não existe `get_secret`, `read_password`, `export` nem equivalente. O servidor MCP é um
binário nativo fino (`svault-mcp.exe`): **não guarda segredos** e só encaminha comandos ao broker.

---

## Manutenção

```powershell
& "C:\SVault\svaultctl.exe" list                      # registros (só metadados)
& "C:\SVault\svaultctl.exe" ops                       # operações autorizadas
& "C:\SVault\svaultctl.exe" update --id CPF_PESSOAL --value  # novo valor
& "C:\SVault\svaultctl.exe" remove --id CPF_PESSOAL   # apaga o segredo
& "C:\SVault\svaultctl.exe" revoke --id login_portal_a
& "C:\SVault\svaultctl.exe" change-passphrase         # re-sela todos os segredos
& "C:\SVault\svaultctl.exe" disable-totp
```

Log de auditoria (sem segredos): `C:\ProgramData\SVault\logs\svault-broker.log`.

---

## Testes

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\run-smoke.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\Mcp.SmokeTest.ps1 -BrokerExe .\artifacts\broker\svault-broker.exe -McpExe .\artifacts\broker\svault-mcp.exe
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\InstallerPackage.SmokeTest.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\InstallRollback.SmokeTest.ps1
```

---

## Limites de segurança

Leia [docs/LIMITES.md](docs/LIMITES.md). Em resumo: **um agente com acesso irrestrito ao terminal e elevação
administrativa é uma ameaça ao modelo inteiro** — o SVault reduz o escopo do dano, mas não
elimina um atacante com privilégios de administrador no seu usuário.
