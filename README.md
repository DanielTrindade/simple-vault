# SVault — cofre de credenciais para agentes de IA

Cofre de dados sensíveis (CPF, senhas, tokens) para uso por agentes como Claude Code,
Codex e OpenCode **sem que os valores entrem no contexto do modelo**.

O agente conhece apenas **identificadores** (`CPF_PESSOAL`, `SENHA_PORTAL_A`). Para usar um
segredo, ele pede a execução de uma **operação previamente autorizada** por você. O broker
executa a operação com o segredo e devolve apenas um **resultado sanitizado**.

---

## Estado atual nesta máquina

| Item | Situação |
|---|---|
| Serviço `SVaultBroker` | instalado, `Running`, início automático |
| Binários | `C:\SVault\` (broker, `svaultctl.exe`, `SVaultManager.exe`, `mcp\`) |
| Dados e log | `C:\ProgramData\SVault\` |
| MCP em opencode | `~/.config/opencode/opencode.jsonc` → `mcp.svault` |
| MCP no Claude Code | `~/.claude.json` (escopo user) → `svault` |
| MCP no Codex | `~/.codex/config.toml` → `[mcp_servers.svault]` |
| Cofre | **não inicializado** — falta você definir a senha do cofre |
| Testes do código desta branch | broker 40/40, MCP 9/9, rollback simulado 6/6; validações complementares documentadas |

**Próximo passo (você, fora do contexto do agente):**

```powershell
& "C:\SVault\svaultctl.exe" init --totp
```

Depois cadastre os segredos com `svaultctl add` ou pela interface `SVaultManager.exe`.
O gerenciador gráfico pede a senha do cofre a cada ação e aprova as solicitações dos agentes.

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
                   │   svault-mcp (Node)  │  cliente fino do pipe          │  │  aprovação │
                   │  NÃO guarda segredos │                                │  └─────┬──────┘
                   └──────────┬───────────┘                                │        │
                              │  \\.\pipe\svault.broker.v1                 │        │
                              │  (DACL: SYSTEM, Admins, seu SID)           │        │
                              ▼                                          │        │
                   ┌──────────────────────────────────────────────┐        │        │
                   │  SVaultBroker (Windows Service, LocalSystem)  │◄───────┘────────┘
                   │  • guarda os segredos (memória + CredMan)    │
                   │  • executa só operações pre-autorizadas      │
                   │  • redige o segredo de toda saída            │
                   └───────────────┬──────────────────────────────┘
                                   │
              ┌────────────────────┴─────────────────────┐
              ▼                                          ▼
   ┌────────────────────────┐              ┌──────────────────────────┐
   │ Windows Credential Mgr │              │  Alvo autorizado         │
   │ (perfil do SYSTEM) +   │              │  (portal, API, processo)  │
   │ AES-256-GCM com a sua  │              │  recebe o segredo real   │
   │ senha do cofre         │              │  nunca o modelo           │
   └────────────────────────┘              └──────────────────────────┘
```

### Quem é forte e onde

| Camada | Proteção | Contra quem |
|---|---|---|
| Serviço como LocalSystem | processo em contexto de sistema, não do seu usuário | agente no seu terminal, sem elevação |
| CredMan + DPAPI | valores atrestados no perfil do SYSTEM | leitura direta do cofre pelo agente |
| AES-256-GCM + PBKDF2 | valores ainda cifrados pela sua senha do cofre | administrador local / dump de LSA |
| Aprovação por operação | cada uso do segredo exige a sua senha do cofre | automação descontrolada do agente |
| TOTP (opcional) | segundo fator do seu celular | roubo da senha do cofre |
| Redação | o valor é substituído por `***REDACTED***` em toda saída | vazamento em logs, erros e respostas |
| allowlist de alvos | o agente não escolhe o destino | exfiltração para servidor arbitrário |

---

## Componentes

| Caminho | Papel |
|---|---|
| `src/SVault.Core` | criptografia, Credential Manager, store, redação, motor de operações, TOTP |
| `src/SVault.Broker` | Windows Service + named pipe + despacho de comandos + fluxo de aprovação |
| `src/SVault.Client` | cliente do pipe (usado pela CLI e pela GUI) |
| `src/SVault.Cli` | `svaultctl` — administration e automação |
| `src/SVault.Manager` | `SVaultManager.exe` — interface gráfica |
| `src/svault-mcp` | servidor MCP (stdio) para os agentes |
| `install/` | instalador e desinstalador elevados |
| `tests/` | testes de fumaça com dados fictícios |

Instalação final:

- `C:\SVault\svault-broker.exe` — broker (Windows Service `SVaultBroker`)
- `C:\SVault\svaultctl.exe` — CLI
- `C:\SVault\SVaultManager.exe` — interface gráfica
- `C:\SVault\mcp\index.mjs` — servidor MCP
- `C:\ProgramData\SVault\` — estado, log e configuração (ACL restrita)

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

- `--action http.request` → faz um POST no alvo fixo, injetando o segredo no corpo.
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
cliente fino: **não guarda segredos** e só encaminha comandos ao broker.

---

## Skill `svault` (instrução para os agentes)

As descrições das ferramentas dizem o que cada uma faz, mas não o *fluxo*. A skill ensina o
agente a usar o cofre corretamente — e a **não** tentar contorná-lo.

Instalada nos três agentes:

| Agente | Caminho |
|---|---|
| Claude Code | `~/.claude/skills/svault/SKILL.md` |
| OpenCode | `~/.config/opencode/skills/svault/SKILL.md` |
| Codex | `~/.codex/skills/svault/SKILL.md` |

Ponteiro para a memória global de cada agente: `~/.claude/CLAUDE.md`,
`~/.config/opencode/AGENTS.md`, `~/.codex/AGENTS.md`.

O que a skill ensina: listar operações → solicitar → **aguardar a aprovação** → ler o
resultado sanitizado; e o que proíbe: pedir a credencial no chat, ler arquivos do cofre,
inventar `get_secret`, ou fazer a requisição autenticada por conta própria.

Verificação (Claude Code, sessão nova):

```
> claude -p "liste as skills disponíveis que começam com sv"
svault
```

---

## Manutenção

```powershell
& "C:\SVault\svaultctl.exe" list                      # registros (só metadados)
& "C:\SVault\svaultctl.exe" ops                       # operações autorizadas
& "C:\SVault\svaultctl.exe" update --id CPF_PESSOAL   # novo valor
& "C:\SVault\svaultctl.exe" remove --id CPF_PESSOAL   # apaga o segredo
& "C:\SVault\svaultctl.exe" revoke --id login_portal_a
& "C:\SVault\svaultctl.exe" change-passphrase        # re-sela todos os segredos
& "C:\SVault\svaultctl.exe" disable-totp
```

Log de auditoria (sem segredos): `C:\ProgramData\SVault\logs\svault-broker.log`.

---

## Testes

```powershell
powershell -ExecutionPolicy Bypass -File .\tests\run-smoke.ps1
node .\tests\mcp-smoke.mjs .\artifacts\broker\svault-broker.exe .\src\svault-mcp\index.mjs
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\InstallRollback.SmokeTest.ps1
```

O teste do broker sobe uma instância isolada com armazenamento de credenciais em memória,
diretório temporário, pipe próprio e servidor HTTP local. Os 40 cenários cobrem fluxos de
aprovação, revogação, rotação, sanitização e validação de destinos. O teste de rollback usa
ações simuladas e não instala o produto nem altera serviços ou permissões reais.

### Revisão e validações pendentes

- [Levantamento original](docs/REVISAO-LOGICA-NEGOCIO-2026-10-20.md).
- [Correções e evidências](docs/IMPLEMENTACAO-REVISAO-2026-10-20.md).
- [Parecer independente e reavaliação final](docs/VALIDACAO-REVISAO-2026-10-20.md#9-adendo--reavaliação-da-primeira-rodada-de-correções).
- [Pendências de validação, impactos e critérios de conclusão](docs/PENDENCIAS-VALIDACAO.md).

As seis pendências A02, A13, A15, A22, A23 e A24 têm alterações implementadas e validação
complementar em aberto. A02 e A24 têm prioridade antes de distribuir ou atualizar instalações
com credenciais importantes. As mudanças desta branch não foram instaladas no ambiente real.

---

## Limites de segurança

Leia `docs/LIMITES.md`. Em resumo: **um agente com acesso irrestrito ao terminal e elevação
administrativa é uma ameaça ao modelo inteiro** — o SVault reduz o escopo do dano, mas não
elimina um atacante com privileges de administrador no seu usuário.
