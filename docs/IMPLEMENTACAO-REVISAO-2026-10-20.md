# Implementação da revisão de lógica de negócio — 2026-10-20

Branch: `fix/correcoes-revisao-negocio`

Base: `ab1106b2a9ec4594acf8c8af49bb27953d51fd99`

Relatório original preservado em `docs/REVISAO-LOGICA-NEGOCIO-2026-10-20.md`.

## Decisões

A rotação grava os segredos sob uma geração GUID nova, valida os blobs e só ativa a nova senha, geração e segredo TOTP após substituir atomicamente o estado. O estado temporário inventaria alvos antes das escritas e `Flush(true)` persiste o arquivo temporário antes da troca. Estados antigos sem geração continuam lendo seus alvos legados; cofres novos usam geração própria. A limpeza só considera alvos conhecidos, sem apagar globalmente por prefixo.

Pedidos de aprovação guardam snapshots de operação, parâmetros, identidades e revisões dos registros envolvidos. Um gate protege o claim e mudanças administrativas; o pedido passa a `running` antes da execução assíncrona, e resultados terminais não podem ser sobrescritos. Exceções do executor retornam estado `failed` com mensagem genérica.

`process.stdin` foi removido do contrato executável do broker, inclusive para autorizações antigas. Assim, o broker não inicia processos enquanto não existir execução sob identidade restrita e validação suficiente de executável, dependências e destino. README e Demo explicitam o comportamento.

Os testes usam dados sintéticos, `MemoryCredentialStore`, diretórios e pipes temporários. O MCP smoke inicia um broker temporário com `--in-memory-credentials`. Nenhuma validação usou Credential Manager, cofre real, serviço instalado ou segredo real.

## Mapa A01–A24

Nos seis itens com validação parcial, a alteração está implementada e faltam evidências complementares. Impactos, prioridades e critérios de conclusão estão no [plano permanente de validação](PENDENCIAS-VALIDACAO.md).

| Achado | Estado | Implementação e evidência |
|---|---|---|
| A01 | Resolvido localmente | `VaultStore` exige o TOTP atual para trocar/desativar fator, trocar senha e resetar; teste direto cobre código ausente e válido. |
| A02 | Parcial | Rotação com estado candidato, geração nova, validação dos blobs, commit atômico, inventário e limpeza limitada. Testes incluem falha de escrita/leitura/commit com reabertura lógica, reset preservando sentinela, fixture legado e rotação com TOTP ativo. Não houve encerramento abrupto de processo nem teste de perda de energia. |
| A03 | Resolvido localmente | Nova senha validada no domínio com mínimo de oito caracteres; teste rejeita senha curta sem alterar a atual. Cofres legados continuam abrindo. |
| A04 | Resolvido localmente | Identidade GUID da autorização e revalidação no claim; teste revoga e reautoriza o mesmo ID e invalida pedido antigo. |
| A05 | Resolvido localmente | Revisões, identidades e alvos dos registros são capturados e revalidados; teste altera registro pendente e confirma que não há chamada ao servidor fake. |
| A06 | Resolvido localmente | Claim sob gate marca `running` antes do executor; teste de duas aprovações concorrentes confirma uma única requisição e rejeição após término. |
| A07 | Resolvido localmente | Resumo expõe parâmetros efetivos, método, destino e IDs auxiliares; Manager mostra esses dados. |
| A08 | Resolvido localmente | Redator cobre segredos curtos e substitui em uma passagem; teste cobre marcador e segredo que começa com o próprio marcador. |
| A09 | Resolvido localmente | Redação recursiva de strings, nomes de propriedades, números e booleanos JSON após parse; teste cobre JSON escapado e booleano. |
| A10 | Resolvido localmente | Autorização rejeita todos os valores não vazios, inclusive segredos de um, dois e três caracteres, quando aparecem em segmentos literais; placeholders são analisados como sintaxe. Teste cobre prefixo/sufixo, valor curto entre placeholders e ausência de persistência. |
| A11 | Resolvido localmente por restrição | `process.stdin` é recusado inclusive em operações antigas, antes de iniciar executável; regressão verifica o bloqueio. |
| A12 | Resolvido por remoção | Execução de processo foi desabilitada; não há canal de processo para bloquear por timeout ou limitar saída. |
| A13 | Parcial | Exceções do executor viram resultado terminal `failed` com mensagem genérica. Falta regressão específica com `Win32Exception` e `ArgumentException`. |
| A14 | Resolvido localmente | Rejeição só aceita pedido pendente; teste confirma conflito para pedido concluído. |
| A15 | Parcial | Expiração é aplicada em pedidos e consultas; fila pendente é limitada e estados terminais são podados. Faltam testes de TTL, retenção e acesso simultâneo à listagem. |
| A16 | Resolvido localmente | Template é validado antes da interpolação; delimitadores vindos de segredo ou parâmetro permanecem dados opacos. Testes cobrem interpolação integral e composta com chaves nos valores, além do caso HTTP `Bearer {{param:usuario}} {{secret}}`. |
| A17 | Resolvido por remoção | Templates de processo deixaram de ser executáveis junto com `process.stdin`; não há expansão de argumentos/ambiente em runtime. |
| A18 | Resolvido localmente | Gramática e parâmetros declarados são validados na autorização e no limite do armazenamento, além da validação antes de criar pedido. Regressão confirma que template inválido não é persistido. |
| A19 | Resolvido localmente | JSON inválido com `ResultFields` falha sem devolver o corpo; teste injeta resposta inválida do servidor fake. |
| A20 | Resolvido localmente | Caminho compara com `Ordinal`; esquema/host ignoram caixa; userinfo e fragmentos são recusados e query tem regra explícita. URL HTTP efetiva é comparada ao alvo aprovado na revalidação antes de abrir segredos; teste legado confirma zero leituras de credencial e zero chamadas ao servidor. |
| A21 | Resolvido localmente | `ICredentialStore` permite armazenamento substituível; SmokeTest e MCP smoke usam memória. Demo exige opt-in para broker instalado. |
| A22 | Parcial | Manager permite campos multilinha e CLI agrega parâmetros/campos repetidos. Faltam testes de interação da UI/CLI para entradas repetidas e formatos multilinha. |
| A23 | Parcial | CLI e Manager consideram `Result.Ok` e status; builds passam. Falta teste de processo para códigos de saída e indicação visual de falha de negócio. |
| A24 | Parcial | Release em staging, checagens de arquivos/comandos, SDK MCP instalado no staging, validação de binários/ACL, serviço existente preservado, ativação com backup e health CLI/MCP antes da limpeza. Rollback tenta cada etapa independentemente e não move backup sobre raiz ativa. Harness simulado cobre falhas de configuração, Environment, ACL, pre-rename, remoção e move do backup; não houve execução do instalador. Faltam validação elevada real e execução do launcher `.cmd`. |

## Verificações

- Builds Broker, CLI, Manager, SmokeTest e Demo com `--no-restore`: sucesso, zero avisos e erros.
- SmokeTest: 40 aprovados, 0 falhas; inclui regressões V01–V03, A18, fixture de estado legado e rotação com TOTP ativo.
- `node --check src/svault-mcp/index.mjs`: sucesso.
- MCP smoke isolado: 9 aprovados, 0 falhas.
- Parser AST de PowerShell em `install/Install-SVault.ps1`: sem erros; instalador não executado.

## Limitações

A rotação foi reaberta em novas instâncias de `VaultStore`, mas não foi simulada queda real de processo ou energia. Alvos legados cujo cleanup falhe podem permanecer como blobs cifrados órfãos; nomes legados compartilhados não são apagados fora de ownership comprovável. A instalação não foi executada contra sistema real. O rollback foi exercitado por harness de ações simuladas, sem SCM, `icacls`, ACL real ou launcher `.cmd`. As lacunas de teste por achado permanecem marcadas como parciais acima.

## Rodada de correção V01–V04 e A18

O parecer independente está preservado em `docs/VALIDACAO-REVISAO-2026-10-20.md`. Esta rodada corrigiu apenas os achados V01–V04 e a lacuna A18 observada na matriz:

- V01/A10: removido o limite mínimo de quatro caracteres na detecção de literais. Valores não vazios são comparados aos segmentos literais do template, preservando placeholders; teste de broker cobre segredos de 1, 2, 3 caracteres e whitespace, prefixo/sufixo e placeholder adjacente. Autorizações recusadas não aparecem no estado.
- V02/A20: na revalidação da aprovação, a URL HTTP efetiva precisa ser equivalente ao alvo fixado. O executor também recusa inconsistência direta. O teste monta operação legada `/Admin` versus `/admin` em memória e verifica `target_not_allowed`, zero leituras no provider de credenciais e nenhuma requisição TCP.
- V03/A16: gramática original é validada antes da substituição; o resultado não é reinterpretado. Teste confirma que `{{...}}` dentro de segredo/parâmetro é preservado e que sintaxe inválida no template original continua falhando.
- V04/A24: `install/SVaultRollback.ps1` isola falhas por etapa, tenta restaurar a release somente quando a raiz está livre e só tenta iniciar o serviço após restaurar os binários. `tests/InstallRollback.SmokeTest.ps1` injeta falha separada em `broker.json`, Environment e ACL, além de falhas pre-rename, remoção da release nova e move do backup.
- A18: templates e parâmetros declarados são validados no broker e no limite do armazenamento antes de persistir autorização. Teste tenta autorizar referência não declarada e confirma ausência da operação.

Comandos e resultados desta rodada:

- `dotnet build tests/SVault.SmokeTest/SVault.SmokeTest.csproj --no-restore`: sucesso, zero avisos/erros.
- `dotnet tests/SVault.SmokeTest/bin/Debug/net8.0-windows/SVault.SmokeTest.dll src/SVault.Broker/bin/Debug/net8.0-windows/svault-broker.exe`: 40 aprovados, 0 falhas.
- `powershell -NoProfile -ExecutionPolicy Bypass -File tests/InstallRollback.SmokeTest.ps1`: 6 cenários aprovados, 0 falhas.
- `dotnet build` de Broker, CLI, Manager e Demo com `--no-restore`: sucesso, zero avisos/erros.
- `node --check src/svault-mcp/index.mjs` e `node tests/mcp-smoke.mjs ...`: sintaxe aprovada; MCP 9/9.
- Parse AST PowerShell de `Install-SVault.ps1`, `SVaultRollback.ps1` e harness: sem erros.

Limite desta rodada: o harness de A24 usa callbacks e estado simulado, não chama comandos de sistema nem instala a release. A reavaliação independente foi concluída: a seção 9 do [parecer](VALIDACAO-REVISAO-2026-10-20.md) marcou V01–V04 e A18 como corrigidos, sem bloqueantes residuais no escopo examinado. Permanecem as [validações complementares](PENDENCIAS-VALIDACAO.md).
