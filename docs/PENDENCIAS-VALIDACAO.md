# Pendências de validação das correções

## 1 Situação e interpretação dos estados

Este documento acompanha as seis validações que permaneceram parciais após a revisão de 20 de outubro de 2026. As correções correspondentes foram implementadas. O complemento de testes permanece pendente.

O acompanhamento separa dois estados:

- **Implementação:** alteração presente no código e examinada na revisão.
- **Validação:** evidências produzidas para os cenários definidos. A validação fica parcial enquanto seus critérios de conclusão não forem atendidos.

A marcação anterior `[~]` reunia esses dois estados no acompanhamento local. As seis pendências abaixo passam a constituir o registro permanente e versionado. As marcações só devem ser encerradas com evidências dos testes complementares.

A reavaliação independente marcou V01–V04 e A18 como corrigidos, sem bloqueantes residuais no escopo examinado. O parecer não declarou cobertura integral de todos os cenários. Consulte a [seção 9 do parecer](VALIDACAO-REVISAO-2026-10-20.md#9-adendo--reavaliação-da-primeira-rodada-de-correções).

## 2 Impacto e prioridade

Os impactos descrevem consequências possíveis de defeitos ainda não detectados. Não há estimativa de probabilidade de ocorrência. A classificação considera a consequência e o contexto de uso, sem afirmar a existência de seis falhas funcionais abertas.

A Tabela 1 apresenta o estado atual e a ordem recomendada para completar a validação.

Tabela 1 — Implementação, cobertura e impacto potencial.

| Achado | Implementação | Validação | Impacto potencial | Prioridade |
|---|---|---|---|---|
| A02 — Troca de senha | Implementada | Parcial; faltam interrupção abrupta e durabilidade | Alto durante interrupção da rotação: perda de acesso às credenciais se a recuperação falhar | P1 |
| A24 — Instalação e atualização | Implementada | Parcial; recuperação simulada, sem instalação elevada real | Alto durante atualização: indisponibilidade do serviço ou restauração incompleta | P1 |
| A13 — Exceções inesperadas | Implementada | Parcial; faltam exceções específicas | Médio: solicitação com estado ou mensagem inadequados diante de falha incomum | P2 |
| A15 — Expiração e retenção | Implementada | Parcial; faltam relógio, volume e concorrência | Médio, especialmente sob volume: fila inconsistente, histórico excessivo ou expiração incorreta | P2 |
| A23 — Resultado da operação | Implementada | Parcial; faltam código de saída e apresentação visual | Médio em automações: falha interpretada como sucesso | P2 |
| A22 — Cadastro na interface e CLI | Implementada | Parcial; falta interação ponta a ponta | Baixo a médio: campos ou parâmetros persistidos incorretamente | P3 |

P1 deve preceder a distribuição ou atualização de instalações com credenciais importantes. P2 complementa a confiabilidade operacional. P3 pode acompanhar a validação funcional da interface.

## 3 Plano e critérios de conclusão

### 3.1 A02 — Recuperação da troca de senha

**Cobertura existente:** falhas de leitura, escrita e gravação final; reabertura lógica; estado legado; rotação com TOTP, senha temporária baseada em tempo. Os testes usam armazenamento substituível e dados sintéticos.

**Complemento necessário:** executar a rotação em processo separado, com armazenamento de teste persistente. Interromper o processo antes e depois da confirmação do novo estado. Reiniciar e conferir a senha ativa, todos os valores e o segundo fator. Incluir falha de limpeza após a confirmação.

**Critério de conclusão:** cada ponto de interrupção mantém uma geração completa recuperável. Uma falha de limpeza não invalida a senha já confirmada. Nenhuma credencial sentinela de outro cofre é alterada.

O encerramento forçado de processo não comprova resistência à perda de energia. Essa alegação exige cenário próprio em máquina virtual descartável e registro das condições de armazenamento.

- [ ] Encerramento abrupto e reabertura com armazenamento sintético persistente.
- [ ] Falha de limpeza após confirmação do novo estado.
- [ ] Durabilidade diante de interrupção da máquina virtual, ou limite dessa garantia explicitamente registrado.

### 3.2 A24 — Instalação, atualização e recuperação

**Cobertura existente:** preparação da versão, análise sintática dos scripts e seis cenários simulados de recuperação. O teste de recuperação não executa os comandos nativos dos callbacks.

**Complemento necessário:** usar máquina virtual Windows descartável, com snapshot e credenciais exclusivamente fictícias. Exercitar instalação nova, atualização e falhas em cópia, permissões, configuração, ambiente e inicialização do serviço. Incluir a interrupção entre mover a versão anterior e ativar a nova.

**Critério de conclusão:** falhas anteriores à ativação preservam a versão anterior. Falhas posteriores tentam todas as etapas de recuperação. Diretórios, configuração e serviço ficam em estado verificável. Quando a recuperação não for possível, o backup permanece preservado e o erro identifica os recursos pendentes.

Verificar também as permissões efetivas, a execução do launcher `.cmd` e a saúde do broker e do servidor Model Context Protocol (MCP) após atualização e recuperação. Definir e testar a preservação de configurações personalizadas em atualizações bem-sucedidas.

- [ ] Instalação nova e atualização na máquina virtual descartável.
- [ ] Falhas nativas e recuperação com verificação de configuração, permissões e serviço.
- [ ] Falha entre movimentação da versão anterior e ativação da nova.
- [ ] Launcher, comunicação MCP e saúde após recuperação.
- [ ] Política de migração das configurações personalizadas documentada e verificada.

### 3.3 A13 — Exceções inesperadas do executor

**Cobertura existente:** tratamento geral que finaliza solicitações como `failed`, com mensagem genérica. Há regressão de falha na seleção de JSON.

**Complemento necessário:** injetar `ArgumentException`, `Win32Exception` e uma exceção inesperada por meio de executor de teste, sem iniciar processos reais.

**Critério de conclusão:** todas as solicitações alcançam estado terminal, têm `FinishedAt` e não expõem segredo, corpo sensível ou detalhe interno da exceção. Consultas posteriores mantêm o resultado terminal.

- [ ] Exceções específicas e inesperadas com verificação de estado e sanitização.

### 3.4 A15 — Expiração, retenção e concorrência

**Cobertura existente:** expiração em solicitações e consultas, limite de pendências e poda do histórico terminal.

**Complemento necessário:** controlar o relógio dos testes, gerar volume acima dos limites e consultar a fila simultaneamente a aprovações e revogações.

**Critério de conclusão:** pedidos expirados deixam a fila e não executam. O histórico respeita a política definida. Operações concorrentes não causam exceções de enumeração, estados incoerentes ou perda de resultados ainda retidos. Os limites de resposta do protocolo devem ser respeitados.

- [ ] Expiração no limite do prazo, retenção e volume.
- [ ] Listagem concorrente com aprovação e revogação.

### 3.5 A23 — Resultado na automação e na interface

**Cobertura existente:** a CLI, interface de linha de comando, e o gerenciador consideram o estado e `Result.Ok` para indicar sucesso.

**Complemento necessário:** executar a CLI como cliente de um broker isolado, com servidor HTTP de teste. Cobrir HTTP 200, 401 e 500, falha de comunicação e solicitação pendente. Conferir a indicação correspondente no gerenciador.

**Critério de conclusão:** sucesso da operação produz retorno zero. Falhas de negócio ou comunicação produzem retorno diferente de zero e indicação visual coerente. Solicitações pendentes permanecem distinguíveis de operações concluídas com sucesso.

O processo a executar neste teste é a própria CLI. A ação `process.stdin` permanece desabilitada.

- [ ] Códigos de saída e mensagens nos cenários definidos.
- [ ] Indicação visual coerente com `Result.Ok` e o estado.

### 3.6 A22 — Campos múltiplos e opções repetidas

**Cobertura existente:** corpo e cabeçalhos multilinha no gerenciador; agregação de opções repetidas na CLI.

**Complemento necessário:** cadastrar uma operação com dois campos de corpo, dois cabeçalhos e parâmetros repetidos. Exercitar interface gráfica e CLI. Conferir a estrutura persistida e a requisição recebida pelo servidor local.

**Critério de conclusão:** todos os pares permanecem presentes, sem sobrescrita acidental ou incorporação do separador ao valor. Valores com acentos e delimitadores mantêm o conteúdo esperado.

- [ ] Cadastro ponta a ponta pela interface e pela CLI.

## 4 Registro das evidências e encerramento

Para cada item concluído, registrar comando ou roteiro, versão do código, ambiente, resultado esperado e resultado observado. Associar o teste ao identificador A02, A13, A15, A22, A23 ou A24. Uma falha confirmada deve originar correção e regressão antes do encerramento.

Os cenários automatizáveis devem integrar a suíte versionada. Resultados manuais devem registrar evidências sanitizadas, sem dados pessoais ou credenciais reais. Testes de instalação e durabilidade devem permanecer restritos ao ambiente descartável definido.

Este trabalho não executou instalação ou atualização no ambiente real. O commit e a abertura do PR não atualizam o serviço instalado. A desativação de `process.stdin` constitui mudança de compatibilidade e deve ser considerada antes da implantação.

## 5 Referências

- [Levantamento original A01–A24](REVISAO-LOGICA-NEGOCIO-2026-10-20.md).
- [Implementação e evidências](IMPLEMENTACAO-REVISAO-2026-10-20.md).
- [Parecer independente e reavaliação](VALIDACAO-REVISAO-2026-10-20.md).
- [Limites de segurança](LIMITES.md).
