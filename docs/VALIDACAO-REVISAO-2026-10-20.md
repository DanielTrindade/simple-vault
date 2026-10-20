# Validação independente da revisão de lógica de negócio

Data: 20 de outubro de 2026. Base: `ab1106b2a9ec4594acf8c8af49bb27953d51fd99`. Avaliação das alterações locais ainda sem commit.

## 1 Objetivo e pareceres

Este parecer verifica os requisitos A01–A24 e a qualidade técnica da implementação apresentada. Foram encontrados quatro defeitos concretos: três reproduzidos e um confirmado por inspeção do tratamento de falhas.

**Parecer de conformidade: não aprovado integralmente.** A10 continua permitindo persistência de segredos curtos. A20 não protege o destino efetivo de operações HTTP legadas. A16 apresenta regressão de interpolação. A24 ainda permite interromper a recuperação antes de restaurar a versão anterior.

**Parecer de qualidade técnica: aprovação condicionada a correções.** A separação do armazenamento, os estados candidatos e o controle de aprovação melhoram a implementação. Entretanto, V01, V02 e V04 bloqueiam a aceitação das garantias de segurança e recuperação. V03 também deve ser corrigido antes de declarar A16 resolvido.

Os dois pareceres são independentes: a presença de regressões automatizadas e compilações bem-sucedidas não comprova conformidade completa com os requisitos.

## 2 Escopo, método e evidências

Foram consultados o relatório original, o registro de implementação, o acompanhamento das tarefas e o pacote de alterações em `artifacts/review-validation/review-package.txt`. A inspeção incluiu armazenamento, broker, executor, sanitizador, protocolo, cliente, terminal, interface gráfica, instalador e testes modificados.

Foram rastreados os caminhos de rotação e leitura legada, segundo fator, revogação, revisões, aprovação concorrente, estados terminais e ativação de versões. Os requisitos foram comparados com o código efetivo, independentemente das classificações declaradas pelo implementador.

O implementador informou cinco compilações sem avisos ou erros, SmokeTest com 36 aprovações e teste MCP com 9 aprovações. Informou também verificações sintáticas de JavaScript e PowerShell. A leitura confirmou a existência dos cenários e o uso de armazenamento em memória nos testes relevantes. O pacote fornecido contém alterações e documentos, sem transcrições completas dessas execuções; seus resultados históricos permanecem evidência informada, não execução independente desta validação.

Não se repetiram essas suítes no mesmo código. Executou-se uma reprodução dirigida para esclarecer três suspeitas novas. O comando foi `dotnet run --project artifacts/review-validation/Validator.csproj`, com saída zero. Esse comando também compilou o programa auxiliar e suas referências.

O programa auxiliar utilizou `MemoryCredentialStore`, diretório temporário exclusivo e conexão TCP restrita ao endereço de loopback. O broker foi instanciado no próprio processo. Nenhum segredo real, cofre instalado, Credential Manager, serviço instalado, instalador ou comando de permissões foi utilizado.

Os resultados foram registrados em `artifacts/review-validation/directed-results.txt`, com programa auxiliar em `artifacts/review-validation/Program.cs`. Esses arquivos pertencem ao diretório local de artefatos, ignorado pelo Git, e não acompanham o PR. As regressões finais estão na suíte versionada. Executou-se também `git diff --check`, sem erros de espaços; foram exibidos apenas avisos de conversão de final de linha.

## 3 Achados concretos

### V01 — A10 ainda permite persistir segredos de um a três caracteres

**Gravidade:** alta. **Evidência:** reproduzido. **Bloqueante:** sim.

**Local:** `src/SVault.Broker/BrokerEngine.cs:784`, em `ValidateNoSecretLiteral`.

A condição `text.Length >= 4` exclui segredos curtos da detecção. O cadastro continua aceitando esses valores. Foi cadastrado o segredo sintético `abc` e autorizada uma operação HTTP com `password=Bearer abc`. A autorização retornou sucesso e o literal apareceu no arquivo de estado.

O defeito mantém a exposição descrita em A10 para parte dos valores aceitos pelo domínio. A correção do sanitizador em A08 não protege os templates persistidos. A alegação de implementação de que os valores aceitos são rejeitados nos templates não corresponde a esse caminho.

**Correção esperada:** detectar todos os valores não vazios aceitos pelo cadastro, inclusive dentro de templates compostos. A política para colisões com nomes e delimitadores de placeholders deve ser explícita. Incluir regressões para um, dois e três caracteres, prefixos, sufixos e placeholders adjacentes; verificar a ausência do literal no estado.

### V02 — A20 não revalida a URL efetiva de operações HTTP legadas

**Gravidade:** alta. **Evidência:** reproduzido. **Bloqueante:** sim.

**Locais:** `src/SVault.Broker/BrokerEngine.cs:837`, em `RevalidateAuthorization`; `src/SVault.Core/Operations/OperationEngine.cs:118` e `:145`, em `ExecuteHttpAsync`.

A nova igualdade entre `Http.Url` e `Target` é aplicada somente na autorização de novas operações, em `BrokerEngine.cs:642`. O caminho de aprovação revalida os registros contra `Operation.Target`. O executor usa `Operation.Http.Url` sem conferir sua equivalência ao alvo aprovado.

A versão anterior aceitava diferenças de caixa entre essas URLs. Portanto, uma operação legada com `Target=/Admin` e `Http.Url=/admin` é um estado anteriormente válido. Após a atualização, a política considera esses caminhos diferentes, mas a aprovação ainda envia a requisição a `/admin`.

A reprodução usou uma operação com esse formato e um servidor TCP local. A execução terminou como `completed`; o servidor recebeu `GET /admin HTTP/1.1`. A mesma política retornou `false` ao comparar a autorização de `/Admin` com o destino efetivo `/admin`. A fixture foi criada pela API de armazenamento para representar um registro legado; não se utilizou a autorização nova, que corretamente rejeita essa diferença.

**Correção esperada:** revalidar a especificação HTTP efetiva contra o alvo fixado no pedido e contra as políticas dos registros, antes de abrir os segredos. Operações legadas incompatíveis devem falhar de forma restritiva e exigir nova autorização. Incluir regressão que carregue o estado legado e comprove ausência de chamada ao destino recusado.

### V03 — A16 rejeita valores válidos depois de interpolar placeholders

**Gravidade:** média. **Evidência:** reproduzido. **Bloqueante de segurança:** não; impede considerar A16 concluído.

**Local:** `src/SVault.Core/Operations/OperationEngine.cs:346`, em `ResolveTemplate`.

A verificação de sintaxe é aplicada ao texto já interpolado. Um segredo cadastrado como `valor{{sintetico}}` e usado pelo template válido `{{secret}}` produz `OperationFailure`. O domínio aceita esse valor, mas o resolvedor interpreta suas chaves como sintaxe inválida. Parâmetros com delimitadores também podem apresentar a mesma regressão.

Antes da mudança, o placeholder integral retornava o valor sem essa rejeição. A falha ocorre mesmo sem rede ou processo externo.

**Correção esperada:** validar a gramática no template original e tratar os valores substituídos como dados opacos. Não interpretar novamente delimitadores introduzidos por segredos ou parâmetros. Incluir testes de interpolação integral e composta com chaves nos valores.

### V04 — A24 pode interromper o rollback antes de restaurar a versão anterior

**Gravidade:** alta. **Evidência:** inspeção. **Bloqueante:** sim.

**Local:** `install/Install-SVault.ps1:265`, com etapas seguintes em `:268`, `:272`, `:274` e `:275`.

O bloco de recuperação restaura configuração, ambiente e permissões antes de restaurar a versão anterior. Essas etapas não possuem isolamento de falhas. Com `$ErrorActionPreference = 'Stop'`, uma exceção em qualquer uma delas abandona o bloco antes da restauração dos binários e da tentativa de reiniciar o serviço anterior.

**Cenário concreto por inspeção:** uma atualização para o serviço, move a instalação anterior ao backup e ativa a nova versão. Um bloqueio de escrita em `broker.json` causa falha em `Set-Content`, na linha 213. A recuperação tenta gravar novamente o arquivo bloqueado com `WriteAllBytes`, na linha 265. A segunda exceção impede chegar às linhas 274–276. O backup anterior permanece preservado, mas não é reativado, e o serviço pode continuar parado.

O mesmo problema pode ocorrer quando a própria restauração de uma lista de controle de acesso falha. Não se afirma que esse caminho apaga o backup anterior: o defeito confirmado é a interrupção prematura da recuperação. A condição `installActivated` evita a remoção indevida da instalação original quando a primeira movimentação falha.

**Correção esperada:** garantir tentativa de recuperação de cada recurso mesmo quando outra etapa falhar. A restauração da versão anterior e do serviço não pode depender do sucesso da recuperação de configuração ou permissões. Preservar os backups necessários, registrar todas as falhas e apresentar o estado final. Testar com operações de arquivo e comandos substituídos por implementações simuladas, sem executar o instalador real.

## 4 Conformidade A01–A24

A Tabela 1 distingue implementação observada, defeitos confirmados e insuficiência de cobertura. “Conforme por inspeção” descreve o caminho examinado; não equivale a certificação de segurança.

Tabela 1 — Parecer por requisito.

| Requisito | Parecer | Evidência e restrição |
|---|---|---|
| A01 | Conforme por inspeção | O armazenamento exige o TOTP atual para substituir/desativar o fator, trocar senha e reiniciar o cofre. Cliente e terminal encaminham o código. A suíte contém testes diretos dessas recusas. |
| A02 | Parcial, sem defeito de rotação confirmado nesta validação | A nova geração é inventariada antes da escrita; a anterior permanece ativa até o salvamento do candidato. O TOTP é recifrado no candidato. A limpeza ocorre após o commit e suas falhas não invalidam a nova senha. Há leitura legada e testes de leitura, escrita, commit e reabertura lógica. Faltam falhas em todas as etapas, limpeza pós-commit e interrupção real. |
| A03 | Conforme por inspeção | Inicialização e rotação validam a nova senha no domínio antes de alterar o estado. Senhas legadas continuam sendo verificadas pela política de abertura anterior. |
| A04 | Conforme por inspeção | Revogação marca pedidos pendentes e o claim confere a identidade da autorização atual. Nova autorização recebe outra identidade. O teste cobre revogação e reutilização do identificador. |
| A05 | Conforme para revisões e políticas dos registros | Revisões e identidades dos registros principais e auxiliares são capturadas e revalidadas antes da abertura. O destino HTTP efetivo ainda apresenta V02, registrado em A20. |
| A06 | Conforme por inspeção | O gate serializa administração, revalidação, abertura e transição para `running`. Uma segunda aprovação recebe conflito. A suíte verifica uma única chamada HTTP. |
| A07 | Conforme por inspeção | O resumo inclui parâmetros, método, destino e auxiliares; a interface apresenta a revisão antes da senha. A aprovação referencia o snapshot do pedido. Não houve interação visual independente. |
| A08 | Conforme nos caminhos examinados | Segredos curtos entram nas variantes. A substituição em uma passagem preserva o marcador e cobre segredo iniciado pelo marcador. Há regressões específicas. |
| A09 | Conforme nos formatos examinados | A redação percorre valores e nomes de propriedades JSON após interpretação, incluindo números e booleanos. Permanecem os limites gerais de transformações não reconhecidas e credenciais novas devolvidas pelo destino. |
| A10 | Não conforme | V01 reproduz persistência de segredo curto. O recorte dos placeholders também exige testes explícitos de colisão, sem pressupor cobertura integral. |
| A11 | Resolvido por restrição do contrato | `process.stdin` não integra `SupportedActions`, não aparece na seleção da interface e falha também no despacho do executor. Operações antigas não alcançam o método privado de execução. A mudança funcional está documentada. |
| A12 | Risco removido do contrato executável | O caminho público não inicia processos. Não se considera corrigida a implementação antiga de timeout: ela ficou inalcançável. |
| A13 | Conforme por inspeção, com lacuna de teste | O tratamento geral após o claim finaliza como `failed` e usa erro genérico. `FinishedAt` é preenchido ao finalizar. A suíte cobre falha de seleção JSON, mas não todas as classes de exceção alegadas. |
| A14 | Conforme por inspeção | Rejeição exige estado pendente sob o mesmo gate. Não sobrescreve pedidos concluídos ou em execução. A suíte testa rejeição após conclusão. |
| A15 | Parcial por cobertura | Listagem e novas solicitações expiram a fila; há limite de 500 pendências e poda dos estados terminais em torno de 1.000 registros. Faltam testes de relógio, retenção e concorrência. Não há paginação. |
| A16 | Parcial com regressão confirmada | A interpolação composta funciona para os casos cobertos, mas V03 rejeita delimitadores presentes nos dados substituídos. |
| A17 | Risco removido do contrato executável | Argumentos e ambiente de processos não são executados. Persistem estruturas e métodos privados antigos; não há cobertura nova que os torne suportados. |
| A18 | Parcial | Pedidos rejeitam tipos inválidos, parâmetros ausentes, excesso de tamanho e caracteres de controle. `ValidateTemplates` é chamado no pedido, mas não na autorização: um template inválido ainda pode ser persistido e só falhar depois. |
| A19 | Conforme por inspeção | Com `ResultFields`, JSON inválido causa erro genérico terminal e o corpo não é devolvido. A suíte contém esse cenário. |
| A20 | Parcial com defeito confirmado | Comparações novas distinguem caixa do caminho e definem regras para consulta, userinfo e fragmento. V02 permite que registros HTTP legados executem outra URL efetiva. |
| A21 | Conforme por inspeção | SmokeTest e teste MCP usam memória e espaços temporários próprios. A demonstração exige autorização explícita para acessar o broker instalado. Não foi necessário acessar Credential Manager para validar os novos defeitos. |
| A22 | Parcial por cobertura | Controles de corpo e cabeçalhos permitem múltiplas linhas; o terminal agrega as opções repetidas selecionadas. Faltam testes de interação e verificação ponta a ponta da estrutura persistida. |
| A23 | Conforme por inspeção, com lacuna de teste | O terminal exige `completed` e `Result.Ok == true` para retorno zero; a interface aplica a mesma condição à cor de sucesso. Faltam verificações de códigos de saída e apresentação visual para HTTP 401/500. |
| A24 | Parcial com defeito confirmado | Preparação em staging, validações de arquivos, dependências, códigos nativos e saúde representam avanço. V04 compromete a recuperação diante de falhas secundárias. Não houve execução elevada nem testes simulados das etapas de recuperação. |

## 5 Qualidade técnica e riscos residuais

O armazenamento substituível tornou viáveis os testes sem dependência do perfil do Windows. Os estados candidatos evitam alterar a representação ativa antes da persistência. Na aprovação, o snapshot e o gate reduzem as corridas anteriormente descritas. Esses aspectos sustentam a avaliação positiva das correções observadas, com as ressalvas registradas.

A rotação foi examinada também após o commit: a nova senha é ativada antes de excluir os alvos anteriores. As falhas de exclusão são absorvidas e não revertem parcialmente a chave. Alvos conhecidos continuam inventariados quando a limpeza não termina. A segurança diante de perda de energia e a durabilidade efetiva das operações no sistema de arquivos não foram comprovadas.

A desativação de processos é uma mudança relevante de produto, explicitada no README. O contrato de execução está bloqueado, mas permaneceram métodos privados de execução, encerramento de processos e partes da interface sem caminho de acesso. Recomenda-se remover esse código morto para reduzir ambiguidade e o risco de reativação sem as garantias necessárias. Trata-se de manutenção; não foi identificado desvio executável para processos nesta validação.

No instalador, a atualização bem-sucedida ainda recria `broker.json` com os valores padrão e substitui `Environment` pela variável `SVAULT_HOME`, nas linhas 207–213 e 231. O rollback tenta restaurar os valores anteriores. A política de migração deve explicitar se configurações personalizadas e outras variáveis precisam sobreviver também ao sucesso da atualização; o documento de implementação não resolve essa decisão.

Não foram confirmados novos vazamentos por mensagens do executor nos caminhos examinados. Isso não amplia o alcance da redação para codificações arbitrárias ou tokens recém-emitidos, que continuam sendo decisões e limitações de domínio do relatório original.

## 6 Lacunas de teste e limites

As lacunas abaixo não constituem, isoladamente, defeitos funcionais confirmados:

- Rotação: falhas sistemáticas em cada etapa, encerramento abrupto, falha de limpeza após commit, recuperação dos alvos órfãos e preservação de dados antigos após cada cenário.
- Fila: avanço controlado do relógio, retenção, volume e concorrência da listagem com aprovação e revogação.
- Resultados: matriz de JSON, caracteres especiais, valores curtos, colisões de nomes redigidos e respostas com tokens novos, conforme a política escolhida.
- Interfaces: cadastro com múltiplos campos, opções repetidas, códigos de saída e apresentação visual de falhas HTTP.
- Instalação: erros simulados de cópia, ativação, restauração de configuração, permissões, ambiente e serviço; falha de restauração do próprio backup; execução do launcher `.cmd` e verificação de saúde após recuperação.

O teste MCP chamado pelo instalador usa um broker isolado. Ele verifica os binários e o ponto de entrada JavaScript instalados, mas não comprova o launcher `.cmd` nem a ligação do MCP ao serviço instalado. A consulta `health` do terminal cobre separadamente o broker ativo.

Não houve execução real elevada, comandos de serviço ou alteração de permissões. Essa restrição não impede registrar V04 por inspeção do fluxo de exceções. Também não houve commit, publicação ou alteração de código de produção durante a validação. Foram criados somente este parecer e os artefatos auxiliares de reprodução.

## 7 Encaminhamento

Devem ser corrigidos V01, V02 e V04 antes de aceitar as garantias pretendidas. V03 deve ser corrigido para restabelecer o funcionamento dos valores aceitos pelo domínio. Após as alterações, são necessários testes dirigidos desses quatro cenários e revisão do código modificado. As demais lacunas devem permanecer explícitas, sem serem apresentadas como cobertura concluída.

## 8 Referências internas

- [Revisão original A01–A24](REVISAO-LOGICA-NEGOCIO-2026-10-20.md).
- [Registro da implementação](IMPLEMENTACAO-REVISAO-2026-10-20.md).
- [Acompanhamento permanente das validações pendentes](PENDENCIAS-VALIDACAO.md).
- [Broker](../src/SVault.Broker/BrokerEngine.cs).
- [Armazenamento](../src/SVault.Core/Storage/VaultStore.cs).
- [Executor](../src/SVault.Core/Operations/OperationEngine.cs).
- [Instalador](../install/Install-SVault.ps1).

Aplicaram-se linguagem impessoal e organização de relatório técnico com seções numeradas. Não há marcadores de preenchimento. Este Markdown não declara diagramação acadêmica completa segundo a ABNT.

## 9 Adendo — Reavaliação da primeira rodada de correções

Data: 20 de outubro de 2026. Este adendo preserva os pareceres históricos das seções anteriores. Os veredictos abaixo substituem somente a situação de V01–V04 e da lacuna A18 após a primeira rodada.

### 9.1 Escopo e método

Foram examinados o diferencial `artifacts/review-validation/fix-round1.diff`, o código atual dos trechos modificados, os testes acrescentados, o adendo de implementação e o acompanhamento das tarefas. A reavaliação ficou restrita aos cinco pontos solicitados e às possíveis regressões introduzidas pela rodada.

O implementador informou SmokeTest com 40 aprovações, MCP com 9 aprovações e seis cenários simulados de recuperação aprovados. Também informou cinco compilações sem avisos ou erros e verificações sintáticas dos scripts. A inspeção confirmou os cenários e as condições verificadas nos testes. Esses resultados são execuções informadas pelo implementador; não foram apresentados como novas execuções independentes.

Não se repetiram as suítes ou as reproduções anteriores, pois a inspeção não revelou dúvida concreta que exigisse nova execução. O programa auxiliar da primeira validação permanece como registro histórico: suas expectativas e a saída em `directed-results.txt` correspondem ao código anterior às correções.

### 9.2 Veredictos dos pontos reavaliados

A Tabela 2 registra os veredictos da rodada e suas evidências no código atual.

Tabela 2 — Reavaliação de V01–V04 e A18.

| Ponto | Veredicto | Evidência |
|---|---|---|
| V01 / A10 | **CORRIGIDO** | `BrokerEngine.cs:770` não descarta segmentos com espaços; `:786` verifica todo segredo não vazio, sem o mínimo de quatro caracteres. A comparação continua restrita aos segmentos literais, preservando os placeholders como sintaxe. O novo teste cobre um, dois e três caracteres, espaço, prefixo/sufixo e literal adjacente a placeholders. Verifica recusa e ausência de persistência. |
| V02 / A20 | **CORRIGIDO** | `BrokerEngine.cs:829` compara a URL HTTP efetiva com o alvo do snapshot durante `RevalidateAuthorization`, antes da verificação da senha e da abertura dos segredos. O executor repete a defesa em `OperationEngine.cs:118`. A regressão legada verifica `target_not_allowed`, zero leituras no armazenamento de credenciais e nenhuma chamada ao servidor. |
| V03 / A16 | **CORRIGIDO** | `OperationEngine.cs:329` valida o template original antes de substituir os placeholders. A verificação posterior sobre o resultado interpolado foi removida. O teste conserva delimitadores vindos de segredo e parâmetro, cobre interpolação composta e continua recusando sintaxe inválida no template original. |
| V04 / A24 | **CORRIGIDO** | `Invoke-SVaultRollback`, em `install/SVaultRollback.ps1:26`, captura falhas de cada etapa e prossegue. As tentativas de remover a versão nova, restaurar o backup e reiniciar o serviço possuem tratamentos próprios. O instalador delega a recuperação a essa função em `Install-SVault.ps1:262`. Falhas de configuração, ambiente ou permissões não impedem alcançar a recuperação dos binários. |
| Lacuna A18 | **CORRIGIDO** | O broker chama `ValidateTemplates` antes da detecção de literais e da persistência, em `BrokerEngine.cs:647`. `VaultStore.AuthorizeOperation` também valida no limite do armazenamento, em `VaultStore.cs:665`. O novo teste verifica referência a parâmetro não declarado, retorno `bad_request` e ausência da autorização na listagem. |

No ponto V04, a nova variável `oldMovedToBackup` distingue a preservação da instalação original da existência de um backup efetivamente criado. A remoção só ocorre quando a versão nova foi ativada. O backup não é movido sobre uma raiz ainda ocupada, e o serviço anterior só é iniciado quando sua versão foi preservada ou restaurada.

Os seis cenários simulados cobrem falhas separadas em configuração, ambiente e permissões, falha anterior à movimentação, falha de remoção e falha de restauração do backup. As duas últimas preservam o backup e evitam iniciar o serviço sobre binários incompatíveis. O controle de fluxo corrige especificamente a interrupção prematura identificada em V04; não garante que recursos bloqueados pelo sistema possam ser restaurados.

### 9.3 Regressões e limites da rodada

Não foram identificados novos defeitos confirmados no diferencial examinado. A validação antecipada da gramática é consistente entre autorização, solicitação e interpolação. Os dados substituídos permanecem opacos, e a verificação da URL legada ocorre antes de qualquer leitura de credenciais.

A recuperação foi examinada também na ligação entre o instalador e os callbacks da nova função. A restauração das permissões tenta todos os snapshots, acumula falhas e permite continuar a recuperação dos demais recursos. Os erros são apresentados por etapa; a falha original da instalação continua sendo propagada.

Permanecem as limitações históricas fora do escopo desta rodada. Em particular, A24 continua parcial quanto à execução elevada real, permissões efetivas, serviço instalado, launcher `.cmd` e saúde após uma recuperação real. O teste simulado não executa as operações nativas dos callbacks. A falha entre mover a versão antiga e ativar a nova é tratada no código, mas não constitui um cenário dedicado entre os seis testes apresentados.

Também permanecem os limites já registrados para interrupção abrupta da rotação, retenção, interfaces e códigos de saída. Esses itens não foram reabertos nem promovidos a defeitos novos. A política de preservação de configurações personalizadas em atualizações bem-sucedidas continua sendo a observação da seção 5.

### 9.4 Pareceres após a rodada

**Parecer final de conformidade da rodada: aprovado.** V01–V04 e a lacuna A18 estão corrigidos nos caminhos examinados. Não há bloqueante residual confirmado nesses cinco pontos. A aprovação não transforma os itens parciais da matriz A01–A24 em cobertura integral.

**Parecer final de qualidade técnica da rodada: aprovado com limitações de validação.** As mudanças são coerentes com os defeitos registrados e incluem regressões pertinentes. Não foi encontrada regressão técnica nova nesta reavaliação. As restrições sobre instalação real e durabilidade continuam explícitas; não se exige executar operações elevadas para reconhecer as correções locais.

Somente este adendo foi acrescentado durante a reavaliação. Não houve alteração de produção, execução de instalador, acesso a credenciais ou serviços reais, commit ou publicação.
