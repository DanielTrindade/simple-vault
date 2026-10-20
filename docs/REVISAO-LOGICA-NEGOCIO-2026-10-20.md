# Revisão técnica do SVault — lógica de negócio e integridade dos fluxos

Data: 20 de outubro de 2026. Base analisada: `ab1106b2a9ec4594acf8c8af49bb27953d51fd99`.

## 1 Objetivo e resultado

Este levantamento avalia o projeto inteiro, com foco nas garantias de autorização, aprovação humana, proteção dos resultados e conservação das credenciais. Foram identificados **24 achados: 2 críticos, 11 altos e 11 médios**.

Os problemas mais urgentes envolvem troca de senha, desativação do segundo fator, revogação ineficaz para solicitações existentes e sanitização incompleta. A compilação dos componentes principais passou, mas esse resultado não comprova a correção das regras de negócio.

O documento registra problemas e propostas de correção. O código de produção não foi alterado.

## 2 Escopo e método

Foram inspecionados os componentes `Core`, `Broker`, `Client`, `Cli`, `Manager`, o servidor Model Context Protocol (MCP), os instaladores e os testes. O `README.md` e `docs/LIMITES.md` forneceram os requisitos e o modelo de ameaça.

A revisão considerou o estado integral do projeto, sem comparação entre versões. Foram rastreados cadastro, atualização, exclusão, autorização, solicitação, aprovação, rejeição, revogação, expiração, troca de senha e segundo fator.

As evidências receberam duas classificações:

- **Reproduzido:** comportamento observado em verificações locais, com dados sintéticos e sem acessar o Credential Manager.
- **Inspeção:** caminho confirmado no código; o cenário completo ou a condição de falha não foi executado nesta revisão.

Gravidade crítica indica perda potencial de acesso ao cofre. Gravidade alta indica quebra de autorização, exposição de credenciais ou comprometimento relevante do serviço. Gravidade média indica inconsistência funcional, operacional ou de contrato.

Não foram acessados os arquivos do cofre instalado, nem realizadas operações autenticadas reais. Não foram executados instaladores, desinstaladores ou a demonstração contra o serviço instalado.

Os testes de integração existentes não foram executados. Embora usem diretórios e canais próprios, os testes do broker compartilham o espaço de nomes do Credential Manager do usuário executor, conforme o achado A21.

## 3 Achados

### A01 — Segundo fator pode ser desativado ou substituído apenas com a senha

**Gravidade:** alta. **Evidência:** inspeção.

**Local:** `src/SVault.Broker/BrokerEngine.cs:690–710`; `src/SVault.Core/Storage/VaultStore.cs:493–521`.

O código TOTP, senha temporária baseada em tempo, é conferido em `ApproveAsync`. Entretanto, `disable_totp` e `set_totp` exigem somente a senha do cofre. O mesmo cliente que solicita operações pode enviar esses comandos pelo canal do broker.

**Cenário:** com a senha comprometida e TOTP ativo, o atacante desativa o segundo fator e aprova uma operação sem o celular. A substituição do segredo TOTP permite resultado equivalente.

**Impacto:** contradiz a proteção atribuída ao segundo fator em `docs/LIMITES.md`, seção 3.2. A ausência dessas ferramentas no MCP não impede chamadas diretas pelo terminal.

**Recomendação:** exigir o fator atual para desativação, substituição e ações administrativas sensíveis. Definir recuperação separada e auditável.

**Validação proposta:** com TOTP ativo, tentativas de alteração sem código válido devem falhar; a configuração anterior deve permanecer intacta.

### A02 — Troca de senha não é transacional e pode inutilizar credenciais

**Gravidade:** crítica. **Evidência:** inspeção; falha intermediária não injetada.

**Local:** `src/SVault.Core/Storage/VaultStore.cs:143–201`.

`ChangePassphrase` sobrescreve cada credencial com a nova chave antes de persistir o novo sal mestre e o verificador. Não existe diário de recuperação ou reversão das escritas concluídas.

**Cenário:** a primeira credencial é recifrada e a segunda leitura ou escrita falha. Uma interrupção do processo durante o laço produz condição semelhante.

**Impacto:** parte das credenciais depende da nova chave, enquanto o estado persistido ainda referencia a antiga. Como o novo sal não foi persistido, a nova senha, sozinha, não permite recuperar os valores afetados. Uma falha no salvamento final também pode comprometer o conjunto inteiro após reinício.

**Recomendação:** implementar rotação por gerações, preservando a anterior até confirmar a nova. Persistir os elementos necessários à recuperação antes de substituir dados e concluir com confirmação atômica.

**Validação proposta:** injetar falha em cada leitura, escrita e salvamento, além de reiniciar o processo em cada etapa. Deve existir recuperação determinística.

### A03 — Nova senha vazia é aceita e bloqueia a abertura posterior

**Gravidade:** crítica. **Evidência:** reproduzido em cofre temporário sem registros.

**Local:** `src/SVault.Core/Storage/VaultStore.cs:143–154,553–560`; `src/SVault.Cli/Program.cs:319–333`.

A inicialização pela CLI exige oito caracteres. A troca de senha não aplica essa regra e deriva uma nova chave até com texto vazio. A abertura posterior rejeita senha vazia antes de verificar a chave.

**Cenário:** confirmar uma nova senha vazia em `change-passphrase`. O estado passa a depender dessa senha, mas o broker não aceita utilizá-la nos comandos seguintes.

**Impacto:** perda de acesso pelo fluxo suportado. O problema também existe com chamadas diretas de inicialização que não passam pela validação da CLI.

**Recomendação:** validar a política de senha no domínio, antes de qualquer alteração. Aplicar a mesma política à inicialização e à rotação.

**Validação proposta:** valores vazios e senhas fora da política devem ser recusados, preservando a senha e o estado anteriores.

### A04 — Revogar operação não invalida solicitações pendentes

**Gravidade:** alta. **Evidência:** inspeção.

**Local:** `src/SVault.Broker/BrokerEngine.cs:195–226,272–324,677–687`; `src/SVault.Core/Storage/VaultStore.cs:478–489`.

A solicitação mantém uma referência ao objeto `OperationRecord`. A revogação remove apenas o registro da lista persistida. A aprovação usa o objeto guardado e não verifica se a operação continua autorizada.

**Cenário:** solicitar uma operação, revogá-la e aprovar a solicitação anterior dentro do prazo.

**Impacto:** uma operação revogada permanece executável mediante aprovação de um pedido antigo. A revogação não produz o efeito esperado sobre a fila.

**Recomendação:** invalidar pedidos associados à operação e conferir identidade e versão da autorização ao aprovar.

**Validação proposta:** pedidos anteriores à revogação devem terminar como cancelados ou revogados e nunca alcançar o executor.

### A05 — Alvo do registro principal não é revalidado na aprovação

**Gravidade:** alta. **Evidência:** inspeção.

**Local:** `src/SVault.Broker/BrokerEngine.cs:205–212,324–345`; `src/SVault.Core/Storage/VaultStore.cs:276–283`.

A lista de alvos do registro principal é conferida na solicitação. Na aprovação, somente os registros auxiliares recebem essa conferência novamente.

**Cenário:** criar um pedido, remover seu destino dos alvos autorizados do registro principal e aprovar o pedido existente.

**Impacto:** envio ao destino cuja permissão foi retirada. A atualização da política não protege solicitações em espera.

**Recomendação:** revalidar todos os registros e suas revisões imediatamente antes de executar. Invalidar solicitações afetadas por mudanças relevantes.

**Validação proposta:** remover o alvo após a solicitação deve impedir execução e abertura do segredo para aquele destino.

### A06 — Aprovação não garante transição atômica para execução única

**Gravidade:** alta. **Evidência:** inspeção; corrida não reproduzida.

**Local:** `src/SVault.Broker/BrokerEngine.cs:22–25,281–317`; `src/SVault.Broker/PipeServer.cs:18,34–42`.

O broker atende quatro conexões. A leitura do estado pendente e sua mudança para aprovado não são protegidas por exclusão mútua. O dicionário concorrente não protege os campos do objeto armazenado. `_executionGate` foi declarado, mas não é usado.

**Cenário:** duas aprovações concorrentes leem `pending_approval` antes da mudança de estado. A verificação da senha serializa acesso ao armazenamento, mas não torna a transição do pedido atômica.

**Impacto:** a mesma solicitação pode executar duas vezes. Operações financeiras ou outras ações irreversíveis no destino ampliam o efeito.

**Recomendação:** realizar transição atômica por solicitação e estabelecer estados terminais imutáveis. Usar chave de idempotência no destino quando disponível.

**Validação proposta:** aprovações simultâneas devem produzir exatamente uma chamada ao executor; as demais devem retornar conflito.

### A07 — Aprovação humana não apresenta os parâmetros efetivos

**Gravidade:** alta. **Evidência:** inspeção.

**Local:** `src/SVault.Broker/BrokerEngine.cs:122–135,773–780`; `src/SVault.Core/Protocol/Protocol.cs`, `OperationSummary`; `src/SVault.Manager/MainForm.cs:482–502`.

O pedido armazena os parâmetros, mas a listagem de aprovações e o resumo não os devolvem. A interface solicita a senha sem mostrar os valores enviados pelo agente, o método HTTP ou os registros auxiliares utilizados.

**Cenário:** duas solicitações usam a mesma operação e o mesmo destino, mas parâmetros diferentes de usuário, recurso ou comando de negócio.

**Impacto:** o proprietário não consegue distinguir os efeitos antes de aprovar. A confirmação autoriza uma execução sem informações suficientes para avaliá-la.

**Recomendação:** apresentar uma visão sanitizada da execução: parâmetros, método, destino, registros envolvidos e descrição do efeito. Vincular a aprovação a uma versão imutável desse conteúdo.

**Validação proposta:** pedidos com parâmetros diferentes devem apresentar diferenças legíveis na tela de confirmação, sem revelar segredos.

### A08 — Segredos com menos de quatro caracteres não são mascarados

**Gravidade:** alta. **Evidência:** reproduzido.

**Local:** `src/SVault.Core/Redaction/SecretRedactor.cs:56–59`; `src/SVault.Core/Storage/VaultStore.cs:205–224`.

O cadastro não exige tamanho mínimo para o valor. O sanitizador exclui variantes com menos de quatro caracteres.

**Cenário:** cadastrar um segredo `abc` e executar `noop.echo` ou uma operação cujo destino devolva esse valor.

**Impacto:** o valor integral chega ao agente sem máscara. A filtragem elimina justamente o segredo que o cadastro aceitou proteger.

**Recomendação:** mascarar todos os valores aceitos ou estabelecer uma restrição explícita no cadastro. Considerar o efeito de segredos curtos sobre a legibilidade dos resultados.

**Validação proposta:** testar valores de um a quatro caracteres em todas as saídas suportadas.

### A09 — Escape JSON comum permite retorno recuperável do segredo

**Gravidade:** alta. **Evidência:** reproduzido.

**Local:** `src/SVault.Core/Redaction/SecretRedactor.cs:29–54,85–94`; `src/SVault.Core/Operations/OperationEngine.cs:206–230`.

A redação usa substituição textual. Não cobre escapes JSON, como `\u0026`, nem todas as representações válidas de caracteres especiais.

**Cenário reproduzido:** o segredo sintético `fake&value123` retorna como `{"echo":"fake\u0026value123"}`. O texto não é mascarado e uma leitura JSON recupera o valor original.

**Impacto:** um formato normal de resposta pode expor o segredo. `docs/LIMITES.md`, seção 5, reconhece variações não cobertas; este caso exige atenção por decorrer de serialização convencional.

**Recomendação:** sanitizar valores JSON após interpretação e antes da serialização final. Aplicar política explícita para conteúdo não estruturado e limitar os dados retornados.

**Validação proposta:** incluir aspas, barras, acentos, caracteres escapados e segredos curtos em respostas JSON e formulários.

### A10 — Validação de segredo literal só detecta igualdade integral

**Gravidade:** alta. **Evidência:** inspeção.

**Local:** `src/SVault.Broker/BrokerEngine.cs:736–760`; `src/SVault.Core/Storage/VaultStore.cs:84–87`.

`ValidateNoSecretLiteral` compara o template inteiro com o segredo. Um valor prefixado, como `Bearer VALOR`, não coincide. Templates curtos e alguns contendo placeholders também são excluídos da verificação.

**Cenário:** o proprietário insere um segredo cadastrado em um cabeçalho com prefixo ou em um argumento fixo.

**Impacto:** o literal é persistido no arquivo de estado. Em argumentos de processo, também pode aparecer na linha de comando. Isso contraria a recusa de literais prometida pelo README.

**Recomendação:** verificar presença dos valores nos campos persistidos, sem descartar templates compostos. Para processos, proibir credenciais em argumentos e ambiente.

**Validação proposta:** testar segredo integral, prefixado, sufixado e misturado a placeholders, verificando ausência no estado e na linha de comando.

### A11 — Processo autorizado por caminho pode ser substituído antes da execução

**Gravidade:** alta. **Evidência:** inspeção; depende de caminho ou dependência gravável pelo agente.

**Local:** `src/SVault.Core/Storage/TargetPolicy.cs`, `PathCovers`; `src/SVault.Core/Operations/OperationEngine.cs:239–272`.

A autorização fixa o caminho, mas não verifica integridade do executável, permissões de escrita ou arquivos carregados por ele. O processo herda a identidade do broker, que roda como `LocalSystem` na instalação documentada.

**Cenário:** autorizar um programa em diretório gravável pelo usuário. Após a autorização, o agente substitui o programa ou uma dependência carregada e aguarda a aprovação.

**Impacto:** código alterado recebe o segredo e pode executar com privilégios do serviço. A aprovação continua necessária, mas o destino executável já não corresponde ao artefato avaliado.

**Recomendação:** restringir executáveis e dependências a locais protegidos, verificar integridade e reduzir a identidade de execução. Não tratar somente o nome do arquivo como identidade confiável.

**Validação proposta:** alterações do executável ou de dependências protegidas devem impedir execução ou exigir nova autorização.

### A12 — Limite de execução não cobre toda a comunicação com processos

**Gravidade:** alta. **Evidência:** inspeção; bloqueio e esgotamento não provocados.

**Local:** `src/SVault.Core/Operations/OperationEngine.cs:274–294`; `src/SVault.Broker/BrokerEngine.cs:359`; `src/SVault.Client/BrokerClient.cs`, `ExchangeAsync`.

O temporizador começa depois da escrita em `stdin`. As leituras completas de saída usam outro token, que no broker é `CancellationToken.None`. Descendentes podem manter os canais abertos após o processo principal terminar.

Além disso, as saídas são acumuladas integralmente antes da redução para 8.192 caracteres. O cliente espera 30 segundos, mas o processo pode ser autorizado por até 300 segundos.

**Impacto:** operações podem permanecer bloqueadas, consumir memória ou aparentar falha no cliente enquanto continuam executando. Quatro execuções bloqueadas podem ocupar todos os atendentes do canal.

**Recomendação:** aplicar um prazo único ao ciclo inteiro, limitar leitura de saída e encerrar a árvore de processos ao cancelar. Separar aceitação da aprovação e consulta do resultado.

**Validação proposta:** processo que não lê entrada, descendente que mantém saída aberta e saída volumosa devem terminar dentro dos limites definidos.

### A13 — Exceções inesperadas deixam solicitações em estado intermediário

**Gravidade:** média. **Evidência:** inspeção.

**Local:** `src/SVault.Broker/BrokerEngine.cs:317–318,391–451,64–73`.

Após marcar o pedido como aprovado, apenas grupos específicos de exceções atualizam o pedido para falha. Outras exceções chegam ao tratamento externo, que responde erro interno sem finalizar o pedido.

**Cenário:** método HTTP inválido ou falha nativa ao iniciar um processo. O estado pode permanecer `approved`, inclusive com `FinishedAt` preenchido antes da execução.

**Impacto:** o agente não recebe um estado terminal coerente e a solicitação não pode ser aprovada novamente pelo fluxo normal.

**Recomendação:** centralizar a finalização com erro sanitizado e distinguir `approved`, `running` e estados terminais. Preencher `FinishedAt` apenas ao terminar.

**Validação proposta:** toda exceção do executor deve produzir um pedido terminal consistente.

### A14 — Rejeição pode sobrescrever estados concluídos ou em execução

**Gravidade:** média. **Evidência:** inspeção.

**Local:** `src/SVault.Broker/BrokerEngine.cs:454–468`.

`Reject` não confere o estado atual. Uma solicitação concluída pode virar rejeitada, mantendo um resultado anterior. Uma rejeição concorrente também não cancela a execução já iniciada.

**Impacto:** a consulta pode afirmar rejeição para uma ação que ocorreu. Em corrida, a conclusão pode sobrescrever a rejeição posteriormente.

**Recomendação:** aceitar rejeição somente de pedidos pendentes. Definir cancelamento em execução como comando separado, caso suportado.

**Validação proposta:** rejeitar pedido concluído ou em execução deve retornar conflito e preservar seu estado.

### A15 — Expiração depende de consulta individual e histórico cresce sem limite

**Gravidade:** média. **Evidência:** inspeção.

**Local:** `src/SVault.Broker/BrokerEngine.cs:33,122–135,226,248–258`.

A listagem de aprovações filtra apenas pelo texto do estado. O prazo só é aplicado ao consultar um pedido específico ou tentar aprová-lo. Não existe remoção dos pedidos finalizados ou expirados.

**Impacto:** a interface continua exibindo pedidos vencidos. Solicitações repetidas aumentam indefinidamente memória, resultados retidos e tamanho da resposta. A listagem pode superar o limite de leitura do cliente.

**Recomendação:** expirar antes de listar, limitar a fila e estabelecer retenção e paginação. Aplicar limites por solicitante quando houver múltiplos clientes.

**Validação proposta:** avançar o relógio deve remover pedidos vencidos da fila; grande volume deve respeitar limites previsíveis.

### A16 — Templates compostos não são resolvidos

**Gravidade:** média. **Evidência:** reproduzido.

**Local:** `src/SVault.Core/Operations/OperationEngine.cs:322–346`.

O resolvedor aceita placeholders como valor completo. `Bearer {{secret}}` permanece literal. A coleta de referências, entretanto, procura placeholders dentro de textos compostos.

**Impacto:** autenticação por cabeçalho Bearer e outros valores compostos falham, sem rejeição antecipada da autorização. A coleta e a execução interpretam a mesma sintaxe de formas diferentes.

**Recomendação:** definir uma gramática única, com interpolação segura, ou recusar explicitamente valores compostos ao autorizar.

**Validação proposta:** testar campos com prefixos, sufixos, múltiplos placeholders e referências auxiliares, inclusive sintaxe inválida.

### A17 — Templates e parâmetros de processos não têm efeito na execução

**Gravidade:** média. **Evidência:** inspeção.

**Local:** `src/SVault.Core/Operations/OperationEngine.cs:54–57,255–268,277`.

A coleta identifica segredos em argumentos e ambiente, mas o executor copia esses campos literalmente. Os parâmetros também não são aplicados. A entrada padrão recebe somente o segredo principal.

**Impacto:** operações podem ser cadastradas com referências verificadas e parâmetros aceitos que nunca são usados. Segredos auxiliares podem ser abertos sem necessidade funcional.

**Recomendação:** definir quais campos admitem parâmetros e rejeitar placeholders de segredo em argumentos e ambiente. Se necessário, criar um formato estruturado de entrada padrão.

**Validação proposta:** placeholders não suportados devem falhar no cadastro; cada parâmetro permitido deve ter efeito observável e seguro.

### A18 — Parâmetros ausentes são aceitos e convertidos em texto vazio

**Gravidade:** média. **Evidência:** reproduzido para o resolvedor; inspeção da validação.

**Local:** `src/SVault.Core/Operations/OperationEngine.cs:340–365`; `src/SVault.Broker/BrokerEngine.cs:899–913`.

A validação verifica somente os parâmetros recebidos. Não confere parâmetros necessários ao template. Valores que não são strings também são descartados pelo leitor do broker.

**Impacto:** requisições com campos obrigatórios ausentes alcançam aprovação e execução. Dependendo da API, um campo vazio pode selecionar um comportamento padrão indesejado.

**Recomendação:** distinguir parâmetros obrigatórios e opcionais e recusar tipos inválidos. Validar os vínculos entre declarações e templates na autorização.

**Validação proposta:** ausência e tipo inválido devem produzir erro antes da criação de um pedido pendente.

### A19 — Seleção de campos retorna corpo inteiro quando o JSON é inválido

**Gravidade:** média. **Evidência:** reproduzido.

**Local:** `src/SVault.Core/Operations/OperationEngine.cs:206–230`.

Quando `ResultFields` está definido e a interpretação JSON falha, o código retorna o corpo completo após redação.

**Impacto:** uma configuração destinada a restringir o retorno deixa de funcionar em páginas HTML, respostas de erro ou JSON incompleto. Tokens novos e informações não cadastradas como segredo podem chegar ao agente.

**Recomendação:** falhar de forma restritiva: devolver erro sanitizado ou resultado vazio quando a seleção não puder ser aplicada.

**Validação proposta:** resposta inválida nunca deve liberar conteúdo fora dos campos escolhidos.

### A20 — Política de URL ignora diferenças entre maiúsculas e minúsculas no caminho

**Gravidade:** média. **Evidência:** reproduzido.

**Local:** `src/SVault.Core/Storage/TargetPolicy.cs`, `UrlCovers`; `src/SVault.Broker/BrokerEngine.cs:614–616`.

O caminho é comparado com `OrdinalIgnoreCase`. A autorização de `/Admin` também cobre `/admin`, embora o servidor possa tratá-los como recursos distintos. A igualdade entre `Http.Url` e `Target` usa a mesma abordagem para a URL inteira.

**Impacto:** o conjunto de destinos permitidos pode exceder o que o proprietário cadastrou.

**Recomendação:** normalizar esquema e host separadamente. Preservar a semântica do caminho e definir explicitamente o tratamento da consulta e das codificações.

**Validação proposta:** caminhos com capitalização diferente devem ser recusados, salvo regra explícita do destino.

### A21 — Testes de integração não isolam as credenciais persistidas

**Gravidade:** alta. **Evidência:** inspeção; suíte não executada.

**Local:** `tests/SVault.SmokeTest/Program.cs:33–40,127–145`; `src/SVault.Core/Storage/VaultStore.cs:21,221–224`; `src/SVault.Core/Storage/CredentialManagerApi.cs:188`.

O diretório temporário e o canal exclusivo não alteram o prefixo `SVault:entry`. Os testes usam identificadores fixos, como `CPF_PESSOAL`, no Credential Manager do usuário que executa o broker de teste.

**Cenário:** existir credencial com o mesmo identificador nesse perfil, ou executar duas suítes simultaneamente. O estado temporário desconhece a credencial anterior e permite sua sobrescrita.

**Impacto:** colisão, perda de dados do mesmo perfil e resultados de teste não determinísticos. Isso não implica acesso automático ao perfil `LocalSystem` por testes executados como usuário comum.

**Recomendação:** permitir armazenamento substituível em testes ou prefixo aleatório por instância. Exigir configuração explícita para demonstrações que usam o canal instalado.

**Validação proposta:** executar suítes paralelas com prefixos distintos e comprovar preservação de uma credencial sentinela no perfil de teste dedicado.

### A22 — Campo HTTP da interface não permite múltiplos campos pelo formato implementado

**Gravidade:** média. **Evidência:** inspeção.

**Local:** `src/SVault.Manager/Dialogs.cs:180–182,328–331,406–422`; `src/SVault.Cli/Program.cs`, `ParseOptions` e `ParseMap`.

Na interface, corpo e cabeçalhos são caixas de texto de linha única. `ParseMap` separa os pares por quebra de linha. O formato com vírgulas usado pela CLI vira parte do valor quando digitado na interface.

**Impacto:** configurar um login com usuário e senha ou múltiplos cabeçalhos fica incompatível com o controle oferecido. Na CLI, opções repetidas sobrescrevem as anteriores, apesar da apresentação de opções singulares como `--param NOME`.

**Recomendação:** oferecer editor de pares ou campos multilinha, com validação e exemplo do formato aceito. Na CLI, acumular opções repetidas ou documentar e validar o separador.

**Validação proposta:** cadastrar pela interface uma operação com dois campos e dois cabeçalhos e conferir sua estrutura persistida, usando somente dados fictícios.

### A23 — CLI retorna sucesso mesmo quando a operação falha

**Gravidade:** média. **Evidência:** inspeção.

**Local:** `src/SVault.Cli/Program.cs:244–271,282–299`; `src/SVault.Manager/MainForm.cs:502–504`.

`approve` e `status` retornam código zero mesmo com estado `failed` ou resultado `Ok = false`. A interface considera `completed` suficiente para apresentar a cor de sucesso.

**Impacto:** automações podem tratar falhas HTTP ou processos com saída de erro como sucesso. O estado `completed` indica conclusão técnica, mas não garante sucesso da ação de negócio.

**Recomendação:** definir o contrato entre estado da solicitação e resultado da operação. Usar códigos de saída e indicação visual coerentes com `Result.Ok` e estados de falha.

**Validação proposta:** HTTP 401/500, processo com código diferente de zero e falha de comunicação devem ser identificáveis sem interpretar texto livre.

### A24 — Instalador pode concluir com atualização parcial e permissões não confirmadas

**Gravidade:** média. **Evidência:** inspeção; instalação não executada.

**Local:** `install/Install-SVault.ps1`, funções `Copy-Tree` e seções 4, 7 e 10.

Falhas de cópia são convertidas em aviso e a instalação prossegue. O código de saída de `icacls.exe` não é validado. A verificação final consulta somente o estado do serviço.

**Impacto:** podem permanecer binários de versões diferentes, permissões anteriores ou MCP indisponível, apesar da mensagem de instalação concluída. O script também copia o projeto MCP sem instalar ou verificar suas dependências.

**Recomendação:** preparar e validar uma versão completa antes de ativá-la. Interromper em falhas de permissões e arquivos essenciais. Verificar a saúde do broker e a inicialização do MCP ao concluir.

**Validação proposta:** simular arquivo bloqueado, erro de ACL e ausência de dependências. A instalação deve falhar claramente e preservar uma versão funcional.

## 4 Verificações executadas

Foram compilados, com `--no-restore`, os projetos `SVault.Broker`, `SVault.Manager` e `SVault.Cli`. Os três concluíram com zero avisos e zero erros. As referências também compilaram `Core` e `Client`.

Executou-se `node --check src/svault-mcp/index.mjs`, sem erro de sintaxe. Essa verificação não avalia negociação MCP, disponibilidade do SDK ou comunicação com o broker.

Um programa local em `artifacts/review-check/`, diretório ignorado pelo Git, executou oito verificações. O programa utilizou os componentes do projeto e um estado temporário sem registros de credenciais. Nenhuma API do Credential Manager foi chamada por essas verificações.

Os oito resultados foram:

1. Segredo de três caracteres retornou sem máscara — A08.
2. `Bearer {{secret}}` permaneceu literal — A16.
3. Parâmetro ausente foi convertido em texto vazio — A18.
4. A autorização de `/Admin` aceitou `/admin` — A20.
5. Segredo com escape JSON permaneceu recuperável — A09.
6. Resposta inválida devolveu conteúdo fora de `ResultFields` — A19.
7. Troca para senha vazia invalidou a senha anterior — A03.
8. A senha vazia usada na rotação foi recusada na abertura — A03.

Esses resultados reproduzem os defeitos descritos; não representam oito testes de aprovação da segurança do sistema. O programa de verificação é um artefato local desta revisão e não integra a suíte versionada.

## 5 Lacunas de cobertura e decisões de domínio

Os testes existentes cobrem o fluxo principal, alvos não autorizados, ausência de leitura direta, literais integrais, TOTP na aprovação e redação de valores simples. Faltam regressões para revogação com pedidos pendentes, alterações de política, concorrência, recuperação e formatos de saída adversos.

As seguintes decisões precisam ser explicitadas antes das correções:

- A aprovação autoriza o valor atual do segredo ou a revisão existente quando o pedido foi criado? Hoje o pedido não fixa a revisão.
- A exclusão de um registro auxiliar deve cancelar as operações que o referenciam? Hoje a exclusão remove somente operações cujo `EntryId` é o registro principal.
- Toda operação exige aprovação? `RequiresApproval = false` pode ser persistido, mas a solicitação sempre fica pendente. A garantia mais restritiva prevalece, porém os metadados são incoerentes.
- O resultado pode conter tokens de sessão recém-emitidos? O sanitizador conhece somente os segredos usados na operação, sem classificar automaticamente credenciais devolvidas pelo destino.
- Solicitações e resultados devem sobreviver ao reinício? Hoje permanecem somente em memória e o identificador passa a retornar ausência após reinício.

Esses pontos são decisões e limitações a especificar; não foram somados aos 24 achados.

Também se observou ausência de limitação de tentativas de autenticação no broker e de controle de reutilização de códigos TOTP. O impacto deve ser avaliado junto ao fluxo de recuperação e à política de múltiplas aprovações.

## 6 Ordem recomendada de correção

**Prioridade imediata:** impedir senhas inválidas no domínio e tornar a rotação recuperável — A02 e A03. Exigir segundo fator para sua alteração — A01.

**Autorização e execução:** invalidar pedidos revogados, revalidar políticas e garantir execução única — A04, A05 e A06. Exibir os dados efetivos da aprovação e proteger executáveis — A07 e A11.

**Proteção das saídas e persistência:** corrigir redação de valores curtos, escapes e detecção de literais — A08, A09 e A10. Restringir retorno quando a seleção falhar — A19.

**Confiabilidade operacional:** isolar as credenciais dos testes antes de ampliar a suíte — A21. Depois, tratar prazos, estados, retenção, templates, interfaces e instalação — demais achados.

Cada correção deve incluir o cenário de regressão descrito no respectivo achado. A validação de falhas de armazenamento e instalação deve ocorrer em ambiente dedicado e descartável.

## 7 Conclusão e limites

A separação entre agente e executor está presente, assim como a restrição de ações, o bloqueio de redirecionamentos HTTP e a criptografia dos valores armazenados. Entretanto, os achados mostram divergências entre essas garantias e alguns fluxos de manutenção, aprovação e retorno.

Recomenda-se resolver os achados críticos e altos antes de ampliar o uso com credenciais reais ou ações de maior impacto. A aprovação humana permanece exigida nos cenários A04, A05 e A11; a revisão não afirma execução automática sem aprovação nesses casos.

Esta avaliação combina inspeção de código, compilação e reproduções isoladas. Não constitui teste de invasão do ambiente instalado, certificação criptográfica ou garantia de ausência de outros defeitos. Condições de corrida, falhas de disco, integração completa e permissões efetivas exigem validação adicional em ambiente controlado.

## 8 Referências internas

- [README do projeto](../README.md): finalidade, arquitetura, comandos e garantias declaradas.
- [Limites de segurança](LIMITES.md): modelo de ameaça e limitações conhecidas.
- [Motor do broker](../src/SVault.Broker/BrokerEngine.cs): comandos e ciclo de aprovação.
- [Armazenamento](../src/SVault.Core/Storage/VaultStore.cs): persistência e ciclo de credenciais.
- [Motor de operações](../src/SVault.Core/Operations/OperationEngine.cs): HTTP, processos e templates.
- [Sanitizador](../src/SVault.Core/Redaction/SecretRedactor.cs): transformações e limites da redação.
- [Testes do broker](../tests/SVault.SmokeTest/Program.cs): cenários de integração existentes.

As referências de linha correspondem à base analisada e podem mudar após alterações. O documento segue estrutura de relatório técnico em Markdown, com seções numeradas; não possui diagramação acadêmica ABNT. Não há marcadores de conteúdo pendente.
