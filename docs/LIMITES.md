# Limites de segurança do SVault

Este documento é honesto sobre o que a solução **não** resolve. Nenhuma destas afirmações
deve ser lida como "o cofre é seguro contra tudo".

---

## 1. O modelo de ameaça

**Assumido como confiável:** você, o sistema operacional Windows, o Service Control Manager
e a sua senha do cofre.

**Assumido como não confiável:** o processo do agente (Claude Code, Codex, OpenCode), o
conteúdo das conversas, o modelo, as ferramentas que o agente inventa e qualquer código que
o agente escreva e execute.

**O agente tem:** terminal completo como o seu usuário, acesso a navegador, e a capacidade de
pedir qualquer ação sua.

---

## 2. O que o SVault resolve

| Ameaça | Mitigação | Limite residual |
|---|---|---|
| Agente lê o arquivo de credenciais | Valores em `Credential Manager` do perfil do SYSTEM, que o agente não acessa | Um admin local pode extrair o DPAPI (ver §3.1) |
| Agente descriptografa o segredo | AES-256-GCM com chave derivada da **sua senha do cofre** | Quem tiver a senha do cofre lê tudo |
| Agente executa `sc.exe query` e lê o segredo | Não há segredo em linha de comando, env ou log | — |
| Agente exfiltra o segredo para um site | Alvo fixo por operação, validado contra a allowlist do registro | O agente escolhe a *operação*, não o destino |
| Agente usa o segredo sem sua ciência | Aprovação por operação (senha do cofre, + TOTP) | Um agente com GUI pode clicar, mas **não sabe a senha** |
| Agente vaza o valor em log/resposta | Redação de todas as saídas | Variações não cobertas pela redação (ver §5) |
| Agente lê a memória do processo do broker | Processo do SYSTEM; o agente não tem `SeDebugPrivilege` | Admin local lê memória de qualquer processo |

---

## 3. O que o SVault **não** resolve

### 3.1 Elevação administrativa
Se o agente obtiver **administrador completo** (UAC aceito por engano, política de UAC
desabilitada, ou credencial de administrador exposta), o atacante pode:

- ler a memória do broker (`svault-broker.exe`, LocalSystem) e extrair a chave mestra em uso;
- extrair as chaves DPAPI do SYSTEM e ler o *Credential Manager* — o que lhe devolve apenas
  **texto cifrado**, porque cada valor continua selado com AES-256-GCM pela sua senha do cofre;
- substituir o binário do serviço e interceptar as aprovações.

A camada da senha do cofre continua de pé contra o dump de LSA/DPAPI, mas **não** contra a
leitura direta da memória de um processo privilegiado.

> No seu ambiente, o UAC está em `ConsentPromptBehaviorAdmin=5` com `PromptOnSecureDesktop=1`:
> um agente **não** consegue clicar em "Sim" sozinho. Ainda assim, um pedido de elevação
> exibido com um nome de programa enganoso pode ser aprovado por você sem muita atenção.

### 3.2 Agente com GUI e a sua senha do cofre
A aprovação exige a senha do cofre. Um agente com controle do navegador/desktop **não
consegue derivá-la**, mas um agente que **você mesmo digitou** em um terminal pode ler o
buffer do console, e um agente que lê a memória do processo `SVaultManager.exe` pode
enxergar a senha que você acabou de digitar. Use o **TOTP** para tornar esse ataque
inútil: mesmo com a senha do cofre, o atacante precisa do código do seu celular.

### 3.3 Janela de exposição
Entre o instante em que você aprova e o instante em que o broker termina, o segredo está
descriptografado na memória do broker. O processo vive no contexto do SYSTEM; um agente sem
elevação não consegue lê-lo. Com elevação, sim (ver §3.1).

### 3.4 Confiabilidade do alvo autorizado
O SVault garante que o segredo vai **para o alvo que você autorizou**. Ele não garante que
esse alvo é honesto. Um site comprometido, um proxy intermediário ou um DNS manipulado
recebem o segredo em claro. Use sempre HTTPS (o broker só aceita HTTP em loopback) e,
para portais frágeis, prefira tokens de escopo limitado a senhas reutilizadas.

### 3.5 O agente controla o **parâmetro**, não o **destino**
Em uma operação `http.request`, o agente preenche os campos `{{param:NOME}}` declarados por
você. O destino, o método, o content-type e a estrutura do corpo são fixos na autorização.
Ainda assim, um parâmetro mal projetado (por exemplo, um campo de URL livre) pode ser
usado para redirecionar a requisição. O broker recusa redirecionamentos automáticos.

### 3.6 Segredos em outros lugares
O SVault não controla o que você faz **fora** dele:

- senhas digitadas em sites, não cadastradas no cofre;
- `.env`, arquivos de configuração e `git` dos seus projetos;
- variáveis de ambiente dos próprios agentes;
- cookies e sessões de navegador.

Recomendação: use o SVault para o que realmente importa (CPF, senhas reutilizadas, tokens de
longa duração) e mantenha o restante em um gerenciador de senhas tradicional (Bitwarden,
KeePassXC) com senha mestra — ele é melhor que o SVault contra o cenário de admin local.

---

## 4. Notas de engenharia (o que a construção ensinou)

1. **DPAPI do mesmo usuário não isola nada.** Um agente com o seu usuário lê o que o seu
   usuário lê. Daí o broker rodar fora do seu usuário (contexto de sistema).
2. **SID de conta Azure AD (`S-1-12-1-…`) não é aceito pelo parser SDDL.** O broker monta a
   DACL do pipe por objetos `SecurityIdentifier`, não por string SDDL.
3. **`sc.exe` aceita um único token em `binPath=`.** Por isso o executável do serviço fica em
   `C:\SVault` (sem espaços) e o diretório de dados chega por variável de ambiente do serviço.
4. **A política local deste equipamento está bloqueada por GPO:** `secedit /configure` falha
   mesmo reimportando um arquivo exportado sem alteração, e `LsaAddAccountRights` recusa
   conceder "Log on as a service" (NTSTATUS `0xC003000C`). Sem esse direito, um serviço não
   roda sob uma conta dedicada — por isso o broker roda como **LocalSystem**, e o isolamento
   dos valores passa a depender inteiramente do envelope AES-256-GCM com a sua senha do cofre.
5. **Trocar a senha do cofre re-sela todos os segredos** (o envelope é reescrito com a nova
   chave derivada). Use `svaultctl change-passphrase`.

---

## 5. Redação: o que é (e não é) coberto

O broker substitui por `***REDACTED***` as ocorrências do valor em: texto puro, minúsculo,
maiúsculo, codificado em URL, em Base64, somente dígitos (CPF) e com pontuação de CPF.

**Não é coberto:** o segredo transformado em outro formato (ex.: codificado em Base32, ou
partido em pedaços e remontado), ou um segredo curto o bastante para gerar falsos positivos
(por isso valores com menos de 4 caracteres não são redigidos). Nenhum valor de segredo é
**exposto deliberadamente** em nenhuma saída; a redação é uma segunda barreira.

---

## 6. Checklist de higiene

- [ ] Senha do cofre forte e **diferente** da senha do Windows.
- [ ] TOTP habilitado (`init --totp` ou `set-totp`).
- [ ] UAC em "notificar sempre" e área de transferência segura ativa.
- [ ] Execute os agentes **sem elevação** — nesse cenário o broker (LocalSystem) já é
      inacessível ao processo do agente.
- [ ] Revise `svaultctl ops` periodicamente: revogue operações que não usa mais.
- [ ] Prefira tokens de escopo mínimo a senhas reutilizadas sempre que o serviço permitir.
- [ ] Trate `svaultctl reset` como operação destrutiva (apaga todos os segredos).

---

## 7. Alternativa mais simples (quando o isolamento não é viável)

Se você precisar de uma garantia mais forte contra **admin local** e aceitar a troca
clássica "digitar a cada uso":

- use um **gerenciador de senhas com senha mestra** (Bitwarden, 1Password, KeePassXC) e
  preencha os campos manualmente quando a automação for realmente necessária;
- ou mantenha o SVault como está e **não execute agentes com elevação** — nesse cenário o
  broker já roda fora do seu usuário.

Em ambos os casos a regra continua: **o agente não deve receber o valor**, e sim o resultado
de uma ação executada por um processo que você controla.
