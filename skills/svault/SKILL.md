---
name: svault
description: Use o cofre de credenciais SVault (ferramentas MCP vault_*) sempre que a tarefa precisar de CPF, senha, token, API key ou outro dado sensível — por exemplo autenticar em um portal, chamar uma API autenticada, preencher formulário com credencial ou automatizar um login. Ensina o fluxo correto (listar operações autorizadas, solicitar, aguardar a aprovação do proprietário e ler o resultado sanitizado) e proíbe qualquer tentativa de obter o valor do segredo.
---

# Cofre SVault

O cofre guarda CPF, senhas e tokens. **Você nunca recebe o valor.** Você executa operações já
autorizadas pelo proprietário e recebe o resultado com o segredo substituído por
`***REDACTED***`. Isso é proposital, não é um bug.

## Ferramentas

| Ferramenta | Para que serve |
|---|---|
| `vault_list_entries` | identificadores disponíveis (nunca valores) |
| `vault_list_operations` | operações autorizadas: alvo fixo, registro usado, parâmetros aceitos |
| `vault_request_operation` | solicita a execução; volta `pending_approval` ou `completed` |
| `vault_operation_status` | andamento e resultado sanitizado de uma solicitação |
| `vault_health` | diagnóstico do serviço |

No Claude Code os nomes aparecem como `mcp__svault__vault_list_operations` etc.
No Codex e no OpenCode são `vault_list_operations` etc.

## Fluxo correto

1. **`vault_list_operations`** e escolha a operação cujo `target` serve à tarefa. Verifique
   `entryId` e `params`. Se nenhuma servir, **pare** (veja "Pedir nova autorização").
2. Preencha **apenas** os `params` declarados daquela operação. Não invente parâmetros e
   não repita o identificador do registro como parâmetro.
3. **`vault_request_operation`** com `operationId` e `params`.
4. Se voltar `status == "pending_approval"`: **não tente aprovar**. Avise o usuário
   ("aprovação pendente no SVault Manager") e aguarde. Consulte `vault_operation_status`
   a cada ~15 s. A solicitação expira em 180 s; se expirar, faça uma nova requisição.
5. Quando `status == "completed"`, leia `result`. Se aparecer `***REDACTED***` onde estava o
   segredo, **é o comportamento correto** — não tente "descobrir" o valor real.
6. `status == "failed"`: o erro vem sanitizado. Reporte ao usuário sem tentar contornar.

## Proibições

- **Não** peça a senha, o CPF ou o token para o usuário colar no chat, nem o leia de arquivos.
- **Não** tente ler `C:\ProgramData\SVault\state\vault-state.json`, o Credential Manager, a
  memória do processo `svault-broker` ou qualquer outro artefato do cofre. O valor é
  inacessível por design; perder tempo nisso é perder tempo do usuário.
- **Não** chame `get_secret`, `read_password`, `export` ou invenções equivalentes: não
  existem, o broker rejeita comandos desconhecidos e o valor jamais sai coberto.
- **Não** faça a requisição autenticada por conta própria (curl, `Invoke-WebRequest` com a
  senha, script com a senha no código). O broker é o único autorizado a injetar o segredo, e
  só no alvo fixo que o proprietário autorizou.
- Se a operação necessária não existe, o caminho é pedir autorização — nunca coletar a
  credencial na conversa.

## Pedir nova autorização

O proprietário executa no terminal dele:

```powershell
& "C:\SVault\svaultctl.exe" authorize --id NOME_OP --entry REGISTRO --action http.request --target ALVO --method POST --content-type application/json --body "campo={{secret}},outro={{param:x}}" --param x
```

Placeholders aceitos:

| Placeholder | Resolve para |
|---|---|
| `{{secret}}` | o segredo do registro ligado à operação |
| `{{secret:OUTRO_ID}}` | o segredo de outro registro (ex.: CPF + senha no mesmo login) |
| `{{param:NOME}}` | um valor que **você** preenche (declarado em `--param`) |

Sugira o comando completo ao usuário, com o alvo e os campos reais, e pare ali: a
autorização é ação do proprietário.

## Como reportar ao usuário

Informe: operação executada, alvo, status e o resultado sanitizado. Se a aprovação ficou
pendente, diga exatamente como aprovar (`svaultctl approve --request <id>` ou pelo
`SVaultManager.exe`, aba "Aprovações"). Nunca invente, deduza ou estime o valor da
credencial.
