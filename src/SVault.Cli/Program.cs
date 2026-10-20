using System.Text.Json;
using SVault.Client;
using SVault.Core.Operations;
using SVault.Core.Protocol;
using SVault.Core.Storage;

var client = new BrokerClient();

if (args.Length == 0)
{
    PrintUsage();
    return 1;
}

try
{
    return await RunAsync(args);
}
catch (BrokerCallException ex)
{
    Console.Error.WriteLine($"erro [{ex.Code}]: {ex.Message}");
    return 2;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"erro: {ex.Message}");
    return 3;
}

async Task<int> RunAsync(string[] args)
{
    var command = args[0].ToLowerInvariant();
    var options = ParseOptions(args.Skip(1).ToArray());

    switch (command)
    {
        case "health":
        {
            var health = await client.HealthAsync();
            Console.WriteLine($"status            : {health.Status}");
            Console.WriteLine($"versao            : {health.Version}");
            Console.WriteLine($"identidade        : {health.ServiceIdentity}");
            Console.WriteLine($"cofre inicializado: {health.VaultInitialized}");
            Console.WriteLine($"totp ativo        : {health.TotpRequired}");
            Console.WriteLine($"registros         : {health.EntryCount}");
            Console.WriteLine($"operacoes         : {health.OperationCount}");
            return 0;
        }

        case "init":
        {
            var passphrase = SecureInput.ReadSecret("Senha do cofre: ");
            if (passphrase.Length < 8)
            {
                Console.Error.WriteLine("A senha do cofre precisa de pelo menos 8 caracteres.");
                return 2;
            }

            var confirm = SecureInput.ReadSecret("Confirme a senha: ");
            if (passphrase != confirm)
            {
                Console.Error.WriteLine("As senhas nao conferem.");
                return 2;
            }

            var enableTotp = options.ContainsKey("totp");
            var result = await client.InitVaultAsync(passphrase, enableTotp);
            Console.WriteLine("Cofre inicializado.");
            if (enableTotp && !string.IsNullOrEmpty(result.TotpUri))
            {
                Console.WriteLine("Adicione este URI no seu aplicativo autenticador (uma unica vez):");
                Console.WriteLine(result.TotpUri);
            }

            return 0;
        }

        case "list":
        {
            var entries = await client.ListEntriesAsync();
            if (entries.Entries.Count == 0)
            {
                Console.WriteLine("(nenhum registro)");
                return 0;
            }

            Console.WriteLine($"{"IDENTIFICADOR",-28} {"TIPO",-10} {"ALVOS",-40} ATUALIZADO");
            foreach (var entry in entries.Entries)
            {
                Console.WriteLine(
                    $"{entry.Id,-28} {entry.Kind,-10} {string.Join(", ", entry.Targets),-40} {entry.UpdatedAt}");
            }

            return 0;
        }

        case "ops":
        {
            var operations = await client.ListOperationsAsync();
            if (operations.Operations.Count == 0)
            {
                Console.WriteLine("(nenhuma operacao)");
                return 0;
            }

            Console.WriteLine($"{"OPERACAO",-28} {"REGISTRO",-22} {"ACAO",-16} ALVO");
            foreach (var operation in operations.Operations)
            {
                Console.WriteLine(
                    $"{operation.Id,-28} {operation.EntryId,-22} {operation.Action,-16} {operation.Target}");
            }

            return 0;
        }

        case "add":
        {
            var id = Require(options, "id");
            var kind = Opt(options, "kind", "generic");
            var label = Opt(options, "label", id);
            var targets = SplitList(Require(options, "target"));
            var value = SecureInput.ReadSecret("Valor do segredo: ");
            var passphrase = SecureInput.ReadSecret("Senha do cofre: ");

            var entry = await client.RegisterEntryAsync(id, kind, label, targets, value, passphrase);
            Console.WriteLine($"Registro {entry.Id} cadastrado (revisao {entry.Revision}).");
            return 0;
        }

        case "update":
        {
            var id = Require(options, "id");
            var passphrase = SecureInput.ReadSecret("Senha do cofre: ");
            string? value = null;
            if (options.ContainsKey("value"))
            {
                value = SecureInput.ReadSecret("Novo valor: ");
            }

            var label = OptNullable(options, "label");
            var targets = options.ContainsKey("target") ? SplitList(options["target"]) : null;

            var entry = await client.UpdateEntryAsync(id, value, label, targets, passphrase);
            Console.WriteLine($"Registro {entry.Id} atualizado (revisao {entry.Revision}).");
            return 0;
        }

        case "remove":
        {
            var id = Require(options, "id");
            var passphrase = SecureInput.ReadSecret("Senha do cofre: ");
            await client.DeleteEntryAsync(id, passphrase);
            Console.WriteLine($"Registro {id} removido.");
            return 0;
        }

        case "authorize":
        {
            var id = Require(options, "id");
            var entryId = Require(options, "entry");
            var action = Require(options, "action");
            var target = Require(options, "target");
            var description = Opt(options, "description", string.Empty);
            var paramNames = SplitList(Opt(options, "param", string.Empty));
            var passphrase = SecureInput.ReadSecret("Senha do cofre: ");

            object? actionSpec = null;
            if (action == OperationEngine.ActionHttpRequest)
            {
                actionSpec = new
                {
                    method = Opt(options, "method", "POST"),
                    url = target,
                    contentType = Opt(options, "content-type", "application/json"),
                    bodyFields = ParseMap(Opt(options, "body", string.Empty)),
                    headers = ParseMap(Opt(options, "header", string.Empty)),
                    resultFields = SplitList(Opt(options, "result-field", string.Empty))
                };
            }
            else if (action == OperationEngine.ActionProcessStdin)
            {
                actionSpec = new
                {
                    executable = target,
                    args = SplitList(Opt(options, "arg", string.Empty)),
                    env = SplitList(Opt(options, "env", string.Empty)),
                    timeoutSeconds = int.TryParse(Opt(options, "timeout", "30"), out var timeout) ? timeout : 30
                };
            }

            var operation = await client.AuthorizeOperationAsync(
                id,
                entryId,
                action,
                target,
                description,
                paramNames,
                passphrase,
                actionSpec);

            Console.WriteLine($"Operacao {operation.Id} autorizada para {operation.EntryId} -> {operation.Target}");
            return 0;
        }

        case "revoke":
        {
            var id = Require(options, "id");
            var passphrase = SecureInput.ReadSecret("Senha do cofre: ");
            await client.RevokeOperationAsync(id, passphrase);
            Console.WriteLine($"Operacao {id} revogada.");
            return 0;
        }

        case "request":
        {
            var opId = Require(options, "op");
            var parameters = ParseMap(Opt(options, "param-value", string.Empty));
            var result = await client.RequestOperationAsync(opId, parameters);
            Console.WriteLine($"requestId : {result.RequestId}");
            Console.WriteLine($"status    : {result.Status}");
            Console.WriteLine($"requer    : {result.Requires}");
            Console.WriteLine($"expira em : {result.ExpiresAt}");
            Console.WriteLine($"operacao  : {result.Summary.OperationId} -> {result.Summary.Target}");
            return 0;
        }

        case "pending":
        {
            var pending = await client.PendingApprovalsAsync();
            if (pending.Requests.Count == 0)
            {
                Console.WriteLine("(nenhuma solicitacao pendente)");
                return 0;
            }

            foreach (var request in pending.Requests)
            {
                var parameters = string.Join(", ", request.Summary.Parameters.Select(pair => $"{pair.Key}={pair.Value}"));
                Console.WriteLine($"{request.RequestId}  {request.Summary.OperationId}  {request.Summary.EntryId}  {request.Summary.Method ?? request.Summary.Action}  {request.Summary.Target}  [{parameters}]  expira {request.ExpiresAt}");
            }

            return 0;
        }

        case "approve":
        {
            var requestId = Require(options, "request");
            var passphrase = SecureInput.ReadSecret("Senha do cofre: ");
            var totp = OptNullable(options, "totp");
            if (totp is null)
            {
                totp = SecureInput.ReadSecret("Codigo TOTP (se ativo): ");
                if (string.IsNullOrWhiteSpace(totp))
                {
                    totp = null;
                }
            }

            var result = await client.ApproveAsync(requestId, passphrase, totp);
            Console.WriteLine($"status : {result.Status}");
            if (result.Result is not null)
            {
                Console.WriteLine($"resultado: {JsonSerializer.Serialize(result.Result, Json.Options)}");
            }

            if (result.Error is not null)
            {
                Console.WriteLine($"erro    : {result.Error}");
            }

            return result.Status == OperationStatuses.Completed && result.Result?.Ok == true ? 0 : 4;
        }

        case "reject":
        {
            var requestId = Require(options, "request");
            var passphrase = SecureInput.ReadSecret("Senha do cofre: ");
            await client.RejectAsync(requestId, passphrase);
            Console.WriteLine("Solicitacao rejeitada.");
            return 0;
        }

        case "status":
        {
            var requestId = Require(options, "request");
            var status = await client.OperationStatusAsync(requestId);
            Console.WriteLine($"status    : {status.Status}");
            Console.WriteLine($"operacao  : {status.Summary.OperationId}");
            Console.WriteLine($"alvo      : {status.Summary.Target}");
            if (status.Result is not null)
            {
                Console.WriteLine($"resultado : {JsonSerializer.Serialize(status.Result, Json.Options)}");
            }

            if (status.Error is not null)
            {
                Console.WriteLine($"erro      : {status.Error}");
            }

            return status.Status == OperationStatuses.Completed && status.Result?.Ok == true ? 0 : 4;
        }

        case "set-totp":
        {
            var secret = Require(options, "secret").Replace(" ", string.Empty).ToUpperInvariant();
            var passphrase = SecureInput.ReadSecret("Senha do cofre: ");
            await client.SetTotpAsync(secret, passphrase, await ReadAdminTotpAsync(client, options));
            Console.WriteLine("TOTP ativado.");
            return 0;
        }

        case "disable-totp":
        {
            var passphrase = SecureInput.ReadSecret("Senha do cofre: ");
            await client.DisableTotpAsync(passphrase, await ReadAdminTotpAsync(client, options));
            Console.WriteLine("TOTP desativado.");
            return 0;
        }

        case "change-passphrase":
        {
            var current = SecureInput.ReadSecret("Senha atual: ");
            var next = SecureInput.ReadSecret("Nova senha: ");
            var confirm = SecureInput.ReadSecret("Confirme a nova senha: ");
            if (next != confirm)
            {
                Console.Error.WriteLine("As senhas nao conferem.");
                return 2;
            }

            await client.ChangePassphraseAsync(current, next, await ReadAdminTotpAsync(client, options));
            Console.WriteLine("Senha do cofre alterada.");
            return 0;
        }

        case "admin":
            return await RunAdminAsync(options);

        case "reset":
        {
            var passphrase = SecureInput.ReadSecret("Senha do cofre: ");
            var result = await client.ResetVaultAsync(passphrase, await ReadAdminTotpAsync(client, options));
            Console.WriteLine($"Cofre reiniciado. {result.EntriesRemoved} registro(s) removido(s).");
            Console.WriteLine("Use 'svaultctl init --totp' para definir uma nova senha do cofre.");
            return 0;
        }

        case "help":
        case "--help":
        case "-h":
            PrintUsage();
            return 0;

        default:
            Console.Error.WriteLine($"Comando desconhecido: {command}");
            PrintUsage();
            return 1;
    }
}

static Task<int> RunAdminAsync(Dictionary<string, string> options)
{
    var action = Opt(options, "action", "setup-service-account");
    var account = Opt(options, "account", "svault_svc");
    var accountName = account.Contains('\\') ? account : $"{Environment.MachineName}\\{account}";

    var sid = new System.Security.Principal.NTAccount(accountName)
        .Translate(typeof(System.Security.Principal.SecurityIdentifier)) as System.Security.Principal.SecurityIdentifier;

    if (sid is null)
    {
        Console.Error.WriteLine($"Nao foi possivel resolver a conta {account}.");
        return Task.FromResult(1);
    }

    switch (action)
    {
        case "setup-service-account":
            LsaRights.Grant(sid.Value, LsaRights.SeServiceLogonRight);
            LsaRights.Grant(
                sid.Value,
                LsaRights.SeDenyInteractiveLogonRight,
                LsaRights.SeDenyRemoteInteractiveLogonRight,
                LsaRights.SeDenyNetworkLogonRight);
            Console.WriteLine($"Direitos aplicados para {account} ({sid.Value}):");
            Console.WriteLine($"  permitido : {LsaRights.SeServiceLogonRight}");
            Console.WriteLine($"  negado    : {LsaRights.SeDenyInteractiveLogonRight}, {LsaRights.SeDenyRemoteInteractiveLogonRight}, {LsaRights.SeDenyNetworkLogonRight}");
            return Task.FromResult(0);

        default:
            Console.Error.WriteLine($"Acao administrativa desconhecida: {action}");
            return Task.FromResult(1);
    }
}

static Dictionary<string, string> ParseOptions(string[] args)
{
    var options = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    for (var i = 0; i < args.Length; i++)
    {
        if (!args[i].StartsWith("--", StringComparison.Ordinal))
        {
            continue;
        }

        var key = args[i][2..];
        string value = "true";
        if (i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal))
        {
            value = args[i + 1];
            i++;
        }

        if (options.TryGetValue(key, out var previous) &&
            new[] { "param", "param-value", "body", "header" }.Contains(key, StringComparer.OrdinalIgnoreCase))
        {
            options[key] = previous + "," + value;
        }
        else
        {
            options[key] = value;
        }
    }

    return options;
}


static string Opt(IReadOnlyDictionary<string, string> options, string key, string fallback = "") =>
    options.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value) ? value : fallback;

static string? OptNullable(IReadOnlyDictionary<string, string> options, string key) =>
    options.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value) ? value : null;

static async Task<string?> ReadAdminTotpAsync(BrokerClient client, IReadOnlyDictionary<string, string> options)
{
    var provided = OptNullable(options, "totp");
    if (provided is not null)
    {
        return provided;
    }

    return (await client.HealthAsync()).TotpRequired
        ? SecureInput.ReadSecret("Codigo TOTP atual: ")
        : null;
}

static string Require(IReadOnlyDictionary<string, string> options, string key) =>
    options.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)
        ? value
        : throw new ArgumentException($"Opcao obrigatoria ausente: --{key}");

static IReadOnlyList<string> SplitList(string value) =>
    string.IsNullOrWhiteSpace(value)
        ? Array.Empty<string>()
        : value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

static Dictionary<string, string> ParseMap(string value)
{
    var map = new Dictionary<string, string>(StringComparer.Ordinal);
    if (string.IsNullOrWhiteSpace(value))
    {
        return map;
    }

    foreach (var pair in value.Split(new[] { ',', '\n' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
    {
        var separator = pair.IndexOf('=');
        if (separator <= 0)
        {
            continue;
        }

        map[pair[..separator].Trim()] = pair[(separator + 1)..].Trim();
    }

    return map;
}

static void PrintUsage()
{
    Console.WriteLine("""
        svaultctl - gerenciamento do cofre SVault (somente para o proprietario)

        Uso: svaultctl <comando> [opcoes]

        Comandos:
          health                                   situacao do broker e do cofre
          init [--totp]                            inicializa o cofre e define a senha do cofre
          list                                     lista identificadores e metadados (nunca valores)
          ops                                      lista operacoes autorizadas
          add --id ID --target ALVO [--kind K] [--label L]
                                                 cadastra um segredo (o valor e lido sem eco)
          update --id ID [--value] [--label L] [--target ALVO]
                                                 atualiza um segredo
          remove --id ID                           remove um segredo
          authorize --id OP --entry ENTRY --action ACAO --target ALVO
                   [--param NOME] [--body k=v] [--header k=v] [--method M]
                                                 autoriza uma operacao pre-definida
          revoke --id OP                           revoga uma operacao
          request --op OP [--param-value k=v]      solicita uma operacao (aguarda aprovacao)
          pending                                  lista solicitacoes aguardando aprovacao
          approve --request ID [--totp CODIGO]     aprova e executa (exige a senha do cofre)
          reject --request ID                      rejeita uma solicitacao
          status --request ID                      mostra o resultado sanitizado
          set-totp --secret BASE32 [--totp CODIGO] ativa ou substitui o TOTP
          disable-totp [--totp CODIGO]             desativa o TOTP
          change-passphrase [--totp CODIGO]        troca a senha do cofre
          admin --action setup-service-account --account NOME
                                                 concede "Log on as a service" via API LSA
                                                 (necessario so se o broker rodar com conta dedicada)

        Observacao: a senha do cofre e sempre digitada interativamente, sem eco e sem area de transferencia.
        """);
}
