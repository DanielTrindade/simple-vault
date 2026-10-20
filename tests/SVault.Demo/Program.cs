using System.Text.Json;
using SVault.Client;
using SVault.Core.Protocol;

namespace SVault.Demo;

/// <summary>
/// Demonstracao ponta a ponta contra o servico real, com valores ficticios.
/// Nada aqui e real: o CPF, a senha e a senha do cofre abaixo sao dados de teste.
/// </summary>
internal static class Program
{
    private const string Passphrase = "senha-ficticia-do-cofre";
    private const string CpfFake = "529.982.247-25";
    private const string SenhaFake = "SenhaFicticia!2026";

    private static async Task<int> Main(string[] args)
    {
        if (!args.Contains("--allow-installed-broker", StringComparer.OrdinalIgnoreCase))
        {
            Console.Error.WriteLine("Esta demonstracao conecta ao broker instalado. Use --allow-installed-broker para autorizar explicitamente.");
            return 2;
        }

        var keep = args.Contains("--keep", StringComparer.OrdinalIgnoreCase);
        var client = new BrokerClient();

        if (args.Length >= 2 && args[0] == "approve")
        {
            var approved = await client.ApproveAsync(args[1], Passphrase);
            Console.WriteLine($"status: {approved.Status}");
            if (approved.Result is not null)
            {
                Console.WriteLine(JsonSerializer.Serialize(approved.Result, Json.Options));
            }

            return 0;
        }

        if (args.Length >= 1 && args[0] == "reset")
        {
            var reset = await client.ResetVaultAsync(Passphrase);
            Console.WriteLine($"cofre reiniciado ({reset.EntriesRemoved} registro removido).");
            return 0;
        }

        using var server = new FakeHttpServer();

        Console.WriteLine("=== SVault: demonstracao com dados ficticios ===");
        Console.WriteLine();

        var health = await client.HealthAsync();
        Console.WriteLine($"[1] broker ativo: {health.Status} | identidade {health.ServiceIdentity} | cofre inicializado: {health.VaultInitialized}");

        if (!health.VaultInitialized)
        {
            await client.InitVaultAsync(Passphrase, enableTotp: false);
            Console.WriteLine("[2] cofre inicializado com senha ficticia");
        }
        else
        {
            Console.WriteLine("[2] cofre ja inicializado (usando a senha de teste)");
        }

        await client.RegisterEntryAsync(
            "CPF_PESSOAL",
            "cpf",
            "CPF pessoal (FICTICIO)",
            new[] { server.BaseUrl },
            CpfFake,
            Passphrase);

        await client.RegisterEntryAsync(
            "SENHA_PORTAL_A",
            "password",
            "Senha do portal A (FICTICIA)",
            new[] { server.BaseUrl },
            SenhaFake,
            Passphrase);

        Console.WriteLine("[3] segredos ficticios cadastrados: CPF_PESSOAL, SENHA_PORTAL_A");

        await client.AuthorizeOperationAsync(
            "login_portal_a",
            "SENHA_PORTAL_A",
            "http.request",
            $"{server.BaseUrl}/api/login",
            "Autenticacao ficticia no portal A",
            new[] { "usuario" },
            Passphrase,
            new
            {
                method = "POST",
                url = $"{server.BaseUrl}/api/login",
                contentType = "application/json",
                bodyFields = new Dictionary<string, string>
                {
                    ["usuario"] = "{{param:usuario}}",
                    ["senha"] = "{{secret}}"
                },
                headers = new Dictionary<string, string>(),
                resultFields = new List<string>()
            });

        await client.AuthorizeOperationAsync(
            "eco_cpf",
            "CPF_PESSOAL",
            "noop.echo",
            "eco",
            "Diagnostico de redacao (sem rede)",
            Array.Empty<string>(),
            Passphrase);

        Console.WriteLine("[4] operacoes autorizadas: login_portal_a (http.request), eco_cpf (noop.echo)");
        Console.WriteLine();

        Console.WriteLine("--- visao do AGENTE (via MCP: list_entries / list_operations) ---");
        var entries = await client.ListEntriesAsync();
        Console.WriteLine(JsonSerializer.Serialize(entries, Json.Options));
        var operations = await client.ListOperationsAsync();
        Console.WriteLine(JsonSerializer.Serialize(operations, Json.Options));
        Console.WriteLine();

        Console.WriteLine("--- AGENTE solicita a operacao ---");
        var request = await client.RequestOperationAsync(
            "login_portal_a",
            new Dictionary<string, string> { ["usuario"] = "usuario-ficticio" });

        Console.WriteLine(JsonSerializer.Serialize(request, Json.Options));
        Console.WriteLine("(status pendente: o agente NAO recebe o segredo e NAO pode executar ainda)");
        Console.WriteLine();

        Console.WriteLine("--- DONO aprova (senha do cofre) ---");
        var approval = await client.ApproveAsync(request.RequestId, Passphrase);
        Console.WriteLine($"status: {approval.Status}");
        Console.WriteLine();

        Console.WriteLine("--- visao do AGENTE apos a execucao (via MCP: operation_status) ---");
        var status = await client.OperationStatusAsync(request.RequestId);
        Console.WriteLine(JsonSerializer.Serialize(status, Json.Options));
        Console.WriteLine();

        Console.WriteLine("--- o portal ficticio recebeu o segredo de verdade? ---");
        lock (server.ReceivedBodies)
        {
            foreach (var body in server.ReceivedBodies)
            {
                Console.WriteLine($"  servidor ficticio recebeu: {body}");
            }
        }

        Console.WriteLine();

        var rendered = JsonSerializer.Serialize(status);
        var leaked = rendered.Contains(SenhaFake, StringComparison.Ordinal)
                     || rendered.Contains(CpfFake, StringComparison.Ordinal);

        Console.WriteLine($"[5] o valor do segredo apareceu na resposta ao agente? {(leaked ? "SIM (FALHA)" : "NAO (correto)")}");
        Console.WriteLine($"[6] a resposta ao agente contem a mascara: {(rendered.Contains("***REDACTED***", StringComparison.Ordinal) ? "SIM (correto)" : "NAO")}");

        if (!keep)
        {
            Console.WriteLine();
            Console.WriteLine("--- limpando o cofre de teste ---");
            var reset = await client.ResetVaultAsync(Passphrase);
            Console.WriteLine($"cofre reiniciado ({reset.EntriesRemoved} registro removido). Use 'svaultctl init --totp' para criar o seu.");
        }
        else
        {
            Console.WriteLine();
            Console.WriteLine("--- cofre de teste mantido (--keep) ---");
        }

        Console.WriteLine();
        return leaked ? 1 : 0;
    }
}
