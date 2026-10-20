using System.Diagnostics;
using System.Text.Json;
using SVault.Client;
using SVault.Core.Crypto;

namespace SVault.SmokeTest;

internal static class Program
{
    private const string Passphrase = "senha-de-teste-2026";
    private const string CpfFake = "529.982.247-25";
    private const string SenhaFake = "S3nh@Ficticia-2026!";

    private static int _passed;
    private static int _failed;
    private static string? _totpSecret;

    private static async Task<int> Main(string[] args)
    {
        if (args.Length == 0)
        {
            Console.Error.WriteLine("uso: SVault.SmokeTest <caminho-do-svault-broker.exe>");
            return 1;
        }

        var brokerExe = Path.GetFullPath(args[0]);
        if (!File.Exists(brokerExe))
        {
            Console.Error.WriteLine($"broker nao encontrado: {brokerExe}");
            return 1;
        }

        var home = Path.Combine(Path.GetTempPath(), "svault-smoke-" + Guid.NewGuid().ToString("N"));
        var pipeName = "svault.smoke." + Guid.NewGuid().ToString("N")[..8];
        Directory.CreateDirectory(home);

        using var server = new FakeHttpServer();
        using var broker = StartBroker(brokerExe, home, pipeName);

        var client = new BrokerClient(pipeName);
        try
        {
            await WaitForPipeAsync(client);
            await RunTestsAsync(client, server, home);
        }
        finally
        {
            broker.Kill(entireProcessTree: true);
            broker.WaitForExit(5000);
            TryDelete(home);
        }

        Console.WriteLine();
        Console.WriteLine($"resultado: {_passed} aprovado(s), {_failed} falha(s)");
        return _failed == 0 ? 0 : 1;
    }

    private static Process StartBroker(string exe, string home, string pipeName)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = exe,
            Arguments = $"--console --home \"{home}\" --pipe {pipeName}",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        var process = new Process { StartInfo = startInfo };
        process.OutputDataReceived += (_, e) => { if (e.Data is not null) Console.WriteLine("  [broker] " + e.Data); };
        process.ErrorDataReceived += (_, e) => { if (e.Data is not null) Console.WriteLine("  [broker:erro] " + e.Data); };
        process.Start();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        return process;
    }

    private static async Task WaitForPipeAsync(BrokerClient client)
    {
        Exception? last = null;
        for (var attempt = 0; attempt < 60; attempt++)
        {
            try
            {
                await client.HealthAsync();
                return;
            }
            catch (Exception ex)
            {
                last = ex;
                await Task.Delay(500);
            }
        }

        throw new InvalidOperationException("O broker nao respondeu no pipe: " + last);
    }

    private static async Task RunTestsAsync(BrokerClient client, FakeHttpServer server, string home)
    {
        await Test("broker responde ao health", async () =>
        {
            var health = await client.HealthAsync();
            Check(health.Status == "ok", "status diferente de ok");
            Check(!health.VaultInitialized, "o cofre deveria comecar nao inicializado");
        });

        await Test("cofre nao inicializado bloqueia leitura de segredos", async () =>
        {
            var error = await ExpectErrorAsync(() => client.SendRawAsync("get_secret", new { id = "CPF_PESSOAL" }));
            Check(error.Code == "bad_request", $"codigo inesperado: {error.Code}");
        });

        await Test("inicializa o cofre", async () =>
        {
            await client.InitVaultAsync(Passphrase, enableTotp: false);
            var health = await client.HealthAsync();
            Check(health.VaultInitialized, "o cofre nao ficou inicializado");
        });

        await Test("senha do cofre errada e rejeitada", async () =>
        {
            var error = await ExpectErrorAsync(() => client.InitVaultAsync("outra-senha", enableTotp: false));
            Check(error.Code == "conflict", $"codigo inesperado: {error.Code}");
        });

        await Test("cadastra segredos ficticios", async () =>
        {
            await client.RegisterEntryAsync(
                "CPF_PESSOAL",
                "cpf",
                "CPF pessoal (ficticio)",
                new[] { server.BaseUrl },
                CpfFake,
                Passphrase);

            await client.RegisterEntryAsync(
                "SENHA_PORTAL_A",
                "password",
                "Senha do portal A (ficticia)",
                new[] { server.BaseUrl },
                SenhaFake,
                Passphrase);
        });

        await Test("senha do cofre errada nao altera segredos", async () =>
        {
            var error = await ExpectErrorAsync(() => client.RegisterEntryAsync(
                "X", "generic", "X", new[] { server.BaseUrl }, "valor", "senha-errada"));
            Check(error.Code == "passphrase_invalid", $"codigo inesperado: {error.Code}");
        });

        await Test("listagem de registros expoe apenas metadados", async () =>
        {
            var entries = await client.ListEntriesAsync();
            Check(entries.Entries.Count == 2, $"esperava 2 registros, veio {entries.Entries.Count}");
            Check(entries.Entries.Any(e => e.Id == "CPF_PESSOAL"), "CPF_PESSOAL ausente");
            Check(!ContainsSecret(entries.Entries), "a listagem vazou um valor de segredo");
        });

        await Test("autoriza operacoes com alvo e acao fixos", async () =>
        {
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
                "enviar_cpf",
                "CPF_PESSOAL",
                "http.request",
                $"{server.BaseUrl}/api/cpf",
                "Envio ficticio de CPF",
                Array.Empty<string>(),
                Passphrase,
                new
                {
                    method = "POST",
                    url = $"{server.BaseUrl}/api/cpf",
                    contentType = "application/json",
                    bodyFields = new Dictionary<string, string> { ["cpf"] = "{{secret}}" },
                    headers = new Dictionary<string, string>(),
                    resultFields = new List<string>()
                });

            await client.AuthorizeOperationAsync(
                "eco_teste",
                "CPF_PESSOAL",
                "noop.echo",
                "eco",
                "Teste de redacao sem rede",
                Array.Empty<string>(),
                Passphrase);
        });

        await Test("alvo nao autorizado para o registro e recusado", async () =>
        {
            var error = await ExpectErrorAsync(() => client.AuthorizeOperationAsync(
                "op_indevida",
                "CPF_PESSOAL",
                "http.request",
                "https://site-nao-autorizado.exemplo.com/login",
                "alvo indevido",
                Array.Empty<string>(),
                Passphrase,
                new
                {
                    method = "POST",
                    url = "https://site-nao-autorizado.exemplo.com/login",
                    contentType = "application/json",
                    bodyFields = new Dictionary<string, string> { ["cpf"] = "{{secret}}" },
                    headers = new Dictionary<string, string>(),
                    resultFields = new List<string>()
                }));

            Check(error.Code == "target_not_allowed", $"codigo inesperado: {error.Code}");
        });

        await Test("segredo literal no template e recusado", async () =>
        {
            var error = await ExpectErrorAsync(() => client.AuthorizeOperationAsync(
                "op_literal",
                "SENHA_PORTAL_A",
                "http.request",
                $"{server.BaseUrl}/api/literal",
                "template com segredo literal",
                Array.Empty<string>(),
                Passphrase,
                new
                {
                    method = "POST",
                    url = $"{server.BaseUrl}/api/literal",
                    contentType = "application/json",
                    bodyFields = new Dictionary<string, string> { ["senha"] = SenhaFake },
                    headers = new Dictionary<string, string>(),
                    resultFields = new List<string>()
                }));

            Check(error.Code == "bad_request", $"codigo inesperado: {error.Code}");
        });

        await Test("solicitacao do agente nao devolve segredo", async () =>
        {
            var request = await client.RequestOperationAsync("login_portal_a",
                new Dictionary<string, string> { ["usuario"] = "usuario-ficticio" });

            Check(request.Status == "pending_approval", $"status inesperado: {request.Status}");
            Check(request.Requires == "passphrase", $"requisicao inesperada: {request.Requires}");
            Check(!ContainsSecret(request), "a solicitacao vazou o segredo");
        });

        await Test("aprovacao com senha errada falha", async () =>
        {
            var request = await client.RequestOperationAsync("login_portal_a",
                new Dictionary<string, string> { ["usuario"] = "usuario-ficticio" });

            var error = await ExpectErrorAsync(() => client.ApproveAsync(request.RequestId, "senha-errada"));
            Check(error.Code == "passphrase_invalid", $"codigo inesperado: {error.Code}");
        });

        await Test("aprovacao executa e devolve resultado sanitizado", async () =>
        {
            var request = await client.RequestOperationAsync("login_portal_a",
                new Dictionary<string, string> { ["usuario"] = "usuario-ficticio" });

            var approval = await client.ApproveAsync(request.RequestId, Passphrase);
            Check(approval.Status == "completed", $"status inesperado: {approval.Status}");

            var rendered = JsonSerializer.Serialize(approval);
            Check(rendered.Contains("***REDACTED***", StringComparison.Ordinal), "o resultado nao foi redigido");
            Check(!rendered.Contains(SenhaFake, StringComparison.Ordinal), "a senha vazou no resultado");
            Check(!rendered.Contains(CpfFake, StringComparison.Ordinal), "o cpf vazou no resultado");

            lock (server.ReceivedBodies)
            {
                Check(server.ReceivedBodies.Count > 0, "o servidor fake nao recebeu a requisicao");
                Check(server.ReceivedBodies[^1].Contains(SenhaFake, StringComparison.Ordinal),
                    "o broker nao enviou o segredo ao destino autorizado");
            }
        });

        await Test("resultado por status permanece sanitizado", async () =>
        {
            var request = await client.RequestOperationAsync("enviar_cpf");
            await client.ApproveAsync(request.RequestId, Passphrase);

            var status = await client.OperationStatusAsync(request.RequestId);
            var rendered = JsonSerializer.Serialize(status);
            Check(status.Status == "completed", $"status inesperado: {status.Status}");
            Check(!rendered.Contains(CpfFake, StringComparison.Ordinal), "o cpf vazou no status");
        });

        await Test("acao noop eco devolve apenas mascara", async () =>
        {
            var request = await client.RequestOperationAsync("eco_teste");
            var approval = await client.ApproveAsync(request.RequestId, Passphrase);

            var rendered = JsonSerializer.Serialize(approval.Result);
            Check(rendered.Contains("***REDACTED***", StringComparison.Ordinal), "o eco nao foi redigido");
            Check(!rendered.Contains(CpfFake, StringComparison.Ordinal), "o cpf vazou no eco");
        });

        await Test("operacao pode combinar dois registros autorizados", async () =>
        {
            await client.RegisterEntryAsync(
                "CPF_AUXILIAR",
                "generic",
                "Segundo registro (ficticio)",
                new[] { server.BaseUrl },
                "AuxiliarFicticio!42",
                Passphrase);

            await client.AuthorizeOperationAsync(
                "op_combinada",
                "SENHA_PORTAL_A",
                "http.request",
                $"{server.BaseUrl}/api/login",
                "Usa dois registros na mesma requisicao",
                Array.Empty<string>(),
                Passphrase,
                new
                {
                    method = "POST",
                    url = $"{server.BaseUrl}/api/login",
                    contentType = "application/json",
                    bodyFields = new Dictionary<string, string>
                    {
                        ["senha"] = "{{secret}}",
                        ["auxiliar"] = "{{secret:CPF_AUXILIAR}}"
                    },
                    headers = new Dictionary<string, string>(),
                    resultFields = new List<string>()
                });

            var request = await client.RequestOperationAsync("op_combinada");
            var approval = await client.ApproveAsync(request.RequestId, Passphrase);
            Check(approval.Status == "completed", $"status inesperado: {approval.Status}");

            var rendered = JsonSerializer.Serialize(approval);
            Check(!rendered.Contains(SenhaFake, StringComparison.Ordinal), "a senha vazou no resultado");
            Check(!rendered.Contains("AuxiliarFicticio!42", StringComparison.Ordinal), "o segredo auxiliar vazou");

            lock (server.ReceivedBodies)
            {
                var last = server.ReceivedBodies[^1];
                Check(last.Contains(SenhaFake, StringComparison.Ordinal), "a senha nao chegou ao destino");
                Check(last.Contains("AuxiliarFicticio!42", StringComparison.Ordinal), "o auxiliar nao chegou ao destino");
            }
        });

        await Test("referencia a registro sem permissao para o alvo e recusada", async () =>
        {
            await client.RegisterEntryAsync(
                "OUTRO_ALVO",
                "generic",
                "Registro de outro alvo (ficticio)",
                new[] { "https://outro-site.exemplo.com" },
                "OutroValorFicticio",
                Passphrase);

            var error = await ExpectErrorAsync(() => client.AuthorizeOperationAsync(
                "op_invalida",
                "SENHA_PORTAL_A",
                "http.request",
                $"{server.BaseUrl}/api/login",
                "referencia indevida",
                Array.Empty<string>(),
                Passphrase,
                new
                {
                    method = "POST",
                    url = $"{server.BaseUrl}/api/login",
                    contentType = "application/json",
                    bodyFields = new Dictionary<string, string>
                    {
                        ["senha"] = "{{secret}}",
                        ["outro"] = "{{secret:OUTRO_ALVO}}"
                    },
                    headers = new Dictionary<string, string>(),
                    resultFields = new List<string>()
                }));

            Check(error.Code == "target_not_allowed", $"codigo inesperado: {error.Code}");
        });

        await Test("agente nao consegue aprovar sem a senha do cofre", async () =>
        {
            var request = await client.RequestOperationAsync("login_portal_a",
                new Dictionary<string, string> { ["usuario"] = "usuario-ficticio" });

            var error = await ExpectErrorAsync(() => client.SendRawAsync("approve", new
            {
                requestId = request.RequestId
            }));

            Check(error.Code == "bad_request", $"codigo inesperado: {error.Code}");
        });

        await Test("agente nao consegue cadastrar segredo sem a senha do cofre", async () =>
        {
            var error = await ExpectErrorAsync(() => client.SendRawAsync("register_entry", new
            {
                id = "INTRUSAO",
                kind = "generic",
                label = "invasor",
                targets = new[] { server.BaseUrl },
                value = "valor-do-invasor"
            }));

            Check(error.Code == "bad_request", $"codigo inesperado: {error.Code}");
        });

        await Test("nenhum comando devolve segredo", async () =>
        {
            foreach (var command in new[] { "get_secret", "read_password", "list_secrets", "export" })
            {
                var error = await ExpectErrorAsync(() => client.SendRawAsync(command, new { id = "CPF_PESSOAL" }));
                Check(error.Code == "bad_request", $"comando {command} deveria ser desconhecido");
            }
        });

        await Test("TOTP habilitada exige codigo na aprovacao", async () =>
        {
            var secret = Totp.GenerateSecret();
            _totpSecret = secret;
            await client.SetTotpAsync(secret, Passphrase);

            var health = await client.HealthAsync();
            Check(health.TotpRequired, "a TOTP nao foi ativada");

            var request = await client.RequestOperationAsync("eco_teste");
            Check(request.Requires == "passphrase+totp", $"requisicao inesperada: {request.Requires}");

            var error = await ExpectErrorAsync(() => client.ApproveAsync(request.RequestId, Passphrase));
            Check(error.Code == "totp_required", $"codigo inesperado: {error.Code}");

            var wrong = await ExpectErrorAsync(() => client.ApproveAsync(request.RequestId, Passphrase, "000000"));
            Check(wrong.Code == "totp_invalid", $"codigo inesperado: {wrong.Code}");

            var code = Totp.GenerateCode(secret, DateTime.UtcNow);
            var approval = await client.ApproveAsync(request.RequestId, Passphrase, code);
            Check(approval.Status == "completed", $"status inesperado: {approval.Status}");
        });

        await Test("revogacao remove a operacao", async () =>
        {
            await client.RevokeOperationAsync("eco_teste", Passphrase);
            var operations = await client.ListOperationsAsync();
            Check(!operations.Operations.Any(o => o.Id == "eco_teste"), "a operacao revogada continua na lista");
        });

        await Test("remocao do registro apaga o segredo do cofre", async () =>
        {
            await client.DeleteEntryAsync("SENHA_PORTAL_A", Passphrase);
            var entries = await client.ListEntriesAsync();
            Check(!entries.Entries.Any(e => e.Id == "SENHA_PORTAL_A"), "o registro removido continua na lista");
        });

        await Test("o log do broker nao contem segredos", async () =>
        {
            var logPath = Path.Combine(home, "logs", "svault-broker.log");
            Check(File.Exists(logPath), "o log nao foi criado");

            var log = await File.ReadAllTextAsync(logPath);
            Check(!log.Contains(SenhaFake, StringComparison.Ordinal), "a senha vazou no log");
            Check(!log.Contains(CpfFake, StringComparison.Ordinal), "o cpf vazou no log");
            Check(!log.Contains(Passphrase, StringComparison.Ordinal), "a senha do cofre vazou no log");
        });

        await Test("a senha do cofre e trocada re-rotulando os segredos", async () =>
        {
            var nova = "nova-senha-de-teste-2026";
            await client.ChangePassphraseAsync(Passphrase, nova);

            var code = Totp.GenerateCode(_totpSecret!, DateTime.UtcNow);

            var request = await client.RequestOperationAsync("enviar_cpf");
            var error = await ExpectErrorAsync(() => client.ApproveAsync(request.RequestId, Passphrase, code));
            Check(error.Code == "passphrase_invalid", $"codigo inesperado: {error.Code}");

            var approval = await client.ApproveAsync(request.RequestId, nova, code);
            Check(approval.Status == "completed", $"status inesperado: {approval.Status}");

            var rendered = JsonSerializer.Serialize(approval);
            Check(!rendered.Contains(CpfFake, StringComparison.Ordinal), "o cpf vazou no resultado");
        });
    }

    private static bool ContainsSecret(object payload)
    {
        var rendered = JsonSerializer.Serialize(payload);
        return rendered.Contains(SenhaFake, StringComparison.Ordinal)
               || rendered.Contains(CpfFake, StringComparison.Ordinal);
    }

    private static async Task<BrokerCallException> ExpectErrorAsync(Func<Task> action)
    {
        try
        {
            await action();
        }
        catch (BrokerCallException ex)
        {
            return ex;
        }

        throw new InvalidOperationException("A chamada deveria ter falhado.");
    }

    private static void Check(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private static async Task Test(string name, Func<Task> body)
    {
        try
        {
            await body();
            _passed++;
            Console.WriteLine($"  [ok]   {name}");
        }
        catch (Exception ex)
        {
            _failed++;
            Console.WriteLine($"  [FALHA] {name}: {ex.Message}");
        }
    }

    private static void TryDelete(string directory)
    {
        try
        {
            Directory.Delete(directory, true);
        }
        catch
        {
        }
    }
}
