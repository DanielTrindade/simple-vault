using System.Diagnostics;
using System.Text.Json;
using SVault.Broker;
using SVault.Client;
using SVault.Core.Crypto;
using SVault.Core.Logging;
using SVault.Core.Protocol;
using SVault.Core.Storage;

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

        await RunVaultStoreRegressionsAsync();

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

    private static async Task RunVaultStoreRegressionsAsync()
    {
        await Test("redacao cobre segredos curtos e JSON escapado sem alterar a mascara", () =>
        {
            var redactor = new SVault.Core.Redaction.SecretRedactor(System.Text.Encoding.UTF8.GetBytes("fake&value"));
            var json = redactor.Redact("{\"echo\":\"fake\\u0026value\"}");
            Check(!json.Contains("fake", StringComparison.Ordinal), "o segredo JSON escapado permaneceu visivel");
            var shortRedactor = new SVault.Core.Redaction.SecretRedactor(System.Text.Encoding.UTF8.GetBytes("R"));
            var once = shortRedactor.Redact("secret=R");
            Check(once == shortRedactor.Redact(once), "a segunda redação alterou o marcador");
            var markerSecret = new SVault.Core.Redaction.SecretRedactor(System.Text.Encoding.UTF8.GetBytes("***REDACTED***suffix-privado"));
            Check(!markerSecret.Redact("prefix=***REDACTED***suffix-privado").Contains("suffix-privado", StringComparison.Ordinal), "segredo que comeca pelo marcador permaneceu visivel");
            var booleanSecret = new SVault.Core.Redaction.SecretRedactor(System.Text.Encoding.UTF8.GetBytes("false"));
            Check(booleanSecret.Redact("{\"value\":false}").Contains(SVault.Core.Redaction.SecretRedactor.Mask, StringComparison.Ordinal), "valor booleano igual ao segredo nao foi redigido");
            return Task.CompletedTask;
        });

        await Test("alteracoes administrativas exigem o TOTP atual", () =>
        {
            var folder = Path.Combine(Path.GetTempPath(), "svault-totp-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(folder);
            try
            {
                var store = new VaultStore(Path.Combine(folder, "state.json"), new MemoryCredentialStore());
                const string passphrase = "senha-totp-de-teste";
                const string secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
                store.Initialize(passphrase, true, secret);
                var code = Totp.GenerateCode(secret, DateTime.UtcNow);
                const string newSecret = "KRUGS4ZANFZSAYJAKRUGS4ZANFZSAYJA";
                ExpectStoreError(() => store.SetTotp(newSecret, passphrase), "totp_invalid");
                ExpectStoreError(() => store.DisableTotp(passphrase), "totp_invalid");
                ExpectStoreError(() => store.ChangePassphrase(passphrase, "nova-senha-totp"), "totp_invalid");
                ExpectStoreError(() => store.Reset(passphrase), "totp_invalid");
                Check(store.TotpEnabled && store.VerifyPassphrase(passphrase), "uma administracao sem TOTP alterou o cofre");
                store.SetTotp(newSecret, passphrase, code);
                Check(store.TotpEnabled, "TOTP valido nao permitiu a troca do fator");
                var newCode = Totp.GenerateCode(newSecret, DateTime.UtcNow);
                store.DisableTotp(passphrase, newCode);
                Check(!store.TotpEnabled, "TOTP valido nao permitiu a desativacao");
            }
            finally
            {
                TryDelete(folder);
            }
            return Task.CompletedTask;
        });

        await Test("politica de URL distingue caminho e normaliza apenas esquema e host", () =>
        {
            Check(!SVault.Core.Storage.TargetPolicy.IsTargetAllowed(new[] { "https://example.com/Admin" }, "https://example.com/admin"), "caminhos diferiram apenas por caixa e foram aceitos");
            Check(SVault.Core.Storage.TargetPolicy.IsTargetAllowed(new[] { "https://example.com/Admin" }, "HTTPS://EXAMPLE.COM/Admin?x=1"), "host ou query permitida foi recusada");
            Check(!SVault.Core.Storage.TargetPolicy.IsTargetAllowed(new[] { "https://example.com/Admin" }, "https://user@example.com/Admin"), "userinfo foi aceito");
            Check(!SVault.Core.Storage.TargetPolicy.IsTargetAllowed(new[] { "https://example.com/Admin" }, "https://example.com/Admin#frag"), "fragmento foi aceito");
            return Task.CompletedTask;
        });

        await Test("interpolacao trata delimitadores em segredos e parametros como dados", () =>
        {
            var secret = System.Text.Encoding.UTF8.GetBytes("valor{{injetado}}");
            var parameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["p"] = "param{{injetado}}"
            };
            var context = new SVault.Core.Operations.OperationContext
            {
                Operation = new SVault.Core.Storage.OperationRecord
                {
                    Action = SVault.Core.Operations.OperationEngine.ActionHttpRequest,
                    Params = new List<string> { "p" },
                    Http = new SVault.Core.Storage.HttpRequestRecord
                    {
                        BodyFields = new Dictionary<string, string> { ["value"] = "{{secret}}/{{param:p}}" }
                    }
                },
                Secret = secret,
                ReferencedSecrets = new Dictionary<string, byte[]>(),
                Parameters = parameters,
                Redactor = new SVault.Core.Redaction.SecretRedactor(new[] { secret }),
                Cancellation = CancellationToken.None
            };
            try
            {
                var result = SVault.Core.Operations.OperationEngine.ResolveTemplate("{{secret}}/{{param:p}}", context);
                Check(result == "valor{{injetado}}/param{{injetado}}", "valores com chaves foram reinterpretados ou recusados");
                var composed = SVault.Core.Operations.OperationEngine.ResolveTemplate("inicio-{{secret}}-fim", context);
                Check(composed == "inicio-valor{{injetado}}-fim", "interpolacao composta alterou o segredo");
                try
                {
                    SVault.Core.Operations.OperationEngine.ResolveTemplate("{{placeholder-invalido}}", context);
                    throw new InvalidOperationException("template original invalido foi aceito");
                }
                catch (SVault.Core.Operations.OperationFailure)
                {
                    Check(true, "a gramática original foi validada");
                }
            }
            finally
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(secret);
            }
            return Task.CompletedTask;
        });

        await Test("process.stdin legado e recusado sem iniciar executavel", async () =>
        {
            var context = new SVault.Core.Operations.OperationContext
            {
                Operation = new SVault.Core.Storage.OperationRecord
                {
                    Action = SVault.Core.Operations.OperationEngine.ActionProcessStdin,
                    Process = new SVault.Core.Storage.ProcessRecord { Executable = "executavel-inexistente" }
                },
                Secret = Array.Empty<byte>(),
                ReferencedSecrets = new Dictionary<string, byte[]>(),
                Parameters = new Dictionary<string, string>(),
                Redactor = new SVault.Core.Redaction.SecretRedactor(Array.Empty<byte[]>()),
                Cancellation = CancellationToken.None
            };
            try
            {
                await SVault.Core.Operations.OperationEngine.ExecuteAsync(context);
                throw new InvalidOperationException("process.stdin legado foi executado");
            }
            catch (SVault.Core.Operations.OperationFailure)
            {
                Check(true, "a execucao de processo permaneceu desabilitada");
            }
        });

        await Test("rotacao falha sem danificar geracao anterior", () =>
        {
            var folder = Path.Combine(Path.GetTempPath(), "svault-rotation-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(folder);
            try
            {
                var stateFile = Path.Combine(folder, "state.json");
                var storage = new FailingCredentialStore(new MemoryCredentialStore());
                var store = new VaultStore(stateFile, storage);
                store.Initialize("senha-antiga-de-teste", false, null);
                store.RegisterEntry("A", "generic", "A", Array.Empty<string>(), System.Text.Encoding.UTF8.GetBytes("segredo-a"), "senha-antiga-de-teste");
                store.RegisterEntry("B", "generic", "B", Array.Empty<string>(), System.Text.Encoding.UTF8.GetBytes("segredo-b"), "senha-antiga-de-teste");
                storage.FailOnWrite(2);

                try
                {
                    store.ChangePassphrase("senha-antiga-de-teste", "senha-nova-de-teste");
                    throw new InvalidOperationException("a falha de escrita deveria interromper a rotacao");
                }
                catch (IOException)
                {
                }

                storage.FailOnWrite(null);
                var reopened = new VaultStore(stateFile, storage);
                Check(reopened.VerifyPassphrase("senha-antiga-de-teste"), "a senha antiga deixou de abrir o cofre");
                Check(!reopened.VerifyPassphrase("senha-nova-de-teste"), "a senha nova foi confirmada sem commit");
                Check(System.Text.Encoding.UTF8.GetString(reopened.UnwrapSecret("A", "senha-antiga-de-teste")) == "segredo-a", "o primeiro segredo foi alterado");
                Check(System.Text.Encoding.UTF8.GetString(reopened.UnwrapSecret("B", "senha-antiga-de-teste")) == "segredo-b", "o segundo segredo foi alterado");

                storage.FailOnRead(1);
                try
                {
                    reopened.ChangePassphrase("senha-antiga-de-teste", "senha-nova-de-teste");
                    throw new InvalidOperationException("a falha de leitura deveria interromper a rotacao");
                }
                catch (IOException)
                {
                }
                storage.FailOnRead(null);
                reopened = new VaultStore(stateFile, storage);
                Check(reopened.VerifyPassphrase("senha-antiga-de-teste"), "a falha de leitura invalidou a senha antiga");
                Check(System.Text.Encoding.UTF8.GetString(reopened.UnwrapSecret("A", "senha-antiga-de-teste")) == "segredo-a", "a falha de leitura alterou o primeiro segredo");

                FileStream? commitBlock = null;
                storage.FailOnWrite(null);
                storage.AfterWrite = number =>
                {
                    if (number == 2)
                    {
                        commitBlock = new FileStream(stateFile, FileMode.Open, FileAccess.Read, FileShare.Read);
                    }
                };
                try
                {
                    reopened.ChangePassphrase("senha-antiga-de-teste", "senha-nova-de-teste");
                    throw new InvalidOperationException("o bloqueio do commit deveria interromper a rotacao");
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                }
                finally
                {
                    commitBlock?.Dispose();
                    storage.AfterWrite = null;
                }
                reopened = new VaultStore(stateFile, storage);
                Check(reopened.VerifyPassphrase("senha-antiga-de-teste"), "a falha no commit invalidou a senha antiga");
                Check(System.Text.Encoding.UTF8.GetString(reopened.UnwrapSecret("B", "senha-antiga-de-teste")) == "segredo-b", "a falha no commit alterou o segundo segredo");

                reopened.ChangePassphrase("senha-antiga-de-teste", "senha-nova-de-teste");
                var afterCommit = new VaultStore(stateFile, storage);
                Check(!afterCommit.VerifyPassphrase("senha-antiga-de-teste"), "a senha antiga permaneceu ativa apos commit");
                Check(afterCommit.VerifyPassphrase("senha-nova-de-teste"), "a senha nova nao abriu apos commit");
                Check(System.Text.Encoding.UTF8.GetString(afterCommit.UnwrapSecret("B", "senha-nova-de-teste")) == "segredo-b", "segredo ausente apos commit");

                try
                {
                    afterCommit.ChangePassphrase("senha-nova-de-teste", "curta");
                    throw new InvalidOperationException("senha fora da politica deveria ser recusada");
                }
                catch (SVault.Core.Storage.VaultException ex) when (ex.Code == "bad_request")
                {
                }

                Check(afterCommit.VerifyPassphrase("senha-nova-de-teste"), "senha curta alterou o estado persistido");
                storage.Write("SVault:entry:sentinela", "teste", System.Text.Encoding.UTF8.GetBytes("nao-remover"));
                afterCommit.Reset("senha-nova-de-teste");
                Check(storage.ListTargets("SVault:entry").SequenceEqual(new[] { "SVault:entry:sentinela" }), "reset removeu alvo de terceiro ou manteve alvo inventariado");
            }
            finally
            {
                TryDelete(folder);
            }
            return Task.CompletedTask;
        });

        await Test("rotacao preserva TOTP e carrega estado legado sem geracao", () =>
        {
            var folder = Path.Combine(Path.GetTempPath(), "svault-legacy-rotation-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(folder);
            try
            {
                var stateFile = Path.Combine(folder, "state.json");
                var credentials = new MemoryCredentialStore();
                var store = new VaultStore(stateFile, credentials);
                const string oldPassphrase = "senha-legada-de-teste";
                const string totpSecret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
                store.Initialize(oldPassphrase, true, totpSecret);
                store.RegisterEntry("A", "generic", "A", Array.Empty<string>(), System.Text.Encoding.UTF8.GetBytes("segredo-legado"), oldPassphrase);

                var legacyState = SVault.Core.Protocol.Json.Deserialize<VaultState>(File.ReadAllText(stateFile))!;
                Check(legacyState.Entries.Count == 1, "fixture nao persistiu um registro");
                var entry = legacyState.Entries.Single();
                var legacyTarget = "SVault:entry:A";
                var currentTarget = legacyState.KnownCredentialTargets.Single(target => target.EndsWith(":" + entry.Id, StringComparison.Ordinal));
                var blob = credentials.Read(currentTarget)!;
                credentials.Write(legacyTarget, entry.Id, blob);
                legacyState.CredentialGeneration = null;
                entry.CredentialVersion = null;
                File.WriteAllText(stateFile, SVault.Core.Protocol.Json.Serialize(legacyState));

                var reopenedLegacy = new VaultStore(stateFile, credentials);
                Check(reopenedLegacy.VerifyPassphrase(oldPassphrase), "estado legado sem geracao nao abriu");
                Check(System.Text.Encoding.UTF8.GetString(reopenedLegacy.UnwrapSecret("A", oldPassphrase)) == "segredo-legado", "alvo de credencial legado nao foi carregado");
                var oldCode = Totp.GenerateCode(totpSecret, DateTime.UtcNow);
                reopenedLegacy.ChangePassphrase(oldPassphrase, "senha-nova-legada", oldCode);

                var reopenedRotated = new VaultStore(stateFile, credentials);
                Check(reopenedRotated.VerifyPassphrase("senha-nova-legada"), "rotacao de estado legado nao persistiu a senha nova");
                Check(reopenedRotated.TotpEnabled, "rotacao desativou o TOTP");
                var newCode = Totp.GenerateCode(totpSecret, DateTime.UtcNow);
                reopenedRotated.ChangePassphrase("senha-nova-legada", "terceira-senha-legada", newCode);
                Check(reopenedRotated.VerifyPassphrase("terceira-senha-legada"), "TOTP preservado nao autorizou nova rotacao");
                Check(reopenedRotated.TotpEnabled, "a segunda rotacao desativou o TOTP");
                Check(System.Text.Encoding.UTF8.GetString(reopenedRotated.UnwrapSecret("A", "terceira-senha-legada")) == "segredo-legado", "rotacao de estado legado perdeu o segredo");
            }
            finally
            {
                TryDelete(folder);
            }
            return Task.CompletedTask;
        });
    }

    private sealed class CountingCredentialStore(ICredentialStore inner) : ICredentialStore
    {
        private int _reads;
        public int ReadCount => Volatile.Read(ref _reads);
        public void ResetReadCount() => Interlocked.Exchange(ref _reads, 0);
        public void Write(string target, string userName, byte[] secret) => inner.Write(target, userName, secret);
        public byte[]? Read(string target)
        {
            Interlocked.Increment(ref _reads);
            return inner.Read(target);
        }
        public void Delete(string target) => inner.Delete(target);
        public IReadOnlyList<string> ListTargets(string filter) => inner.ListTargets(filter);
    }

    private sealed class FailingCredentialStore(ICredentialStore inner) : ICredentialStore
    {
        private int _writes;
        private int _reads;
        public int? FailWriteNumber { get; set; }
        public int? FailReadNumber { get; set; }
        public Action<int>? AfterWrite { get; set; }
        public void FailOnWrite(int? number)
        {
            _writes = 0;
            _reads = 0;
            FailWriteNumber = number;
            FailReadNumber = null;
        }
        public void Write(string target, string userName, byte[] secret)
        {
            _writes++;
            if (_writes == FailWriteNumber)
            {
                throw new IOException("falha de armazenamento sintetica");
            }

            inner.Write(target, userName, secret);
            AfterWrite?.Invoke(_writes);
        }
        public void FailOnRead(int? number)
        {
            _reads = 0;
            FailReadNumber = number;
        }
        public byte[]? Read(string target)
        {
            _reads++;
            if (_reads == FailReadNumber)
            {
                throw new IOException("falha sintetica de leitura");
            }
            return inner.Read(target);
        }
        public void Delete(string target) => inner.Delete(target);
        public IReadOnlyList<string> ListTargets(string filter) => inner.ListTargets(filter);
    }

    private static Process StartBroker(string exe, string home, string pipeName)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = exe,
            Arguments = $"--console --in-memory-credentials --home \"{home}\" --pipe {pipeName}",
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
                        ["usuario"] = "Bearer {{param:usuario}} {{secret}}",
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

            await client.AuthorizeOperationAsync(
                "json_invalido",
                "CPF_PESSOAL",
                "http.request",
                $"{server.BaseUrl}/invalid-json",
                "Teste de selecao restritiva",
                Array.Empty<string>(),
                Passphrase,
                new
                {
                    method = "POST",
                    url = $"{server.BaseUrl}/invalid-json",
                    contentType = "application/json",
                    bodyFields = new Dictionary<string, string> { ["cpf"] = "{{secret}}" },
                    headers = new Dictionary<string, string>(),
                    resultFields = new[] { "safe" }
                });
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

        await Test("segredos de um a tres caracteres nao podem ser persistidos em templates", async () =>
        {
            var created = false;
            try
            {
                await client.RegisterEntryAsync("SEGREDO_CURTO", "generic", "segredo curto sintético", new[] { server.BaseUrl }, "a", Passphrase);
                created = true;
                var cases = new[] { "a", "bc", "xyz", " " };
                for (var index = 0; index < cases.Length; index++)
                {
                    var secret = cases[index];
                    await client.UpdateEntryAsync("SEGREDO_CURTO", secret, null, null, Passphrase);
                    var literalTemplate = $"literal-prefix-{secret}-suffix";
                    var error = await ExpectErrorAsync(() => client.AuthorizeOperationAsync(
                        $"curto_literal_{index}",
                        "SEGREDO_CURTO",
                        "http.request",
                        $"{server.BaseUrl}/curto/{index}",
                        "validacao de segredo literal curto",
                        Array.Empty<string>(),
                        Passphrase,
                        new
                        {
                            method = "POST",
                            url = $"{server.BaseUrl}/curto/{index}",
                            contentType = "application/json",
                            bodyFields = new Dictionary<string, string> { ["value"] = literalTemplate },
                            headers = new Dictionary<string, string>(),
                            resultFields = Array.Empty<string>()
                        }));
                    Check(error.Code == "bad_request", $"literal de {secret.Length} caractere(s) foi aceito");

                    if (index == 2)
                    {
                        var adjacent = await ExpectErrorAsync(() => client.AuthorizeOperationAsync(
                            "curto_placeholder_adjacente",
                            "SEGREDO_CURTO",
                            "http.request",
                            $"{server.BaseUrl}/curto/placeholder",
                            "literal entre placeholders",
                            new[] { "p" },
                            Passphrase,
                            new
                            {
                                method = "POST",
                                url = $"{server.BaseUrl}/curto/placeholder",
                                contentType = "application/json",
                                bodyFields = new Dictionary<string, string> { ["value"] = "{{secret}}xyz{{param:p}}" },
                                headers = new Dictionary<string, string>(),
                                resultFields = Array.Empty<string>()
                            }));
                        Check(adjacent.Code == "bad_request", "segredo curto adjacente a placeholders foi aceito");
                    }
                }

                var persisted = File.ReadAllText(Path.Combine(home, "state", "vault-state.json"));
                Check(!persisted.Contains("literal-prefix-xyz-suffix", StringComparison.Ordinal), "literal curto apareceu no arquivo de estado");
                var operations = await client.ListOperationsAsync();
                Check(!operations.Operations.Any(operation => operation.Id.StartsWith("curto_literal_", StringComparison.Ordinal)), "autorizacao recusada foi persistida");
            }
            finally
            {
                if (created)
                {
                    await client.DeleteEntryAsync("SEGREDO_CURTO", Passphrase);
                }
            }
        });

        await Test("templates invalidos sao recusados antes de persistir autorizacao", async () =>
        {
            var error = await ExpectErrorAsync(() => client.AuthorizeOperationAsync(
                "template_parametro_nao_declarado",
                "CPF_PESSOAL",
                "http.request",
                $"{server.BaseUrl}/template-invalido",
                "template com parametro nao declarado",
                Array.Empty<string>(),
                Passphrase,
                new
                {
                    method = "POST",
                    url = $"{server.BaseUrl}/template-invalido",
                    contentType = "application/json",
                    bodyFields = new Dictionary<string, string> { ["value"] = "{{param:ausente}}" },
                    headers = new Dictionary<string, string>(),
                    resultFields = Array.Empty<string>()
                }));
            Check(error.Code == "bad_request", $"template invalido retornou {error.Code}");
            var operations = await client.ListOperationsAsync();
            Check(!operations.Operations.Any(operation => operation.Id == "template_parametro_nao_declarado"), "template invalido foi persistido");
        });

        await Test("URL efetiva de autorizacao legada e revalidada antes de abrir segredos", async () =>
        {
            var folder = Path.Combine(Path.GetTempPath(), "svault-legacy-url-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(folder);
            try
            {
                var credentials = new CountingCredentialStore(new MemoryCredentialStore());
                var store = new VaultStore(Path.Combine(folder, "state.json"), credentials);
                const string passphrase = "senha-legada-url";
                store.Initialize(passphrase, false, null);
                var target = server.BaseUrl + "/Admin";
                store.RegisterEntry("LEGACY_URL", "generic", "destino legado", new[] { target }, System.Text.Encoding.UTF8.GetBytes("segredo-sintetico"), passphrase);
                store.AuthorizeOperation(new OperationRecord
                {
                    Id = "http_legado",
                    EntryId = "LEGACY_URL",
                    Action = "http.request",
                    Target = target,
                    Http = new HttpRequestRecord
                    {
                        Method = "GET",
                        Url = server.BaseUrl + "/admin",
                        BodyFields = new Dictionary<string, string>(),
                        Headers = new Dictionary<string, string>()
                    }
                }, passphrase);

                var engine = new BrokerEngine(store, new VaultLog(Path.Combine(folder, "broker.log")), new SVault.Core.BrokerConfig());
                var requestResponse = await engine.HandleAsync(new Envelope
                {
                    Cmd = "request_operation",
                    Body = JsonSerializer.SerializeToElement(new { opId = "http_legado", @params = new { } }, Json.Options)
                }, "sintetico");
                Check(requestResponse.Ok && requestResponse.Data.HasValue, "a solicitacao legada de teste nao foi criada");
                var request = JsonSerializer.Deserialize<SVault.Core.Protocol.OperationRequestResult>(requestResponse.Data!.Value.GetRawText(), Json.Options)!;
                credentials.ResetReadCount();
                int receivedBefore;
                lock (server.ReceivedBodies) receivedBefore = server.ReceivedBodies.Count;

                var approval = await engine.HandleAsync(new Envelope
                {
                    Cmd = "approve",
                    Body = JsonSerializer.SerializeToElement(new { requestId = request.RequestId, passphrase }, Json.Options)
                }, "sintetico");

                int receivedAfter;
                lock (server.ReceivedBodies) receivedAfter = server.ReceivedBodies.Count;
                Check(!approval.Ok && approval.Error?.Code == "target_not_allowed", "URL legada divergente nao foi recusada");
                Check(credentials.ReadCount == 0, "segredo foi aberto antes de validar a URL efetiva");
                Check(receivedAfter == receivedBefore, "pedido chegou ao destino fora do alvo autorizado");
            }
            finally
            {
                TryDelete(folder);
            }
        });

        await Test("solicitacao do agente nao devolve segredo", async () =>
        {
            var request = await client.RequestOperationAsync("login_portal_a",
                new Dictionary<string, string> { ["usuario"] = "usuario-ficticio" });

            Check(request.Status == "pending_approval", $"status inesperado: {request.Status}");
            Check(request.Requires == "passphrase", $"requisicao inesperada: {request.Requires}");
            Check(request.Summary.Parameters.TryGetValue("usuario", out var shown) && shown == "usuario-ficticio", "parametro efetivo ausente do resumo");
            Check(!ContainsSecret(request), "a solicitacao vazou o segredo");
        });

        await Test("parametro obrigatorio ausente e recusado antes de criar solicitacao", async () =>
        {
            var error = await ExpectErrorAsync(() => client.RequestOperationAsync("login_portal_a"));
            Check(error.Code == "bad_request", $"codigo inesperado: {error.Code}");
            var typeError = await ExpectErrorAsync(() => client.SendRawAsync("request_operation", new { opId = "login_portal_a", @params = new { usuario = 7 } }));
            Check(typeError.Code == "bad_request", $"tipo de parametro inesperado aceito: {typeError.Code}");
        });

        await Test("JSON invalido nunca retorna corpo fora da selecao", async () =>
        {
            var request = await client.RequestOperationAsync("json_invalido");
            var result = await client.ApproveAsync(request.RequestId, Passphrase);
            var rendered = JsonSerializer.Serialize(result);
            Check(result.Status == "failed", $"status inesperado: {result.Status}");
            Check(!rendered.Contains("raw-invalid-secret", StringComparison.Ordinal), "corpo JSON invalido foi devolvido");
            Check(result.Error == "Falha na execucao autorizada.", "erro de execucao expôs detalhe externo");
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
                Check(server.ReceivedBodies[^1].Contains("Bearer usuario-ficticio", StringComparison.Ordinal),
                    "template composto nao resolveu o parametro junto com texto literal");
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

        await Test("aprovacao concorrente executa uma unica requisicao", async () =>
        {
            var request = await client.RequestOperationAsync("login_portal_a", new Dictionary<string, string> { ["usuario"] = "concorrente" });
            int before;
            lock (server.ReceivedBodies) before = server.ReceivedBodies.Count;

            async Task<string> AttemptAsync()
            {
                try
                {
                    var result = await client.ApproveAsync(request.RequestId, Passphrase);
                    return result.Status ?? "unknown";
                }
                catch (BrokerCallException ex)
                {
                    return ex.Code ?? "error";
                }
            }

            var outcomes = await Task.WhenAll(AttemptAsync(), AttemptAsync());
            Check(outcomes.Count(value => value == "completed") == 1, "nao houve exatamente uma aprovacao concluida");
            Check(outcomes.Count(value => value == "conflict") == 1, "a segunda aprovacao nao recebeu conflito");
            lock (server.ReceivedBodies) Check(server.ReceivedBodies.Count == before + 1, "a requisicao foi enviada mais de uma vez");
            var rejected = await ExpectErrorAsync(() => client.RejectAsync(request.RequestId, Passphrase));
            Check(rejected.Code == "conflict", "rejeicao sobrescreveu uma operacao concluida");
        });

        await Test("acao noop eco devolve apenas mascara", async () =>
        {
            var request = await client.RequestOperationAsync("eco_teste");
            var approval = await client.ApproveAsync(request.RequestId, Passphrase);

            var rendered = JsonSerializer.Serialize(approval.Result);
            Check(rendered.Contains("***REDACTED***", StringComparison.Ordinal), "o eco nao foi redigido");
            Check(!rendered.Contains(CpfFake, StringComparison.Ordinal), "o cpf vazou no eco");
        });

        await Test("revogar e reautorizar mesmo ID invalida pedido antigo", async () =>
        {
            var request = await client.RequestOperationAsync("eco_teste");
            await client.RevokeOperationAsync("eco_teste", Passphrase);
            await client.AuthorizeOperationAsync("eco_teste", "CPF_PESSOAL", "noop.echo", "eco", "Teste de redacao sem rede", Array.Empty<string>(), Passphrase);
            var error = await ExpectErrorAsync(() => client.ApproveAsync(request.RequestId, Passphrase));
            Check(error.Code == "conflict", $"pedido revogado foi reutilizado: {error.Code}");
        });

        await Test("mudanca de registro invalida pedido pendente", async () =>
        {
            var request = await client.RequestOperationAsync("login_portal_a", new Dictionary<string, string> { ["usuario"] = "alvo-alterado" });
            var previousCount = server.ReceivedBodies.Count;
            await client.UpdateEntryAsync("SENHA_PORTAL_A", null, null, new[] { server.BaseUrl + "/changed" }, Passphrase);
            var error = await ExpectErrorAsync(() => client.ApproveAsync(request.RequestId, Passphrase));
            Check(error.Code == "conflict", $"pedido continuou válido após revisão do registro: {error.Code}");
            await client.UpdateEntryAsync("SENHA_PORTAL_A", null, null, new[] { server.BaseUrl }, Passphrase);
            Check(server.ReceivedBodies.Count == previousCount, "pedido inválido alcançou o servidor");
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
            var code = Totp.GenerateCode(_totpSecret!, DateTime.UtcNow);
            await client.ChangePassphraseAsync(Passphrase, nova, code);

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

    private static void ExpectStoreError(Action action, string code)
    {
        try
        {
            action();
        }
        catch (SVault.Core.Storage.VaultException ex) when (ex.Code == code)
        {
            return;
        }

        throw new InvalidOperationException($"esperava erro {code}");
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
