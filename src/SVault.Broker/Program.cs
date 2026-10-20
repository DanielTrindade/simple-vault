using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.WindowsServices;
using SVault.Broker;
using SVault.Core;
using SVault.Core.Logging;
using SVault.Core.Protocol;
using SVault.Core.Storage;

var options = BrokerOptions.Parse(args);

if (options.Console)
{
    Paths.EnsureDirectories();
}

var config = BrokerConfig.Load(options.ConfigPath);
var log = new VaultLog(options.LogPath);
var store = new VaultStore(options.StatePath, options.InMemoryCredentials ? new MemoryCredentialStore() : null);
var engine = new BrokerEngine(store, log, config);

var currentSid = System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value ?? string.Empty;
var allowedSids = config.AllowedClientSids
    .Concat(new[] { currentSid })
    .Where(sid => !string.IsNullOrWhiteSpace(sid))
    .Distinct(StringComparer.OrdinalIgnoreCase)
    .ToArray();

var security = PipeSecurityFactory.Build(currentSid, allowedSids);

var host = Host.CreateDefaultBuilder(args)
    .UseWindowsService(options =>
    {
        options.ServiceName = "SVaultBroker";
    })
    .ConfigureServices(services =>
    {
        services.AddSingleton(sp => new BrokerRuntime(engine, log, security, options));
        services.AddHostedService<PipeServerService>();
    })
    .Build();

if (options.Console)
{
    Console.WriteLine($"SVault broker em modo console.");
    Console.WriteLine($"  home      : {options.Home}");
    Console.WriteLine($"  pipe      : \\\\.\\pipe\\{options.PipeName}");
    Console.WriteLine($"  identidade: {Environment.UserName}@{Environment.MachineName}");
    Console.WriteLine($"  cofre     : {(store.IsInitialized ? "inicializado" : "nao inicializado")}");
    Console.WriteLine("Pressione Ctrl+C para encerrar.");

    await host.RunAsync();
    return 0;
}

await host.RunAsync();
return 0;

namespace SVault.Broker
{
    public sealed class BrokerOptions
    {
        public bool Console { get; init; }
        public string? Home { get; init; }
        public string? ConfigPath { get; init; }
        public string? StatePath { get; init; }
        public string? LogPath { get; init; }
        public bool InMemoryCredentials { get; init; }
        public string PipeName { get; init; } = Paths.PipeName;

        public static BrokerOptions Parse(string[] args)
        {
            var console = args.Contains("--console", StringComparer.OrdinalIgnoreCase);
            var home = GetValue(args, "--home");
            var configPath = GetValue(args, "--config");
            var statePath = GetValue(args, "--state");
            var logPath = GetValue(args, "--log");
            var pipeName = GetValue(args, "--pipe");
            var inMemoryCredentials = args.Contains("--in-memory-credentials", StringComparer.OrdinalIgnoreCase);
            if (inMemoryCredentials && !console)
            {
                throw new ArgumentException("O armazenamento em memoria so pode ser usado em modo console.");
            }

            if (string.IsNullOrWhiteSpace(home))
            {
                var envHome = Environment.GetEnvironmentVariable(Paths.EnvHome);
                if (!string.IsNullOrWhiteSpace(envHome))
                {
                    home = envHome;
                }
                else if (console)
                {
                    home = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SVault");
                }
                else
                {
                    home = Paths.Home;
                }
            }

            if (!string.IsNullOrWhiteSpace(home))
            {
                Environment.SetEnvironmentVariable(Paths.EnvHome, home);
            }

            return new BrokerOptions
            {
                Console = console,
                Home = home!,
                ConfigPath = configPath ?? Path.Combine(home!, BrokerConfig.FileName),
                StatePath = statePath ?? Path.Combine(home!, "state", "vault-state.json"),
                LogPath = logPath ?? Path.Combine(home!, "logs", "svault-broker.log"),
                PipeName = string.IsNullOrWhiteSpace(pipeName) ? Paths.PipeName : pipeName.Trim(),
                InMemoryCredentials = inMemoryCredentials
            };
        }

        private static string? GetValue(string[] args, string name)
        {
            var index = Array.FindIndex(args, a => string.Equals(a, name, StringComparison.OrdinalIgnoreCase));
            if (index >= 0 && index + 1 < args.Length)
            {
                return args[index + 1];
            }

            return null;
        }
    }

    public sealed class BrokerRuntime
    {
        public BrokerRuntime(BrokerEngine engine, VaultLog log, System.IO.Pipes.PipeSecurity security, BrokerOptions options)
        {
            Engine = engine;
            Log = log;
            Security = security;
            Options = options;
        }

        public BrokerEngine Engine { get; }
        public VaultLog Log { get; }
        public System.IO.Pipes.PipeSecurity Security { get; }
        public BrokerOptions Options { get; }
    }

    public sealed class PipeServerService : BackgroundService
    {
        private readonly BrokerRuntime _runtime;

        public PipeServerService(BrokerRuntime runtime)
        {
            _runtime = runtime;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _runtime.Log.Write("broker_started", new Dictionary<string, object?>
            {
                ["identity"] = Environment.UserName + "@" + Environment.MachineName,
                ["pipe"] = _runtime.Options.PipeName
            });

            var server = new PipeServer(
                _runtime.Options.PipeName,
                _runtime.Security,
                HandleAsync,
                _runtime.Log);

            await server.RunAsync(stoppingToken).ConfigureAwait(false);
        }

        private async Task<byte[]> HandleAsync(byte[] requestBytes, string clientSid)
        {
            EnvelopeResponse response;
            try
            {
                var envelope = Json.Deserialize<Envelope>(Encoding.UTF8.GetString(requestBytes));
                if (envelope is null)
                {
                    response = new EnvelopeResponse
                    {
                        Ok = false,
                        Error = new ErrorPayload { Code = ErrorCodes.BadRequest, Message = "Envelope invalido." }
                    };
                }
                else
                {
                    response = await _runtime.Engine.HandleAsync(envelope, clientSid).ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                _runtime.Log.Write("request_error", new Dictionary<string, object?>
                {
                    ["type"] = ex.GetType().Name
                });

                response = new EnvelopeResponse
                {
                    Ok = false,
                    Error = new ErrorPayload { Code = ErrorCodes.Internal, Message = "Falha interna no broker." }
                };
            }

            return Encoding.UTF8.GetBytes(Json.Serialize(response));
        }
    }
}
