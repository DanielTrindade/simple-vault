namespace SVault.Core;

public static class Paths
{
    public const string PipeName = "svault.broker.v1";

    public const string EnvHome = "SVAULT_HOME";

    public static string Home
    {
        get
        {
            var configured = Environment.GetEnvironmentVariable(EnvHome);
            if (!string.IsNullOrWhiteSpace(configured))
            {
                return configured.Trim();
            }

            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "SVault");
        }
    }

    public static string StateDir => Path.Combine(Home, "state");

    public static string StateFile => Path.Combine(StateDir, "vault-state.json");

    public static string LogDir => Path.Combine(Home, "logs");

    public static string LogFile => Path.Combine(LogDir, "svault-broker.log");

    public static string PipePath => $@"\\.\pipe\{PipeName}";

    public static void EnsureDirectories()
    {
        Directory.CreateDirectory(StateDir);
        Directory.CreateDirectory(LogDir);
    }
}
