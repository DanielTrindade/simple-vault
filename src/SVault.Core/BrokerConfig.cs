using System.Text.Json;
using System.Text.Json.Serialization;

namespace SVault.Core;

/// <summary>Broker configuration written by the elevated installer.</summary>
public sealed class BrokerConfig
{
    public const string FileName = "broker.json";

    public string Version { get; set; } = "1.0.0";

    /// <summary>SIDs allowed to connect to the broker pipe (besides SYSTEM and Administrators).</summary>
    public List<string> AllowedClientSids { get; set; } = new();

    /// <summary>Seconds a pending approval request stays valid.</summary>
    public int ApprovalTtlSeconds { get; set; } = 180;

    /// <summary>Seconds an unlocked vault key stays cached in memory.</summary>
    public int UnlockTtlSeconds { get; set; } = 300;

    public static string DefaultPath => Path.Combine(Paths.Home, FileName);

    public static BrokerConfig Load(string? path = null)
    {
        var file = path ?? DefaultPath;
        if (!File.Exists(file))
        {
            return new BrokerConfig();
        }

        try
        {
            return System.Text.Json.JsonSerializer.Deserialize<BrokerConfig>(
                       File.ReadAllText(file),
                       Protocol.Json.Options)
                   ?? new BrokerConfig();
        }
        catch (JsonException)
        {
            return new BrokerConfig();
        }
    }
}
