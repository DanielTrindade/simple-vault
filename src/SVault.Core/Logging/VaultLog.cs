using System.Text;
using SVault.Core.Protocol;

namespace SVault.Core.Logging;

/// <summary>
/// Event log for the broker. Only identifiers, targets and outcomes are recorded:
/// never secret values, never parameter values, never request bodies.
/// </summary>
public sealed class VaultLog
{
    private readonly string _file;
    private readonly object _gate = new();

    public VaultLog(string? file = null)
    {
        _file = file ?? Paths.LogFile;
    }

    public void Write(string eventName, IReadOnlyDictionary<string, object?> fields)
    {
        var payload = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["ts"] = DateTime.UtcNow.ToString("o"),
            ["event"] = eventName
        };

        foreach (var (key, value) in fields)
        {
            payload[key] = value;
        }

        var line = Json.Serialize(payload);

        lock (_gate)
        {
            try
            {
                var directory = Path.GetDirectoryName(_file)!;
                Directory.CreateDirectory(directory);
                File.AppendAllText(_file, line + Environment.NewLine, new UTF8Encoding(false));
            }
            catch
            {
                // Logging must never take the broker down.
            }
        }
    }
}
