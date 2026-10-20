using System.Text;

namespace SVault.Core.Redaction;

/// <summary>
/// Removes a secret from any text that may reach the agent, a log file or an error message.
/// Works on the textual projections of the secret that are likely to show up in payloads:
/// raw value, url encoded, base64 and digit-only (for CPF style identifiers).
/// </summary>
public sealed class SecretRedactor
{
    public const string Mask = "***REDACTED***";
    public const int MaxOutputLength = 8_192;

    private readonly string[] _variants;

    public SecretRedactor(byte[] secret) : this(new[] { secret })
    {
    }

    public SecretRedactor(IEnumerable<byte[]> secrets)
    {
        var set = new HashSet<string>(StringComparer.Ordinal);

        foreach (var secret in secrets)
        {
            var raw = Encoding.UTF8.GetString(secret);
            Add(set, raw);

            var digits = new string(raw.Where(char.IsAsciiDigit).ToArray());
            if (digits.Length >= 8 && digits.Length != raw.Length)
            {
                Add(set, digits);
            }

            var formatted = new string(raw.Where(c => char.IsAsciiDigit(c) || c == '.' || c == '-' || c == '/').ToArray());
            if (formatted.Length >= 8)
            {
                Add(set, formatted);
            }

            if (raw.Length >= 6)
            {
                Add(set, Uri.EscapeDataString(raw));
                Add(set, Convert.ToBase64String(secret));
            }

            if (raw.Length >= 8)
            {
                Add(set, raw.ToUpperInvariant());
                Add(set, raw.ToLowerInvariant());
            }
        }

        _variants = set
            .Where(v => v.Length >= 4)
            .OrderByDescending(v => v.Length)
            .ToArray();
    }

    private static void Add(HashSet<string> set, string value)
    {
        if (!string.IsNullOrEmpty(value))
        {
            set.Add(value);
        }
    }

    public string Redact(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return string.Empty;
        }

        var result = text;
        foreach (var variant in _variants)
        {
            if (result.Contains(variant, StringComparison.Ordinal))
            {
                result = result.Replace(variant, Mask, StringComparison.Ordinal);
            }
        }

        return Truncate(result);
    }

    public string? RedactNullable(string? text) => text is null ? null : Redact(text);

    public static string Truncate(string text)
    {
        if (text.Length <= MaxOutputLength)
        {
            return text;
        }

        return string.Concat(text.AsSpan(0, MaxOutputLength), "\n...[truncated]");
    }
}
