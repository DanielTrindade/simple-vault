using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

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

            Add(set, Uri.EscapeDataString(raw));
            Add(set, Convert.ToBase64String(secret));

            Add(set, raw.ToUpperInvariant());
            Add(set, raw.ToLowerInvariant());
        }

        _variants = set.OrderByDescending(v => v.Length).ToArray();
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

        try
        {
            var node = JsonNode.Parse(text);
            if (node is not null)
            {
                var redacted = RedactNode(node);
                return Truncate(redacted?.ToJsonString() ?? "null");
            }
        }
        catch (JsonException)
        {
        }

        return Truncate(RedactText(text));
    }

    private JsonNode? RedactNode(JsonNode? node)
    {
        if (node is JsonObject obj)
        {
            var entries = obj.ToArray();
            foreach (var (key, value) in entries)
            {
                var redactedKey = RedactText(key);
                var redactedValue = RedactNode(value);
                if (!string.Equals(key, redactedKey, StringComparison.Ordinal))
                {
                    obj.Remove(key);
                    obj[redactedKey] = redactedValue;
                }
                else if (!ReferenceEquals(value, redactedValue))
                {
                    obj[key] = redactedValue;
                }
            }

            return obj;
        }

        if (node is JsonArray array)
        {
            for (var i = 0; i < array.Count; i++)
            {
                var original = array[i];
                var redacted = RedactNode(original);
                if (!ReferenceEquals(original, redacted))
                {
                    array[i] = redacted;
                }
            }

            return array;
        }

        if (node is JsonValue valueNode && valueNode.TryGetValue<string>(out var stringValue))
        {
            return JsonValue.Create(RedactText(stringValue));
        }

        if (node is JsonValue scalarNode && scalarNode.TryGetValue<JsonElement>(out var element) &&
            element.ValueKind is JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False)
        {
            var raw = element.GetRawText();
            var redacted = RedactText(raw);
            return string.Equals(raw, redacted, StringComparison.Ordinal) ? node : JsonValue.Create(redacted);
        }

        return node;
    }

    private string RedactText(string text)
    {
        if (_variants.Length == 0 || text.Length == 0)
        {
            return text;
        }

        var builder = new StringBuilder(text.Length);
        var index = 0;
        while (index < text.Length)
        {
            var match = _variants.FirstOrDefault(variant =>
                index + variant.Length <= text.Length && text.AsSpan(index, variant.Length).SequenceEqual(variant.AsSpan()));

            if (text.AsSpan(index).StartsWith(Mask.AsSpan(), StringComparison.Ordinal) &&
                (match is null || match.Length < Mask.Length))
            {
                builder.Append(Mask);
                index += Mask.Length;
                continue;
            }

            if (match is null)
            {
                builder.Append(text[index++]);
                continue;
            }

            builder.Append(Mask);
            index += match.Length;
        }

        return builder.ToString();
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
