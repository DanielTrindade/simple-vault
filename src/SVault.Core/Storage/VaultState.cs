using System.Text.Json.Serialization;

namespace SVault.Core.Storage;

/// <summary>Non-secret vault metadata. Secret values never live in this file.</summary>
public sealed class VaultState
{
    public int Version { get; set; } = 1;

    public bool Initialized { get; set; }

    /// <summary>Base64 salt for the PBKDF2 pass phrase derivation.</summary>
    public string MasterSalt { get; set; } = string.Empty;

    /// <summary>Base64 AES-GCM envelope over a known constant; used to validate a pass phrase.</summary>
    public string KeyCheck { get; set; } = string.Empty;

    public string? CredentialGeneration { get; set; }

    /// <summary>True when a TOTP second factor is enrolled for this vault.</summary>
    public bool TotpEnabled { get; set; }

    /// <summary>Base64 AES-GCM envelope over the TOTP secret, sealed with the vault key.</summary>
    public string TotpSecret { get; set; } = string.Empty;

    public List<EntryRecord> Entries { get; set; } = new();

    public List<OperationRecord> Operations { get; set; } = new();
    public List<string> KnownCredentialTargets { get; set; } = new();
}

public sealed class EntryRecord
{
    public string IdentityId { get; set; } = string.Empty;
    public string Id { get; set; } = string.Empty;
    public string Kind { get; set; } = "generic";
    public string Label { get; set; } = string.Empty;
    public List<string> Targets { get; set; } = new();
    public string CreatedAt { get; set; } = string.Empty;
    public string UpdatedAt { get; set; } = string.Empty;
    public int Revision { get; set; } = 1;

    /// <summary>Base64 per-entry salt used to derive the entry key from the vault key.</summary>
    public string EntrySalt { get; set; } = string.Empty;
    public string? CredentialVersion { get; set; }
}

public sealed class OperationRecord
{
    public string AuthorizationId { get; set; } = string.Empty;
    public string Id { get; set; } = string.Empty;
    public string EntryId { get; set; } = string.Empty;
    public string Action { get; set; } = string.Empty;
    public string Target { get; set; } = string.Empty;
    public bool RequiresApproval { get; set; } = true;
    public string Description { get; set; } = string.Empty;
    public List<string> Params { get; set; } = new();
    public HttpRequestRecord? Http { get; set; }
    public ProcessRecord? Process { get; set; }
}

public sealed class HttpRequestRecord
{
    public string Method { get; set; } = "POST";
    public string Url { get; set; } = string.Empty;
    public string ContentType { get; set; } = "application/json";
    public Dictionary<string, string> BodyFields { get; set; } = new();
    public Dictionary<string, string> Headers { get; set; } = new();
    public List<string> ResultFields { get; set; } = new();}

public sealed class ProcessRecord
{
    public string Executable { get; set; } = string.Empty;
    public List<string> Args { get; set; } = new();
    public List<string> Env { get; set; } = new();
    public int TimeoutSeconds { get; set; } = 30;
}

[JsonSerializable(typeof(VaultState))]
public partial class VaultStateSerializerContext : JsonSerializerContext
{
}
