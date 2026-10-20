using System.Text.Json;
using System.Text.Json.Serialization;

namespace SVault.Core.Protocol;

public static class Json
{
    public static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = false
    };

    public static string Serialize<T>(T value) => JsonSerializer.Serialize(value, Options);

    public static T? Deserialize<T>(string json) => JsonSerializer.Deserialize<T>(json, Options);
}

public sealed record Envelope
{
    public string Cmd { get; init; } = string.Empty;
    public JsonElement? Body { get; init; }
}

public sealed record EnvelopeResponse
{
    public bool Ok { get; init; }
    public JsonElement? Data { get; init; }
    public ErrorPayload? Error { get; init; }
}

public sealed record ErrorPayload
{
    public string Code { get; init; } = "error";
    public string Message { get; init; } = string.Empty;
}

public static class ErrorCodes
{
    public const string BadRequest = "bad_request";
    public const string Unauthorized = "unauthorized";
    public const string PassphraseRequired = "passphrase_required";
    public const string PassphraseInvalid = "passphrase_invalid";
    public const string TotpRequired = "totp_required";
    public const string TotpInvalid = "totp_invalid";
    public const string NotFound = "not_found";
    public const string NotAuthorized = "not_authorized";
    public const string TargetNotAllowed = "target_not_allowed";
    public const string Conflict = "conflict";
    public const string Expired = "expired";
    public const string ExecutionFailed = "execution_failed";
    public const string VaultNotInitialized = "vault_not_initialized";
    public const string Internal = "internal_error";
}

public sealed record HealthInfo
{
    public string Status { get; init; } = "ok";
    public string Version { get; init; } = "1.0.0";
    public string ServiceIdentity { get; init; } = string.Empty;
    public bool VaultInitialized { get; init; }
    public bool TotpRequired { get; init; }
    public string StatePath { get; init; } = string.Empty;
    public int EntryCount { get; init; }
    public int OperationCount { get; init; }
}

public sealed record EntryMetadata
{
    public string Id { get; init; } = string.Empty;
    public string Kind { get; init; } = "generic";
    public string Label { get; init; } = string.Empty;
    public string[] Targets { get; init; } = Array.Empty<string>();
    public string CreatedAt { get; init; } = string.Empty;
    public string UpdatedAt { get; init; } = string.Empty;
    public int Revision { get; init; }
}

public sealed record OperationMetadata
{
    public string Id { get; init; } = string.Empty;
    public string EntryId { get; init; } = string.Empty;
    public string Action { get; init; } = string.Empty;
    public string Target { get; init; } = string.Empty;
    public bool RequiresApproval { get; init; } = true;
    public string Description { get; init; } = string.Empty;
    public string[] Params { get; init; } = Array.Empty<string>();
}

public sealed record OperationSummary
{
    public string OperationId { get; init; } = string.Empty;
    public string EntryId { get; init; } = string.Empty;
    public string Action { get; init; } = string.Empty;
    public string Target { get; init; } = string.Empty;
    public bool RequiresApproval { get; init; }
    public string Description { get; init; } = string.Empty;
}

public sealed record OperationRequestResult
{
    public string RequestId { get; init; } = string.Empty;
    public string Status { get; init; } = string.Empty;
    public string Requires { get; init; } = string.Empty;
    public string ExpiresAt { get; init; } = string.Empty;
    public OperationSummary Summary { get; init; } = new();
}

public sealed record OperationStatusResult
{
    public string RequestId { get; init; } = string.Empty;
    public string Status { get; init; } = string.Empty;
    public OperationSummary Summary { get; init; } = new();
    public string CreatedAt { get; init; } = string.Empty;
    public string? FinishedAt { get; init; }
    public OperationOutcome? Result { get; init; }
    public string? Error { get; init; }
}

public sealed record OperationOutcome
{
    public string Kind { get; init; } = string.Empty;
    public int? StatusCode { get; init; }
    public bool Ok { get; init; }
    public string? Body { get; set; }
    public string? Output { get; set; }
    public int? ExitCode { get; init; }
    public string DurationMs { get; set; } = string.Empty;
}

public static class OperationStatuses
{
    public const string PendingApproval = "pending_approval";
    public const string Approved = "approved";
    public const string Running = "running";
    public const string Completed = "completed";
    public const string Failed = "failed";
    public const string Rejected = "rejected";
    public const string Expired = "expired";
}

public static class ApprovalRequirements
{
    public const string Passphrase = "passphrase";
    public const string PassphraseAndTotp = "passphrase+totp";
    public const string None = "none";
}
