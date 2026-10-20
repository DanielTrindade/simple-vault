using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using SVault.Core;
using SVault.Core.Protocol;

namespace SVault.Client;

public sealed class BrokerCallException : Exception
{
    public BrokerCallException(string code, string message) : base(message)
    {
        Code = code;
    }

    public string Code { get; }
}

/// <summary>
/// Thin client for the broker pipe. This process never holds secret values:
/// it only forwards commands and receives sanitized answers.
/// </summary>
public sealed class BrokerClient
{
    private readonly string _pipeName;
    private readonly TimeSpan _timeout;

    public BrokerClient(string? pipeName = null, TimeSpan? timeout = null)
    {
        _pipeName = pipeName ?? Paths.PipeName;
        _timeout = timeout ?? TimeSpan.FromSeconds(30);
    }

    public async Task<T> SendAsync<T>(string cmd, object? body = null)
    {
        var payload = new Envelope
        {
            Cmd = cmd,
            Body = body is null
                ? null
                : JsonSerializer.SerializeToElement(body, Json.Options)
        };

        var requestBytes = Encoding.UTF8.GetBytes(Json.Serialize(payload));
        var responseBytes = await ExchangeAsync(requestBytes).ConfigureAwait(false);

        var response = Json.Deserialize<EnvelopeResponse>(Encoding.UTF8.GetString(responseBytes))
                       ?? throw new BrokerCallException(ErrorCodes.Internal, "Resposta invalida do broker.");

        if (!response.Ok)
        {
            throw new BrokerCallException(
                response.Error?.Code ?? ErrorCodes.Internal,
                response.Error?.Message ?? "Erro desconhecido.");
        }

        if (typeof(T) == typeof(object))
        {
            return (T)Convert.ChangeType(response.Data ?? default, typeof(object));
        }

        if (response.Data is null || response.Data.Value.ValueKind == JsonValueKind.Undefined)
        {
            return default!;
        }

        return response.Data.Value.Deserialize<T>(Json.Options)
               ?? throw new BrokerCallException(ErrorCodes.Internal, "Resposta sem conteudo.");
    }

    public async Task<JsonElement> SendRawAsync(string cmd, object? body = null)
    {
        var payload = new Envelope
        {
            Cmd = cmd,
            Body = body is null
                ? null
                : JsonSerializer.SerializeToElement(body, Json.Options)
        };

        var requestBytes = Encoding.UTF8.GetBytes(Json.Serialize(payload));
        var responseBytes = await ExchangeAsync(requestBytes).ConfigureAwait(false);

        var response = Json.Deserialize<EnvelopeResponse>(Encoding.UTF8.GetString(responseBytes))
                       ?? throw new BrokerCallException(ErrorCodes.Internal, "Resposta invalida do broker.");

        if (!response.Ok)
        {
            throw new BrokerCallException(
                response.Error?.Code ?? ErrorCodes.Internal,
                response.Error?.Message ?? "Erro desconhecido.");
        }

        return response.Data ?? default;
    }

    private async Task<byte[]> ExchangeAsync(byte[] requestBytes)
    {
        using var timeout = new CancellationTokenSource(_timeout);

        for (var attempt = 1; ; attempt++)
        {
            try
            {
                using var pipe = new NamedPipeClientStream(
                    ".",
                    _pipeName,
                    PipeDirection.InOut,
                    PipeOptions.Asynchronous);

                await pipe.ConnectAsync(timeout.Token).ConfigureAwait(false);
                await PipeFraming.WriteAsync(pipe, requestBytes, timeout.Token).ConfigureAwait(false);
                return await PipeFraming.ReadAsync(pipe, PipeFraming.MaxResponseBytes, timeout.Token).ConfigureAwait(false);
            }
            catch (IOException) when (attempt < 3)
            {
                await Task.Delay(200, timeout.Token).ConfigureAwait(false);
            }
        }
    }

    public Task<HealthInfo> HealthAsync() => SendAsync<HealthInfo>("health");

    public Task<EntryList> ListEntriesAsync() => SendAsync<EntryList>("list_entries");

    public Task<OperationList> ListOperationsAsync() => SendAsync<OperationList>("list_operations");

    public Task<OperationRequestResult> RequestOperationAsync(string opId, IReadOnlyDictionary<string, string>? parameters = null) =>
        SendAsync<OperationRequestResult>("request_operation", new
        {
            opId,
            @params = parameters ?? new Dictionary<string, string>()
        });

    public Task<OperationStatusResult> OperationStatusAsync(string requestId) =>
        SendAsync<OperationStatusResult>("operation_status", new { requestId });

    public Task<PendingList> PendingApprovalsAsync() => SendAsync<PendingList>("pending_approvals");

    public Task<OkResult> InitVaultAsync(string passphrase, bool enableTotp) =>
        SendAsync<OkResult>("init_vault", new { passphrase, enableTotp });

    public Task<EntryMetadata> RegisterEntryAsync(
        string id,
        string kind,
        string label,
        IReadOnlyList<string> targets,
        string value,
        string passphrase) =>
        SendAsync<EntryMetadata>("register_entry", new
        {
            id,
            kind,
            label,
            targets,
            value,
            passphrase
        });

    public Task<EntryMetadata> UpdateEntryAsync(
        string id,
        string? value,
        string? label,
        IReadOnlyList<string>? targets,
        string passphrase) =>
        SendAsync<EntryMetadata>("update_entry", new
        {
            id,
            value,
            label,
            targets,
            passphrase
        });

    public Task<OkResult> DeleteEntryAsync(string id, string passphrase) =>
        SendAsync<OkResult>("delete_entry", new { id, passphrase });

    public Task<OperationMetadata> AuthorizeOperationAsync(
        string id,
        string entryId,
        string action,
        string target,
        string description,
        IReadOnlyList<string> paramNames,
        string passphrase,
        object? actionSpec = null) =>
        SendAsync<OperationMetadata>("authorize_operation", Merge(
            new
            {
                id,
                entryId,
                action,
                target,
                description,
                @params = paramNames,
                passphrase
            },
            actionSpec));

    public Task<OkResult> RevokeOperationAsync(string id, string passphrase) =>
        SendAsync<OkResult>("revoke_operation", new { id, passphrase });

    public Task<OkResult> ApproveAsync(string requestId, string passphrase, string? totp = null) =>
        SendAsync<OkResult>("approve", new { requestId, passphrase, totp });

    public Task<OkResult> RejectAsync(string requestId, string passphrase) =>
        SendAsync<OkResult>("reject", new { requestId, passphrase });

    public Task<OkResult> SetTotpAsync(string secret, string passphrase) =>
        SendAsync<OkResult>("set_totp", new { secret, passphrase });

    public Task<OkResult> DisableTotpAsync(string passphrase) =>
        SendAsync<OkResult>("disable_totp", new { passphrase });

    public Task<OkResult> ChangePassphraseAsync(string current, string next) =>
        SendAsync<OkResult>("change_passphrase", new { currentPassphrase = current, newPassphrase = next });

    public Task<OkResult> ResetVaultAsync(string passphrase) =>
        SendAsync<OkResult>("reset_vault", new { passphrase });

    private static Dictionary<string, object?> Merge(object primary, object? extra)
    {
        var result = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var property in primary.GetType().GetProperties())
        {
            result[JsonNamingPolicy.CamelCase.ConvertName(property.Name)] = property.GetValue(primary);
        }

        if (extra is not null)
        {
            foreach (var property in extra.GetType().GetProperties())
            {
                result[JsonNamingPolicy.CamelCase.ConvertName(property.Name)] = property.GetValue(extra);
            }
        }

        return result;
    }
}

public sealed class EntryList
{
    public List<EntryMetadata> Entries { get; set; } = new();
}

public sealed class OperationList
{
    public List<OperationMetadata> Operations { get; set; } = new();
}

public sealed class PendingList
{
    public List<PendingRequest> Requests { get; set; } = new();
}

public sealed class PendingRequest
{
    public string RequestId { get; set; } = string.Empty;
    public string CreatedAt { get; set; } = string.Empty;
    public string ExpiresAt { get; set; } = string.Empty;
    public OperationSummary Summary { get; set; } = new();
}

public sealed class OkResult
{
    public bool Ok { get; set; } = true;
    public string? RequestId { get; set; }
    public string? Status { get; set; }
    public bool Deleted { get; set; }
    public bool Revoked { get; set; }
    public bool Changed { get; set; }
    public bool TotpEnabled { get; set; }
    public bool Initialized { get; set; }
    public bool Reset { get; set; }
    public int EntriesRemoved { get; set; }
    public string? TotpUri { get; set; }
    public OperationOutcome? Result { get; set; }
    public string? Error { get; set; }
}
