using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SVault.Core;
using SVault.Core.Crypto;
using SVault.Core.Logging;
using SVault.Core.Operations;
using SVault.Core.Protocol;
using SVault.Core.Redaction;
using SVault.Core.Storage;

namespace SVault.Broker;

public sealed class PendingOperation
{
    public required string RequestId { get; init; }
    public required OperationRecord Operation { get; init; }
    public required IReadOnlyDictionary<string, string> Parameters { get; init; }
    public required string CreatedAt { get; init; }
    public required string ExpiresAt { get; init; }
    public required string AuthorizationId { get; init; }
    public required IReadOnlyDictionary<string, int> EntryRevisions { get; init; }
    public required IReadOnlyDictionary<string, string> EntryIdentities { get; init; }
    public string Status { get; set; } = OperationStatuses.PendingApproval;
    public string? FinishedAt { get; set; }
    public OperationOutcome? Result { get; set; }
    public string? Error { get; set; }
}

public sealed class BrokerEngine
{
    private readonly VaultStore _store;
    private readonly VaultLog _log;
    private readonly BrokerConfig _config;
    private readonly ConcurrentDictionary<string, PendingOperation> _pending = new();
    private readonly object _executionGate = new();

    public BrokerEngine(VaultStore store, VaultLog log, BrokerConfig config)
    {
        _store = store;
        _log = log;
        _config = config;
    }

    public async Task<EnvelopeResponse> HandleAsync(Envelope envelope, string clientSid)
    {
        try
        {
            return await DispatchAsync(envelope, clientSid).ConfigureAwait(false);
        }
        catch (VaultException ex)
        {
            _log.Write("command_error", new Dictionary<string, object?>
            {
                ["cmd"] = envelope.Cmd,
                ["code"] = ex.Code,
                ["client"] = clientSid
            });

            return Failure(ex.Code, ex.Message);
        }
        catch (OperationFailure ex)
        {
            return Failure(ErrorCodes.BadRequest, ex.Message);
        }
        catch (Exception ex)
        {
            _log.Write("internal_error", new Dictionary<string, object?>
            {
                ["cmd"] = envelope.Cmd,
                ["type"] = ex.GetType().Name,
                ["client"] = clientSid
            });

            return Failure(ErrorCodes.Internal, "Falha interna no broker.");
        }
    }

    private async Task<EnvelopeResponse> DispatchAsync(Envelope envelope, string clientSid)
    {
        var body = envelope.Body ?? JsonSerializer.SerializeToElement(new Dictionary<string, object?>());

        switch (envelope.Cmd)
        {
            case "health":
                return Success(Health());

            case "list_entries":
                return Success(new
                {
                    entries = _store.State.Entries.Select(e => new EntryMetadata
                    {
                        Id = e.Id,
                        Kind = e.Kind,
                        Label = e.Label,
                        Targets = e.Targets.ToArray(),
                        CreatedAt = e.CreatedAt,
                        UpdatedAt = e.UpdatedAt,
                        Revision = e.Revision
                    }).ToArray()
                });

            case "list_operations":
                return Success(new
                {
                    operations = _store.State.Operations.Select(o => new OperationMetadata
                    {
                        Id = o.Id,
                        EntryId = o.EntryId,
                        Action = o.Action,
                        Target = o.Target,
                        RequiresApproval = o.RequiresApproval,
                        Description = o.Description,
                        Params = o.Params.ToArray()
                    }).ToArray()
                });

            case "request_operation":
                lock (_executionGate)
                {
                    return Success(RequestOperation(body, clientSid));
                }

            case "operation_status":
                return Success(OperationStatus(body));

            case "pending_approvals":
                lock (_executionGate)
                {
                ExpirePending();
                return Success(new
                {
                    requests = _pending.Values
                        .Where(r => r.Status == OperationStatuses.PendingApproval)
                        .OrderBy(r => r.CreatedAt)
                        .Select(r => new
                        {
                            requestId = r.RequestId,
                            createdAt = r.CreatedAt,
                            expiresAt = r.ExpiresAt,
                            summary = Summarize(r.Operation, r.Parameters)
                        })
                        .ToArray()
                });
                }

            case "init_vault":
                lock (_executionGate) return Success(InitVault(body));

            case "register_entry":
                lock (_executionGate) return Success(RegisterEntry(body));

            case "update_entry":
                lock (_executionGate) return Success(UpdateEntry(body));

            case "delete_entry":
                lock (_executionGate) return Success(DeleteEntry(body));

            case "authorize_operation":
                lock (_executionGate) return Success(AuthorizeOperation(body));

            case "revoke_operation":
                lock (_executionGate) return Success(RevokeOperation(body));

            case "approve":
                return await ApproveAsync(body, clientSid).ConfigureAwait(false);

            case "reject":
                return Success(Reject(body));

            case "set_totp":
                lock (_executionGate) return Success(SetTotp(body));

            case "disable_totp":
                lock (_executionGate) return Success(DisableTotp(body));

            case "change_passphrase":
                lock (_executionGate) return Success(ChangePassphrase(body));

            case "reset_vault":
                lock (_executionGate) return Success(ResetVault(body));

            default:
                return Failure(ErrorCodes.BadRequest, "Comando desconhecido: " + envelope.Cmd);
        }
    }

    private object Health()
    {
        var state = _store.State;
        return new HealthInfo
        {
            Status = "ok",
            Version = _config.Version,
            ServiceIdentity = Environment.UserName + "@" + Environment.MachineName,
            VaultInitialized = state.Initialized,
            TotpRequired = _store.TotpEnabled,
            StatePath = Paths.StateFile,
            EntryCount = state.Entries.Count,
            OperationCount = state.Operations.Count
        };
    }

    private OperationRequestResult RequestOperation(JsonElement body, string clientSid)
    {
        var opId = ReadString(body, "opId");
        var parameters = ReadParameters(body);
        var state = _store.State;

        var operation = state.Operations.FirstOrDefault(o => string.Equals(o.Id, opId, StringComparison.OrdinalIgnoreCase))
                        ?? throw new VaultException(ErrorCodes.NotFound, $"Operacao nao encontrada: {opId}");

        OperationEngine.ValidateParameters(operation, parameters);

        var entry = state.Entries.FirstOrDefault(e => string.Equals(e.Id, operation.EntryId, StringComparison.OrdinalIgnoreCase))
                    ?? throw new VaultException(ErrorCodes.NotFound, $"Registro nao encontrado: {operation.EntryId}");

        if (operation.Action != OperationEngine.ActionNoopEcho && !TargetPolicy.IsTargetAllowed(entry.Targets, operation.Target))
        {
            throw new VaultException(
                ErrorCodes.TargetNotAllowed,
                $"O alvo {operation.Target} nao esta autorizado para o registro {entry.Id}.");
        }

        var requestId = RandomId();
        var now = DateTime.UtcNow;
        ExpirePending();
        if (_pending.Values.Count(r => r.Status == OperationStatuses.PendingApproval) >= 500)
        {
            throw new VaultException(ErrorCodes.Conflict, "A fila de aprovacoes atingiu o limite.");
        }

        var operationSnapshot = CloneOperation(operation);
        var revisions = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase) { [entry.Id] = entry.Revision };
        var identities = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { [entry.Id] = entry.IdentityId };
        foreach (var id in OperationEngine.CollectReferencedEntries(operationSnapshot))
        {
            var referenced = state.Entries.FirstOrDefault(e => string.Equals(e.Id, id, StringComparison.OrdinalIgnoreCase))
                             ?? throw new VaultException(ErrorCodes.NotFound, $"Segredo referenciado nao encontrado: {id}");
            revisions[id] = referenced.Revision;
            identities[id] = referenced.IdentityId;
        }

        var pending = new PendingOperation
        {
            RequestId = requestId,
            Operation = operationSnapshot,
            Parameters = new Dictionary<string, string>(parameters, StringComparer.OrdinalIgnoreCase),
            AuthorizationId = operation.AuthorizationId,
            EntryRevisions = revisions,
            EntryIdentities = identities,
            CreatedAt = now.ToString("o"),
            ExpiresAt = now.AddSeconds(_config.ApprovalTtlSeconds).ToString("o")
        };

        _pending[requestId] = pending;

        _log.Write("operation_requested", new Dictionary<string, object?>
        {
            ["requestId"] = requestId,
            ["operationId"] = operation.Id,
            ["entryId"] = operation.EntryId,
            ["action"] = operation.Action,
            ["target"] = operation.Target,
            ["client"] = clientSid
        });

        return new OperationRequestResult
        {
            RequestId = requestId,
            Status = OperationStatuses.PendingApproval,
            Requires = _store.TotpEnabled ? ApprovalRequirements.PassphraseAndTotp : ApprovalRequirements.Passphrase,
            ExpiresAt = pending.ExpiresAt,
            Summary = Summarize(operationSnapshot, pending.Parameters)
        };
    }

    private OperationStatusResult OperationStatus(JsonElement body)
    {
        var requestId = ReadString(body, "requestId");
        lock (_executionGate)
        {
        var pending = _pending.Values.FirstOrDefault(r => string.Equals(r.RequestId, requestId, StringComparison.OrdinalIgnoreCase))
                      ?? throw new VaultException(ErrorCodes.NotFound, "Requisicao nao encontrada.");

        if (pending.Status == OperationStatuses.PendingApproval && DateTimeOffset.UtcNow > DateTimeOffset.Parse(pending.ExpiresAt))
        {
            pending.Status = OperationStatuses.Expired;
            pending.FinishedAt = DateTime.UtcNow.ToString("o");
        }

        return new OperationStatusResult
        {
            RequestId = pending.RequestId,
            Status = pending.Status,
            Summary = Summarize(pending.Operation, pending.Parameters),
            CreatedAt = pending.CreatedAt,
            FinishedAt = pending.FinishedAt,
            Result = pending.Result,
            Error = pending.Error
        };
        }
    }

    private async Task<EnvelopeResponse> ApproveAsync(JsonElement body, string clientSid)
    {
        var requestId = ReadString(body, "requestId");
        var passphrase = ReadString(body, "passphrase");
        var totp = ReadOptionalString(body, "totp");

        PendingOperation pending;
        byte[] secret = Array.Empty<byte>();
        var referenced = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        lock (_executionGate)
        {
        pending = _pending.Values.FirstOrDefault(r => string.Equals(r.RequestId, requestId, StringComparison.OrdinalIgnoreCase))
                      ?? throw new VaultException(ErrorCodes.NotFound, "Requisicao nao encontrada.");

        if (pending.Status != OperationStatuses.PendingApproval)
        {
            throw new VaultException(ErrorCodes.Conflict, "A requisicao nao esta aguardando aprovacao.");
        }

        if (DateTimeOffset.UtcNow > DateTimeOffset.Parse(pending.ExpiresAt))
        {
            pending.Status = OperationStatuses.Expired;
            pending.FinishedAt = DateTime.UtcNow.ToString("o");
            throw new VaultException(ErrorCodes.Expired, "A requisicao expirou.");
        }

        RevalidateAuthorization(pending);

        if (!_store.VerifyPassphrase(passphrase))
        {
            throw new VaultException(ErrorCodes.PassphraseInvalid, "Senha do cofre invalida.");
        }

        if (_store.TotpEnabled)
        {
            var totpSecret = _store.GetTotpSecret(passphrase);
            if (string.IsNullOrEmpty(totpSecret))
            {
                throw new VaultException(ErrorCodes.TotpRequired, "Codigo TOTP obrigatorio.");
            }

            if (string.IsNullOrWhiteSpace(totp))
            {
                throw new VaultException(ErrorCodes.TotpRequired, "Codigo TOTP obrigatorio.");
            }

            if (!Totp.VerifyCode(totpSecret, totp, DateTime.UtcNow))
            {
                throw new VaultException(ErrorCodes.TotpInvalid, "Codigo TOTP invalido.");
            }
        }

        var opened = UnwrapApprovedSecrets(pending, passphrase);
        secret = opened.Secret;
        referenced = opened.Referenced;
        pending.Status = OperationStatuses.Running;
        }

        try
        {
            var allSecrets = new List<byte[]> { secret };
            allSecrets.AddRange(referenced.Values);
            var redactor = new SecretRedactor(allSecrets);

            var context = new OperationContext
            {
                Operation = pending.Operation,
                Secret = secret,
                ReferencedSecrets = referenced,
                Parameters = pending.Parameters,
                Redactor = redactor,
                Cancellation = CancellationToken.None
            };

            var outcome = await OperationEngine.ExecuteAsync(context).ConfigureAwait(false);
            outcome.Body = redactor.RedactNullable(outcome.Body);
            outcome.Output = redactor.RedactNullable(outcome.Output);

            lock (_executionGate)
            {
                pending.Result = outcome;
                pending.Status = OperationStatuses.Completed;
                pending.FinishedAt = DateTime.UtcNow.ToString("o");
            }

            _log.Write("operation_completed", new Dictionary<string, object?>
            {
                ["requestId"] = pending.RequestId,
                ["operationId"] = pending.Operation.Id,
                ["entryId"] = pending.Operation.EntryId,
                ["ok"] = outcome.Ok,
                ["durationMs"] = outcome.DurationMs,
                ["client"] = clientSid
            });

            return Success(new OperationStatusResult
            {
                RequestId = pending.RequestId,
                Status = pending.Status,
            Summary = Summarize(pending.Operation, pending.Parameters),
                CreatedAt = pending.CreatedAt,
                FinishedAt = pending.FinishedAt,
                Result = pending.Result,
                Error = pending.Error
            });
        }
        catch (Exception ex)
        {
            if (pending.Status != OperationStatuses.Running)
            {
                return Success(new OperationStatusResult
                {
                    RequestId = pending.RequestId,
                    Status = pending.Status,
                    Summary = Summarize(pending.Operation, pending.Parameters),
                    CreatedAt = pending.CreatedAt,
                    FinishedAt = pending.FinishedAt,
                    Result = pending.Result,
                    Error = pending.Error
                });
            }

            lock (_executionGate)
            {
                pending.Status = OperationStatuses.Failed;
                pending.FinishedAt = DateTime.UtcNow.ToString("o");
                pending.Error = "Falha na execucao autorizada.";
            }

            _log.Write("operation_failed", new Dictionary<string, object?>
            {
                ["requestId"] = pending.RequestId,
                ["operationId"] = pending.Operation.Id,
                ["type"] = ex.GetType().Name,
                ["client"] = clientSid
            });

            return Success(new OperationStatusResult
            {
                RequestId = pending.RequestId,
                Status = pending.Status,
                Summary = Summarize(pending.Operation, pending.Parameters),
                CreatedAt = pending.CreatedAt,
                FinishedAt = pending.FinishedAt,
                Result = pending.Result,
                Error = pending.Error
            });
        }
        finally
        {
            if (secret.Length > 0)
            {
                CryptographicOperations.ZeroMemory(secret);
            }

            foreach (var value in referenced.Values)
            {
                CryptographicOperations.ZeroMemory(value);
            }
        }
    }

    private object Reject(JsonElement body)
    {
        var requestId = ReadString(body, "requestId");
        var passphrase = ReadString(body, "passphrase");

        PendingOperation pending;
        lock (_executionGate)
        {
            if (!_store.VerifyPassphrase(passphrase))
            {
                throw new VaultException(ErrorCodes.PassphraseInvalid, "Senha do cofre invalida.");
            }

            pending = _pending.Values.FirstOrDefault(r => string.Equals(r.RequestId, requestId, StringComparison.OrdinalIgnoreCase))
                      ?? throw new VaultException(ErrorCodes.NotFound, "Requisicao nao encontrada.");
            if (pending.Status != OperationStatuses.PendingApproval)
            {
                throw new VaultException(ErrorCodes.Conflict, "Somente solicitacoes pendentes podem ser rejeitadas.");
            }

            pending.Status = OperationStatuses.Rejected;
            pending.FinishedAt = DateTime.UtcNow.ToString("o");
        }

        return new
        {
            requestId = pending.RequestId,
            status = pending.Status
        };
    }

    private object InitVault(JsonElement body)
    {
        var passphrase = ReadString(body, "passphrase");
        var enableTotp = ReadOptionalBool(body, "enableTotp") ?? false;
        var totpSecret = ReadOptionalString(body, "totpSecret");

        var generated = _store.Initialize(passphrase, enableTotp, totpSecret);

        _log.Write("vault_initialized", new Dictionary<string, object?>
        {
            ["totp"] = enableTotp
        });

        return new
        {
            initialized = true,
            totpEnabled = enableTotp,
            totpUri = enableTotp
                ? Totp.BuildOtpAuthUri(
                    string.IsNullOrWhiteSpace(totpSecret) ? generated : totpSecret.Trim(),
                    Environment.MachineName)
                : null
        };
    }

    private object RegisterEntry(JsonElement body)
    {
        var id = ReadString(body, "id");
        var kind = ReadOptionalString(body, "kind") ?? "generic";
        var label = ReadOptionalString(body, "label") ?? id;
        var targets = ReadStringArray(body, "targets");
        var passphrase = ReadString(body, "passphrase");
        var value = ReadSecret(body, "value");

        var record = _store.RegisterEntry(id, kind, label, targets, value, passphrase);
        Array.Clear(value);

        _log.Write("entry_registered", new Dictionary<string, object?>
        {
            ["id"] = record.Id,
            ["kind"] = record.Kind
        });

        return new
        {
            id = record.Id,
            kind = record.Kind,
            label = record.Label,
            targets = record.Targets.ToArray(),
            revision = record.Revision
        };
    }

    private object UpdateEntry(JsonElement body)
    {
        var id = ReadString(body, "id");
        var passphrase = ReadString(body, "passphrase");
        var label = ReadOptionalString(body, "label");
        var targets = ReadOptionalStringArray(body, "targets");
        var value = ReadOptionalSecret(body, "value");

        var record = _store.UpdateEntry(id, value, label, targets, passphrase);
        if (value is not null)
        {
            Array.Clear(value);
        }

        _log.Write("entry_updated", new Dictionary<string, object?>
        {
            ["id"] = record.Id,
            ["revision"] = record.Revision
        });

        return new
        {
            id = record.Id,
            kind = record.Kind,
            label = record.Label,
            targets = record.Targets.ToArray(),
            revision = record.Revision
        };
    }

    private object DeleteEntry(JsonElement body)
    {
        var id = ReadString(body, "id");
        var passphrase = ReadString(body, "passphrase");

        _store.DeleteEntry(id, passphrase);

        _log.Write("entry_deleted", new Dictionary<string, object?>
        {
            ["id"] = id
        });

        return new { id, deleted = true };
    }

    private object AuthorizeOperation(JsonElement body)
    {
        var id = ReadString(body, "id");
        var entryId = ReadString(body, "entryId");
        var action = ReadString(body, "action");
        var target = ReadString(body, "target");
        var description = ReadOptionalString(body, "description") ?? string.Empty;
        var paramNames = ReadStringArray(body, "params");
        var requiresApproval = true;
        var passphrase = ReadString(body, "passphrase");

        if (!OperationEngine.SupportedActions.Contains(action, StringComparer.Ordinal))
        {
            throw new VaultException(ErrorCodes.BadRequest, "Acao nao suportada: " + action);
        }

        if (action == OperationEngine.ActionProcessStdin)
        {
            throw new VaultException(ErrorCodes.BadRequest, "Acoes de processo estao desabilitadas pelo contrato de seguranca atual.");
        }

        var record = new OperationRecord
        {
            AuthorizationId = Guid.NewGuid().ToString("N"),
            Id = id,
            EntryId = entryId,
            Action = action,
            Target = target,
            Description = description,
            RequiresApproval = requiresApproval,
            Params = paramNames.ToList()
        };

        if (action == OperationEngine.ActionHttpRequest)
        {
            record.Http = new HttpRequestRecord
            {
                Method = ReadOptionalString(body, "method") ?? "POST",
                Url = ReadOptionalString(body, "url") ?? target,
                ContentType = ReadOptionalString(body, "contentType") ?? "application/json",
                BodyFields = ReadStringMap(body, "bodyFields"),
                Headers = ReadStringMap(body, "headers"),
                ResultFields = ReadStringArray(body, "resultFields").ToList()
            };

            if (!TargetPolicy.AreEquivalentUrls(record.Http.Url, target))
            {
                throw new VaultException(ErrorCodes.BadRequest, "A URL deve ser igual ao alvo autorizado.");
            }

            OperationEngine.ValidateTemplates(record);

            ValidateNoSecretLiteral(record.Http.BodyFields.Values, passphrase);
            ValidateNoSecretLiteral(record.Http.Headers.Values, passphrase);
        }
        else if (action == OperationEngine.ActionProcessStdin)
        {
            record.Process = new ProcessRecord
            {
                Executable = ReadOptionalString(body, "executable") ?? target,
                Args = ReadStringArray(body, "args").ToList(),
                Env = ReadStringArray(body, "env").ToList(),
                TimeoutSeconds = ReadOptionalInt(body, "timeoutSeconds") ?? 30
            };

            if (!string.Equals(record.Process.Executable, target, StringComparison.OrdinalIgnoreCase))
            {
                throw new VaultException(ErrorCodes.BadRequest, "O executavel deve ser igual ao alvo autorizado.");
            }

            ValidateNoSecretLiteral(record.Process.Args, passphrase);
            ValidateNoSecretLiteral(record.Process.Env, passphrase);
        }

        foreach (var referencedId in OperationEngine.CollectReferencedEntries(record))
        {
            var referencedEntry = _store.State.Entries
                .FirstOrDefault(e => string.Equals(e.Id, referencedId, StringComparison.OrdinalIgnoreCase))
                ?? throw new VaultException(ErrorCodes.NotFound, $"Segredo referenciado nao encontrado: {referencedId}");

            if (!TargetPolicy.IsTargetAllowed(referencedEntry.Targets, record.Target))
            {
                throw new VaultException(
                    ErrorCodes.TargetNotAllowed,
                    $"O alvo {record.Target} nao esta autorizado para o registro {referencedEntry.Id}.");
            }
        }

        var stored = _store.AuthorizeOperation(record, passphrase);

        _log.Write("operation_authorized", new Dictionary<string, object?>
        {
            ["id"] = stored.Id,
            ["entryId"] = stored.EntryId,
            ["action"] = stored.Action,
            ["target"] = stored.Target
        });

        return new
        {
            id = stored.Id,
            entryId = stored.EntryId,
            action = stored.Action,
            target = stored.Target,
            requiresApproval = stored.RequiresApproval,
            description = stored.Description,
            paramNames = stored.Params.ToArray()
        };
    }

    private object RevokeOperation(JsonElement body)
    {
        var id = ReadString(body, "id");
        _store.RevokeOperation(id, ReadString(body, "passphrase"));
        foreach (var pending in _pending.Values.Where(r =>
                     r.Status == OperationStatuses.PendingApproval &&
                     string.Equals(r.Operation.Id, id, StringComparison.OrdinalIgnoreCase)))
        {
            pending.Status = OperationStatuses.Revoked;
            pending.FinishedAt = DateTime.UtcNow.ToString("o");
        }

        _log.Write("operation_revoked", new Dictionary<string, object?>
        {
            ["id"] = id
        });

        return new { id, revoked = true };
    }

    private object SetTotp(JsonElement body)
    {
        var secret = ReadString(body, "secret");
        _store.SetTotp(secret, ReadString(body, "passphrase"), ReadOptionalString(body, "totp"));

        _log.Write("totp_enabled", new Dictionary<string, object?>());

        return new { totpEnabled = true };
    }

    private object DisableTotp(JsonElement body)
    {
        _store.DisableTotp(ReadString(body, "passphrase"), ReadOptionalString(body, "totp"));
        _log.Write("totp_disabled", new Dictionary<string, object?>());
        return new { totpEnabled = false };
    }

    private object ChangePassphrase(JsonElement body)
    {
        _store.ChangePassphrase(ReadString(body, "currentPassphrase"), ReadString(body, "newPassphrase"), ReadOptionalString(body, "totp"));
        _log.Write("passphrase_changed", new Dictionary<string, object?>());
        return new { changed = true };
    }

    private object ResetVault(JsonElement body)
    {
        var removed = _store.Reset(ReadString(body, "passphrase"), ReadOptionalString(body, "totp"));
        _log.Write("vault_reset", new Dictionary<string, object?>
        {
            ["entriesRemoved"] = removed
        });

        return new
        {
            reset = true,
            entriesRemoved = removed,
            initialized = false
        };
    }

    private void ValidateNoSecretLiteral(IEnumerable<string> templates, string passphrase)
    {
        var literals = templates
            .Where(t => !string.IsNullOrEmpty(t))
            .SelectMany(t => System.Text.RegularExpressions.Regex.Split(t, @"\{\{(?:secret(?::[^{}]+)?|param:[^{}]+)\}\}"))
            .Where(t => t.Length > 0)
            .ToArray();

        if (literals.Length == 0)
        {
            return;
        }

        var secrets = _store.UnwrapAllSecrets(passphrase);
        try
        {
            foreach (var (entryId, secret) in secrets)
            {
                var text = Encoding.UTF8.GetString(secret);
                if (text.Length > 0 && literals.Any(l => l.Contains(text, StringComparison.Ordinal)))
                {
                    throw new VaultException(
                        ErrorCodes.BadRequest,
                        $"O template contem literalmente o segredo do registro {entryId}. Use apenas os placeholders.");
                }
            }
        }
        finally
        {
            foreach (var secret in secrets.Values)
            {
                Array.Clear(secret);
            }
        }
    }

    private static OperationSummary Summarize(OperationRecord operation, IReadOnlyDictionary<string, string>? parameters = null) => new()
    {
        OperationId = operation.Id,
        EntryId = operation.EntryId,
        Action = operation.Action,
        Target = operation.Target,
        RequiresApproval = operation.RequiresApproval,
        Description = operation.Description,
        Parameters = parameters is null ? new(StringComparer.OrdinalIgnoreCase) : new(parameters, StringComparer.OrdinalIgnoreCase),
        Method = operation.Http?.Method,
        ReferencedEntries = OperationEngine.CollectReferencedEntries(operation).ToArray()
    };

    private static OperationRecord CloneOperation(OperationRecord operation) =>
        JsonSerializer.Deserialize<OperationRecord>(JsonSerializer.Serialize(operation, Json.Options), Json.Options)!;

    private void RevalidateAuthorization(PendingOperation pending)
    {
        var state = _store.State;
        var currentOperation = state.Operations.FirstOrDefault(o =>
            string.Equals(o.Id, pending.Operation.Id, StringComparison.OrdinalIgnoreCase));
        if (currentOperation is null || !string.Equals(currentOperation.AuthorizationId, pending.AuthorizationId, StringComparison.Ordinal))
        {
            throw new VaultException(ErrorCodes.Conflict, "A operacao foi revogada ou substituida.");
        }

        if (pending.Operation.Action == OperationEngine.ActionHttpRequest &&
            (pending.Operation.Http is null ||
             !TargetPolicy.AreEquivalentUrls(pending.Operation.Http.Url, pending.Operation.Target)))
        {
            throw new VaultException(ErrorCodes.TargetNotAllowed, "A URL efetiva da operacao difere do alvo autorizado; autorize novamente.");
        }

        foreach (var (entryId, revision) in pending.EntryRevisions)
        {
            var current = state.Entries.FirstOrDefault(e => string.Equals(e.Id, entryId, StringComparison.OrdinalIgnoreCase));
            if (current is null || current.Revision != revision ||
                !pending.EntryIdentities.TryGetValue(entryId, out var identity) ||
                !string.Equals(current.IdentityId, identity, StringComparison.Ordinal))
            {
                throw new VaultException(ErrorCodes.Conflict, "Um registro usado pela solicitacao foi alterado.");
            }

            if (pending.Operation.Action != OperationEngine.ActionNoopEcho &&
                !TargetPolicy.IsTargetAllowed(current.Targets, pending.Operation.Target))
            {
                throw new VaultException(ErrorCodes.TargetNotAllowed, "O alvo deixou de estar autorizado.");
            }
        }
    }

    private (byte[] Secret, Dictionary<string, byte[]> Referenced) UnwrapApprovedSecrets(PendingOperation pending, string passphrase)
    {
        var secret = _store.UnwrapSecret(pending.Operation.EntryId, passphrase);
        var referenced = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var state = _store.State;
            var referencedIds = OperationEngine.CollectReferencedEntries(pending.Operation);
            foreach (var referencedId in referencedIds)
            {
                var entry = state.Entries.FirstOrDefault(e => string.Equals(e.Id, referencedId, StringComparison.OrdinalIgnoreCase))
                            ?? throw new VaultException(ErrorCodes.Conflict, "Um registro usado pela solicitacao nao existe mais.");
        if (pending.Operation.Action != OperationEngine.ActionNoopEcho &&
            !TargetPolicy.IsTargetAllowed(entry.Targets, pending.Operation.Target))
                {
                    throw new VaultException(ErrorCodes.TargetNotAllowed, "O alvo deixou de estar autorizado.");
                }
            }

            foreach (var pair in _store.UnwrapSecrets(referencedIds, passphrase))
            {
                referenced[pair.Key] = pair.Value;
            }

            if (referencedIds.Any(id => !referenced.ContainsKey(id)))
            {
                throw new VaultException(ErrorCodes.NotFound, "Um segredo referenciado nao esta disponivel.");
            }

            return (secret, referenced);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(secret);
            foreach (var value in referenced.Values)
            {
                CryptographicOperations.ZeroMemory(value);
            }

            throw;
        }
    }

    private void ExpirePending()
    {
        lock (_executionGate)
        {
            var now = DateTimeOffset.UtcNow;
            foreach (var pending in _pending.Values)
            {
                if (pending.Status == OperationStatuses.PendingApproval && now > DateTimeOffset.Parse(pending.ExpiresAt))
                {
                    pending.Status = OperationStatuses.Expired;
                    pending.FinishedAt = DateTime.UtcNow.ToString("o");
                }
            }

            foreach (var pending in _pending.Values
                         .Where(p => p.Status != OperationStatuses.PendingApproval && p.Status != OperationStatuses.Running)
                         .OrderBy(p => p.FinishedAt)
                         .Take(Math.Max(0, _pending.Count - 1000)))
            {
                _pending.TryRemove(pending.RequestId, out _);
            }
        }
    }

    private static string RandomId()
    {
        var bytes = RandomNumberGenerator.GetBytes(16);
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private static string ReadString(JsonElement body, string name)
    {
        if (!body.TryGetProperty(name, out var element) || element.ValueKind != JsonValueKind.String)
        {
            throw new VaultException(ErrorCodes.BadRequest, $"Campo obrigatorio ausente: {name}");
        }

        var value = element.GetString();
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new VaultException(ErrorCodes.BadRequest, $"Campo obrigatorio vazio: {name}");
        }

        return value;
    }

    private static string? ReadOptionalString(JsonElement body, string name)
    {
        if (!body.TryGetProperty(name, out var element) || element.ValueKind != JsonValueKind.String)
        {
            return null;
        }

        var value = element.GetString();
        return string.IsNullOrEmpty(value) ? null : value;
    }

    private static bool? ReadOptionalBool(JsonElement body, string name)
    {
        if (!body.TryGetProperty(name, out var element))
        {
            return null;
        }

        return element.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => null
        };
    }

    private static int? ReadOptionalInt(JsonElement body, string name)
    {
        if (!body.TryGetProperty(name, out var element) || element.ValueKind != JsonValueKind.Number)
        {
            return null;
        }

        return element.GetInt32();
    }

    private static byte[] ReadSecret(JsonElement body, string name)
    {
        var value = ReadOptionalString(body, name)
                    ?? throw new VaultException(ErrorCodes.BadRequest, $"Campo obrigatorio ausente: {name}");
        return Encoding.UTF8.GetBytes(value);
    }

    private static byte[]? ReadOptionalSecret(JsonElement body, string name)
    {
        var value = ReadOptionalString(body, name);
        return value is null ? null : Encoding.UTF8.GetBytes(value);
    }

    private static IReadOnlyList<string> ReadStringArray(JsonElement body, string name)
    {
        if (!body.TryGetProperty(name, out var element) || element.ValueKind != JsonValueKind.Array)
        {
            return Array.Empty<string>();
        }

        return element.EnumerateArray()
            .Where(e => e.ValueKind == JsonValueKind.String)
            .Select(e => e.GetString()!)
            .ToArray();
    }

    private static IReadOnlyList<string>? ReadOptionalStringArray(JsonElement body, string name)
    {
        if (!body.TryGetProperty(name, out var element) || element.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        return element.EnumerateArray()
            .Where(e => e.ValueKind == JsonValueKind.String)
            .Select(e => e.GetString()!)
            .ToArray();
    }

    private static Dictionary<string, string> ReadStringMap(JsonElement body, string name)
    {
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        if (!body.TryGetProperty(name, out var element) || element.ValueKind != JsonValueKind.Object)
        {
            return map;
        }

        foreach (var property in element.EnumerateObject())
        {
            if (property.Value.ValueKind == JsonValueKind.String)
            {
                map[property.Name] = property.Value.GetString()!;
            }
        }

        return map;
    }

    private static IReadOnlyDictionary<string, string> ReadParameters(JsonElement body)
    {
        var parameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (!body.TryGetProperty("params", out var element))
        {
            return parameters;
        }

        if (element.ValueKind != JsonValueKind.Object)
        {
            throw new VaultException(ErrorCodes.BadRequest, "O campo params deve ser um objeto de strings.");
        }

        foreach (var property in element.EnumerateObject())
        {
            if (property.Value.ValueKind != JsonValueKind.String)
            {
                throw new VaultException(ErrorCodes.BadRequest, $"O parametro {property.Name} deve ser texto.");
            }

            parameters[property.Name] = property.Value.GetString()!;
        }

        return parameters;
    }

    private static EnvelopeResponse Success(object data) => new()
    {
        Ok = true,
        Data = JsonSerializer.SerializeToElement(data, Json.Options)
    };

    private static EnvelopeResponse Failure(string code, string message) => new()
    {
        Ok = false,
        Error = new ErrorPayload { Code = code, Message = message }
    };
}
