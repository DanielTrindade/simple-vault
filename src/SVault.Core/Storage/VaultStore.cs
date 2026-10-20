using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SVault.Core.Crypto;
using SVault.Core.Protocol;

namespace SVault.Core.Storage;

public sealed class VaultException : Exception
{
    public VaultException(string code, string message) : base(message)
    {
        Code = code;
    }

    public string Code { get; }
}

public sealed class VaultStore
{
    public const string EntryTargetPrefix = "SVault:entry";
    public const string TotpTarget = "SVault:totp";
    public const string SecretUserName = "svault";

    private const string KeyCheckPlaintext = "svault-keycheck-v1";
    private static readonly byte[] KeyCheckBytes = Encoding.UTF8.GetBytes(KeyCheckPlaintext);

    private readonly object _gate = new();
    private readonly string _stateFile;
    private readonly ICredentialStore _credentials;
    private VaultState _state = new();

    public VaultStore(string? stateFile = null, ICredentialStore? credentials = null)
    {
        _stateFile = stateFile ?? Paths.StateFile;
        _credentials = credentials ?? new WindowsCredentialStore();
        Load();
    }

    public VaultState State
    {
        get
        {
            lock (_gate)
            {
                return CloneState(_state);
            }
        }
    }

    public bool IsInitialized => State.Initialized;

    public bool TotpEnabled
    {
        get
        {
            lock (_gate)
            {
                return _state.TotpEnabled && !string.IsNullOrEmpty(_state.TotpSecret);
            }
        }
    }

    private void Load()
    {
        lock (_gate)
        {
            if (!File.Exists(_stateFile))
            {
                _state = new VaultState();
                return;
            }

            var json = File.ReadAllText(_stateFile);
            _state = JsonSerializer.Deserialize<VaultState>(json, Json.Options) ?? new VaultState();
        }
    }

    private void Save(VaultState? candidate = null)
    {
        lock (_gate)
        {
            var directory = Path.GetDirectoryName(_stateFile)!;
            Directory.CreateDirectory(directory);

            var json = JsonSerializer.Serialize(candidate ?? _state, Json.Options);
            var temp = _stateFile + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                using (var writer = new StreamWriter(stream, new UTF8Encoding(false)))
                {
                    writer.Write(json);
                    writer.Flush();
                    stream.Flush(flushToDisk: true);
                }

                File.Move(temp, _stateFile, overwrite: true);
            }
            finally
            {
                if (File.Exists(temp))
                {
                    try
                    {
                        File.Delete(temp);
                    }
                    catch
                    {
                    }
                }
            }
        }
    }

    public string Initialize(string passphrase, bool enableTotp, string? totpSecret)
    {
        lock (_gate)
        {
            ValidateNewPassphrase(passphrase);
            if (_state.Initialized)
            {
                throw new VaultException(ErrorCodes.Conflict, "O cofre ja esta inicializado.");
            }

            var masterSalt = VaultCrypto.RandomSalt();
            var vaultKey = VaultCrypto.DeriveVaultKey(passphrase, masterSalt);
            try
            {
                var candidate = CloneState(_state);
                candidate.MasterSalt = VaultCrypto.ToBase64(masterSalt);
                candidate.KeyCheck = VaultCrypto.ToBase64(VaultCrypto.Seal(KeyCheckBytes, vaultKey));
                candidate.CredentialGeneration = Guid.NewGuid().ToString("N");
                candidate.Initialized = true;

                string? generatedTotp = null;
                if (enableTotp)
                {
                    generatedTotp = string.IsNullOrWhiteSpace(totpSecret) ? Totp.GenerateSecret() : totpSecret.Trim();
                    ValidateTotpSecret(generatedTotp);
                    candidate.TotpSecret = VaultCrypto.ToBase64(
                        VaultCrypto.Seal(Encoding.ASCII.GetBytes(generatedTotp), vaultKey));
                    candidate.TotpEnabled = true;
                }

                Save(candidate);
                _state = candidate;
                return generatedTotp ?? string.Empty;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(vaultKey);
            }
        }
    }

    public bool VerifyPassphrase(string passphrase)
    {
        lock (_gate)
        {
            if (!_state.Initialized)
            {
                return false;
            }

            var vaultKey = DeriveVaultKeyOrThrow(passphrase);
            try
            {
                return KeyCheckMatches(vaultKey);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(vaultKey);
            }
        }
    }

    public void ChangePassphrase(string currentPassphrase, string newPassphrase, string? currentTotpCode = null)
    {
        lock (_gate)
        {
            ValidateNewPassphrase(newPassphrase);
            if (!VerifyPassphrase(currentPassphrase))
            {
                throw new VaultException(ErrorCodes.PassphraseInvalid, "Senha do cofre invalida.");
            }

            var vaultKey = DeriveVaultKeyOrThrow(currentPassphrase);
            byte[]? newVaultKey = null;
            var stagingState = CloneState(_state);
            VaultState? candidate = null;
            string[] oldTargets = Array.Empty<string>();

            try
            {
                VerifyCurrentTotp(vaultKey, currentTotpCode);
                var newMasterSalt = VaultCrypto.RandomSalt();
                newVaultKey = VaultCrypto.DeriveVaultKey(newPassphrase, newMasterSalt);
                var newGeneration = Guid.NewGuid().ToString("N");
                oldTargets = stagingState.Entries.Select(e => EntryTarget(e.Id, e.CredentialVersion ?? _state.CredentialGeneration)).ToArray();
                var legacyTargets = stagingState.Entries
                    .Where(e => string.IsNullOrEmpty(e.CredentialVersion ?? _state.CredentialGeneration))
                    .Select(e => EntryTarget(e.Id, null))
                    .ToArray();
                var newTargets = stagingState.Entries.Select(e => EntryTarget(e.Id, newGeneration)).ToArray();
                stagingState.KnownCredentialTargets = stagingState.KnownCredentialTargets
                    .Except(legacyTargets, StringComparer.Ordinal)
                    .Concat(newTargets)
                    .Distinct(StringComparer.Ordinal)
                    .ToList();
                Save(stagingState);
                _state = stagingState;
                candidate = CloneState(stagingState);
                candidate.CredentialGeneration = newGeneration;
                foreach (var entry in candidate.Entries)
                {
                    entry.CredentialVersion = null;
                }
                foreach (var entry in candidate.Entries)
                {
                    var original = _state.Entries.First(e => string.Equals(e.Id, entry.Id, StringComparison.OrdinalIgnoreCase));
                    var blob = _credentials.Read(EntryTarget(entry.Id, original.CredentialVersion ?? _state.CredentialGeneration))
                               ?? throw new VaultException(ErrorCodes.NotFound, $"Segredo ausente: {entry.Id}.");

                    var entryKey = VaultCrypto.DeriveEntryKey(vaultKey, entry.Id, VaultCrypto.FromBase64(entry.EntrySalt));
                    byte[]? plaintext = null;
                    byte[]? newEntryKey = null;
                    try
                    {
                        if (!VaultCrypto.TryOpen(blob, entryKey, out plaintext))
                        {
                            throw new VaultException(ErrorCodes.PassphraseInvalid, "Falha ao abrir segredo durante rotacao.");
                        }

                        newEntryKey = VaultCrypto.DeriveEntryKey(newVaultKey!, entry.Id, VaultCrypto.FromBase64(entry.EntrySalt));
                        var resealed = VaultCrypto.Seal(plaintext, newEntryKey);
                        _credentials.Write(EntryTarget(entry.Id, candidate.CredentialGeneration), SecretUserName, resealed);

                        var check = _credentials.Read(EntryTarget(entry.Id, candidate.CredentialGeneration));
                        if (check is null || !VaultCrypto.TryOpen(check, newEntryKey, out var verified))
                        {
                            throw new VaultException(ErrorCodes.Internal, "Falha ao validar credencial durante rotacao.");
                        }

                        try
                        {
                            if (!CryptographicOperations.FixedTimeEquals(verified, plaintext))
                            {
                                throw new VaultException(ErrorCodes.Internal, "Falha ao validar credencial durante rotacao.");
                            }
                        }
                        finally
                        {
                            CryptographicOperations.ZeroMemory(verified);
                        }
                    }
                    finally
                    {
                        if (plaintext is not null) CryptographicOperations.ZeroMemory(plaintext);
                        CryptographicOperations.ZeroMemory(entryKey);
                        if (newEntryKey is not null) CryptographicOperations.ZeroMemory(newEntryKey);
                    }
                }

                candidate.MasterSalt = VaultCrypto.ToBase64(newMasterSalt);
                candidate.KeyCheck = VaultCrypto.ToBase64(VaultCrypto.Seal(KeyCheckBytes, newVaultKey!));

                if (candidate.TotpEnabled && !string.IsNullOrEmpty(candidate.TotpSecret))
                {
                    if (!VaultCrypto.TryOpen(VaultCrypto.FromBase64(candidate.TotpSecret), vaultKey, out var totpPlain))
                    {
                        throw new VaultException(ErrorCodes.PassphraseInvalid, "Falha ao abrir o segredo TOTP durante rotacao.");
                    }

                    try
                    {
                        candidate.TotpSecret = VaultCrypto.ToBase64(VaultCrypto.Seal(totpPlain, newVaultKey!));
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(totpPlain);
                    }
                }

                Save(candidate);
                _state = candidate;
                foreach (var target in oldTargets)
                {
                    try
                    {
                        _credentials.Delete(target);
                        if (!string.IsNullOrEmpty(_state.CredentialGeneration))
                        {
                            var cleanupState = CloneState(_state);
                            cleanupState.KnownCredentialTargets.Remove(target);
                            Save(cleanupState);
                            _state = cleanupState;
                            candidate = cleanupState;
                        }
                    }
                    catch
                    {
                    }
                }

                try
                {
                    Save(candidate);
                    _state = candidate;
                }
                catch
                {
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(vaultKey);
                if (newVaultKey is not null) CryptographicOperations.ZeroMemory(newVaultKey);
            }
        }
    }

    private static void ValidateNewPassphrase(string passphrase)
    {
        if (string.IsNullOrWhiteSpace(passphrase) || passphrase.Length < 8)
        {
            throw new VaultException(ErrorCodes.BadRequest, "A nova senha deve ter pelo menos oito caracteres.");
        }
    }

    private static string EntryTarget(string id, string? generation) =>
        CredentialManagerApi.BuildTarget(string.IsNullOrEmpty(generation) ? EntryTargetPrefix : EntryTargetPrefix + ":" + generation, id);

    private static VaultState CloneState(VaultState state) =>
        JsonSerializer.Deserialize<VaultState>(JsonSerializer.Serialize(state, Json.Options), Json.Options)!;

    private static EntryRecord CloneEntry(EntryRecord entry) =>
        JsonSerializer.Deserialize<EntryRecord>(JsonSerializer.Serialize(entry, Json.Options), Json.Options)!;

    private static OperationRecord CloneOperation(OperationRecord operation) =>
        JsonSerializer.Deserialize<OperationRecord>(JsonSerializer.Serialize(operation, Json.Options), Json.Options)!;

    private void PrepareCredentialTarget(string target)
    {
        if (!_state.KnownCredentialTargets.Contains(target, StringComparer.Ordinal))
        {
            _state.KnownCredentialTargets.Add(target);
            Save();
        }
    }

    public EntryRecord RegisterEntry(string id, string kind, string label, IReadOnlyList<string> targets, byte[] value, string passphrase)
    {
        lock (_gate)
        {
            var vaultKey = RequireVaultKey(passphrase);
            try
            {
                if (_state.Entries.Any(e => string.Equals(e.Id, id, StringComparison.OrdinalIgnoreCase)))
                {
                    throw new VaultException(ErrorCodes.Conflict, $"Ja existe um registro com o identificador {id}.");
                }

                var entrySalt = VaultCrypto.RandomSalt();
                var entryKey = VaultCrypto.DeriveEntryKey(vaultKey, id, entrySalt);
                var sealedValue = VaultCrypto.Seal(value, entryKey);

                var target = EntryTarget(id, _state.CredentialGeneration);
                PrepareCredentialTarget(target);
                _credentials.Write(
                    target,
                    SecretUserName,
                    sealedValue);

                var now = DateTime.UtcNow.ToString("o");
                var record = new EntryRecord
                {
                    IdentityId = Guid.NewGuid().ToString("N"),
                    Id = id,
                    Kind = kind,
                    Label = label,
                    Targets = targets.ToList(),
                    CreatedAt = now,
                    UpdatedAt = now,
                    Revision = 1,
                    EntrySalt = VaultCrypto.ToBase64(entrySalt)
                };

                var candidate = CloneState(_state);
                candidate.Entries.Add(record);
                Save(candidate);
                _state = candidate;
                return CloneEntry(record);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(vaultKey);
            }
        }
    }

    public EntryRecord UpdateEntry(string id, byte[]? value, string? label, IReadOnlyList<string>? targets, string passphrase)
    {
        lock (_gate)
        {
            var vaultKey = RequireVaultKey(passphrase);
            try
            {
                var current = _state.Entries.FirstOrDefault(e => string.Equals(e.Id, id, StringComparison.OrdinalIgnoreCase))
                              ?? throw new VaultException(ErrorCodes.NotFound, $"Registro nao encontrado: {id}.");
                var oldTarget = EntryTarget(current.Id, current.CredentialVersion ?? _state.CredentialGeneration);
                var candidate = CloneState(_state);
                var record = candidate.Entries.First(e => string.Equals(e.Id, id, StringComparison.OrdinalIgnoreCase));

                if (value is not null)
                {
                    var entryKey = VaultCrypto.DeriveEntryKey(vaultKey, record.Id, VaultCrypto.FromBase64(record.EntrySalt));
                    try
                    {
                        var version = "entry-" + Guid.NewGuid().ToString("N");
                        var newTarget = EntryTarget(record.Id, version);
                        var staging = CloneState(_state);
                        if (!staging.KnownCredentialTargets.Contains(newTarget, StringComparer.Ordinal))
                        {
                            staging.KnownCredentialTargets.Add(newTarget);
                            Save(staging);
                            _state = staging;
                            candidate = CloneState(staging);
                            record = candidate.Entries.First(e => string.Equals(e.Id, id, StringComparison.OrdinalIgnoreCase));
                        }

                        _credentials.Write(newTarget, SecretUserName, VaultCrypto.Seal(value, entryKey));
                        record.CredentialVersion = version;
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(entryKey);
                    }
                }

                if (label is not null)
                {
                    record.Label = label;
                }

                if (targets is not null)
                {
                    record.Targets = targets.ToList();
                }

                record.UpdatedAt = DateTime.UtcNow.ToString("o");
                record.Revision += 1;
                Save(candidate);
                _state = candidate;
                if (value is not null)
                {
                    try
                    {
                        _credentials.Delete(oldTarget);
                        var cleanupState = CloneState(_state);
                        cleanupState.KnownCredentialTargets.Remove(oldTarget);
                        Save(cleanupState);
                        _state = cleanupState;
                        candidate = cleanupState;
                    }
                    catch
                    {
                    }
                }

                return CloneEntry(record);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(vaultKey);
            }
        }
    }

    public void DeleteEntry(string id, string passphrase)
    {
        lock (_gate)
        {
            var vaultKey = RequireVaultKey(passphrase);
            CryptographicOperations.ZeroMemory(vaultKey);

            var record = _state.Entries.FirstOrDefault(e => string.Equals(e.Id, id, StringComparison.OrdinalIgnoreCase))
                         ?? throw new VaultException(ErrorCodes.NotFound, $"Registro nao encontrado: {id}.");

                var oldTarget = EntryTarget(record.Id, record.CredentialVersion ?? _state.CredentialGeneration);
                var candidate = CloneState(_state);
                candidate.Entries.RemoveAll(e => string.Equals(e.Id, record.Id, StringComparison.OrdinalIgnoreCase));
                candidate.Operations.RemoveAll(o => string.Equals(o.EntryId, record.Id, StringComparison.OrdinalIgnoreCase));
                Save(candidate);
                _state = candidate;
                try
                {
                    _credentials.Delete(oldTarget);
                    var cleanupState = CloneState(_state);
                    cleanupState.KnownCredentialTargets.Remove(oldTarget);
                    Save(cleanupState);
                    _state = cleanupState;
                }
                catch
                {
                }
        }
    }

    public byte[] UnwrapSecret(string entryId, string passphrase)
    {
        lock (_gate)
        {
            var vaultKey = RequireVaultKey(passphrase);
            try
            {
                var record = _state.Entries.FirstOrDefault(e => string.Equals(e.Id, entryId, StringComparison.OrdinalIgnoreCase))
                             ?? throw new VaultException(ErrorCodes.NotFound, $"Registro nao encontrado: {entryId}.");

                var blob = _credentials.Read(EntryTarget(record.Id, record.CredentialVersion ?? _state.CredentialGeneration))
                           ?? throw new VaultException(ErrorCodes.NotFound, $"Segredo ausente: {entryId}.");

                var entryKey = VaultCrypto.DeriveEntryKey(vaultKey, record.Id, VaultCrypto.FromBase64(record.EntrySalt));
                try
                {
                    if (!VaultCrypto.TryOpen(blob, entryKey, out var plaintext))
                    {
                        throw new VaultException(ErrorCodes.PassphraseInvalid, "Nao foi possivel descriptografar o segredo.");
                    }

                    return plaintext;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(entryKey);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(vaultKey);
            }
        }
    }

    public IReadOnlyDictionary<string, byte[]> UnwrapAllSecrets(string passphrase)
    {
        lock (_gate)
        {
            var vaultKey = RequireVaultKey(passphrase);
            var result = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
            try
            {
                foreach (var record in _state.Entries)
                {
                    var blob = _credentials.Read(EntryTarget(record.Id, record.CredentialVersion ?? _state.CredentialGeneration));
                    if (blob is null)
                    {
                        continue;
                    }

                    var entryKey = VaultCrypto.DeriveEntryKey(vaultKey, record.Id, VaultCrypto.FromBase64(record.EntrySalt));
                    try
                    {
                        if (VaultCrypto.TryOpen(blob, entryKey, out var plaintext))
                        {
                            result[record.Id] = plaintext;
                        }
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(entryKey);
                    }
                }

                return result;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(vaultKey);
            }
        }
    }

    /// <summary>Apaga todos os segredos e reinicia o cofre (estado e Credential Manager).</summary>
    public int Reset(string passphrase, string? currentTotpCode = null)
    {
        lock (_gate)
        {
            var vaultKey = RequireVaultKey(passphrase);
            try
            {
                VerifyCurrentTotp(vaultKey, currentTotpCode);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(vaultKey);
            }

            var ownedTargets = _state.KnownCredentialTargets
                .Concat(_state.Entries.Select(e => EntryTarget(e.Id, e.CredentialVersion ?? _state.CredentialGeneration)))
                .Distinct(StringComparer.Ordinal)
                .ToArray();
            foreach (var target in ownedTargets)
            {
                _credentials.Delete(target);
            }

            var removed = _state.Entries.Count;
            var resetState = new VaultState();
            Save(resetState);
            _state = resetState;
            return removed;
        }
    }

    public IReadOnlyDictionary<string, byte[]> UnwrapSecrets(IEnumerable<string> entryIds, string passphrase)
    {
        lock (_gate)
        {
            var vaultKey = RequireVaultKey(passphrase);
            var result = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
            try
            {
                foreach (var id in entryIds)
                {
                    var record = _state.Entries.FirstOrDefault(e => string.Equals(e.Id, id, StringComparison.OrdinalIgnoreCase));
                    if (record is null)
                    {
                        continue;
                    }

                    var blob = _credentials.Read(EntryTarget(record.Id, record.CredentialVersion ?? _state.CredentialGeneration));
                    if (blob is null)
                    {
                        continue;
                    }

                    var entryKey = VaultCrypto.DeriveEntryKey(vaultKey, record.Id, VaultCrypto.FromBase64(record.EntrySalt));
                    try
                    {
                        if (VaultCrypto.TryOpen(blob, entryKey, out var plaintext))
                        {
                            result[record.Id] = plaintext;
                        }
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(entryKey);
                    }
                }

                return result;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(vaultKey);
            }
        }
    }

    public OperationRecord AuthorizeOperation(OperationRecord record, string passphrase)
    {
        try
        {
            Operations.OperationEngine.ValidateTemplates(record);
        }
        catch (Operations.OperationFailure ex)
        {
            throw new VaultException(ErrorCodes.BadRequest, ex.Message);
        }

        lock (_gate)
        {
            var vaultKey = RequireVaultKey(passphrase);
            CryptographicOperations.ZeroMemory(vaultKey);

            if (_state.Operations.Any(o => string.Equals(o.Id, record.Id, StringComparison.OrdinalIgnoreCase)))
            {
                throw new VaultException(ErrorCodes.Conflict, $"Ja existe uma operacao com o identificador {record.Id}.");
            }

            var entry = _state.Entries.FirstOrDefault(e => string.Equals(e.Id, record.EntryId, StringComparison.OrdinalIgnoreCase))
                        ?? throw new VaultException(ErrorCodes.NotFound, $"Registro nao encontrado: {record.EntryId}.");

            if (record.Action != Operations.OperationEngine.ActionNoopEcho &&
                !TargetPolicy.IsTargetAllowed(entry.Targets, record.Target))
            {
                throw new VaultException(
                    ErrorCodes.TargetNotAllowed,
                    $"O alvo {record.Target} nao esta autorizado para o registro {entry.Id}.");
            }

            var candidate = CloneState(_state);
            var operation = CloneOperation(record);
            if (string.IsNullOrWhiteSpace(operation.AuthorizationId))
            {
                operation.AuthorizationId = Guid.NewGuid().ToString("N");
            }
            candidate.Operations.Add(operation);
            Save(candidate);
            _state = candidate;
            return CloneOperation(operation);
        }
    }

    public void RevokeOperation(string operationId, string passphrase)
    {
        lock (_gate)
        {
            var vaultKey = RequireVaultKey(passphrase);
            CryptographicOperations.ZeroMemory(vaultKey);

            var record = _state.Operations.FirstOrDefault(o => string.Equals(o.Id, operationId, StringComparison.OrdinalIgnoreCase))
                         ?? throw new VaultException(ErrorCodes.NotFound, $"Operacao nao encontrada: {operationId}");

            var candidate = CloneState(_state);
            candidate.Operations.RemoveAll(o => string.Equals(o.Id, operationId, StringComparison.OrdinalIgnoreCase));
            Save(candidate);
            _state = candidate;
        }
    }

    public void SetTotp(string secret, string passphrase, string? currentTotpCode = null)
    {
        lock (_gate)
        {
            var vaultKey = RequireVaultKey(passphrase);
            try
            {
                VerifyCurrentTotp(vaultKey, currentTotpCode);
                ValidateTotpSecret(secret.Trim());
                var candidate = CloneState(_state);
                candidate.TotpSecret = VaultCrypto.ToBase64(
                    VaultCrypto.Seal(Encoding.ASCII.GetBytes(secret.Trim()), vaultKey));
                candidate.TotpEnabled = true;
                Save(candidate);
                _state = candidate;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(vaultKey);
            }
        }
    }

    public void DisableTotp(string passphrase, string? currentTotpCode = null)
    {
        lock (_gate)
        {
            var vaultKey = RequireVaultKey(passphrase);
            try
            {
                VerifyCurrentTotp(vaultKey, currentTotpCode);
                var candidate = CloneState(_state);
                candidate.TotpSecret = string.Empty;
                candidate.TotpEnabled = false;
                Save(candidate);
                _state = candidate;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(vaultKey);
            }
        }
    }

    private void VerifyCurrentTotp(byte[] vaultKey, string? code)
    {
        if (!_state.TotpEnabled || string.IsNullOrEmpty(_state.TotpSecret))
        {
            return;
        }

        if (!VaultCrypto.TryOpen(VaultCrypto.FromBase64(_state.TotpSecret), vaultKey, out var secretBytes))
        {
            throw new VaultException(ErrorCodes.Internal, "Falha ao verificar o segundo fator.");
        }

        try
        {
            var secret = Encoding.ASCII.GetString(secretBytes);
            if (string.IsNullOrWhiteSpace(code) || !Totp.VerifyCode(secret, code, DateTime.UtcNow))
            {
                throw new VaultException(ErrorCodes.TotpInvalid, "Codigo do segundo fator invalido.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secretBytes);
        }
    }

    private static void ValidateTotpSecret(string secret)
    {
        try
        {
            var decoded = Base32.Decode(secret);
            try
            {
                if (decoded.Length < 16)
                {
                    throw new VaultException(ErrorCodes.BadRequest, "O segredo TOTP deve conter ao menos 16 bytes codificados.");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(decoded);
            }
        }
        catch (FormatException)
        {
            throw new VaultException(ErrorCodes.BadRequest, "O segredo TOTP tem formato invalido.");
        }
    }

    public string? GetTotpSecret(string passphrase)
    {
        lock (_gate)
        {
            if (!_state.TotpEnabled || string.IsNullOrEmpty(_state.TotpSecret))
            {
                return null;
            }

            var vaultKey = RequireVaultKey(passphrase);
            try
            {
                if (!VaultCrypto.TryOpen(VaultCrypto.FromBase64(_state.TotpSecret), vaultKey, out var opened))
                {
                    return null;
                }

                var secret = Encoding.ASCII.GetString(opened);
                CryptographicOperations.ZeroMemory(opened);
                return secret;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(vaultKey);
            }
        }
    }

    private byte[] DeriveVaultKeyOrThrow(string passphrase)
    {
        if (string.IsNullOrEmpty(passphrase))
        {
            throw new VaultException(ErrorCodes.PassphraseRequired, "Senha do cofre obrigatoria.");
        }

        return VaultCrypto.DeriveVaultKey(passphrase, VaultCrypto.FromBase64(_state.MasterSalt));
    }

    private byte[] RequireVaultKey(string passphrase)
    {
        if (!_state.Initialized)
        {
            throw new VaultException(ErrorCodes.VaultNotInitialized, "Cofre ainda nao inicializado.");
        }

        var vaultKey = DeriveVaultKeyOrThrow(passphrase);
        if (!KeyCheckMatches(vaultKey))
        {
            CryptographicOperations.ZeroMemory(vaultKey);
            throw new VaultException(ErrorCodes.PassphraseInvalid, "Senha do cofre invalida.");
        }

        return vaultKey;
    }

    private bool KeyCheckMatches(byte[] vaultKey)
    {
        if (!VaultCrypto.TryOpen(VaultCrypto.FromBase64(_state.KeyCheck), vaultKey, out var opened))
        {
            return false;
        }

        var ok = opened.AsSpan().SequenceEqual(KeyCheckBytes);
        CryptographicOperations.ZeroMemory(opened);
        return ok;
    }
}
