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
    private VaultState _state = new();

    public VaultStore(string? stateFile = null)
    {
        _stateFile = stateFile ?? Paths.StateFile;
        Load();
    }

    public VaultState State
    {
        get
        {
            lock (_gate)
            {
                return _state;
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

    private void Save()
    {
        lock (_gate)
        {
            var directory = Path.GetDirectoryName(_stateFile)!;
            Directory.CreateDirectory(directory);

            var json = JsonSerializer.Serialize(_state, Json.Options);
            var temp = _stateFile + ".tmp";
            File.WriteAllText(temp, json, new UTF8Encoding(false));
            File.Move(temp, _stateFile, overwrite: true);
        }
    }

    public string Initialize(string passphrase, bool enableTotp, string? totpSecret)
    {
        lock (_gate)
        {
            if (_state.Initialized)
            {
                throw new VaultException(ErrorCodes.Conflict, "O cofre ja esta inicializado.");
            }

            var masterSalt = VaultCrypto.RandomSalt();
            var vaultKey = VaultCrypto.DeriveVaultKey(passphrase, masterSalt);

            _state.MasterSalt = VaultCrypto.ToBase64(masterSalt);
            _state.KeyCheck = VaultCrypto.ToBase64(VaultCrypto.Seal(KeyCheckBytes, vaultKey));
            _state.Initialized = true;

            string? generatedTotp = null;
            if (enableTotp)
            {
                generatedTotp = string.IsNullOrWhiteSpace(totpSecret) ? Totp.GenerateSecret() : totpSecret.Trim();
                _state.TotpSecret = VaultCrypto.ToBase64(
                    VaultCrypto.Seal(Encoding.ASCII.GetBytes(generatedTotp), vaultKey));
                _state.TotpEnabled = true;
            }

            Save();
            CryptographicOperations.ZeroMemory(vaultKey);
            return generatedTotp ?? string.Empty;
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

    public void ChangePassphrase(string currentPassphrase, string newPassphrase)
    {
        lock (_gate)
        {
            if (!VerifyPassphrase(currentPassphrase))
            {
                throw new VaultException(ErrorCodes.PassphraseInvalid, "Senha do cofre invalida.");
            }

            var vaultKey = DeriveVaultKeyOrThrow(currentPassphrase);
            var newMasterSalt = VaultCrypto.RandomSalt();
            var newVaultKey = VaultCrypto.DeriveVaultKey(newPassphrase, newMasterSalt);

            try
            {
                foreach (var entry in _state.Entries)
                {
                    var blob = CredentialManagerApi.Read(CredentialManagerApi.BuildTarget(EntryTargetPrefix, entry.Id))
                               ?? throw new VaultException(ErrorCodes.NotFound, $"Segredo ausente: {entry.Id}.");

                    var entryKey = VaultCrypto.DeriveEntryKey(vaultKey, entry.Id, VaultCrypto.FromBase64(entry.EntrySalt));
                    if (!VaultCrypto.TryOpen(blob, entryKey, out var plaintext))
                    {
                        throw new VaultException(ErrorCodes.PassphraseInvalid, "Falha ao abrir segredo durante rotacao.");
                    }

                    var newEntryKey = VaultCrypto.DeriveEntryKey(newVaultKey, entry.Id, VaultCrypto.FromBase64(entry.EntrySalt));
                    var resealed = VaultCrypto.Seal(plaintext, newEntryKey);
                    CredentialManagerApi.Write(
                        CredentialManagerApi.BuildTarget(EntryTargetPrefix, entry.Id),
                        SecretUserName,
                        resealed);

                    CryptographicOperations.ZeroMemory(plaintext);
                    CryptographicOperations.ZeroMemory(entryKey);
                    CryptographicOperations.ZeroMemory(newEntryKey);
                }

                _state.MasterSalt = VaultCrypto.ToBase64(newMasterSalt);
                _state.KeyCheck = VaultCrypto.ToBase64(VaultCrypto.Seal(KeyCheckBytes, newVaultKey));

                if (_state.TotpEnabled && !string.IsNullOrEmpty(_state.TotpSecret))
                {
                    if (!VaultCrypto.TryOpen(VaultCrypto.FromBase64(_state.TotpSecret), vaultKey, out var totpPlain))
                    {
                        throw new VaultException(ErrorCodes.PassphraseInvalid, "Falha ao abrir o segredo TOTP durante rotacao.");
                    }

                    _state.TotpSecret = VaultCrypto.ToBase64(VaultCrypto.Seal(totpPlain, newVaultKey));
                    CryptographicOperations.ZeroMemory(totpPlain);
                }

                Save();
            }
            finally
            {
                CryptographicOperations.ZeroMemory(vaultKey);
                CryptographicOperations.ZeroMemory(newVaultKey);
            }
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

                CredentialManagerApi.Write(
                    CredentialManagerApi.BuildTarget(EntryTargetPrefix, id),
                    SecretUserName,
                    sealedValue);

                var now = DateTime.UtcNow.ToString("o");
                var record = new EntryRecord
                {
                    Id = id,
                    Kind = kind,
                    Label = label,
                    Targets = targets.ToList(),
                    CreatedAt = now,
                    UpdatedAt = now,
                    Revision = 1,
                    EntrySalt = VaultCrypto.ToBase64(entrySalt)
                };

                _state.Entries.Add(record);
                Save();
                return record;
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
                var record = _state.Entries.FirstOrDefault(e => string.Equals(e.Id, id, StringComparison.OrdinalIgnoreCase))
                             ?? throw new VaultException(ErrorCodes.NotFound, $"Registro nao encontrado: {id}.");

                if (value is not null)
                {
                    var entryKey = VaultCrypto.DeriveEntryKey(vaultKey, record.Id, VaultCrypto.FromBase64(record.EntrySalt));
                    var sealedValue = VaultCrypto.Seal(value, entryKey);
                    CredentialManagerApi.Write(
                        CredentialManagerApi.BuildTarget(EntryTargetPrefix, record.Id),
                        SecretUserName,
                        sealedValue);
                    CryptographicOperations.ZeroMemory(entryKey);
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
                Save();
                return record;
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

            CredentialManagerApi.Delete(CredentialManagerApi.BuildTarget(EntryTargetPrefix, record.Id));
            _state.Entries.Remove(record);
            _state.Operations.RemoveAll(o => string.Equals(o.EntryId, record.Id, StringComparison.OrdinalIgnoreCase));
            Save();
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

                var blob = CredentialManagerApi.Read(CredentialManagerApi.BuildTarget(EntryTargetPrefix, record.Id))
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
                    var blob = CredentialManagerApi.Read(CredentialManagerApi.BuildTarget(EntryTargetPrefix, record.Id));
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
    public int Reset()
    {
        lock (_gate)
        {
            var removed = 0;
            foreach (var entry in _state.Entries)
            {
                CredentialManagerApi.Delete(CredentialManagerApi.BuildTarget(EntryTargetPrefix, entry.Id));
                removed++;
            }

            CredentialManagerApi.Delete(TotpTarget);

            _state = new VaultState();
            Save();
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

                    var blob = CredentialManagerApi.Read(CredentialManagerApi.BuildTarget(EntryTargetPrefix, record.Id));
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

            _state.Operations.Add(record);
            Save();
            return record;
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

            _state.Operations.Remove(record);
            Save();
        }
    }

    public void SetTotp(string secret, string passphrase)
    {
        lock (_gate)
        {
            var vaultKey = RequireVaultKey(passphrase);
            try
            {
                _state.TotpSecret = VaultCrypto.ToBase64(
                    VaultCrypto.Seal(Encoding.ASCII.GetBytes(secret.Trim()), vaultKey));
                _state.TotpEnabled = true;
                Save();
            }
            finally
            {
                CryptographicOperations.ZeroMemory(vaultKey);
            }
        }
    }

    public void DisableTotp(string passphrase)
    {
        lock (_gate)
        {
            var vaultKey = RequireVaultKey(passphrase);
            CryptographicOperations.ZeroMemory(vaultKey);

            _state.TotpSecret = string.Empty;
            _state.TotpEnabled = false;
            Save();
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
