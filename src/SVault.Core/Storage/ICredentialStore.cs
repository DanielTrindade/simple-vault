namespace SVault.Core.Storage;

public interface ICredentialStore
{
    void Write(string target, string userName, byte[] secret);
    byte[]? Read(string target);
    void Delete(string target);
    IReadOnlyList<string> ListTargets(string filter);
}

public sealed class WindowsCredentialStore : ICredentialStore
{
    public void Write(string target, string userName, byte[] secret) => CredentialManagerApi.Write(target, userName, secret);
    public byte[]? Read(string target) => CredentialManagerApi.Read(target);
    public void Delete(string target) => CredentialManagerApi.Delete(target);
    public IReadOnlyList<string> ListTargets(string filter) => CredentialManagerApi.ListTargets(filter);
}

public sealed class MemoryCredentialStore : ICredentialStore
{
    private readonly object _gate = new();
    private readonly Dictionary<string, byte[]> _items = new(StringComparer.Ordinal);

    public void Write(string target, string userName, byte[] secret)
    {
        lock (_gate)
        {
            _items[target] = secret.ToArray();
        }
    }

    public byte[]? Read(string target)
    {
        lock (_gate)
        {
            return _items.TryGetValue(target, out var value) ? value.ToArray() : null;
        }
    }

    public void Delete(string target)
    {
        lock (_gate)
        {
            _items.Remove(target);
        }
    }

    public IReadOnlyList<string> ListTargets(string filter)
    {
        lock (_gate)
        {
            return _items.Keys.Where(target => target.StartsWith(filter, StringComparison.Ordinal)).ToArray();
        }
    }
}
