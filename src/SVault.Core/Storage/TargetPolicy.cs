namespace SVault.Core.Storage;

/// <summary>
/// Decides whether an operation target is covered by the targets the human authorized for an entry.
/// </summary>
public static class TargetPolicy
{
    public static bool IsTargetAllowed(IReadOnlyList<string> authorizedTargets, string operationTarget)
    {
        if (authorizedTargets.Count == 0 || string.IsNullOrWhiteSpace(operationTarget))
        {
            return false;
        }

        if (IsUrl(operationTarget))
        {
            return authorizedTargets
                .Where(IsUrl)
                .Any(allowed => UrlCovers(allowed, operationTarget));
        }

        var executable = NormalizePath(operationTarget);
        return authorizedTargets
            .Where(t => !IsUrl(t))
            .Any(allowed => PathCovers(allowed, executable));
    }

    public static bool IsUrl(string value) =>
        value.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
        value.StartsWith("https://", StringComparison.OrdinalIgnoreCase);

    private static bool UrlCovers(string allowed, string target)
    {
        if (!Uri.TryCreate(allowed, UriKind.Absolute, out var allowedUri) ||
            !Uri.TryCreate(target, UriKind.Absolute, out var targetUri))
        {
            return false;
        }

        if (!IsClean(allowedUri) || !IsClean(targetUri) ||
            !string.Equals(allowedUri.Scheme, targetUri.Scheme, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(allowedUri.Host, targetUri.Host, StringComparison.OrdinalIgnoreCase) ||
            allowedUri.Port != targetUri.Port)
        {
            return false;
        }

        var allowedPath = allowedUri.AbsolutePath.TrimEnd('/');
        var targetPath = targetUri.AbsolutePath.TrimEnd('/');
        var pathMatches = allowedPath.Length == 0 ||
                          targetPath.Equals(allowedPath, StringComparison.Ordinal) ||
                          targetPath.StartsWith(allowedPath + "/", StringComparison.Ordinal);
        if (!pathMatches)
        {
            return false;
        }

        var allowedQuery = allowedUri.Query;
        return allowedQuery.Length == 0 || string.Equals(allowedQuery, targetUri.Query, StringComparison.Ordinal);
    }

    public static bool AreEquivalentUrls(string left, string right)
    {
        if (!Uri.TryCreate(left, UriKind.Absolute, out var leftUri) ||
            !Uri.TryCreate(right, UriKind.Absolute, out var rightUri) ||
            !IsClean(leftUri) || !IsClean(rightUri))
        {
            return false;
        }

        return string.Equals(leftUri.Scheme, rightUri.Scheme, StringComparison.OrdinalIgnoreCase) &&
               string.Equals(leftUri.Host, rightUri.Host, StringComparison.OrdinalIgnoreCase) &&
               leftUri.Port == rightUri.Port &&
               string.Equals(leftUri.AbsolutePath, rightUri.AbsolutePath, StringComparison.Ordinal) &&
               string.Equals(leftUri.Query, rightUri.Query, StringComparison.Ordinal);
    }

    private static bool IsClean(Uri uri) => string.IsNullOrEmpty(uri.UserInfo) && string.IsNullOrEmpty(uri.Fragment);

    private static bool PathCovers(string allowed, string target)
    {
        var normalizedAllowed = NormalizePath(allowed);
        if (normalizedAllowed.EndsWith(Path.DirectorySeparatorChar))
        {
            return target.StartsWith(normalizedAllowed, StringComparison.OrdinalIgnoreCase);
        }

        return string.Equals(normalizedAllowed, target, StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizePath(string path) => path.Trim().TrimEnd('/');
}
