using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using SVault.Core.Protocol;
using SVault.Core.Redaction;
using SVault.Core.Storage;

namespace SVault.Core.Operations;

public sealed class OperationContext
{
    public required OperationRecord Operation { get; init; }

    /// <summary>Segredo da entrada principal da operacao (o que {{secret}} resolve).</summary>
    public required byte[] Secret { get; init; }

    /// <summary>Outros segredos referenciados por {{secret:IDENTIFICADOR}}.</summary>
    public required IReadOnlyDictionary<string, byte[]> ReferencedSecrets { get; init; }

    public required IReadOnlyDictionary<string, string> Parameters { get; init; }
    public required SecretRedactor Redactor { get; init; }
    public required CancellationToken Cancellation { get; init; }

    public string SecretText => Encoding.UTF8.GetString(Secret);
}

public static class OperationEngine
{
    public const string ActionNoopEcho = "noop.echo";
    public const string ActionHttpRequest = "http.request";
    public const string ActionProcessStdin = "process.stdin";

    public const string PlaceholderSecret = "{{secret}}";
    public const string ParamPrefix = "{{param:";
    public const string SecretPrefix = "{{secret:";

    public static readonly string[] SupportedActions =
    {
        ActionNoopEcho,
        ActionHttpRequest
    };

    /// <summary>Extrai os identificadores referenciados por {{secret:ID}} nos templates da operacao.</summary>
    public static IReadOnlyList<string> CollectReferencedEntries(OperationRecord operation)
    {
        var templates = new List<string>();
        if (operation.Http is not null)
        {
            templates.AddRange(operation.Http.BodyFields.Values);
            templates.AddRange(operation.Http.Headers.Values);
        }

        if (operation.Process is not null)
        {
            templates.AddRange(operation.Process.Args);
            templates.AddRange(operation.Process.Env);
        }

        var ids = new List<string>();
        foreach (var template in templates)
        {
            var index = template.IndexOf(SecretPrefix, StringComparison.Ordinal);
            while (index >= 0)
            {
                var end = template.IndexOf("}}", index, StringComparison.Ordinal);
                if (end < 0)
                {
                    break;
                }

                var id = template[(index + SecretPrefix.Length)..end].Trim();
                if (id.Length > 0 && !ids.Contains(id, StringComparer.OrdinalIgnoreCase))
                {
                    ids.Add(id);
                }

                index = template.IndexOf(SecretPrefix, end, StringComparison.Ordinal);
            }
        }

        return ids;
    }

    public static async Task<OperationOutcome> ExecuteAsync(OperationContext context)
    {
        var stopwatch = Stopwatch.StartNew();

        var outcome = context.Operation.Action switch
        {
            ActionNoopEcho => ExecuteEcho(context),
            ActionHttpRequest => await ExecuteHttpAsync(context).ConfigureAwait(false),
            ActionProcessStdin => throw new OperationFailure("Acoes de processo estao desabilitadas pelo contrato de seguranca atual."),
            _ => throw new OperationFailure("Acao nao suportada: " + context.Operation.Action)
        };

        stopwatch.Stop();
        outcome.DurationMs = stopwatch.ElapsedMilliseconds.ToString();
        return outcome;
    }

    private static OperationOutcome ExecuteEcho(OperationContext context)
    {
        var payload = "secret=" + context.SecretText;
        return new OperationOutcome
        {
            Kind = "echo",
            Ok = true,
            Body = context.Redactor.Redact(payload)
        };
    }

    private static async Task<OperationOutcome> ExecuteHttpAsync(OperationContext context)
    {
        var spec = context.Operation.Http
                   ?? throw new OperationFailure("Operacao http.request sem especificacao.");

        if (!TargetPolicy.AreEquivalentUrls(spec.Url, context.Operation.Target))
        {
            throw new OperationFailure("URL efetiva diferente do alvo autorizado.");
        }

        if (!Uri.TryCreate(spec.Url, UriKind.Absolute, out var uri))
        {
            throw new OperationFailure("URL da operacao invalida.");
        }

        if (!TargetPolicy.IsUrl(spec.Url))
        {
            throw new OperationFailure("Alvo HTTP invalido.");
        }

        if (uri.Scheme != Uri.UriSchemeHttps && !IsLoopback(uri))
        {
            throw new OperationFailure("Somente HTTPS e loopback sao permitidos.");
        }

        var body = BuildBody(spec, context);
        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false
        };

        using var client = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(30)
        };

        using var request = new HttpRequestMessage(new HttpMethod(spec.Method.ToUpperInvariant()), uri);
        if (body is not null)
        {
            request.Content = body;
        }

        foreach (var (name, template) in spec.Headers)
        {
            var value = ResolveTemplate(template, context);
            if (!request.Headers.TryAddWithoutValidation(name, value))
            {
                request.Content?.Headers.TryAddWithoutValidation(name, value);
            }
        }

        using var response = await client.SendAsync(request, context.Cancellation).ConfigureAwait(false);
        var raw = await response.Content.ReadAsStringAsync(context.Cancellation).ConfigureAwait(false);

        var rendered = SelectResultFields(spec, raw, context.Redactor);
        var location = response.Headers.Location?.ToString();

        return new OperationOutcome
        {
            Kind = "http",
            StatusCode = (int)response.StatusCode,
            Ok = response.IsSuccessStatusCode,
            Body = rendered,
            Output = location is null ? null : context.Redactor.Redact(location)
        };
    }

    private static bool IsLoopback(Uri uri) =>
        uri.IsLoopback ||
        string.Equals(uri.Host, "localhost", StringComparison.OrdinalIgnoreCase);

    private static HttpContent? BuildBody(HttpRequestRecord spec, OperationContext context)
    {
        if (spec.BodyFields.Count == 0)
        {
            return null;
        }

        var resolved = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (key, template) in spec.BodyFields)
        {
            resolved[key] = ResolveTemplate(template, context);
        }

        if (spec.ContentType.Contains("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
        {
            return new FormUrlEncodedContent(resolved);
        }

        if (spec.ContentType.Contains("application/json", StringComparison.OrdinalIgnoreCase))
        {
            return new StringContent(JsonSerializer.Serialize(resolved, Json.Options), Encoding.UTF8, "application/json");
        }

        throw new OperationFailure("Content-Type nao suportado.");
    }

    private static string SelectResultFields(HttpRequestRecord spec, string raw, SecretRedactor redactor)
    {
        if (spec.ResultFields.Count == 0)
        {
            return redactor.Redact(raw);
        }

        try
        {
            using var document = JsonDocument.Parse(raw);
            var selected = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
            foreach (var field in spec.ResultFields)
            {
                if (document.RootElement.ValueKind == JsonValueKind.Object &&
                    document.RootElement.TryGetProperty(field, out var value))
                {
                    selected[field] = value;
                }
            }

            return redactor.Redact(JsonSerializer.Serialize(selected, Json.Options));
        }
        catch (JsonException)
        {
            throw new OperationFailure("A resposta nao permite aplicar a selecao de campos configurada.");
        }
    }

    private static async Task<OperationOutcome> ExecuteProcessAsync(OperationContext context)
    {
        var spec = context.Operation.Process
                   ?? throw new OperationFailure("Operacao process.stdin sem especificacao.");

        if (!File.Exists(spec.Executable))
        {
            throw new OperationFailure("Executavel nao encontrado.");
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = spec.Executable,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = Path.GetDirectoryName(spec.Executable) ?? Environment.CurrentDirectory
        };

        foreach (var arg in spec.Args)
        {
            startInfo.ArgumentList.Add(arg);
        }

        foreach (var pair in spec.Env)
        {
            var separator = pair.IndexOf('=');
            if (separator <= 0)
            {
                continue;
            }

            startInfo.Environment[pair[..separator]] = pair[(separator + 1)..];
        }

        using var process = new Process { StartInfo = startInfo };
        process.Start();

        var stdoutTask = process.StandardOutput.ReadToEndAsync(context.Cancellation);
        var stderrTask = process.StandardError.ReadToEndAsync(context.Cancellation);

        await process.StandardInput.WriteAsync(context.SecretText.AsMemory(), context.Cancellation).ConfigureAwait(false);
        process.StandardInput.Close();

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(context.Cancellation);
        timeout.CancelAfter(TimeSpan.FromSeconds(Math.Clamp(spec.TimeoutSeconds, 1, 300)));

        try
        {
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            TryKill(process);
            throw new OperationFailure("Execucao excedeu o tempo limite.");
        }

        var stdout = await stdoutTask.ConfigureAwait(false);
        var stderr = await stderrTask.ConfigureAwait(false);

        var combined = string.Concat(stdout, Environment.NewLine, stderr).Trim();

        return new OperationOutcome
        {
            Kind = "process",
            ExitCode = process.ExitCode,
            Ok = process.ExitCode == 0,
            Output = context.Redactor.Redact(combined)
        };
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch
        {
            // The process already exited or cannot be killed; nothing else to do.
        }
    }

    public static string ResolveTemplate(string template, OperationContext context)
    {
        ValidateTemplate(template, context.Operation.Params);

        return Regex.Replace(template, @"\{\{(secret(?::[^{}]+)?|param:[^{}]+)\}\}", match =>
        {
            var token = match.Groups[1].Value;
            if (string.Equals(token, "secret", StringComparison.Ordinal))
            {
                return context.SecretText;
            }

            if (token.StartsWith("secret:", StringComparison.Ordinal))
            {
                var id = token["secret:".Length..].Trim();
                return context.ReferencedSecrets.TryGetValue(id, out var value)
                    ? Encoding.UTF8.GetString(value)
                    : throw new OperationFailure("Segredo referenciado nao autorizado: " + id);
            }

            var name = token["param:".Length..].Trim();
            return context.Parameters.TryGetValue(name, out var parameter)
                ? parameter
                : throw new OperationFailure("Parametro obrigatorio ausente: " + name);
        });
    }

    public static void ValidateTemplates(OperationRecord operation)
    {
        var templates = operation.Http is null
            ? Array.Empty<string>()
            : operation.Http.BodyFields.Values.Concat(operation.Http.Headers.Values).ToArray();

        foreach (var template in templates)
        {
            ValidateTemplate(template, operation.Params);
        }
    }

    private static void ValidateTemplate(string template, IReadOnlyList<string> declaredParameters)
    {
        var remainder = Regex.Replace(template, @"\{\{(secret(?::[^{}]+)?|param:[^{}]+)\}\}", string.Empty);
        if (remainder.Contains("{{", StringComparison.Ordinal) || remainder.Contains("}}", StringComparison.Ordinal))
        {
            throw new OperationFailure("Template contem placeholder invalido.");
        }

        foreach (Match match in Regex.Matches(template, @"\{\{param:([^{}]+)\}\}"))
        {
            var name = match.Groups[1].Value.Trim();
            if (name.Length == 0 || !declaredParameters.Contains(name, StringComparer.OrdinalIgnoreCase))
            {
                throw new OperationFailure("Template usa parametro nao declarado.");
            }
        }
    }

    public static void ValidateParameters(OperationRecord operation, IReadOnlyDictionary<string, string> parameters)
    {
        ValidateTemplates(operation);
        foreach (var (name, value) in parameters)
        {
            if (!operation.Params.Contains(name, StringComparer.OrdinalIgnoreCase))
            {
                throw new OperationFailure($"Parametro nao declarado: {name}");
            }

            if (value.Length > 512)
            {
                throw new OperationFailure($"Parametro muito longo: {name}");
            }

            if (value.Any(char.IsControl))
            {
                throw new OperationFailure($"Parametro invalido: {name}");
            }
        }

        var required = operation.Http is null
            ? Array.Empty<string>()
            : operation.Http.BodyFields.Values.Concat(operation.Http.Headers.Values)
                .SelectMany(template => Regex.Matches(template, @"\{\{param:([^{}]+)\}\}").Cast<Match>())
                .Select(match => match.Groups[1].Value.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
        foreach (var name in required)
        {
            if (!parameters.TryGetValue(name, out var value) || string.IsNullOrWhiteSpace(value))
            {
                throw new OperationFailure("Parametro obrigatorio ausente: " + name);
            }
        }
    }
}

public sealed class OperationFailure : Exception
{
    public OperationFailure(string message) : base(message)
    {
    }
}
