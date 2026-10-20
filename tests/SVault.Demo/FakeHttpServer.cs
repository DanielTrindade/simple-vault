using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace SVault.Demo;

/// <summary>Servidor HTTP minimo que ecoa o corpo recebido, usado para provar a redacao ponta a ponta.</summary>
internal sealed class FakeHttpServer : IDisposable
{
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cts = new();

    public FakeHttpServer()
    {
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _ = Task.Run(AcceptLoopAsync);
    }

    public int Port { get; }

    public List<string> ReceivedBodies { get; } = new();

    public string BaseUrl => $"http://127.0.0.1:{Port}";

    private async Task AcceptLoopAsync()
    {
        try
        {
            while (!_cts.IsCancellationRequested)
            {
                using var client = await _listener.AcceptTcpClientAsync(_cts.Token);
                await HandleAsync(client);
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (SocketException)
        {
        }
    }

    private async Task HandleAsync(TcpClient client)
    {
        using var stream = client.GetStream();
        var buffer = new byte[64 * 1024];
        var read = await stream.ReadAsync(buffer, _cts.Token);
        var request = Encoding.UTF8.GetString(buffer, 0, read);

        var separator = request.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        var head = separator > 0 ? request[..separator] : request;
        var body = separator > 0 ? request[(separator + 4)..] : string.Empty;

        if (head.Contains("Content-Length: ", StringComparison.OrdinalIgnoreCase))
        {
            var lengthText = head.Split('\n')
                .First(l => l.Contains("Content-Length: ", StringComparison.OrdinalIgnoreCase))
                .Split(':')[1].Trim();
            var length = int.Parse(lengthText);
            while (body.Length < length)
            {
                var more = await stream.ReadAsync(buffer, _cts.Token);
                if (more == 0)
                {
                    break;
                }

                body += Encoding.UTF8.GetString(buffer, 0, more);
            }
        }

        lock (ReceivedBodies)
        {
            ReceivedBodies.Add(body);
        }

        var payload = JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["status"] = "ok",
            ["echo"] = body
        });

        var response = Encoding.UTF8.GetBytes(
            "HTTP/1.1 200 OK\r\n" +
            "Content-Type: application/json; charset=utf-8\r\n" +
            $"Content-Length: {payload.Length}\r\n" +
            "Connection: close\r\n\r\n" +
            payload);

        await stream.WriteAsync(response, _cts.Token);
        await stream.FlushAsync(_cts.Token);
    }

    public void Dispose()
    {
        _cts.Cancel();
        _listener.Stop();
        _cts.Dispose();
    }
}
