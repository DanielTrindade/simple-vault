using System.Buffers.Binary;

namespace SVault.Core.Protocol;

/// <summary>Length prefixed framing: 4 byte little endian length + UTF-8 JSON payload.</summary>
public static class PipeFraming
{
    public const int MaxRequestBytes = 64 * 1024;
    public const int MaxResponseBytes = 1024 * 1024;

    public static async Task<byte[]> ReadAsync(Stream stream, int maxBytes, CancellationToken cancellationToken)
    {
        var header = new byte[4];
        await ReadExactlyAsync(stream, header, cancellationToken).ConfigureAwait(false);

        var length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length <= 0 || length > maxBytes)
        {
            throw new InvalidDataException("Tamanho de mensagem invalido.");
        }

        var payload = new byte[length];
        await ReadExactlyAsync(stream, payload, cancellationToken).ConfigureAwait(false);
        return payload;
    }

    public static async Task WriteAsync(Stream stream, byte[] payload, CancellationToken cancellationToken)
    {
        var header = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(header, payload.Length);
        await stream.WriteAsync(header, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task ReadExactlyAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset, buffer.Length - offset), cancellationToken)
                .ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException("Conexao encerrada pelo peer.");
            }

            offset += read;
        }
    }
}
