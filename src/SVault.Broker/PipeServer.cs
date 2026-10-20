using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using SVault.Core.Logging;
using SVault.Core.Protocol;

namespace SVault.Broker;

/// <summary>
/// Host for the broker pipe. The pipe DACL is the process level boundary: only SYSTEM,
/// Administrators and the explicitly authorized interactive user can connect.
/// </summary>
public sealed class PipeServer
{
    private const int InstanceCount = 4;
    private const int ReadTimeoutSeconds = 30;

    private readonly string _pipeName;
    private readonly PipeSecurity _security;
    private readonly Func<byte[], string, Task<byte[]>> _handler;
    private readonly VaultLog _log;

    public PipeServer(string pipeName, PipeSecurity security, Func<byte[], string, Task<byte[]>> handler, VaultLog log)
    {
        _pipeName = pipeName;
        _security = security;
        _handler = handler;
        _log = log;
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        var workers = new List<Task>();
        for (var i = 0; i < InstanceCount; i++)
        {
            workers.Add(AcceptLoopAsync(cancellationToken));
        }

        await Task.WhenAll(workers).ConfigureAwait(false);
    }

    private async Task AcceptLoopAsync(CancellationToken cancellationToken)
    {
        NamedPipeServerStream? instance = null;

        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    instance = CreateInstance();

                    await instance.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);

                    var clientSid = ResolveClientSid(instance);

                    using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                    timeout.CancelAfter(TimeSpan.FromSeconds(ReadTimeoutSeconds));

                    try
                    {
                        var request = await PipeFraming.ReadAsync(instance, PipeFraming.MaxRequestBytes, timeout.Token)
                            .ConfigureAwait(false);
                        var response = await _handler(request, clientSid).ConfigureAwait(false);
                        await PipeFraming.WriteAsync(instance, response, cancellationToken).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                    {
                        _log.Write("pipe_timeout", new Dictionary<string, object?> { ["client"] = clientSid });
                    }
                    catch (Exception ex) when (ex is IOException or InvalidDataException or EndOfStreamException)
                    {
                        _log.Write("pipe_client_error", new Dictionary<string, object?>
                        {
                            ["type"] = ex.GetType().Name,
                            ["client"] = clientSid
                        });
                    }
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _log.Write("pipe_error", new Dictionary<string, object?>
                    {
                        ["type"] = ex.GetType().Name,
                        ["message"] = ex.Message,
                        ["hresult"] = ex.HResult
                    });
                    await Task.Delay(500, cancellationToken).ConfigureAwait(false);
                }
                finally
                {
                    instance?.Dispose();
                    instance = null;
                }
            }
        }
        finally
        {
            instance?.Dispose();
        }
    }

    private NamedPipeServerStream CreateInstance()
    {
        return NamedPipeServerStreamAcl.Create(
            _pipeName,
            PipeDirection.InOut,
            NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            4096,
            4096,
            _security);
    }

    private static string ResolveClientSid(NamedPipeServerStream server)
    {
        IntPtr process = IntPtr.Zero;
        IntPtr token = IntPtr.Zero;
        IntPtr buffer = IntPtr.Zero;

        try
        {
            if (!NamedPipeClient.GetClientProcessId(server, out var clientProcessId))
            {
                return "unknown";
            }

            process = NativeMethods.OpenProcess(NativeMethods.ProcessQueryLimitedInformation, false, clientProcessId);
            if (process == IntPtr.Zero)
            {
                return "unknown";
            }

            if (!NativeMethods.OpenProcessToken(process, NativeMethods.TokenQuery, out token))
            {
                return "unknown";
            }

            NativeMethods.GetTokenInformation(token, NativeMethods.TokenUserClass, IntPtr.Zero, 0, out var size);
            if (size <= 0)
            {
                return "unknown";
            }

            buffer = Marshal.AllocHGlobal((int)size);
            if (!NativeMethods.GetTokenInformation(token, NativeMethods.TokenUserClass, buffer, (int)size, out _))
            {
                return "unknown";
            }

            var user = Marshal.PtrToStructure<NativeMethods.TokenUser>(buffer);
            return new SecurityIdentifier(user.User.Sid).Value;
        }
        catch
        {
            return "unknown";
        }
        finally
        {
            if (buffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(buffer);
            }

            if (token != IntPtr.Zero)
            {
                NativeMethods.CloseHandle(token);
            }

            if (process != IntPtr.Zero)
            {
                NativeMethods.CloseHandle(process);
            }
        }
    }
}

internal static class NativeMethods
{
    public const int ProcessQueryLimitedInformation = 0x1000;
    public const int TokenQuery = 0x0008;
    public const int TokenUserClass = 1;

    [StructLayout(LayoutKind.Sequential)]
    public struct SidAndAttributes
    {
        public IntPtr Sid;
        public int Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TokenUser
    {
        public SidAndAttributes User;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(int access, bool inherit, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr handle);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr process, int access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool GetTokenInformation(
        IntPtr token,
        int tokenInformationClass,
        IntPtr tokenInformation,
        int tokenInformationLength,
        out int returnLength);
}

public static class NamedPipeClient
{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeClientProcessId(NamedPipeServerStream pipe, out int clientProcessId);

    public static bool GetClientProcessId(NamedPipeServerStream pipe, out int clientProcessId) =>
        GetNamedPipeClientProcessId(pipe, out clientProcessId);
}

public static class PipeSecurityFactory
{
    public static PipeSecurity Build(string ownerSid, IEnumerable<string> allowedClientSids)
    {
        var security = new PipeSecurity();
        security.SetOwner(new SecurityIdentifier(ownerSid));
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

        var serverRights = PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance;

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(ownerSid),
            serverRights,
            AccessControlType.Allow));

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            serverRights,
            AccessControlType.Allow));

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            serverRights,
            AccessControlType.Allow));

        foreach (var sid in allowedClientSids.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            security.AddAccessRule(new PipeAccessRule(
                new SecurityIdentifier(sid),
                PipeAccessRights.ReadWrite,
                AccessControlType.Allow));
        }

        return security;
    }
}
