using System.Runtime.InteropServices;
using System.Text;

namespace SVault.Core.Storage;

/// <summary>
/// Concede ou revoga direitos de conta diretamente pela LSA (LsaAddAccountRights).
/// Usado para permitir "Log on as a service" e negar logon interativo, remoto e via rede
/// da conta de servico do SVault, sem depender do secedit (que falha quando a politica
/// local esta bloqueada por GPO).
/// </summary>
public static class LsaRights
{
    public const string SeServiceLogonRight = "SeServiceLogonRight";
    public const string SeDenyInteractiveLogonRight = "SeDenyInteractiveLogonRight";
    public const string SeDenyRemoteInteractiveLogonRight = "SeDenyRemoteInteractiveLogonRight";
    public const string SeDenyNetworkLogonRight = "SeDenyNetworkLogonRight";
    public const string SeBatchLogonRight = "SeBatchLogonRight";

    private const int PolicyAllAccess = 0x0008F0FF;
    private const int PolicyCreateAccount = 0x00000040;
    private const int PolicyLookupNames = 0x00000800;
    private const int PolicyGetPrivateInformation = 0x00000004;

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(
        IntPtr tokenHandle,
        bool disableAllPrivileges,
        ref TOKEN_PRIVILEGES newState,
        int bufferLength,
        IntPtr previousState,
        IntPtr returnLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool LookupPrivilegeValue(string? systemName, string name, out LUID luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID_AND_ATTRIBUTES Privileges;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LSA_UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LSA_OBJECT_ATTRIBUTES
    {
        public uint Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint LsaOpenPolicy(
        IntPtr systemName,
        ref LSA_OBJECT_ATTRIBUTES objectAttributes,
        int desiredAccess,
        out IntPtr policyHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint LsaAddAccountRights(
        IntPtr policyHandle,
        IntPtr accountSid,
        IntPtr objectAttributes,
        IntPtr rights,
        uint countOfRights,
        out LSA_UNICODE_STRING[] allocatedRights);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint LsaRemoveAccountRights(
        IntPtr policyHandle,
        IntPtr accountSid,
        IntPtr rights,
        uint countOfRights,
        out LSA_UNICODE_STRING[] allocatedRights);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint LsaNtStatusToWinError(uint status);

    public static void Grant(string accountSid, params string[] rights)
    {
        Apply(accountSid, rights, remove: false);
    }

    public static void Revoke(string accountSid, params string[] rights)
    {
        Apply(accountSid, rights, remove: true);
    }

    private static void Apply(string accountSid, string[] rights, bool remove)
    {
        if (rights.Length == 0)
        {
            return;
        }

        EnablePrivilege("SeSecurityPrivilege");
        EnablePrivilege("SeTakeOwnershipPrivilege");

        var sid = new System.Security.Principal.SecurityIdentifier(accountSid);
        byte[] sidBytes = new byte[sid.BinaryLength];
        sid.GetBinaryForm(sidBytes, 0);

        var nameBuffer = IntPtr.Zero;
        var nameStruct = IntPtr.Zero;
        var sidBuffer = IntPtr.Zero;
        var policy = IntPtr.Zero;

        try
        {
            var nameUnicode = AllocateUnicodeString(accountSid);
            nameBuffer = nameUnicode.Buffer;
            nameStruct = Marshal.AllocHGlobal(Marshal.SizeOf<LSA_UNICODE_STRING>());
            Marshal.StructureToPtr(nameUnicode, nameStruct, false);

            sidBuffer = Marshal.AllocHGlobal(sidBytes.Length);
            Marshal.Copy(sidBytes, 0, sidBuffer, sidBytes.Length);

            var attributes = new LSA_OBJECT_ATTRIBUTES
            {
                Length = (uint)Marshal.SizeOf<LSA_OBJECT_ATTRIBUTES>(),
                RootDirectory = IntPtr.Zero,
                ObjectName = nameStruct,
                Attributes = 0,
                SecurityDescriptor = IntPtr.Zero,
                SecurityQualityOfService = IntPtr.Zero
            };

            var status = LsaOpenPolicy(
                IntPtr.Zero,
                ref attributes,
                PolicyAllAccess,
                out policy);
            if (status != 0)
            {
                throw new InvalidOperationException(
                    "LsaOpenPolicy falhou: NTSTATUS 0x" + status.ToString("X8") +
                    " (win32 " + LsaNtStatusToWinError(status) + ")");
            }

            var marshalled = new LSA_UNICODE_STRING[rights.Length];
            var arrayPointer = IntPtr.Zero;
            try
            {
                for (var i = 0; i < rights.Length; i++)
                {
                    marshalled[i] = AllocateUnicodeString(rights[i]);
                }

                var elementSize = Marshal.SizeOf<LSA_UNICODE_STRING>();
                arrayPointer = Marshal.AllocHGlobal(elementSize * marshalled.Length);
                for (var i = 0; i < marshalled.Length; i++)
                {
                    Marshal.StructureToPtr(marshalled[i], IntPtr.Add(arrayPointer, i * elementSize), false);
                }

                if (remove)
                {
                    status = LsaRemoveAccountRights(policy, sidBuffer, arrayPointer, (uint)marshalled.Length, out _);
                }
                else
                {
                    status = LsaAddAccountRights(policy, sidBuffer, IntPtr.Zero, arrayPointer, (uint)marshalled.Length, out _);
                }

                if (status != 0)
                {
                    throw new InvalidOperationException(
                        (remove ? "LsaRemoveAccountRights" : "LsaAddAccountRights") +
                        " falhou: NTSTATUS 0x" + status.ToString("X8") +
                        " (win32 " + LsaNtStatusToWinError(status) + ")");
                }
            }
            finally
            {
                if (arrayPointer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(arrayPointer);
                }

                foreach (var entry in marshalled)
                {
                    if (entry.Buffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(entry.Buffer);
                    }
                }
            }
        }
        finally
        {
            if (nameBuffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(nameBuffer);
            }

            if (nameStruct != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(nameStruct);
            }

            if (sidBuffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(sidBuffer);
            }
        }
    }

    private static void EnablePrivilege(string name)
    {
        if (!OpenProcessToken(GetCurrentProcess(), 0x0020 | 0x0008, out var token))
        {
            return;
        }

        try
        {
            if (!LookupPrivilegeValue(null, name, out var luid))
            {
                return;
            }

            var privileges = new TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Privileges = new LUID_AND_ATTRIBUTES
                {
                    Luid = luid,
                    Attributes = 0x00000002
                }
            };

            AdjustTokenPrivileges(token, false, ref privileges, 0, IntPtr.Zero, IntPtr.Zero);
        }
        catch
        {
            // sem o privilegio, a API retorna o erro correspondente
        }
        finally
        {
            CloseHandle(token);
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    private static LSA_UNICODE_STRING AllocateUnicodeString(string value)    {
        var bytes = Encoding.Unicode.GetBytes(value + "\0");
        var buffer = Marshal.AllocHGlobal(bytes.Length);
        Marshal.Copy(bytes, 0, buffer, bytes.Length);

        return new LSA_UNICODE_STRING
        {
            Length = (ushort)(value.Length * 2),
            MaximumLength = (ushort)(bytes.Length),
            Buffer = buffer
        };
    }
}
