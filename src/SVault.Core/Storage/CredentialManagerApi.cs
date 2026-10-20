using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace SVault.Core.Storage;

/// <summary>
/// Thin wrapper over the Windows Credential Manager (advapi32). Secrets are protected by DPAPI
/// in the profile of the account that owns the vault, which is why the broker runs under a
/// dedicated service account instead of the interactive user.
/// </summary>
public static class CredentialManagerApi
{
    private const int CredTypeGeneric = 1;
    private const int CredPersistLocalMachine = 2;
    private const int CredPersistSession = 3;
    private const int ErrorNotFound = 1168;
    private const int ErrorInvalidFlags = 1004;
    private const int ErrorBadArguments = 1008;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct Credential
    {
        public int Flags;
        public int Type;
        public IntPtr TargetName;
        public IntPtr Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public int CredentialBlobSize;
        public IntPtr CredentialBlob;
        public int Persist;
        public int AttributeCount;
        public IntPtr Attributes;
        public IntPtr TargetAlias;
        public IntPtr UserName;
    }

    [DllImport("advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredWrite(ref Credential credential, int flags);

    [DllImport("advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredRead(string target, int type, int flags, out IntPtr credentialPtr);

    [DllImport("advapi32.dll", EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredDelete(string target, int type, int flags);

    [DllImport("advapi32.dll", EntryPoint = "CredEnumerateW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredEnumerate(string filter, int flags, out int count, out IntPtr credentialsPtr);

    [DllImport("advapi32.dll", EntryPoint = "CredFree", SetLastError = true)]
    private static extern void CredFree(IntPtr buffer);

    public static void Write(string target, string userName, byte[] secret)
    {
        var targetPtr = IntPtr.Zero;
        var userPtr = IntPtr.Zero;
        var blobPtr = IntPtr.Zero;

        try
        {
            targetPtr = Marshal.StringToHGlobalUni(target);
            userPtr = Marshal.StringToHGlobalUni(userName);
            blobPtr = Marshal.AllocHGlobal(Math.Max(secret.Length, 1));

            if (secret.Length > 0)
            {
                Marshal.Copy(secret, 0, blobPtr, secret.Length);
            }

            var credential = new Credential
            {
                Type = CredTypeGeneric,
                TargetName = targetPtr,
                CredentialBlob = blobPtr,
                CredentialBlobSize = secret.Length,
                Persist = CredPersistLocalMachine,
                UserName = userPtr
            };

            if (!CredWrite(ref credential, 0))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CredWrite failed.");
            }
        }
        finally
        {
            if (blobPtr != IntPtr.Zero)
            {
                for (var i = 0; i < secret.Length; i++)
                {
                    Marshal.WriteByte(blobPtr, i, 0);
                }

                Marshal.FreeHGlobal(blobPtr);
            }

            if (targetPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(targetPtr);
            }

            if (userPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(userPtr);
            }
        }
    }

    public static byte[]? Read(string target)
    {
        if (!CredRead(target, CredTypeGeneric, 0, out var credentialPtr))
        {
            var error = Marshal.GetLastWin32Error();
            if (error == ErrorNotFound)
            {
                return null;
            }

            throw new Win32Exception(error, "CredRead failed.");
        }

        try
        {
            var credential = Marshal.PtrToStructure<Credential>(credentialPtr);
            if (credential.CredentialBlobSize == 0 || credential.CredentialBlob == IntPtr.Zero)
            {
                return Array.Empty<byte>();
            }

            var blob = new byte[credential.CredentialBlobSize];
            Marshal.Copy(credential.CredentialBlob, blob, 0, credential.CredentialBlobSize);
            return blob;
        }
        finally
        {
            CredFree(credentialPtr);
        }
    }

    public static void Delete(string target)
    {
        if (!CredDelete(target, CredTypeGeneric, 0))
        {
            var error = Marshal.GetLastWin32Error();
            if (error == ErrorNotFound)
            {
                return;
            }

            throw new Win32Exception(error, "CredDelete failed.");
        }
    }

    public static IReadOnlyList<string> ListTargets(string filter)
    {
        if (!CredEnumerate(filter, 0, out var count, out var credentialsPtr))
        {
            var error = Marshal.GetLastWin32Error();
            if (error == ErrorNotFound || error == ErrorBadArguments || error == ErrorInvalidFlags)
            {
                return Array.Empty<string>();
            }

            throw new Win32Exception(error, "CredEnumerate failed.");
        }

        try
        {
            var targets = new List<string>(count);
            for (var i = 0; i < count; i++)
            {
                var itemPtr = IntPtr.Add(credentialsPtr, i * Marshal.SizeOf<Credential>());
                var credential = Marshal.PtrToStructure<Credential>(itemPtr);
                if (credential.TargetName != IntPtr.Zero)
                {
                    targets.Add(Marshal.PtrToStringUni(credential.TargetName) ?? string.Empty);
                }
            }

            return targets;
        }
        finally
        {
            CredFree(credentialsPtr);
        }
    }

    public static string BuildTarget(string prefix, string id) => $"{prefix}:{id}";

    public static string DescribeScope() =>
        "Windows Credential Manager (DPAPI, perfil da conta proprietaria do cofre)";
}
