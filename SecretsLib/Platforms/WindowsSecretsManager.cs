using System;
using System.Runtime.InteropServices;
using System.Text;

namespace SecretsLib.Platforms
{
    internal static class WindowsSecretsManager
    {
        private const uint CredTypeGeneric = 1;
        private const uint CredPersistLocalMachine = 2;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct CREDENTIAL
        {
            public uint Flags;
            public uint Type;
            public string TargetName;
            public string Comment;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
            public uint CredentialBlobSize;
            public IntPtr CredentialBlob;
            public uint Persist;
            public uint AttributeCount;
            public IntPtr Attributes;
            public string TargetAlias;
            public string UserName;
        }

        [DllImport("Advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CredWriteW(ref CREDENTIAL credential, uint flags);

        [DllImport("Advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CredReadW(string target, uint type, uint flags, out IntPtr credential);

        [DllImport("Advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CredDeleteW(string target, uint type, uint flags);

        [DllImport("Advapi32.dll")]
        static extern void CredFree(IntPtr buffer);

        internal static string AppName = "secretslib";

        private static string BuildKey(string key) => $"{AppName}/{key}";

        public static void StoreSecret(string key, string secret)
        {
            byte[] blob = Encoding.UTF8.GetBytes(secret);
            GCHandle handle = GCHandle.Alloc(blob, GCHandleType.Pinned);

            try
            {
                CREDENTIAL credential = new CREDENTIAL
                {
                    Type = CredTypeGeneric,
                    TargetName = BuildKey(key),
                    CredentialBlobSize = (uint)blob.Length,
                    CredentialBlob = handle.AddrOfPinnedObject(),
                    Persist = CredPersistLocalMachine,
                    UserName = Environment.UserName,
                };

                if (!CredWriteW(ref credential, 0))
                {
                    throw new InvalidOperationException($"CredWrite failed: {Marshal.GetLastWin32Error()}");
                }
            }
            finally
            {
                handle.Free();
            }
        }

        public static string? LookupSecret(string key)
        {
            if (!CredReadW(BuildKey(key), CredTypeGeneric, 0, out IntPtr ptr))
            {
                return null;
            }

            try
            {
                CREDENTIAL credential = Marshal.PtrToStructure<CREDENTIAL>(ptr);
                if (credential.CredentialBlobSize == 0 || credential.CredentialBlob == IntPtr.Zero)
                {
                    return null;
                }

                byte[] blob = new byte[credential.CredentialBlobSize];
                Marshal.Copy(credential.CredentialBlob, blob, 0, blob.Length);
                
                return Encoding.UTF8.GetString(blob);
            }
            finally
            {
                CredFree(ptr);
            }
        }

        public static void ClearSecret(string key)
        {
            CredDeleteW(BuildKey(key), CredTypeGeneric, 0);
        }
    }
}