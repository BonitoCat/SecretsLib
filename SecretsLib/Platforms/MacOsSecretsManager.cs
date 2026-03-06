using System;
using System.Runtime.InteropServices;
using System.Text;

namespace SecretsLib.Platforms
{
    internal static class MacOsSecretsManager
    {
        private const string SecurityLib = "/System/Library/Frameworks/Security.framework/Security";
        private const int ErrSecSuccess = 0;
        private const int ErrSecItemNotFound = -25300;

        [DllImport(SecurityLib)]
        static extern int SecKeychainAddGenericPassword(IntPtr keychain, uint serviceLen, byte[] service, uint accountLen, byte[] account, uint passwordLen, byte[] password, IntPtr itemRef);

        [DllImport(SecurityLib)]
        static extern int SecKeychainFindGenericPassword(IntPtr keychain, uint serviceLen, byte[] service, uint accountLen, byte[] account, out uint passwordLen, out IntPtr passwordData, out IntPtr itemRef);

        [DllImport(SecurityLib)]
        static extern int SecKeychainItemDelete(IntPtr itemRef);

        [DllImport(SecurityLib)]
        static extern int SecKeychainItemFreeContent(IntPtr attrList, IntPtr data);

        internal static string ServiceName = "secretslib";

        private static byte[] ToBytes(string value) => Encoding.UTF8.GetBytes(value);

        public static void StoreSecret(string key, string secret)
        {
            byte[] serviceBytes = ToBytes(ServiceName);
            byte[] accountBytes = ToBytes(key);
            byte[] secretBytes = ToBytes(secret);

            ClearSecret(key);

            int result = SecKeychainAddGenericPassword(
                IntPtr.Zero,
                (uint)serviceBytes.Length, serviceBytes,
                (uint)accountBytes.Length, accountBytes,
                (uint)secretBytes.Length, secretBytes,
                IntPtr.Zero);

            if (result != ErrSecSuccess)
            {
                throw new InvalidOperationException($"SecKeychainAddGenericPassword failed: {result}");
            }
        }

        public static string? LookupSecret(string key)
        {
            byte[] serviceBytes = ToBytes(ServiceName);
            byte[] accountBytes = ToBytes(key);

            int result = SecKeychainFindGenericPassword(
                IntPtr.Zero,
                (uint)serviceBytes.Length, serviceBytes,
                (uint)accountBytes.Length, accountBytes,
                out uint passwordLen,
                out IntPtr passwordData,
                out _);

            if (result == ErrSecItemNotFound)
            {
                return null;
            }

            if (result != ErrSecSuccess)
            {
                throw new InvalidOperationException($"SecKeychainFindGenericPassword failed: {result}");
            }

            try
            {
                byte[] bytes = new byte[passwordLen];
                Marshal.Copy(passwordData, bytes, 0, (int)passwordLen);
                return Encoding.UTF8.GetString(bytes);
            }
            finally
            {
                SecKeychainItemFreeContent(IntPtr.Zero, passwordData);
            }
        }

        public static void ClearSecret(string key)
        {
            byte[] serviceBytes = ToBytes(ServiceName);
            byte[] accountBytes = ToBytes(key);

            int result = SecKeychainFindGenericPassword(
                IntPtr.Zero,
                (uint)serviceBytes.Length, serviceBytes,
                (uint)accountBytes.Length, accountBytes,
                out _, out _,
                out IntPtr itemRef);

            if (result == ErrSecItemNotFound)
            {
                return;
            }

            if (result != ErrSecSuccess)
            {
                throw new InvalidOperationException($"SecKeychainFindGenericPassword failed: {result}");
            }

            SecKeychainItemDelete(itemRef);
        }
    }
}