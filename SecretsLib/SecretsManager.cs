
#nullable enable
using System;
using System.Runtime.InteropServices;
using SecretsLib.Platforms;

namespace SecretsLib
{
    public static class SecretsManager
    {
        public static bool Initialized;
        
        /// <summary>
        /// Initializes the SecretsManager
        /// </summary>
        /// <param name="name">Should be a unique value per application. E.g. username.your-app.secret.</param>
        public static void Initialize(string name)
        {
            LinuxSecretsManager.SchemaName = name;
            WindowsSecretsManager.AppName = name;
            MacOsSecretsManager.ServiceName = name;
            
            Initialized = true;
        }
        
        /// <summary>
        /// Store or overwrite an existing secret.
        /// </summary>
        /// <param name="key">This value can be used to lookup the secret</param>
        /// <param name="secret">The value to store</param>
        public static void StoreSecret(string key, string secret)
        {
            if (!Initialized)
            {
                throw new InvalidOperationException("Secrets manager has not been initialized");
            }
            
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                WindowsSecretsManager.StoreSecret(key, secret);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                LinuxSecretsManager.StoreSecret(key, secret);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                MacOsSecretsManager.StoreSecret(key, secret);
            }
            else
            {
                throw new PlatformNotSupportedException("Secrets are not supported on this platform");
            }
        }

        /// <summary>
        /// Lookup a previously stored secret
        /// </summary>
        /// <param name="key">The key to find the secret</param>
        /// <returns></returns>
        public static string? LookupSecret(string key)
        {
            if (!Initialized)
            {
                throw new InvalidOperationException("Secrets manager has not been initialized");
            }
            
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return WindowsSecretsManager.LookupSecret(key);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                return LinuxSecretsManager.LookupSecret(key);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                return MacOsSecretsManager.LookupSecret(key);
            }
            
            throw new PlatformNotSupportedException("Secrets are not supported on this platform");
        }

        /// <summary>
        /// Remove a previously added secret
        /// </summary>
        /// <param name="key">The key of the secret to remove</param>
        public static void ClearSecret(string key)
        {
            if (!Initialized)
            {
                throw new InvalidOperationException("Secrets manager has not been initialized");
            }
            
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                WindowsSecretsManager.ClearSecret(key);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                LinuxSecretsManager.ClearSecret(key);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                MacOsSecretsManager.ClearSecret(key);
            }
            else
            {
                throw new PlatformNotSupportedException("Secrets are not supported on this platform");
            }
        }
    }
}