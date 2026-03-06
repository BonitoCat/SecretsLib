using System;
using System.Runtime.InteropServices;

namespace SecretsLib.Platforms
{
    internal static class LinuxSecretsManager
    {
        [StructLayout(LayoutKind.Sequential)]
        struct SecretSchemaAttribute
        {
            public IntPtr Name;
            public int Type;
        }

        [StructLayout(LayoutKind.Sequential)]
        unsafe struct SecretSchema
        {
            public IntPtr Name;
            public int Flags;
            private int _padding;
            public fixed byte Attributes[32 * 16];
        }
        
        [DllImport("libsecret-1.so.0")]
        static extern bool secret_password_store_sync(ref SecretSchema schema, IntPtr collection, string label, string password, IntPtr cancellable, out IntPtr error, string attrName, string attrValue, IntPtr terminator);

        [DllImport("libsecret-1.so.0")]
        static extern IntPtr secret_password_lookup_sync(ref SecretSchema schema, IntPtr cancellable, out IntPtr error, string attrName, string attrValue, IntPtr terminator);

        [DllImport("libsecret-1.so.0")]
        static extern bool secret_password_clear_sync(ref SecretSchema schema, IntPtr cancellable, out IntPtr error, string attrName, string attrValue, IntPtr terminator);

        [DllImport("libsecret-1.so.0")]
        static extern void secret_password_free(IntPtr password);
        
        internal static string SchemaName = "com.secretslib.secret";
        private const string AttrKey = "key";
        
        public static void StoreSecret(string key, string secret)
        {
            SecretSchema schema = BuildSchema();
            secret_password_store_sync(ref schema, IntPtr.Zero, key, secret, IntPtr.Zero, out IntPtr error, AttrKey, key, IntPtr.Zero);
            
            FreeSchema(ref schema);
            if (error != IntPtr.Zero)
            {
                throw new InvalidOperationException($"libsecret store error: {error}");
            }
        }

        public static string? LookupSecret(string key)
        {
            SecretSchema schema = BuildSchema();
            IntPtr result = secret_password_lookup_sync(ref schema, IntPtr.Zero, out IntPtr error, AttrKey, key, IntPtr.Zero);
            
            FreeSchema(ref schema);
            
            if (error != IntPtr.Zero)
            {
                throw new InvalidOperationException($"libsecret lookup error: {error}");
            }

            if (result == IntPtr.Zero)
            {
                return null;
            }

            string? value = Marshal.PtrToStringAnsi(result);
            secret_password_free(result);
            
            return value;
        }

        public static void ClearSecret(string key)
        {
            SecretSchema schema = BuildSchema();
            secret_password_clear_sync(ref schema, IntPtr.Zero, out IntPtr error, AttrKey, key, IntPtr.Zero);
            
            FreeSchema(ref schema);
            if (error != IntPtr.Zero)
            {
                throw new InvalidOperationException($"libsecret clear error: {error}");
            }
        }
        
        static SecretSchema BuildSchema()
        {
            SecretSchema schema = new SecretSchema
            {
                Name = Marshal.StringToHGlobalAnsi(SchemaName),
                Flags = 0,
            };

            SetAttribute(ref schema, 0, Marshal.StringToHGlobalAnsi(AttrKey), 0);
            
            return schema;
        }
        
        static void FreeSchema(ref SecretSchema schema)
        {
            if (schema.Name != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(schema.Name);
            }

            unsafe
            {
                fixed (byte* ptr = schema.Attributes)
                {
                    SecretSchemaAttribute* attrs = (SecretSchemaAttribute*) ptr;
                    if (attrs[0].Name != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(attrs[0].Name);
                    }
                }
            }
        }
        
        static unsafe void SetAttribute(ref SecretSchema schema, int index, IntPtr name, int type)
        {
            fixed (byte* ptr = schema.Attributes)
            {
                SecretSchemaAttribute* attrs = (SecretSchemaAttribute*) ptr;
                attrs[index].Name = name;
                attrs[index].Type = type;
            }
        }
    }
}