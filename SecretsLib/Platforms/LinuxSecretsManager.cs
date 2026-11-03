using System;
using System.Runtime.InteropServices;
using System.Text;

namespace SecretsLib.Platforms
{
    internal static class LinuxSecretsManager
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct SecretSchemaAttribute
        {
            public IntPtr Name;
            public int Type;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SecretSchema
        {
            public IntPtr Name;
            public int Flags;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public SecretSchemaAttribute[]? Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct GError
        {
            public uint Domain;
            public int Code;
            public IntPtr Message;
        }

        private const string LibSecret = "libsecret-1.so.0";
        private const string LibGlib = "libglib-2.0.so.0";

        internal static string SchemaName = "com.secretslib.secret";
        private const string AttrKey = "key";

        [DllImport(LibSecret, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool secret_password_storev_sync(
            ref SecretSchema schema,
            IntPtr attributes,
            IntPtr collection,
            string label,
            string password,
            IntPtr cancellable,
            out IntPtr error);

        [DllImport(LibSecret, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr secret_password_lookupv_sync(
            ref SecretSchema schema,
            IntPtr attributes,
            IntPtr cancellable,
            out IntPtr error);

        [DllImport(LibSecret, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool secret_password_clearv_sync(
            ref SecretSchema schema,
            IntPtr attributes,
            IntPtr cancellable,
            out IntPtr error);

        [DllImport(LibSecret, CallingConvention = CallingConvention.Cdecl)]
        private static extern void secret_password_free(IntPtr password);

        [DllImport(LibGlib, CallingConvention = CallingConvention.Cdecl)]
        private static extern void g_error_free(IntPtr error);

        [DllImport(LibGlib, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr g_hash_table_new_full(
            IntPtr hashFunc,
            IntPtr equalFunc,
            IntPtr keyDestroyFunc,
            IntPtr valueDestroyFunc);

        [DllImport(LibGlib, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool g_hash_table_insert(
            IntPtr hashTable,
            IntPtr key,
            IntPtr value);

        [DllImport(LibGlib, CallingConvention = CallingConvention.Cdecl)]
        private static extern void g_hash_table_destroy(IntPtr hashTable);

        [DllImport(LibGlib, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr g_str_hash(IntPtr v);

        [DllImport(LibGlib, CallingConvention = CallingConvention.Cdecl)]
        private static extern bool g_str_equal(IntPtr v1, IntPtr v2);

        [DllImport(LibGlib, CallingConvention = CallingConvention.Cdecl)]
        private static extern void g_free(IntPtr ptr);

        public static void StoreSecret(string key, string secret)
        {
            SecretSchema schema = BuildSchema();
            IntPtr attributes = IntPtr.Zero;

            try
            {
                attributes = BuildAttributes(key);

                bool ok = secret_password_storev_sync(
                    ref schema,
                    attributes,
                    IntPtr.Zero,
                    key,
                    secret,
                    IntPtr.Zero,
                    out IntPtr error);

                ThrowIfError(error, "store");

                if (!ok)
                {
                    throw new InvalidOperationException("libsecret store failed without a GError.");
                }
            }
            finally
            {
                if (attributes != IntPtr.Zero)
                {
                    g_hash_table_destroy(attributes);
                }

                FreeSchema(ref schema);
            }
        }

        public static string? LookupSecret(string key)
        {
            SecretSchema schema = BuildSchema();
            IntPtr attributes = IntPtr.Zero;

            try
            {
                attributes = BuildAttributes(key);

                IntPtr result = secret_password_lookupv_sync(
                    ref schema,
                    attributes,
                    IntPtr.Zero,
                    out IntPtr error);

                ThrowIfError(error, "lookup");

                if (result == IntPtr.Zero)
                {
                    return null;
                }

                try
                {
                    return PtrToStringUtf8(result);
                }
                finally
                {
                    secret_password_free(result);
                }
            }
            finally
            {
                if (attributes != IntPtr.Zero)
                {
                    g_hash_table_destroy(attributes);
                }

                FreeSchema(ref schema);
            }
        }

        public static void ClearSecret(string key)
        {
            SecretSchema schema = BuildSchema();
            IntPtr attributes = IntPtr.Zero;

            try
            {
                attributes = BuildAttributes(key);

                bool ok = secret_password_clearv_sync(
                    ref schema,
                    attributes,
                    IntPtr.Zero,
                    out IntPtr error);

                ThrowIfError(error, "clear");

                if (!ok)
                {
                    throw new InvalidOperationException("libsecret clear failed without a GError.");
                }
            }
            finally
            {
                if (attributes != IntPtr.Zero)
                {
                    g_hash_table_destroy(attributes);
                }

                FreeSchema(ref schema);
            }
        }

        private static SecretSchema BuildSchema()
        {
            SecretSchema schema = new SecretSchema
            {
                Name = StringToUtf8HGlobal(SchemaName),
                Flags = 0,
                Attributes = new SecretSchemaAttribute[32],
            };

            schema.Attributes[0] = new SecretSchemaAttribute
            {
                Name = StringToUtf8HGlobal(AttrKey),
                Type = 0,
            };

            schema.Attributes[1] = new SecretSchemaAttribute
            {
                Name = IntPtr.Zero,
                Type = 0,
            };

            return schema;
        }

        private static void FreeSchema(ref SecretSchema schema)
        {
            if (schema.Name != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(schema.Name);
                schema.Name = IntPtr.Zero;
            }

            if (schema.Attributes == null)
            {
                return;
            }

            for (int i = 0; i < schema.Attributes.Length; i++)
            {
                if (schema.Attributes[i].Name == IntPtr.Zero)
                {
                    continue;
                }
                
                Marshal.FreeHGlobal(schema.Attributes[i].Name);
                schema.Attributes[i].Name = IntPtr.Zero;
            }
        }

        private static IntPtr BuildAttributes(string key)
        {
            IntPtr table = g_hash_table_new_full(
                Marshal.GetFunctionPointerForDelegate(_gStrHash),
                Marshal.GetFunctionPointerForDelegate(_gStrEqual),
                Marshal.GetFunctionPointerForDelegate(_gFree),
                Marshal.GetFunctionPointerForDelegate(_gFree));

            if (table == IntPtr.Zero)
            {
                throw new InvalidOperationException("Failed to create GLib hash table.");
            }

            IntPtr attrNamePtr = IntPtr.Zero;
            IntPtr attrValuePtr = IntPtr.Zero;

            try
            {
                attrNamePtr = StringToUtf8HGlobal(AttrKey);
                attrValuePtr = StringToUtf8HGlobal(key);

                bool inserted = g_hash_table_insert(table, attrNamePtr, attrValuePtr);
                if (!inserted)
                {
                    throw new InvalidOperationException("Failed to insert libsecret attribute.");
                }

                attrNamePtr = IntPtr.Zero;
                attrValuePtr = IntPtr.Zero;

                return table;
            }
            catch
            {
                if (attrNamePtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(attrNamePtr);
                }

                if (attrValuePtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(attrValuePtr);
                }

                g_hash_table_destroy(table);
                throw;
            }
        }

        private static void ThrowIfError(IntPtr errorPtr, string operation)
        {
            if (errorPtr == IntPtr.Zero)
            {
                return;
            }

            try
            {
                GError error = Marshal.PtrToStructure<GError>(errorPtr);
                string message = PtrToStringUtf8(error.Message);
                
                throw new InvalidOperationException($"libsecret {operation} error: {message} (code {error.Code})");
            }
            finally
            {
                g_error_free(errorPtr);
            }
        }

        private static string PtrToStringUtf8(IntPtr ptr)
        {
            if (ptr == IntPtr.Zero)
            {
                return string.Empty;
            }

            int len = 0;
            while (Marshal.ReadByte(ptr, len) != 0)
            {
                len++;
            }

            byte[] buffer = new byte[len];
            Marshal.Copy(ptr, buffer, 0, len);
            
            return Encoding.UTF8.GetString(buffer);
        }

        private static IntPtr StringToUtf8HGlobal(string value)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(value);
            IntPtr ptr = Marshal.AllocHGlobal(bytes.Length + 1);
            Marshal.Copy(bytes, 0, ptr, bytes.Length);
            Marshal.WriteByte(ptr, bytes.Length, 0);
            
            return ptr;
        }

        private delegate IntPtr GHashFunc(IntPtr key);
        private delegate bool GEqualFunc(IntPtr a, IntPtr b);
        private delegate void GDestroyNotify(IntPtr data);

        private static readonly GHashFunc _gStrHash = new GHashFunc(g_str_hash);
        private static readonly GEqualFunc _gStrEqual = new GEqualFunc(g_str_equal);
        private static readonly GDestroyNotify _gFree = new GDestroyNotify(g_free);
    }
}