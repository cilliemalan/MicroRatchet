using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using Dbg = System.Diagnostics.Debug;

namespace MicroRatchet
{
    internal static class Log
    {
        static Lazy<bool> _debugger = new Lazy<bool>(() => Debugger.IsAttached);
        static bool IsDebuggerAttached = _debugger.Value;

        [Conditional("TRACE")]
        public static void Verbose(string message)
        {
            if (IsDebuggerAttached)
            {
                Dbg.WriteLine(message);
            }
        }

        [Conditional("TRACE")]
        public static void Debug(string message)
        {
            if (IsDebuggerAttached)
            {
                Dbg.WriteLine(message);
            }
        }

        [Conditional("TRACE")]
        public static void Info(string message)
        {
            if (IsDebuggerAttached)
            {
                Dbg.WriteLine(message);
            }
        }

        public static string ShowBytes(ArraySegment<byte> data) =>
            ShowBytes(data.Array, data.Offset, data.Count);

        public static string ShowBytes(byte[] data) => ShowBytes(data, 0, data?.Length ?? 0);

        public static string ShowBytes(byte[] data, int offset, int cnt)
        {
            if (IsDebuggerAttached)
            {
                if (data == null) return "<null>";
                else if (data.Length == 0) return "<empty>";
                else return Helpers.ByteArrayToHexViaLookup32(data, offset, cnt);
            }
            else
            {
                return null;
            }
        }

        // by CodesInChaos https://stackoverflow.com/a/24343727
#if DEBUG
        private unsafe static class Helpers
        {
            private static readonly uint[] _lookup32Unsafe = CreateLookup32Unsafe();
            private static readonly uint* _lookup32UnsafeP = (uint*)GCHandle.Alloc(_lookup32Unsafe, GCHandleType.Pinned).AddrOfPinnedObject();

            private static uint[] CreateLookup32Unsafe()
            {
                var result = new uint[256];
                for (int i = 0; i < 256; i++)
                {
                    string s = i.ToString("X2", CultureInfo.InvariantCulture);
                    if (BitConverter.IsLittleEndian)
                        result[i] = ((uint)s[0]) + ((uint)s[1] << 16);
                    else
                        result[i] = ((uint)s[1]) + ((uint)s[0] << 16);
                }
                return result;
            }

            public static string ByteArrayToHexViaLookup32(byte[] bytes, int offset, int cnt)
            {
                if (offset + cnt > bytes.Length) throw new ArgumentOutOfRangeException(nameof(offset));

                var lookupP = _lookup32UnsafeP;
                var result = new string((char)0, cnt * 2);
                fixed (byte* bytesP = &bytes[offset])
                fixed (char* resultP = result)
                {
                    uint* resultP2 = (uint*)resultP;
                    for (int i = 0; i < cnt; i++)
                    {
                        resultP2[i] = lookupP[bytesP[i]];
                    }
                }
                return result;
            }
        }
    }
#else
        private static class Helpers
        {
            private static readonly uint[] _lookup32 = CreateLookup32();

            private static uint[] CreateLookup32()
            {
                var result = new uint[256];
                for (int i = 0; i < 256; i++)
                {
                    string s=i.ToString("X2");
                    result[i] = ((uint)s[0]) + ((uint)s[1] << 16);
                }
                return result;
            }

            public static string ByteArrayToHexViaLookup32(byte[] bytes, int offset, int cnt)
            {
                if (offset + cnt > bytes.Length) throw new ArgumentOutOfRangeException();

                var lookup32 = _lookup32;
                var result = new char[cnt * 2];
                for (int i = 0; i < cnt; i++)
                {
                    var val = lookup32[bytes[i + offset]];
                    result[2*i] = (char)val;
                    result[2*i + 1] = (char) (val >> 16);
                }
                return new string(result);
            }
        }
    }
#endif
}
