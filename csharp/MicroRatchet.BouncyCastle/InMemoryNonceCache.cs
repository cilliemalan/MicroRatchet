using System;
using System.Collections.Concurrent;
using System.Collections.Generic;

namespace MicroRatchet.BouncyCastle
{
    internal class InMemoryNonceCache : INonceCache
    {
        private ConcurrentDictionary<byte[], int> cache;

        public InMemoryNonceCache()
        {
            cache = new ConcurrentDictionary<byte[], int>(ByteArrayComparer.Instance);
        }

        public bool MarkNonce(ArraySegment<byte> nonce)
        {
            byte[] tocache = new byte[nonce.Count];
            Array.Copy(nonce.Array, nonce.Offset, tocache, 0, nonce.Count);
            return cache.TryAdd(tocache, 0);
        }

        private class ByteArrayComparer : IEqualityComparer<byte[]>
        {
            private ByteArrayComparer() { }

            public static IEqualityComparer<byte[]> Instance { get; } = new ByteArrayComparer();

            public bool Equals(byte[] x, byte[] y)
            {
                if (x.Length != y.Length) return false;
                if (x.Length == 0 && y.Length == 0) return true;
                for (int i = 0; i < x.Length; i++)
                {
                    if (x[i] != y[i]) return false;
                }

                return true;
            }

            public int GetHashCode(byte[] obj)
            {
                return obj[0] << 24 | obj[1] << 16 | obj[2] << 8 | obj[3];
            }
        }
    }
}