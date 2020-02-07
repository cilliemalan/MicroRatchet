using Org.BouncyCastle.Crypto.Digests;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace MicroRatchet.BouncyCastle
{
    /// <summary>
    /// SHA256 Digest.
    /// </summary>
    public sealed class Digest : IDisposable, IDigest
    {
        Sha256Digest _sha = new Sha256Digest();

        public int DigestSize => 32;

        public void Reset()
        {
            _sha.Reset();
        }

        public byte[] Compute()
        {
            if (_sha == null) throw new ObjectDisposedException(nameof(Digest));
            byte[] output = new byte[_sha.GetDigestSize()];
            _sha.DoFinal(output, 0);
            _sha.Reset();
            return output;
        }

        public void Process(ArraySegment<byte> data)
        {
            if (_sha == null) throw new ObjectDisposedException(nameof(Digest));
            _sha.BlockUpdate(data.Array, data.Offset, data.Count);
        }

        public void Dispose()
        {
            _sha?.Reset();
            _sha = null;
        }
    }
}
