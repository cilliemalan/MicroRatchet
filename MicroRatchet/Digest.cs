using Org.BouncyCastle.Crypto.Digests;
using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet
{
    internal class Digest : IDisposable, IDigest
    {
        Sha256Digest _sha = new Sha256Digest();

        public int DigestSize => 256;
        
        public byte[] ComputeDigest(ArraySegment<byte> data)
        {
            if (_sha == null) throw new ObjectDisposedException(nameof(Digest));

            _sha.BlockUpdate(data.Array, data.Offset, data.Count);
            byte[] output = new byte[_sha.GetDigestSize()];
            _sha.DoFinal(output, 0);
            return output;
        }

        public void Dispose()
        {
            _sha?.Reset();
            _sha = null;
        }
    }
}
