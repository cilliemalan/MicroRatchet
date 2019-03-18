using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet
{
    public interface IVerifier
    {
        int SignatureSize { get; }
        byte[] PublicKey { get; }
        bool Verify(ArraySegment<byte> data, byte[] signature);
    }
}
