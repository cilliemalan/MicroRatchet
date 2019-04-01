using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet
{
    public interface IVerifier
    {
        int SignatureSize { get; }
        bool Verify(ArraySegment<byte> data, ArraySegment<byte> signature);
    }
}
