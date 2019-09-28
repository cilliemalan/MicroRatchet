using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet
{
    public interface IVerifierFactory
    {
        int SignatureSize { get; }
        IVerifier Create(ArraySegment<byte> publicKey);
    }
}
