using System;

namespace MicroRatchet
{
    public interface ISignature : IVerifier
    {
        byte[] Sign(ArraySegment<byte> data);
    }
}