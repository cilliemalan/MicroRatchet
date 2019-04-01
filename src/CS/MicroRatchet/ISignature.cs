using System;

namespace MicroRatchet
{
    public interface ISignature : IVerifier
    {
        byte[] PublicKey { get; }
        byte[] Sign(ArraySegment<byte> data);
    }
}