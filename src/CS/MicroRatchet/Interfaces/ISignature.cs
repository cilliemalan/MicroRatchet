using System;

namespace MicroRatchet
{
    public interface ISignature : IVerifier
    {
        int PublicKeySize { get; }
        byte[] PublicKey { get; }
        byte[] Sign(ArraySegment<byte> data);
    }
}