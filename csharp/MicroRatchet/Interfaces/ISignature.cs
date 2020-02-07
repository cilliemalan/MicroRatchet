using System;

namespace MicroRatchet
{
    public interface ISignature : IVerifier
    {
        int PublicKeySize { get; }
        byte[] GetPublicKey();
        byte[] Sign(ArraySegment<byte> data);
    }
}