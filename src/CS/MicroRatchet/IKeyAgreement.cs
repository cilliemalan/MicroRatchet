using System;
using System.IO;

namespace MicroRatchet
{
    public interface IKeyAgreement
    {
        int Id { get; }
        byte[] DeriveKey(ArraySegment<byte> otherPublicKey);
        byte[] GetPublicKey();
        void Serialize(Stream stream);
    }
}