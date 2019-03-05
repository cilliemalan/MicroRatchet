using System;

namespace MicroRatchet
{
    public interface ICipher
    {
        void Initialize(byte[] key, byte[] iv);
        byte[] Decrypt(ArraySegment<byte> data);
        byte[] Encrypt(ArraySegment<byte> data);
    }
}