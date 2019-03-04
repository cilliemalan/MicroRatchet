using System;

namespace MicroRatchet
{
    public interface ICipher
    {
        byte[] Decrypt(ArraySegment<byte> data);
        byte[] Encrypt(ArraySegment<byte> data);
    }
}