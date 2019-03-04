using System;

namespace MicroRatchet
{
    public interface IAeadCipher
    {
        int BlockSize { get; }
        int MacSize { get; }
        byte[] Decrypt(byte[] nonce, ArraySegment<byte> data, byte[] ad = null);
        byte[] Encrypt(byte[] nonce, ArraySegment<byte> data, byte[] ad = null);
    }
}