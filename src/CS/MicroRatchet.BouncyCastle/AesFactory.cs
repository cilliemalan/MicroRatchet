using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet.BouncyCastle
{
    public class AesFactory : IAesFactory
    {
        public int BlockSize => 16;
        public int[] GetAcceptedKeySizes() => new[] { 16, 32 };
        public IAes GetAes(bool forEncryption, ArraySegment<byte> key)
        {
            var aes = new Aes();
            aes.Initialize(forEncryption, key);
            return aes;
        }
    }
}
