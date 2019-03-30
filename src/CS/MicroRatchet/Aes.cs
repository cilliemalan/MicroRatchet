using System;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace MicroRatchet
{
    internal class Aes : IAes
    {
        private AesEngine _aes;

        public void Initialize(bool encryption, byte[] key)
        {
            _aes = new Org.BouncyCastle.Crypto.Engines.AesEngine();
            _aes.Init(encryption, new KeyParameter(key));
        }

        public void Process(ArraySegment<byte> input, ArraySegment<byte> output)
        {
            if (input.Count != 16) throw new ArgumentException("Input must be exactly 16 bytes long");
            if (output.Count != 16) throw new ArgumentException("Input must be exactly 16 bytes long");

            _aes.ProcessBlock(input.Array, input.Offset, output.Array, output.Offset);
        }
    }
}
