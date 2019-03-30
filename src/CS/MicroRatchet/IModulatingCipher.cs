using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet
{
    public interface IModulatingCipher
    {
        void Initialize(byte[] key, byte[] iv = null);
        void Process(uint generation, ArraySegment<byte> data, ArraySegment<byte> output);
    }
}
