using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet
{
    public interface IAesFactory
    {
        int[] GetAcceptedKeySizes();
        int BlockSize { get; }
        IAes GetAes(bool forEncryption, ArraySegment<byte> key);
    }
}
