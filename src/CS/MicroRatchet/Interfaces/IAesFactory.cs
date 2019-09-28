using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet
{
    public interface IAesFactory
    {
        int[] AcceptedKeySizes { get; }
        int BlockSize { get; }
        IAes GetAes(bool forEncryption, ArraySegment<byte> key);
    }
}
