using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet
{
    public interface IAesFactory
    {
        IAes GetAes(bool forEncryption, ArraySegment<byte> key);
    }
}
