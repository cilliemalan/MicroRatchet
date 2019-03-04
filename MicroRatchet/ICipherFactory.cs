using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet
{
    public interface ICipherFactory
    {
        ICipher GetCipher(byte[] key, byte[] iv);
        IAeadCipher GetAeadCipher(byte[] key, int macSize = 128);
    }
}
