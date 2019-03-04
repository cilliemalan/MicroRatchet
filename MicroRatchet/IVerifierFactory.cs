using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet
{
    public interface IVerifierFactory
    {
        IVerifier Create(byte[] publicKey);
    }
}
