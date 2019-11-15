using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet.BouncyCastle
{
    public class VerifierFactory : IVerifierFactory
    {
        public int SignatureSize => 64;

        public IVerifier Create(ArraySegment<byte> publicKey) =>
            new Verifier(publicKey);
    }
}
