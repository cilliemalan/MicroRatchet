using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace MicroRatchet.BouncyCastle
{
    public class KeyAgreementFactory : IKeyAgreementFactory
    {
        public int PublicKeySize => 32;
        public IKeyAgreement Deserialize(Stream stream) => KeyAgreement.Deserialize(stream);
        public IKeyAgreement GenerateNew() => new KeyAgreement(KeyGeneration.GeneratePrivateKey());
    }
}
