using MicroRatchet.BouncyCastle;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace MicroRatchet.Tests
{
    internal class DefaultKexFactory : IKeyAgreementFactory
    {
        public static IKeyAgreementFactory Instance = new DefaultKexFactory();
        public IKeyAgreement Deserialize(Stream stream) => KeyAgreement.Deserialize(stream);
        public IKeyAgreement GenerateNew() => new KeyAgreement(KeyGeneration.GeneratePrivateKey());
    }
}
