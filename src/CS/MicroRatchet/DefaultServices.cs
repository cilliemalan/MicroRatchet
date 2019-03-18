using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace MicroRatchet
{
    public class DefaultServices : IServices
    {
        public DefaultServices(byte[] privateKey, int hotSpace = 1024, int coldSpace = 8192)
        {
            var fac = new DefaultFactories();
            KeyAgreementFactory = fac;
            VerifierFactory = fac;

            Signature = new Signature(privateKey);
            var storage = new InMemoryStorage(hotSpace, coldSpace);
            Storage = storage;
        }

        public IDigest Digest { get; set; } = new Digest();
        public ISignature Signature { get; set; }
        public IRandomNumberGenerator RandomNumberGenerator { get; set; } = new RandomNumberGenerator();
        public IStorageProvider Storage { get; set; }
        public IKeyAgreementFactory KeyAgreementFactory { get; set; }
        public ICipher Cipher { get; set; } = new Cipher();
        public IVerifierFactory VerifierFactory { get; set; }
        public IMac Mac { get; set; } = new GMac();

        private class DefaultFactories : IKeyAgreementFactory, IVerifierFactory
        {
            public IVerifier Create(byte[] publicKey) => new Verifier(publicKey);
            public IKeyAgreement GenerateNew() => new KeyAgreement(KeyGeneration.GeneratePrivateKey(), null);
            public IKeyAgreement Deserialize(Stream stream) => KeyAgreement.Deserialize(stream);
        }

        private class InMemoryStorage : IStorageProvider
        {
            private byte[] hot;
            private byte[] cold;

            public InMemoryStorage(int hotSpace, int coldSpace)
            {
                hot = new byte[hotSpace];
                cold = new byte[coldSpace];
            }

            public Stream LockHot() => new MemoryStream(hot);
            public Stream LockCold() => new MemoryStream(cold);
        }
    }
}
