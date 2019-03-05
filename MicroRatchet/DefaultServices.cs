using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet
{
    public class DefaultServices : IServices
    {
        public DefaultServices(byte[] privateKey)
        {
            var fac = new DefaultFactories();
            KeyAgreementFactory = fac;
            VerifierFactory = fac;

            Signature = new Signature(privateKey);
        }

        public IDigest Digest { get; set; } = new Digest();
        public ISignature Signature { get; set; }
        public IRandomNumberGenerator RandomNumberGenerator { get; set; } = new RandomNumberGenerator();
        public ISecureStorage SecureStorage { get; set; } = new InMemoryStorage();
        public IKeyAgreementFactory KeyAgreementFactory { get; set; }
        public ICipher Cipher { get; set; } = new Cipher();
        public IVerifierFactory VerifierFactory { get; set; }
        public IMac Mac { get; set; } = new GMac();

        private class DefaultFactories : IKeyAgreementFactory, IVerifierFactory
        {
            public IVerifier Create(byte[] publicKey) => new Verifier(publicKey);
            public IKeyAgreement Deserialize(byte[] data) => _kexCache.GetOrAdd(data, d => new KeyAgreement(d));
            public IKeyAgreement GenerateNew()
            {
                var pvt = KeyGeneration.GeneratePrivateKey();
                return _kexCache[pvt] = new KeyAgreement(pvt);
            }

            private ConcurrentDictionary<byte[], KeyAgreement> _kexCache = new ConcurrentDictionary<byte[], KeyAgreement>();
        }

        private class InMemoryStorage : ISecureStorage
        {
            private byte[] storage;

            public byte[] LoadAsync() => (byte[])storage?.Clone();

            public void StoreAsync(byte[] data)
            {
                storage = (byte[])data?.Clone();
            }
        }
    }
}
