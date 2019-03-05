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
            CipherFactory = fac;
            VerifierFactory = fac;

            Signature = new Signature(privateKey);
        }

        public IDigest Digest { get; set; } = new Digest();
        public ISignature Signature { get; set; }
        public IRandomNumberGenerator RandomNumberGenerator { get; set; } = new RandomNumberGenerator();
        public ISecureStorage SecureStorage { get; set; } = new InMemoryStorage();
        public IKeyAgreementFactory KeyAgreementFactory { get; set; }
        public ICipherFactory CipherFactory { get; set; }
        public IVerifierFactory VerifierFactory { get; set; }
        public IMac Mac { get; set; } = new GMac();

        private class DefaultFactories : IKeyAgreementFactory, ICipherFactory, IVerifierFactory
        {
            public IVerifier Create(byte[] publicKey) => new Verifier(publicKey);
            public IKeyAgreement Deserialize(byte[] data) => _kexCache.GetOrAdd(data, d => new KeyAgreement(d));
            public IKeyAgreement GenerateNew()
            {
                var pvt = KeyGeneration.GeneratePrivateKey();
                return _kexCache[pvt] = new KeyAgreement(pvt);
            }
            public IAeadCipher GetAeadCipher(byte[] key, int macSize = 128) => new AeadCipher(key, macSize);
            public ICipher GetCipher(byte[] key, byte[] iv) { var c = new Cipher(); c.Initialize(key, iv); return c; }

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
