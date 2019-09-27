using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace MicroRatchet
{
    /// <summary>
    /// A default implementation of the services needed by <see cref="MicroRatchetClient" />.
    /// </summary>
    public class DefaultServices : IServices
    {
        public DefaultServices(byte[] privateKey, int hotSpace = 1024, int coldSpace = 8192)
        {
            var fac = new DefaultFactories();
            KeyAgreementFactory = fac;
            VerifierFactory = fac;
            AesFactory = fac;

            Signature = new Signature(new ArraySegment<byte>(privateKey));
            var storage = new InMemoryStorage(hotSpace, coldSpace);
            Storage = storage;
        }

        public IDigest Digest { get; set; } = new Digest();
        public ISignature Signature { get; set; }
        public IRandomNumberGenerator RandomNumberGenerator { get; set; } = new RandomNumberGenerator();
        public IStorageProvider Storage { get; set; }
        public IKeyAgreementFactory KeyAgreementFactory { get; set; }
        public IVerifierFactory VerifierFactory { get; set; }
        public IAesFactory AesFactory { get; }

        private class DefaultFactories : IKeyAgreementFactory, IVerifierFactory, IAesFactory
        {
            public IVerifier Create(ArraySegment<byte> publicKey) => new Verifier(publicKey);
            public IKeyAgreement GenerateNew() => new KeyAgreement(KeyGeneration.GeneratePrivateKey(),default);
            public IKeyAgreement Deserialize(Stream stream) => KeyAgreement.Deserialize(stream);
            public IAes GetAes(bool forEncryption, ArraySegment<byte> key) { var a = new Aes(); a.Initialize(forEncryption, key); return a; }
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
