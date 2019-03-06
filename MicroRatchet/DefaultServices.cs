using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
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
            public IKeyAgreement Deserialize(byte[] data) => _kexCache.GetOrAdd(data, d => KeyAgreement.Deserialize(d));
            public IKeyAgreement GenerateNew()
            {
                var pvt = KeyGeneration.GeneratePrivateKey();
                var kex = new KeyAgreement(pvt, null);
                return _kexCache[kex.Serialize()] = kex;
            }

            private ConcurrentDictionary<byte[], KeyAgreement> _kexCache = new ConcurrentDictionary<byte[], KeyAgreement>();
        }

        private class InMemoryStorage : IStorageProvider
        {
            private byte[] storage;
            private byte[] hot;
            private byte[] cold;

            public int HotSpace => hot.Length;
            public int ColdSpace => cold.Length;

            public void ReadCold(int readOffset, ArraySegment<byte> destination) => Read(cold, readOffset, destination);
            public void ReadHot(int readOffset, ArraySegment<byte> destination) => Read(hot, readOffset, destination);
            public void WriteCold(int storeOffset, ArraySegment<byte> data) => Write(cold, storeOffset, data);
            public void WriteHot(int storeOffset, ArraySegment<byte> data) => Write(hot, storeOffset, data);
            
            public InMemoryStorage(int hotSpace, int coldSpace)
            {
                hot = new byte[hotSpace];
                cold = new byte[coldSpace];
            }

            private void Read(byte[] storage, int offset, ArraySegment<byte> data)
            {
                int amt = data.Count;
                if (offset + amt > storage.Length) throw new InvalidOperationException("Cannot read past end of storage");
                if (offset < 0) throw new InvalidOperationException("Cannot read past start of storage");
                Array.Copy(storage, offset, data.Array, data.Offset, amt);
            }

            private void Write(byte[] storage, int offset, ArraySegment<byte> data)
            {
                int amt = data.Count;
                if (offset + amt > storage.Length) throw new InvalidOperationException("Cannot write past end of storage");
                if (offset < 0) throw new InvalidOperationException("Cannot write past start of storage");
                Array.Copy(data.Array, data.Offset, storage, offset, amt);
            }
        }
    }
}
