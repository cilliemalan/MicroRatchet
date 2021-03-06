﻿using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace MicroRatchet.BouncyCastle
{
    /// <summary>
    /// A default implementation of the services needed by <see cref="MicroRatchetContext" />.
    /// </summary>
    public class BouncyCastleServices : IServices
    {
        public BouncyCastleServices(byte[] privateKey)
        {
            var fac = new DefaultFactories();
            KeyAgreementFactory = fac;
            VerifierFactory = fac;
            AesFactory = fac;
            Signature = new Signature(new ArraySegment<byte>(privateKey));
        }

        public IDigest Digest { get; set; } = new Digest();
        public ISignature Signature { get; set; }
        public IRandomNumberGenerator RandomNumberGenerator { get; set; } = new RandomNumberGenerator();
        public IKeyAgreementFactory KeyAgreementFactory { get; set; }
        public IVerifierFactory VerifierFactory { get; set; }
        public IAesFactory AesFactory { get; }
        public INonceCache NonceCache { get; set; } = new InMemoryNonceCache();

        private class DefaultFactories : IKeyAgreementFactory, IVerifierFactory, IAesFactory
        {
            int IKeyAgreementFactory.PublicKeySize => 32;
            int IVerifierFactory.SignatureSize => 64;
            int[] IAesFactory.GetAcceptedKeySizes() => new int[] { 16, 32 };
            int IAesFactory.BlockSize => 16;

            public IVerifier Create(ArraySegment<byte> publicKey) => new Verifier(publicKey);
            public IKeyAgreement GenerateNew() => new KeyAgreement(KeyGeneration.GeneratePrivateKey(),default);
            public IKeyAgreement Deserialize(Stream stream) => KeyAgreement.Deserialize(stream);
            public IAes GetAes(bool forEncryption, ArraySegment<byte> key) { var a = new Aes(); a.Initialize(forEncryption, key); return a; }
        }
    }
}
