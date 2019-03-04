using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Xunit;

namespace MicroRatchet.Tests
{
    public class KeyAgreementTests
    {
        [Fact]
        public void BasicTest()
        {
            byte[] priKey1 = KeyGeneration.GeneratePrivateKey();
            byte[] priKey2 = KeyGeneration.GeneratePrivateKey();

            var ke1 = new KeyAgreement(priKey1);
            var ke2 = new KeyAgreement(priKey2);

            var pub1 = ke1.GetPublicKey();
            var pub2 = ke2.GetPublicKey();

            var k1 = ke1.DeriveKey(pub2);
            var k2 = ke2.DeriveKey(pub1);

            Assert.NotEqual(priKey1, priKey2);
            Assert.NotEqual(pub1, pub2);
            Assert.Equal(k1, k2);
        }

        [Fact]
        public void RepeatabilityTest()
        {
            Enumerable.Range(0, 30)
                .AsParallel()
                .ForAll(i =>
                {
                    BasicTest();
                });
        }

        [Fact]
        public void DisposeTest()
        {
            byte[] priKey = KeyGeneration.GeneratePrivateKey();
            var ke = new KeyAgreement(priKey);
            ke.Dispose();
            Assert.Throws<ObjectDisposedException>(() => ke.GetPublicKey());
            Assert.Throws<ObjectDisposedException>(() => ke.DeriveKey(new byte[0]));
        }
    }
}
