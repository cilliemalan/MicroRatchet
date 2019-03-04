using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace MicroRatchet.Tests
{
    public class SignatureTests
    {
        [Fact]
        public void SignatureTest()
        {
            var key = KeyGeneration.GeneratePrivateKey();
            var sha = new Digest();
            byte[] message = sha.ComputeDigest(new byte[32]);
            Signature sig = new Signature(key);
            var signature = sig.Sign(message);

            Assert.NotNull(signature);
            Assert.Equal(64, signature.Length);
        }

        [Fact]
        public void VerifyTest()
        {
            var key = KeyGeneration.GeneratePrivateKey();
            var sha = new Digest();
            byte[] message = sha.ComputeDigest(new byte[32]);
            Signature sig = new Signature(key);
            var signature = sig.Sign(message);
            Assert.NotNull(signature);
            Assert.Equal(64, signature.Length);

            var verified = sig.Verify(message, signature);
            Assert.True(verified);
        }

        [Fact]
        public void VerifyFailTest()
        {
            var key = KeyGeneration.GeneratePrivateKey();
            var sha = new Digest();
            byte[] message = sha.ComputeDigest(new byte[32]);
            Signature sig = new Signature(key);
            var signature = sig.Sign(message);
            Assert.NotNull(signature);
            Assert.Equal(64, signature.Length);

            message[0]++;

            var verified = sig.Verify(message, signature);
            Assert.False(verified);
        }

        [Fact]
        public void VerifyFailTestModSig()
        {
            var key = KeyGeneration.GeneratePrivateKey();
            var sha = new Digest();
            byte[] message = sha.ComputeDigest(new byte[32]);
            Signature sig = new Signature(key);
            var signature = sig.Sign(message);
            Assert.NotNull(signature);
            Assert.Equal(64, signature.Length);

            signature[0]++;

            var verified = sig.Verify(message, signature);
            Assert.False(verified);
        }

        [Fact]
        public void RepeatabilityTest()
        {
            for (int i = 0; i < 30; i++)
            {
                VerifyTest();
            }
        }
    }
}
