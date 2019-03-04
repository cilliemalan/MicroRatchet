using Org.BouncyCastle.Crypto.Digests;
using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace MicroRatchet.Tests
{
    public class DigestTests
    {
        [Fact]
        public void BasicTest()
        {
            byte[] bytes1 = new byte[100];
            byte[] bytes2 = new byte[100];

            bytes1[0] = 1;
            bytes2[0] = 2;

            Digest d = new Digest();
            var d1 = d.ComputeDigest(bytes1);
            var d2 = d.ComputeDigest(bytes2);

            Assert.NotEqual(d1, d2);
        }

        [Fact]
        public void ShaTest()
        {
            for (int i = 0; i < 100; i++)
            {
                byte[] bytes = new byte[100];
                new Random().NextBytes(bytes);

                var d1 = new Digest().ComputeDigest(bytes);

                var _sha = new Sha256Digest();
                _sha.BlockUpdate(bytes, 0, bytes.Length);
                byte[] d2 = new byte[_sha.GetDigestSize()];
                _sha.DoFinal(d2, 0);

                Assert.Equal(d1, d2);
            }
        }

        [Fact]
        public void DisposeTest()
        {
            var c = new Digest();
            c.Dispose();
            Assert.Throws<ObjectDisposedException>(() => c.ComputeDigest(new byte[0]));
        }
    }
}
