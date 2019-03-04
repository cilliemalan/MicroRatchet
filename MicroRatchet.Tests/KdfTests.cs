using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using Xunit;

namespace MicroRatchet.Tests
{
    public class KdfTests
    {
        private Random r = new Random();

        [Fact(DisplayName = "HKDF works with all zero input")]
        public void BasicReferenceTest()
        {
            byte[] key = new byte[32];
            byte[] info = new byte[32];

            var derived = new KeyDerivation(new Digest()).GenerateBytes(key, info, 32);

            var bcKdf = new HkdfBytesGenerator(new Sha256Digest());
            HkdfParameters hkdfparms = HkdfParameters.SkipExtractParameters(key, info);
            bcKdf.Init(hkdfparms);
            byte[] bcDerived = new byte[32];
            bcKdf.GenerateBytes(bcDerived, 0, 32);

            Assert.Equal(bcDerived, derived);
        }

        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        [InlineData(4)]
        [InlineData(5)]
        [Theory(DisplayName = "HKDF works with random data")]
        public void RandomReferenceTest(int i)
        {
            byte[] key = new byte[32];
            byte[] info = new byte[32];
            r.NextBytes(key);
            r.NextBytes(info);

            var derived = new KeyDerivation(new Digest()).GenerateBytes(key, info, 32);

            var bcKdf = new HkdfBytesGenerator(new Sha256Digest());
            HkdfParameters hkdfparms = HkdfParameters.SkipExtractParameters(key, info);
            bcKdf.Init(hkdfparms);
            byte[] bcDerived = new byte[32];
            bcKdf.GenerateBytes(bcDerived, 0, 32);

            Assert.Equal(bcDerived, derived);
        }

        [InlineData(32)]
        [InlineData(64)]
        [InlineData(55)]
        [InlineData(155)]
        [InlineData(1242)]
        [InlineData(3333)]
        [Theory(DisplayName = "HKDF works with various output lengths")]
        public void VariableLengthOutputTest(int outputLength)
        {
            byte[] key = new byte[32];
            byte[] info = new byte[32];
            r.NextBytes(key);
            r.NextBytes(info);

            var derived = new KeyDerivation(new Digest()).GenerateBytes(key, info, outputLength);

            var bcKdf = new HkdfBytesGenerator(new Sha256Digest());
            HkdfParameters hkdfparms = HkdfParameters.SkipExtractParameters(key, info);
            bcKdf.Init(hkdfparms);
            byte[] bcDerived = new byte[outputLength];
            bcKdf.GenerateBytes(bcDerived, 0, outputLength);

            Assert.Equal(bcDerived, derived);
        }

        [InlineData(32)]
        [InlineData(64)]
        [InlineData(55)]
        [InlineData(155)]
        [InlineData(1242)]
        [InlineData(3333)]
        [Theory(DisplayName = "HKDF works with various info lengths")]
        public void VariableLengthInfoTest(int infoLength)
        {
            byte[] key = new byte[32];
            byte[] info = new byte[infoLength];
            r.NextBytes(key);
            r.NextBytes(info);

            var derived = new KeyDerivation(new Digest()).GenerateBytes(key, info, 32);

            var bcKdf = new HkdfBytesGenerator(new Sha256Digest());
            HkdfParameters hkdfparms = HkdfParameters.SkipExtractParameters(key, info);
            bcKdf.Init(hkdfparms);
            byte[] bcDerived = new byte[32];
            bcKdf.GenerateBytes(bcDerived, 0, 32);

            Assert.Equal(bcDerived, derived);
        }
    }
}
