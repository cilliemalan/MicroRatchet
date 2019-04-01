using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace MicroRatchet.Tests
{
    public class AesKdfTests
    {
        private Random r = new Random();

        private class AesFactory : IAesFactory
        {
            public IAes GetAes(bool forEncryption, byte[] key)
            {
                var aes = new Aes();
                aes.Initialize(forEncryption, key);
                return aes;
            }
        }
        
        [Fact(DisplayName = "AESKDF works with all zero input")]
        public void BasicReferenceTest()
        {
            byte[] key = new byte[32];
            byte[] info = new byte[32];

            var derived = new AesKdf(new AesFactory()).GenerateBytes(key, info, 32);
        }

        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        [InlineData(4)]
        [InlineData(5)]
        [Theory(DisplayName = "AESKDF works with random data")]
        public void RandomReferenceTest(int i)
        {
            byte[] key = new byte[32];
            byte[] info = new byte[32];
            r.NextBytes(key);
            r.NextBytes(info);

            var derived = new AesKdf(new AesFactory()).GenerateBytes(key, info, 32);
        }

        [InlineData(3)]
        [InlineData(16)]
        [InlineData(18)]
        [InlineData(32)]
        [InlineData(55)]
        [InlineData(64)]
        [InlineData(77)]
        [InlineData(155)]
        [InlineData(1242)]
        [InlineData(3333)]
        [InlineData(8160)]
        [Theory(DisplayName = "AESKDF works with various output lengths")]
        public void VariableLengthOutputTest(int outputLength)
        {
            byte[] key = new byte[32];
            byte[] info = new byte[32];
            r.NextBytes(key);
            r.NextBytes(info);

            var derived = new AesKdf(new AesFactory()).GenerateBytes(key, info, outputLength);
        }

        [InlineData(3)]
        [InlineData(16)]
        [InlineData(18)]
        [InlineData(32)]
        [InlineData(55)]
        [InlineData(64)]
        [InlineData(77)]
        [InlineData(155)]
        [InlineData(1242)]
        [InlineData(3333)]
        [InlineData(8160)]
        [Theory(DisplayName = "AESKDF works with various info lengths")]
        public void VariableLengthInfoTest(int infoLength)
        {
            byte[] key = new byte[32];
            byte[] info = new byte[infoLength];
            r.NextBytes(key);
            r.NextBytes(info);

            var derived = new AesKdf(new AesFactory()).GenerateBytes(key, info, 32);
        }
    }
}
