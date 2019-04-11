using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using Xunit;

namespace MicroRatchet.Tests
{
    public class SymmetricRatchetTests
    {
        private AesKdf kdf = new AesKdf(Common.AesFactory);

        [Fact]
        public void InitializeTest()
        {
            RandomNumberGenerator rng = new RandomNumberGenerator();
            SymmetricRacthet sr = new SymmetricRacthet();
            byte[] headerKey = rng.Generate(32);
            byte[] chainKey = rng.Generate(32);
            byte[] nextHeaderKey = rng.Generate(32);
            sr.Initialize(headerKey, chainKey, nextHeaderKey);

            Assert.NotNull(sr.HeaderKey);
            Assert.NotNull(sr.ChainKey);
            Assert.NotNull(sr.NextHeaderKey);
            Assert.Equal(headerKey, sr.HeaderKey);
            Assert.Equal(chainKey, sr.ChainKey);
            Assert.Equal(nextHeaderKey, sr.NextHeaderKey);
            Assert.NotNull(sr.LostKeys);
            Assert.Equal(0, sr.Generation);
        }

        [Fact]
        public void BasicSendRatchetTest()
        {
            RandomNumberGenerator rng = new RandomNumberGenerator();
            SymmetricRacthet sr = new SymmetricRacthet();
            sr.Initialize(rng.Generate(32), rng.Generate(32), rng.Generate(32));

            var (key, generation) = sr.RatchetForSending(kdf);

            Assert.NotNull(key);
            Assert.Equal(16, key.Length);
            Assert.Equal(1, generation);
        }

        [Fact]
        public void HeaderKeysOptionalTest()
        {
            RandomNumberGenerator rng = new RandomNumberGenerator();
            SymmetricRacthet sr = new SymmetricRacthet();
            sr.Initialize(null, rng.Generate(32), null);

            var (key, generation) = sr.RatchetForSending(kdf);

            Assert.NotNull(key);
            Assert.Equal(16, key.Length);
            Assert.Equal(1, generation);
        }

        [Fact]
        public void ChainKeyModulationTest()
        {
            RandomNumberGenerator rng = new RandomNumberGenerator();
            SymmetricRacthet sr = new SymmetricRacthet();
            byte[] chainKey = rng.Generate(32);
            sr.Initialize(rng.Generate(32), chainKey, rng.Generate(32));

            var (key, generation) = sr.RatchetForSending(kdf);

            Assert.NotNull(key);
            Assert.Equal(16, key.Length);
            Assert.Equal(1, generation);
            Assert.NotEqual(chainKey, sr.ChainKey);
        }

        [Fact]
        public void MultiSendRatchetTest()
        {
            RandomNumberGenerator rng = new RandomNumberGenerator();
            SymmetricRacthet sr = new SymmetricRacthet();
            sr.Initialize(rng.Generate(32), rng.Generate(32), rng.Generate(32));

            var (key1, generation1) = sr.RatchetForSending(kdf);
            var (key2, generation2) = sr.RatchetForSending(kdf);

            Assert.NotNull(key1);
            Assert.Equal(16, key1.Length);
            Assert.Equal(1, generation1);
            Assert.NotNull(key2);
            Assert.Equal(16, key2.Length);
            Assert.Equal(2, generation2);
            Assert.NotEqual(key2, key1);
        }

        [Fact]
        public void BasicSymmetryTest()
        {
            RandomNumberGenerator rng = new RandomNumberGenerator();
            SymmetricRacthet send = new SymmetricRacthet();
            SymmetricRacthet recv = new SymmetricRacthet();
            byte[] headerKey = rng.Generate(32);
            byte[] chainKey = rng.Generate(32);
            byte[] nextHeaderKey = rng.Generate(32);
            send.Initialize(headerKey, chainKey, nextHeaderKey);
            recv.Initialize(headerKey, chainKey, nextHeaderKey);

            var (skey, sgeneration) = send.RatchetForSending(kdf);
            var (rkey, rgeneration) = recv.RatchetForReceiving(kdf, sgeneration);

            Assert.NotNull(skey);
            Assert.NotNull(rkey);
            Assert.Equal(rgeneration, sgeneration);
            Assert.Equal(skey, rkey);
        }

        [Fact]
        public void MultiSymmetryTest()
        {
            RandomNumberGenerator rng = new RandomNumberGenerator();
            SymmetricRacthet send = new SymmetricRacthet();
            SymmetricRacthet recv = new SymmetricRacthet();
            byte[] headerKey = rng.Generate(32);
            byte[] chainKey = rng.Generate(32);
            byte[] nextHeaderKey = rng.Generate(32);
            send.Initialize(headerKey, chainKey, nextHeaderKey);
            recv.Initialize(headerKey, chainKey, nextHeaderKey);

            var (skey1, sgeneration1) = send.RatchetForSending(kdf);
            var (skey2, sgeneration2) = send.RatchetForSending(kdf);
            var (rkey1, rgeneration1) = recv.RatchetForReceiving(kdf, sgeneration1);
            var (rkey2, rgeneration2) = recv.RatchetForReceiving(kdf, sgeneration2);

            Assert.NotNull(skey1);
            Assert.NotNull(skey2);
            Assert.NotNull(rkey1);
            Assert.NotNull(rkey2);
            Assert.Equal(sgeneration1, rgeneration1);
            Assert.Equal(sgeneration2, rgeneration2);
            Assert.Equal(skey1, rkey1);
            Assert.Equal(skey2, rkey2);
        }

        [InlineData(1)]
        [InlineData(10)]
        [InlineData(100)]
        [InlineData(1000)]
        [InlineData(10000)]
        [InlineData(100000)]
        [Theory]
        public void DeepSymmetryTest(int depth)
        {
            RandomNumberGenerator rng = new RandomNumberGenerator();
            SymmetricRacthet send = new SymmetricRacthet();
            SymmetricRacthet recv = new SymmetricRacthet();
            byte[] headerKey = rng.Generate(32);
            byte[] chainKey = rng.Generate(32);
            byte[] nextHeaderKey = rng.Generate(32);
            send.Initialize(headerKey, chainKey, nextHeaderKey);
            recv.Initialize(headerKey, chainKey, nextHeaderKey);

            byte[] key;
            for (; ; )
            {
                var r = send.RatchetForSending(kdf);
                if (r.generation == depth)
                {
                    key = r.key;
                    break;
                }
            }

            var (rk, rg) = recv.RatchetForReceiving(kdf, depth);

            Assert.Equal(depth, rg);
            Assert.Equal(key, rk);
        }

        [InlineData(10000)]
        [InlineData(100000)]
        [Theory]
        public void NonduplicationTest(int howmany)
        {
            RandomNumberGenerator rng = new RandomNumberGenerator();
            SymmetricRacthet sr = new SymmetricRacthet();
            sr.Initialize(null, rng.Generate(32), null);
            List<byte[]> allkeys = new List<byte[]>();

            for (int i = 0; i < howmany; i++)
            {
                var (key, _) = sr.RatchetForSending(kdf);
                allkeys.Add(key);
            }

            Assert.Equal(allkeys.Count, allkeys.Distinct().Count());
        }

        [InlineData(10000)]
        [InlineData(100000)]
        [Theory]
        public void RatchetForReceivingManyTest(int howmany)
        {
            RandomNumberGenerator rng = new RandomNumberGenerator();
            SymmetricRacthet recv = new SymmetricRacthet();
            recv.Initialize(rng.Generate(32), rng.Generate(32), rng.Generate(32));

            recv.RatchetForReceiving(kdf, howmany);
        }

        [InlineData(new byte[] { 0x77, 0xca, 0x3d, 0xca, 0x28, 0x86, 0xe9, 0xe4, 0x93, 0xf2, 0xe7, 0x8a, 0xfe, 0x62, 0x81, 0x69, 0x92, 0x29, 0x93, 0x0e, 0x7a, 0x5e, 0x9e, 0x34, 0x3f, 0x5a, 0xb3, 0x12, 0xc3, 0xae, 0x3c, 0x32 }, 39479, new byte[] { 0x00, 0x75, 0xd8, 0xad, 0xe6, 0xcb, 0xbf, 0xa0, 0x79, 0xb5, 0xe0, 0xeb, 0x36, 0x96, 0x35, 0x2c })]
        [InlineData(new byte[] { 0x7c, 0x0c, 0x8a, 0x0f, 0x87, 0x7b, 0x4b, 0x31, 0x09, 0xfd, 0xc5, 0xbf, 0x31, 0x80, 0xaa, 0xfa, 0x28, 0x9d, 0xe2, 0x08, 0x0a, 0x44, 0xe5, 0x95, 0x32, 0x31, 0x92, 0x29, 0x7e, 0x7a, 0x7f, 0xad }, 94435, new byte[] { 0x29, 0x31, 0xc7, 0xe3, 0xbf, 0xab, 0xcd, 0x5c, 0x85, 0x44, 0x1d, 0xf4, 0x77, 0x8f, 0x09, 0x3d })]
        [InlineData(new byte[] { 0x57, 0x2d, 0x42, 0x30, 0x60, 0xd8, 0xca, 0xa7, 0xca, 0xd0, 0x89, 0x0e, 0x0a, 0x33, 0x47, 0x2a, 0xef, 0x71, 0x75, 0xa3, 0x29, 0x22, 0xf5, 0x6e, 0x97, 0x46, 0xcd, 0xf3, 0xdf, 0x51, 0x5f, 0x37 }, 11164, new byte[] { 0x33, 0xc9, 0x48, 0xb7, 0x1f, 0xdc, 0x17, 0xb0, 0x0e, 0xef, 0x7a, 0x2a, 0x89, 0x20, 0x37, 0x09 })]
        [InlineData(new byte[] { 0xa6, 0xb9, 0x29, 0x93, 0x1d, 0x68, 0x74, 0xcf, 0x66, 0x3e, 0x2c, 0xef, 0xf5, 0x8a, 0x73, 0x8c, 0xa6, 0x7b, 0x24, 0x34, 0xbc, 0xb0, 0x0e, 0x0c, 0x48, 0x5d, 0xe5, 0xf5, 0xeb, 0x03, 0xa0, 0x1e }, 58129, new byte[] { 0xaf, 0x82, 0x60, 0x58, 0x7f, 0x78, 0xb3, 0x96, 0xd2, 0xea, 0x65, 0x5b, 0xec, 0xa5, 0x9a, 0x36 })]
        [InlineData(new byte[] { 0xf9, 0xad, 0xcc, 0x2b, 0x22, 0x3f, 0x82, 0x16, 0xa4, 0x8b, 0xec, 0xb9, 0xa2, 0x3e, 0x9b, 0xe1, 0x24, 0x61, 0x07, 0xbe, 0x9c, 0x7b, 0xbd, 0x73, 0xa4, 0x1e, 0xa6, 0xe8, 0x45, 0xe5, 0xee, 0x51 }, 97922, new byte[] { 0xd4, 0x23, 0xb7, 0x51, 0xb4, 0x77, 0xcf, 0xef, 0xe4, 0x4e, 0x55, 0xe6, 0x6e, 0x52, 0x31, 0x63 })]
        [Theory]
        public void ReferenceTest(byte[] chainkey, int generation, byte[] expectedkey)
        {
            SymmetricRacthet sr = new SymmetricRacthet();
            sr.Initialize(null, chainkey, null);

            for (; ; )
            {
                var (key, gen) = sr.RatchetForSending(kdf);
                if (gen == generation)
                {
                    Assert.Equal(expectedkey, key);
                    break;
                }
            }
        }
    }
}
