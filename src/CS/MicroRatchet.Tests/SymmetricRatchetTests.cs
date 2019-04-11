using System;
using System.Collections.Generic;
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
            for(; ;)
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
        [InlineData(1000000)]
        [Theory]
        public void RatchetForReceivingSpeedTest(int howmany)
        {
            RandomNumberGenerator rng = new RandomNumberGenerator();
            SymmetricRacthet recv = new SymmetricRacthet();
            recv.Initialize(rng.Generate(32), rng.Generate(32), rng.Generate(32));

            recv.RatchetForReceiving(kdf, howmany);
        }
    }
}
