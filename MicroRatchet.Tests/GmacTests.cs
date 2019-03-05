using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace MicroRatchet.Tests
{
    public class GmacTests
    {
        [InlineData(4, 32, 320, 128)]
        [InlineData(32, 32, 32, 128)]
        [InlineData(16, 32, 32, 128)]
        [InlineData(4, 32, 32, 128)]
        [InlineData(32, 32, 64, 128)]
        [InlineData(16, 32, 64, 128)]
        [InlineData(4, 32, 64, 128)]
        [InlineData(32, 32, 32, 96)]
        [InlineData(16, 32, 32, 96)]
        [InlineData(4, 32, 32, 96)]
        [InlineData(32, 32, 64, 96)]
        [InlineData(16, 32, 64, 96)]
        [InlineData(4, 32, 64, 96)]
        [Theory]
        public void BasicGmacTests(int nonceBytes, int keyBytes, int dataBytes, int macSize)
        {
            RandomNumberGenerator rng = new RandomNumberGenerator();
            byte[] nonce = rng.Generate(nonceBytes);
            byte[] key = rng.Generate(keyBytes);
            byte[] data = rng.Generate(dataBytes);

            GMac gmac = new GMac();
            gmac.Init(key, nonce, macSize);
            gmac.Process(new ArraySegment<byte>(data));
            byte[] mac = gmac.Compute();

            var bcgmac = new Org.BouncyCastle.Crypto.Macs.GMac(new GcmBlockCipher(new AesEngine()), macSize);
            bcgmac.Init(new ParametersWithIV(new KeyParameter(key), nonce));
            bcgmac.BlockUpdate(data, 0, data.Length);
            byte[] bcmac = new byte[bcgmac.GetMacSize()];
            bcgmac.DoFinal(bcmac, 0);


            Assert.Equal(bcmac, mac);
        }

        [Fact]
        public void ReuseKeyTest()
        {
            RandomNumberGenerator rng = new RandomNumberGenerator();
            byte[] nonce1 = rng.Generate(16);
            byte[] nonce2 = rng.Generate(16);
            byte[] key = rng.Generate(32);
            byte[] data1 = rng.Generate(64);
            byte[] data2 = rng.Generate(64);

            GMac gmac = new GMac();
            gmac.Init(key, nonce1, 96);
            gmac.Process(new ArraySegment<byte>(data1));
            byte[] mac1 = gmac.Compute();
            gmac.Init(key, nonce2, 96);
            gmac.Process(new ArraySegment<byte>(data2));
            byte[] mac2 = gmac.Compute();

            var bcgmac = new Org.BouncyCastle.Crypto.Macs.GMac(new GcmBlockCipher(new AesEngine()), 96);
            bcgmac.Init(new ParametersWithIV(new KeyParameter(key), nonce1));
            bcgmac.BlockUpdate(data1, 0, data1.Length);
            byte[] bcmac1 = new byte[bcgmac.GetMacSize()];
            bcgmac.DoFinal(bcmac1, 0);
            bcgmac.Init(new ParametersWithIV(new KeyParameter(key), nonce2));
            bcgmac.BlockUpdate(data2, 0, data2.Length);
            byte[] bcmac2 = new byte[bcgmac.GetMacSize()];
            bcgmac.DoFinal(bcmac2, 0);


            Assert.Equal(bcmac1, mac1);
            Assert.Equal(bcmac2, mac2);
        }
    }
}
