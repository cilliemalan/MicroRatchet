using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using Xunit;

namespace MicroRatchet.Tests
{
    public class HMacTests
    {
        [Fact]
        public void BasicHmacTest()
        {
            RandomNumberGenerator rng = new RandomNumberGenerator();
            byte[] key = rng.Generate(32);
            byte[] info = rng.Generate(32);

            HMac hmac = new HMac(new Digest());
            hmac.Init(key);
            hmac.Process(info);
            var output = hmac.Compute();

            var bcHmac = new Org.BouncyCastle.Crypto.Macs.HMac(new Sha256Digest());
            bcHmac.Init(new KeyParameter(key));
            bcHmac.BlockUpdate(info, 0, info.Length);
            byte[] bcoutput = new byte[bcHmac.GetMacSize()];
            int bcoutLen = bcHmac.DoFinal(bcoutput, 0);

            Assert.Equal(bcoutLen, output.Length);
            Assert.Equal(bcoutput, output);
        }

        [Fact]
        public void BasicHmacLargeInfoTest()
        {
            RandomNumberGenerator rng = new RandomNumberGenerator();
            byte[] key = rng.Generate(32);
            byte[] info = rng.Generate(320);

            HMac hmac = new HMac(new Digest());
            hmac.Init(key);
            hmac.Process(info);
            var output = hmac.Compute();

            var bcHmac = new Org.BouncyCastle.Crypto.Macs.HMac(new Sha256Digest());
            bcHmac.Init(new KeyParameter(key));
            bcHmac.BlockUpdate(info, 0, info.Length);
            byte[] bcoutput = new byte[bcHmac.GetMacSize()];
            int bcoutLen = bcHmac.DoFinal(bcoutput, 0);

            Assert.Equal(bcoutLen, output.Length);
            Assert.Equal(bcoutput, output);
        }

        [Fact]
        public void BasicHmacLargeKeyTest()
        {
            RandomNumberGenerator rng = new RandomNumberGenerator();
            byte[] key = rng.Generate(320);
            byte[] info = rng.Generate(32);

            HMac hmac = new HMac(new Digest());
            hmac.Init(key);
            hmac.Process(info);
            var output = hmac.Compute();

            var bcHmac = new Org.BouncyCastle.Crypto.Macs.HMac(new Sha256Digest());
            bcHmac.Init(new KeyParameter(key));
            bcHmac.BlockUpdate(info, 0, info.Length);
            byte[] bcoutput = new byte[bcHmac.GetMacSize()];
            int bcoutLen = bcHmac.DoFinal(bcoutput, 0);

            Assert.Equal(bcoutLen, output.Length);
            Assert.Equal(bcoutput, output);
        }

        [Fact]
        public void MultiUseTest()
        {
            RandomNumberGenerator rng = new RandomNumberGenerator();
            byte[] key = rng.Generate(32);
            byte[] info1 = rng.Generate(32);
            byte[] info2 = rng.Generate(32);

            HMac hmac = new HMac(new Digest());
            hmac.Init(key);
            hmac.Process(info1);
            var output1 = hmac.Compute();
            hmac.Process(info2);
            var output2 = hmac.Compute();

            var bcHmac = new Org.BouncyCastle.Crypto.Macs.HMac(new Sha256Digest());
            bcHmac.Init(new KeyParameter(key));
            bcHmac.BlockUpdate(info1, 0, info1.Length);
            byte[] bcoutput1 = new byte[bcHmac.GetMacSize()];
            int bcoutLen1 = bcHmac.DoFinal(bcoutput1, 0);
            bcHmac.BlockUpdate(info2, 0, info2.Length);
            byte[] bcoutput2 = new byte[bcHmac.GetMacSize()];
            int bcoutLen2 = bcHmac.DoFinal(bcoutput2, 0);

            Assert.Equal(bcoutLen1, output1.Length);
            Assert.Equal(bcoutput1, output1);
            Assert.Equal(bcoutLen2, output2.Length);
            Assert.Equal(bcoutput2, output2);
        }

        [Fact]
        public void MultiUseTest2()
        {
            RandomNumberGenerator rng = new RandomNumberGenerator();
            byte[] key1 = rng.Generate(32);
            byte[] key2 = rng.Generate(32);
            byte[] info1 = rng.Generate(32);
            byte[] info2 = rng.Generate(32);

            HMac hmac = new HMac(new Digest());
            hmac.Init(key1);
            hmac.Process(info1);
            var output1 = hmac.Compute();
            hmac.Init(key2);
            hmac.Process(info2);
            var output2 = hmac.Compute();

            var bcHmac = new Org.BouncyCastle.Crypto.Macs.HMac(new Sha256Digest());
            bcHmac.Init(new KeyParameter(key1));
            bcHmac.BlockUpdate(info1, 0, info1.Length);
            byte[] bcoutput1 = new byte[bcHmac.GetMacSize()];
            int bcoutLen1 = bcHmac.DoFinal(bcoutput1, 0);
            bcHmac.Init(new KeyParameter(key2));
            bcHmac.BlockUpdate(info2, 0, info2.Length);
            byte[] bcoutput2 = new byte[bcHmac.GetMacSize()];
            int bcoutLen2 = bcHmac.DoFinal(bcoutput2, 0);

            Assert.Equal(bcoutLen1, output1.Length);
            Assert.Equal(bcoutput1, output1);
            Assert.Equal(bcoutLen2, output2.Length);
            Assert.Equal(bcoutput2, output2);
        }

        [InlineData(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, new byte[] { 0xd1, 0x29, 0xe, 0xb2, 0x59, 0x65, 0x23, 0x3c, 0x91, 0x3c, 0x3d, 0xeb, 0x22, 0x2e, 0x79, 0x86, 0x68, 0x4c, 0xe6, 0xb0, 0x8d, 0x93, 0x21, 0xab, 0xc1, 0x11, 0xd8, 0x70, 0x68, 0xe3, 0xd7, 0xf8 })]
        [InlineData(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, new byte[] { 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF }, new byte[] { 0xbd, 0xe4, 0x45, 0x73, 0xaf, 0xad, 0xe2, 0xc0, 0x8b, 0x2c, 0xaa, 0xc1, 0x4c, 0x46, 0xc8, 0x85, 0xc7, 0xb2, 0x1e, 0x24, 0xf6, 0x7d, 0x76, 0xb6, 0xaa, 0x0, 0xeb, 0xe5, 0xa1, 0xe4, 0xac, 0xf })]
        [InlineData(new byte[] { 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF }, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, new byte[] { 0x7, 0x45, 0x19, 0x3f, 0x99, 0x2f, 0x6f, 0x7e, 0xa2, 0xfb, 0x7d, 0xdb, 0xa0, 0x82, 0x85, 0x71, 0xdc, 0xc9, 0x8c, 0xb5, 0x82, 0xdd, 0x5, 0xe1, 0xd0, 0x26, 0x57, 0x7a, 0x92, 0xb1, 0x56, 0x99 })]
        [Theory]
        public void ReferenceTest(byte[] key, byte[] info, byte[] expected)
        {
            HMac hmac = new HMac(new Digest());
            hmac.Init(key);
            hmac.Process(info);
            var output = hmac.Compute();

            var bcHmac = new Org.BouncyCastle.Crypto.Macs.HMac(new Sha256Digest());
            bcHmac.Init(new KeyParameter(key));
            bcHmac.BlockUpdate(info, 0, info.Length);
            byte[] bcoutput = new byte[bcHmac.GetMacSize()];
            int bcoutLen = bcHmac.DoFinal(bcoutput, 0);

            Assert.Equal(expected.Length, bcoutput.Length);
            Assert.Equal(expected, bcoutput);
            Assert.Equal(expected.Length, output.Length);
            Assert.Equal(expected, output);
        }
    }
}
