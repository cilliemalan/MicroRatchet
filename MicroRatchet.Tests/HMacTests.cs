using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
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
    }
}
