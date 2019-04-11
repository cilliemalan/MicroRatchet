using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using Xunit;

namespace MicroRatchet.Tests
{
    public class PolyTests
    {
        [InlineData(16, 320, 128)]
        [InlineData(16, 32, 128)]
        [InlineData(16, 64, 128)]
        [InlineData(16, 32, 96)]
        [InlineData(16, 64, 96)]
        [InlineData(16, 80, 96)]
        [InlineData(16, 1, 128)]
        [InlineData(16, 2, 128)]
        [InlineData(16, 3, 128)]
        [InlineData(16, 4, 128)]
        [InlineData(16, 5, 128)]
        [InlineData(16, 8, 128)]
        [InlineData(16, 9, 128)]
        [InlineData(16, 16, 128)]
        [InlineData(16, 16, 96)]
        [InlineData(16, 13, 128)]
        [InlineData(16, 13, 96)]
        [Theory]
        public void BasicPolyTests(int ivBytes, int dataBytes, int macSize)
        {
            RandomNumberGenerator rng = new RandomNumberGenerator();
            byte[] iv = rng.Generate(ivBytes);
            byte[] key = rng.Generate(32);
            byte[] data = rng.Generate(dataBytes);

            Poly pmac = new Poly(Common.AesFactory);
            var bcpoly = new Poly1305(new AesEngine());
            pmac.Init(key, iv, macSize);
            bcpoly.Init(new ParametersWithIV(new KeyParameter(key), iv));
            pmac.Process(new ArraySegment<byte>(data));
            byte[] mac = pmac.Compute();

            bcpoly.BlockUpdate(data, 0, data.Length);
            byte[] bcmac = new byte[bcpoly.GetMacSize()];
            bcpoly.DoFinal(bcmac, 0);
            bcmac = bcmac.Take(macSize / 8).ToArray();

            Assert.Equal(bcmac, mac);
        }

        [InlineData(16, 320, 128)]
        [InlineData(16, 32, 128)]
        [InlineData(16, 64, 128)]
        [InlineData(16, 32, 96)]
        [InlineData(16, 64, 96)]
        [InlineData(16, 80, 96)]
        [InlineData(16, 1, 128)]
        [InlineData(16, 2, 128)]
        [InlineData(16, 3, 128)]
        [InlineData(16, 4, 128)]
        [InlineData(16, 5, 128)]
        [InlineData(16, 8, 128)]
        [InlineData(16, 9, 128)]
        [InlineData(16, 16, 128)]
        [InlineData(16, 16, 96)]
        [InlineData(16, 13, 128)]
        [InlineData(16, 13, 96)]
        [Theory]
        public void PolyReuseKeyTest(int ivBytes, int dataBytes, int macSize)
        {
            RandomNumberGenerator rng = new RandomNumberGenerator();
            byte[] iv = rng.Generate(ivBytes);
            byte[] key = rng.Generate(32);
            byte[] data1 = rng.Generate(dataBytes);
            byte[] data2 = rng.Generate(dataBytes);

            var pmac = new Poly(Common.AesFactory);
            pmac.Init(key, iv, macSize);
            pmac.Process(new ArraySegment<byte>(data1));
            byte[] mac1 = pmac.Compute();
            pmac.Init(key, iv, macSize);
            pmac.Process(new ArraySegment<byte>(data2));
            byte[] mac2 = pmac.Compute();

            var bcpoly1 = new Poly1305(new AesEngine());
            bcpoly1.Init(new ParametersWithIV(new KeyParameter(key), iv));
            bcpoly1.BlockUpdate(data1, 0, data1.Length);
            byte[] bcmac1 = new byte[bcpoly1.GetMacSize()];
            bcpoly1.DoFinal(bcmac1, 0);
            bcmac1 = bcmac1.Take(macSize / 8).ToArray();

            var bcpoly2 = new Poly1305(new AesEngine());
            bcpoly2.Init(new ParametersWithIV(new KeyParameter(key), iv));
            bcpoly2.BlockUpdate(data2, 0, data2.Length);
            byte[] bcmac2 = new byte[bcpoly2.GetMacSize()];
            bcpoly2.DoFinal(bcmac2, 0);
            bcmac2 = bcmac2.Take(macSize / 8).ToArray();

            Assert.Equal(bcmac1, mac1);
            Assert.Equal(bcmac2, mac2);
        }

        [Fact]
        public void PolyMultiTest()
        {
            RandomNumberGenerator rng = new RandomNumberGenerator();
            byte[] iv = rng.Generate(16);
            byte[] key = rng.Generate(32);
            byte[] data = rng.Generate(100);

            Poly pmac = new Poly(Common.AesFactory);
            pmac.Init(key, iv, 128);
            pmac.Process(new ArraySegment<byte>(data));
            byte[] mac1 = pmac.Compute();

            pmac = new Poly(Common.AesFactory);
            pmac.Init(key, iv, 128);
            pmac.Process(new ArraySegment<byte>(data, 0, 50));
            pmac.Process(new ArraySegment<byte>(data, 50, 50));
            byte[] mac2 = pmac.Compute();

            pmac = new Poly(Common.AesFactory);
            pmac.Init(key, iv, 128);
            pmac.Process(new ArraySegment<byte>(data, 0, 33));
            pmac.Process(new ArraySegment<byte>(data, 33, 33));
            pmac.Process(new ArraySegment<byte>(data, 66, 34));
            byte[] mac3 = pmac.Compute();
            
            Assert.Equal(mac1, mac2);
            Assert.Equal(mac1, mac3);
        }

        [InlineData(new byte[] { 0x88, 0x0b, 0x0d, 0xfe, 0x91, 0x6c, 0x66, 0xd7, 0x4b, 0x07, 0x08, 0x09, 0xfe, 0x91, 0x6c, 0x31, 0x88, 0x0b, 0x02, 0x03, 0x04, 0x05, 0x07, 0x08, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x0d, 0x6c, 0x31 }, new byte[] { 0x02, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 }, new byte[] { 0xd7, 0x08, 0x09, 0x08, 0x09, 0x08, 0x09, 0x6c }, new byte[] { 0xaa, 0xdf, 0xb0, 0xcc, 0x2f, 0xd6, 0xd8, 0x1a, 0x24, 0x77, 0x84, 0x2c, 0x9a, 0x3b, 0x34, 0x97 })]
        [InlineData(new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x6c, 0x66, 0xd7, 0x0c, 0x0d, 0x66, 0xd7, 0x4b, 0x07, 0x08, 0x09, 0xfe, 0x04, 0x91, 0x6c, 0x08, 0x09, 0x0a, 0x31, 0x88, 0x0b, 0x0d, 0x04 }, new byte[] { 0x03, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 }, new byte[] { 0x6c, 0x31, 0x88, 0x0b, 0x02, 0x07, 0x08, 0x6c, 0x66, 0x6c, 0x08, 0x09, 0x0a, 0x31, 0x88, 0x0b, 0x02, 0xfe, 0x04, 0x91, 0x6c, 0x08, 0xd7, 0x0c, 0x0d, 0x66 }, new byte[] { 0xc5, 0xe3, 0x07, 0x75, 0xf6, 0x86, 0x67, 0xd7, 0x62, 0xdb, 0x9b, 0x7f, 0x09, 0x1c, 0xa3, 0x87 })]
        [InlineData(new byte[] { 0x04, 0x91, 0x6c, 0x08, 0x09, 0x31, 0x03, 0x04, 0x05, 0x07, 0x08, 0x0c, 0x0d, 0x0f, 0x07, 0x08, 0x91, 0x6c, 0x31, 0x88, 0x0b, 0x02, 0x03, 0x04, 0x05, 0x07, 0x08, 0x07, 0x66, 0x4b, 0x07, 0x08 }, new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 }, new byte[] { 0x00 }, new byte[] { 0x0b, 0x49, 0x88, 0x1f, 0x31, 0x17, 0x1f, 0x1c, 0xbf, 0xb3, 0x59, 0x70, 0xea, 0x1d, 0x95, 0x20 })]
        [Theory]
        public void PolyReferenceTests(byte[] key, byte[] iv, byte[] data, byte[] expected)
        {
            Poly pmac = new Poly(Common.AesFactory);
            pmac.Init(key, iv, 128);
            pmac.Process(new ArraySegment<byte>(data));
            byte[] mac = pmac.Compute();

            var bcpoly = new Poly1305(new AesEngine());
            bcpoly.Init(new ParametersWithIV(new KeyParameter(key), iv));
            bcpoly.BlockUpdate(data, 0, data.Length);
            byte[] bcmac = new byte[bcpoly.GetMacSize()];
            bcpoly.DoFinal(bcmac, 0);

            var _key = string.Join(", ", key.Select(b => $"0x{b:x2}"));
            var _iv = string.Join(", ", iv.Select(b => $"0x{b:x2}"));
            var _data = string.Join(", ", data.Select(b => $"0x{b:x2}"));
            var _expected = string.Join(", ", bcmac.Select(b => $"0x{b:x2}"));
            Log.Verbose($"[InlineData(new byte[] {{{_key}}}, new byte[] {{{_iv}}}, new byte[] {{{_data}}}, new byte[] {{{_expected}}})]");
            
            Assert.Equal(expected, mac);
            Assert.Equal(expected, bcmac);
        }
    }
}
