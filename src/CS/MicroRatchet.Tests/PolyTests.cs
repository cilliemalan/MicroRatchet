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
        [InlineData(320, 128)]
        [InlineData(32, 128)]
        [InlineData(64, 128)]
        [InlineData(32, 96)]
        [InlineData(64, 96)]
        [Theory]
        public void BasicPolyTests(int dataBytes, int macSize)
        {
            RandomNumberGenerator rng = new RandomNumberGenerator();
            byte[] key = rng.Generate(32);
            byte[] data = rng.Generate(dataBytes);

            Poly pmac = new Poly();
            pmac.Init(key, null, macSize);
            pmac.Process(new ArraySegment<byte>(data));
            byte[] mac = pmac.Compute();

            var bcpoly = new Org.BouncyCastle.Crypto.Macs.Poly1305();
            bcpoly.Init(new Org.BouncyCastle.Crypto.Parameters.KeyParameter(key));
            bcpoly.BlockUpdate(data, 0, data.Length);
            byte[] bcmac = new byte[bcpoly.GetMacSize()];
            bcpoly.DoFinal(bcmac, 0);
            bcmac = bcmac.Take(macSize / 8).ToArray();

            Assert.Equal(bcmac, mac);
        }

        [Fact]
        public void PolyReuseKeyTest()
        {
            RandomNumberGenerator rng = new RandomNumberGenerator();
            byte[] key = rng.Generate(32);
            byte[] data1 = rng.Generate(64);
            byte[] data2 = rng.Generate(64);

            var pmac = new Poly();
            pmac.Init(key, null, 96);
            pmac.Process(new ArraySegment<byte>(data1));
            byte[] mac1 = pmac.Compute();
            pmac.Init(key, null, 96);
            pmac.Process(new ArraySegment<byte>(data2));
            byte[] mac2 = pmac.Compute();

            var bcpoly1 = new Org.BouncyCastle.Crypto.Macs.Poly1305();
            bcpoly1.Init(new Org.BouncyCastle.Crypto.Parameters.KeyParameter(key));
            bcpoly1.BlockUpdate(data1, 0, data1.Length);
            byte[] bcmac1 = new byte[bcpoly1.GetMacSize()];
            bcpoly1.DoFinal(bcmac1, 0);
            bcmac1 = bcmac1.Take(96 / 8).ToArray();

            var bcpoly2 = new Org.BouncyCastle.Crypto.Macs.Poly1305();
            bcpoly2.Init(new Org.BouncyCastle.Crypto.Parameters.KeyParameter(key));
            bcpoly2.BlockUpdate(data2, 0, data2.Length);
            byte[] bcmac2 = new byte[bcpoly2.GetMacSize()];
            bcpoly2.DoFinal(bcmac2, 0);
            bcmac2 = bcmac2.Take(96 / 8).ToArray();

            Assert.Equal(bcmac1, mac1);
            Assert.Equal(bcmac2, mac2);
        }

        [InlineData(new byte[] { 0x04, 0x91, 0x6c, 0x08, 0x09, 0x31, 0x03, 0x04, 0x05, 0x07, 0x08, 0x0c, 0x0d, 0x0f, 0x07, 0x08, 0x91, 0x6c, 0x31, 0x88, 0x0b, 0x02, 0x03, 0x04, 0x05, 0x07, 0x08, 0x07, 0x66, 0x4b, 0x07, 0x08 }, new byte[] { 0x00 }, new byte[] { 0x9b, 0x70, 0xc2, 0xf4, 0x13, 0x0a, 0x34, 0x07, 0x09, 0x0b, 0x0f, 0x0f, 0x72, 0x57, 0x16, 0x0f })]
        [InlineData(new byte[] { 0x88, 0x0b, 0x0d, 0xfe, 0x91, 0x6c, 0x66, 0xd7, 0x4b, 0x07, 0x08, 0x09, 0xfe, 0x91, 0x6c, 0x31, 0x88, 0x0b, 0x02, 0x03, 0x04, 0x05, 0x07, 0x08, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x0d, 0x6c, 0x31 }, new byte[] { 0xd7, 0x08, 0x09, 0x08, 0x09, 0x08, 0x09, 0x6c }, new byte[] { 0xc1, 0x35, 0x43, 0x8c, 0x94, 0x48, 0x13, 0x75, 0x1f, 0x3d, 0xd3, 0x81, 0x30, 0x80, 0xdf, 0x07 })]
        [InlineData(new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x6c, 0x66, 0xd7, 0x0c, 0x0d, 0x66, 0xd7, 0x4b, 0x07, 0x08, 0x09, 0xfe, 0x04, 0x91, 0x6c, 0x08, 0x09, 0x0a, 0x31, 0x88, 0x0b, 0x0d, 0x04 }, new byte[] { 0x6c, 0x31, 0x88, 0x0b, 0x02, 0x07, 0x08, 0x6c, 0x66, 0x6c, 0x08, 0x09, 0x0a, 0x31, 0x88, 0x0b, 0x02, 0xfe, 0x04, 0x91, 0x6c, 0x08, 0xd7, 0x0c, 0x0d, 0x66 }, new byte[] { 0xd4, 0xa4, 0x13, 0xed, 0xa4, 0x5f, 0xac, 0x6b, 0x0a, 0xa1, 0x3f, 0xa7, 0x94, 0xa1, 0x26, 0x80 })]
        [Theory]
        public void PolyReferenceTests(byte[] key, byte[] data, byte[] expected)
        {
            Poly pmac = new Poly();
            pmac.Init(key, null, 128);
            pmac.Process(new ArraySegment<byte>(data));
            byte[] mac = pmac.Compute();

            var bcpoly = new Org.BouncyCastle.Crypto.Macs.Poly1305();
            bcpoly.Init(new Org.BouncyCastle.Crypto.Parameters.KeyParameter(key));
            bcpoly.BlockUpdate(data, 0, data.Length);
            byte[] bcmac = new byte[bcpoly.GetMacSize()];
            bcpoly.DoFinal(bcmac, 0);

            Assert.Equal(expected, mac);
            Assert.Equal(expected, bcmac);

        }
    }
}
