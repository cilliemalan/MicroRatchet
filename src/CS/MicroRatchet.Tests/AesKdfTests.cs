﻿using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace MicroRatchet.Tests
{
    public class AesKdfTests
    {
        private Random r = new Random();
        
        [Fact(DisplayName = "AESKDF works with all zero input")]
        public void BasicReferenceTest()
        {
            byte[] key = new byte[32];
            byte[] info = new byte[32];

            var derived = new AesKdf(Common.AesFactory).GenerateBytes(key, info, 32);
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
            key[0] = (byte)i; // just to get rid of a warning
            r.NextBytes(key);
            r.NextBytes(info);

            var derived = new AesKdf(Common.AesFactory).GenerateBytes(key, info, 32);
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

            var derived = new AesKdf(Common.AesFactory).GenerateBytes(key, info, outputLength);
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

            var derived = new AesKdf(Common.AesFactory).GenerateBytes(key, info, 32);
        }

        [Theory]
        [InlineData(new byte[] { 0x0b, 0x19, 0x3f, 0x99, 0x2f, 0xdc, 0xc9, 0x8c, 0xb5, 0x82, 0xdd, 0x05, 0xe1, 0xd0, 0x26, 0x99 }, new byte[] { 0x07, 0x45, 0x19, 0x3f, 0x99, 0x2f, 0x6f, 0x7e, 0xa2, 0xfb, 0x7d, 0xdb, 0xa0, 0x82, 0x85, 0x71, 0x07, 0x45, 0x19, 0x3f, 0x99, 0x2f, 0x6f, 0x7e, 0xa2, 0xfb, 0x7d, 0xdb, 0xa0, 0x82, 0x85, 0x71 }, new byte[] { 0xbe, 0x20, 0x74, 0x12, 0xd8, 0xe0, 0x6b, 0xe5 })]
        [InlineData(new byte[] { 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x07, 0x45, 0x19, 0x3f, 0x99, 0x2f, 0x6f, 0x7e, 0xa2, 0xfb, 0x7d, 0xdb, 0xa0, 0x82, 0x85, 0x71 }, new byte[] { 0xb2, 0x59, 0x65, 0x23, 0x3c, 0x91, 0x3c, 0x3d, 0xeb, 0x22, 0x2e, 0x79, 0x86, 0x68, 0x4c, 0xe6 }, new byte[] { 0xef, 0x1d, 0x15, 0xca, 0x50, 0xf5, 0x28, 0x83, 0xc4, 0xf9, 0xf2, 0x32, 0xfc, 0x4e, 0x8d, 0xd3 })]
        [InlineData(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, new byte[] { 0x5c, 0xf1, 0x91, 0x76, 0x25, 0xb1, 0x16, 0x5f })]
        [InlineData(new byte[] { 0x0a, 0x19, 0x3f, 0x99, 0x2f, 0xdc, 0xc9, 0x8c, 0xb5, 0x82, 0xdd, 0x05, 0xe1, 0xd0, 0x26, 0x99 }, new byte[] { 0x07, 0x45, 0x19, 0x3f }, new byte[] { 0x33, 0x8c, 0xd0, 0xfc, 0x25, 0x27, 0x24, 0x98 })]
        [InlineData(new byte[] { 0x07, 0x45, 0x19, 0x3f, 0x99, 0x2f, 0x6f, 0x7e, 0xa2, 0xfb, 0x7d, 0xdb, 0xa0, 0x82, 0x85, 0x71, 0xdc, 0xc9, 0x8c, 0xb5, 0x82, 0xdd, 0x05, 0xe1, 0xd0, 0x26, 0x57, 0x7a, 0x92, 0xb1, 0x56, 0x99 }, new byte[] { 0x07, 0x45, 0x19, 0x3f, 0x99, 0x2f, 0x6f, 0x7e, 0xa2, 0xfb, 0x7d, 0xdb, 0xa0, 0x82, 0x85, 0x71 }, new byte[] { 0xce, 0x3c, 0xa5, 0x38, 0xf5, 0xd6, 0x80, 0x8d })]
        [InlineData(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, new byte[] { 0x37, 0xe4, 0x95, 0xd0, 0x0e, 0x00, 0xdb, 0xed })]
        [InlineData(new byte[] { 0x07, 0x0a, 0x0b, 0x0c, 0x0d, 0x07, 0x45, 0x19, 0x3f, 0x99, 0x2f, 0x6f, 0x7e, 0xa2, 0xfb, 0x71 }, new byte[] { 0xb2, 0x59, 0x65, 0x23, 0x3c, 0x91, 0x3c, 0x3d, 0xeb, 0x22, 0x2e, 0x79, 0x86, 0x68, 0x4c, 0xe6 }, new byte[] { 0xa8, 0x76, 0x14, 0x7a, 0x94, 0x66, 0x0f, 0xa5, 0x1b, 0x80, 0xf9, 0x29, 0xe0, 0x98, 0x85, 0x38 })]
        [InlineData(new byte[] { 0x09, 0x19, 0x3f, 0x99, 0x2f, 0xdc, 0xc9, 0x8c, 0xb5, 0x82, 0xdd, 0x05, 0xe1, 0xd0, 0x26, 0x99 }, new byte[] { 0x07, 0x45, 0x19, 0x3f, 0x99, 0x2f, 0x6f, 0x7e, 0xa2, 0xfb, 0x7d, 0xdb, 0xa0, 0x82, 0x85, 0x71 }, new byte[] { 0x07, 0xab, 0xa0, 0x21, 0xc9, 0xd4, 0xd4, 0xce })]
        [InlineData(new byte[] { 0x08, 0x19, 0x3f, 0x99, 0x2f, 0xdc, 0xc9, 0x8c, 0xb5, 0x82, 0xdd, 0x05, 0xe1, 0xd0, 0x26, 0x99 }, new byte[] { 0x07, 0x45, 0x19, 0x3f, 0x99, 0x2f, 0x6f, 0x7e, 0xa2, 0xfb, 0x7d, 0xdb, 0xa0, 0x82, 0x85, 0x71 }, new byte[] { 0xa8, 0x64, 0x81, 0xde, 0x7e, 0x14, 0xd2, 0xe2 })]
        [InlineData(new byte[] { 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x07, 0x45, 0x19, 0x3f, 0x99, 0x2f, 0x6f, 0x7e, 0xa2, 0xfb, 0x71 }, new byte[] { 0xb2, 0x59, 0x65, 0x23, 0x3c, 0x91, 0x3c, 0x3d, 0xeb, 0x22, 0x2e, 0x79, 0x86, 0x68, 0x4c, 0xe6 }, new byte[] { 0x78, 0x88, 0x8f, 0xbd, 0x04, 0x44, 0xbf, 0x99, 0xfa, 0xf9, 0x56, 0x9a, 0x3f, 0x87, 0x41, 0xbe })]
        public void ReferenceTest(byte[] key, byte[] info, byte[] expected)
        {
            var output = new AesKdf(Common.AesFactory).GenerateBytes(key, info, expected.Length);

            Assert.Equal(expected, output);
        }
    }
}
