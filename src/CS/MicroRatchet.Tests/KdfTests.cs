﻿using Org.BouncyCastle.Crypto.Digests;
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

        [InlineData(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20 }, new byte[] { 0x01, 0x02, 0x03, 0x04, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 }, new byte[] { 0x34, 0x1b, 0x91, 0x41, 0x2e, 0xc0, 0xad, 0x16, 0x74, 0x85, 0xea, 0x9f, 0x61, 0x4f, 0x0f, 0x92, 0x95, 0x73, 0xd8, 0x19, 0xc5, 0x0b, 0x05, 0xb5, 0x0c, 0xad, 0xb5, 0xf7, 0xbf, 0x52, 0xe9, 0x1a })]
        [InlineData(new byte[] { 0x01, 0x02, 0x03, 0x04 }, new byte[] { 0x01, 0x02, 0x03, 0x04, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 }, new byte[] { 0xd6, 0x6a, 0x19, 0xaf, 0x4f, 0x4a, 0x04, 0x18, 0xe2, 0x06, 0x13, 0x90, 0x4c, 0x27, 0x2c, 0x70, 0x76, 0x94, 0x0f, 0x26, 0x09, 0x4a, 0x2f, 0xfd, 0x88, 0x04, 0x14, 0x9a, 0x38, 0x54, 0x29, 0x7c })]
        [InlineData(new byte[] { }, new byte[] { }, new byte[] { 0x3d, 0x7a, 0xfb, 0x66, 0x31, 0x24, 0xec, 0xbf, 0x2c, 0x95, 0x3f, 0x86, 0x3d, 0x4f, 0xc8, 0x79, 0x6e, 0xeb, 0x2d, 0x37, 0x2b, 0x64, 0xaa, 0xd5, 0x86, 0x97, 0xec, 0x52, 0x64, 0x64, 0x9c, 0xdb })]
        [InlineData(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 }, new byte[] { 0x05, 0x06, 0x07, 0x08 }, new byte[] { 0x7e, 0xa3, 0xfb, 0xf9, 0xd1, 0x9e, 0x72, 0xa0, 0x01, 0x96, 0xfb, 0x26, 0x2c, 0x60, 0xc7, 0xe8, 0x00, 0xcb, 0x37, 0x7d, 0x0e, 0xb5, 0xe8, 0x20, 0x0a, 0xf0, 0xd1, 0x45, 0x1b, 0x0b, 0x62, 0xbb })]
        [InlineData(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40 }, new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40 }, new byte[] { 0xda, 0xa0, 0x48, 0x0a, 0x9e, 0x09, 0xd0, 0x1f, 0xe4, 0xce, 0x5f, 0xb7, 0x3f, 0x83, 0x1f, 0xdc, 0x8a, 0x7c, 0xc4, 0xa2, 0x40, 0x4a, 0xc8, 0x1a, 0xe2, 0xc3, 0xb8, 0xd2, 0x24, 0x9a, 0x80, 0x79 })]
        [InlineData(new byte[] { 0x01, 0x02, 0x03, 0x04 }, new byte[] { 0x05, 0x06, 0x07, 0x08 }, new byte[] { 0xd7, 0xc4, 0x0d, 0x1d, 0xa2, 0x4e, 0xf2, 0xde, 0x6d, 0xc9, 0xa8, 0x9f, 0x08, 0xc0, 0x82, 0xda, 0x74, 0xe8, 0xd5, 0x98, 0xc7, 0x9a, 0x7d, 0xe5, 0x6e, 0xef, 0xa2, 0x45, 0x57, 0xa7, 0x9f, 0x02, 0x81, 0x5b, 0xc7, 0xe8, 0xfa, 0x81, 0x60, 0xff, 0x00, 0x4e, 0x38, 0xc6, 0xbb, 0x0f, 0xdb, 0x89, 0x22, 0xd4, 0x99, 0x43, 0xc3, 0x61, 0xda, 0x20, 0xf8, 0x13, 0x08, 0x17, 0x8d, 0x7c, 0xd2, 0x10 })]
        [InlineData(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 }, new byte[] { 0x01, 0x02, 0x03, 0x04, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 }, new byte[] { 0x0e, 0xe5, 0x7b, 0x8b, 0x94, 0x5b, 0xd2, 0xd4, 0x8e, 0x22, 0x8d, 0xfc, 0x48, 0xea, 0x07, 0x3c, 0x86, 0xac, 0x64, 0x4b, 0xc8, 0xdd, 0x7f, 0x4b, 0x3d, 0xa2, 0x16, 0x04, 0x51, 0x31, 0xa7, 0xfa })]
        [InlineData(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40 }, new byte[] { 0x05, 0x06, 0x07, 0x08 }, new byte[] { 0x04, 0x77, 0xbb, 0x00, 0x2d, 0x60, 0x66, 0xaf, 0x71, 0x99, 0xca, 0x3f, 0x9c, 0x37, 0x84, 0x6c, 0xef, 0xb0, 0x52, 0xe9, 0x26, 0x2f, 0xc1, 0xc8, 0xde, 0x0b, 0x87, 0x3c, 0xf5, 0xc5, 0x2a, 0x82 })]
        [InlineData(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20 }, new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40 }, new byte[] { 0x04, 0x90, 0x92, 0xef, 0x27, 0x57, 0x51, 0xe9, 0x92, 0xe6, 0xd6, 0x2c, 0x44, 0xee, 0x90, 0xfd, 0xe6, 0x28, 0xb9, 0x6c, 0x43, 0x2d, 0x88, 0xff, 0x02, 0xa8, 0x4c, 0x9a, 0x29, 0x7c, 0x98, 0x25 })]
        [InlineData(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20 }, new byte[] { 0x05, 0x06, 0x07, 0x08 }, new byte[] { 0x48, 0xad, 0xd1, 0xcb, 0xc6, 0xf3, 0xb1, 0x3f, 0x12, 0x98, 0x77, 0x05, 0x31, 0xa0, 0x00, 0x69, 0xdc, 0xb8, 0xbf, 0x2f, 0xe8, 0xfb, 0xf5, 0x49, 0xae, 0x59, 0xef, 0x6f, 0xcc, 0xdc, 0x1a, 0xbc })]
        [InlineData(new byte[] { 0x01, 0x02, 0x03, 0x04 }, new byte[] { 0x05, 0x06, 0x07, 0x08 }, new byte[] { 0xd7, 0xc4, 0x0d, 0x1d, 0xa2, 0x4e, 0xf2, 0xde, 0x6d, 0xc9, 0xa8, 0x9f, 0x08, 0xc0, 0x82, 0xda, 0x74, 0xe8, 0xd5, 0x98, 0xc7, 0x9a, 0x7d, 0xe5, 0x6e, 0xef, 0xa2, 0x45, 0x57, 0xa7, 0x9f, 0x02, 0x81, 0x5b, 0xc7, 0xe8, 0xfa, 0x81, 0x60, 0xff, 0x00, 0x4e, 0x38, 0xc6, 0xbb, 0x0f, 0xdb, 0x89, 0x22, 0xd4, 0x99, 0x43, 0xc3, 0x61, 0xda, 0x20, 0xf8, 0x13, 0x08, 0x17, 0x8d, 0x7c, 0xd2, 0x10, 0x29, 0x55, 0x86, 0x72, 0xaa, 0x20, 0x00, 0x65, 0x4a, 0xb9, 0x73, 0x45, 0xad, 0xc5, 0x49, 0xd3, 0xb6, 0xd6, 0x8d, 0x5e, 0x57, 0x1f, 0x9a, 0xd1, 0x8d, 0xbf, 0x20, 0xf0, 0xe5, 0x8a, 0x88, 0xb6, 0x82, 0x88, 0xcb, 0x0a, 0x8b, 0x97, 0x84, 0xaa, 0x74, 0xc0, 0xd5, 0xfb, 0x18, 0x02, 0x3a, 0xaf, 0x9d, 0x3c, 0x25, 0x84, 0xa8, 0xe7, 0xeb, 0xd3, 0x87, 0xed, 0x42, 0xef, 0x5a, 0x53, 0x80, 0x11 })]
        [InlineData(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40 }, new byte[] { 0x01, 0x02, 0x03, 0x04, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 }, new byte[] { 0x6d, 0xc4, 0xf0, 0x8a, 0x01, 0x7b, 0x5e, 0x1d, 0xa8, 0xf1, 0x30, 0x41, 0x30, 0xbe, 0xf9, 0xff, 0x64, 0xbc, 0x04, 0x82, 0x88, 0x36, 0x05, 0x6a, 0x63, 0x48, 0x94, 0x5c, 0xa8, 0xda, 0x60, 0x67 })]
        [InlineData(new byte[] { 0x01, 0x02, 0x03, 0x04 }, new byte[] { 0x05, 0x06, 0x07, 0x08 }, new byte[] { 0xd7, 0xc4, 0x0d, 0x1d, 0xa2, 0x4e, 0xf2, 0xde, 0x6d, 0xc9, 0xa8, 0x9f, 0x08, 0xc0, 0x82, 0xda, 0x74, 0xe8, 0xd5, 0x98, 0xc7, 0x9a, 0x7d, 0xe5, 0x6e, 0xef, 0xa2, 0x45, 0x57, 0xa7, 0x9f, 0x02 })]
        [InlineData(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 }, new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40 }, new byte[] { 0xff, 0x70, 0xb3, 0x2f, 0xad, 0x2b, 0xc8, 0xb3, 0x52, 0x8b, 0x83, 0x11, 0x5e, 0xd4, 0xf4, 0xe6, 0x8a, 0xde, 0xae, 0x27, 0x33, 0xaf, 0xb0, 0xdb, 0x94, 0x9a, 0x02, 0xa7, 0x52, 0x09, 0x0e, 0xe7 })]
        [InlineData(new byte[] { 0x01, 0x02, 0x03, 0x04 }, new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40 }, new byte[] { 0x83, 0x32, 0xf2, 0x54, 0x72, 0x25, 0xd5, 0x09, 0x54, 0x52, 0x9f, 0xc6, 0x9f, 0x39, 0xaa, 0xc7, 0xd4, 0x24, 0x8b, 0x40, 0x2b, 0x39, 0x15, 0x4c, 0x27, 0xa4, 0x3b, 0xec, 0xba, 0x1d, 0xed, 0xa6 })]
        [Theory]
        public void ReferenceTest(byte[] key, byte[] info, byte[] expected)
        {
            var derived = new KeyDerivation(new Digest()).GenerateBytes(key, info, expected.Length);
            Assert.Equal(expected, derived);
        }
    }
}
