﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using Xunit;

namespace MicroRatchet.Tests
{
    public class ModulatingCipherTests
    {
        [InlineData(16, 16, 16)]
        [InlineData(32, 16, 16)]
        [InlineData(16, 32, 16)]
        [InlineData(32, 32, 16)]
        [InlineData(16, 8, 16)]
        [InlineData(32, 8, 16)]
        [InlineData(16, 16, 160)]
        [InlineData(32, 16, 160)]
        [InlineData(16, 16, 1024)]
        [InlineData(32, 16, 1024)]
        [InlineData(16, 16, 1024 * 1024)]
        [InlineData(32, 16, 1024 * 1024)]
        [Theory]
        public void BasicTest(int keySize, int ivSize, int dataSize)
        {
            var r = new Random();
            byte[] iv = new byte[ivSize];
            byte[] key = new byte[keySize];
            byte[] data = new byte[dataSize];
            byte[] encrypted1 = new byte[dataSize];
            byte[] decrypted1 = new byte[dataSize];
            byte[] encrypted2 = new byte[dataSize];
            byte[] decrypted2 = new byte[dataSize];
            r.NextBytes(iv);
            r.NextBytes(key);
            r.NextBytes(data);

            ModulatingCipher cipher = new ModulatingCipher();
            cipher.Initialize(key, iv);

            cipher.Process(0, data, encrypted1);
            cipher.Process(0, encrypted1, decrypted1);
            cipher.Process(1, data, encrypted2);
            cipher.Process(1, encrypted2, decrypted2);

            Assert.Equal(data, decrypted1);
            Assert.Equal(data, decrypted2);
            Assert.NotEqual(data, encrypted1);
            Assert.NotEqual(data, encrypted2);
            Assert.NotEqual(encrypted1, encrypted2);
        }

        [InlineData(16, 16, 16)]
        [InlineData(32, 16, 16)]
        [InlineData(16, 32, 16)]
        [InlineData(32, 32, 16)]
        [InlineData(16, 8, 16)]
        [InlineData(32, 8, 16)]
        [InlineData(16, 16, 160)]
        [InlineData(32, 16, 160)]
        [InlineData(16, 16, 1024)]
        [InlineData(32, 16, 1024)]
        [Theory]
        public void ArbitraryGenerationTest(int keySize, int ivSize, int dataSize)
        {
            var r = new Random();
            byte[] iv = new byte[ivSize];
            byte[] key = new byte[keySize];
            byte[] data = new byte[dataSize];
            byte[] encrypted1 = new byte[dataSize];
            byte[] decrypted1 = new byte[dataSize];
            byte[] encrypted2 = new byte[dataSize];
            byte[] decrypted2 = new byte[dataSize];
            r.NextBytes(iv);
            r.NextBytes(key);
            r.NextBytes(data);
            uint g1 = (uint)r.Next();
            uint g2 = (uint)r.Next();

            ModulatingCipher cipher = new ModulatingCipher();
            cipher.Initialize(key, iv);

            cipher.Process(g1, data, encrypted1);
            cipher.Process(g1, encrypted1, decrypted1);
            cipher.Process(g2, data, encrypted2);
            cipher.Process(g2, encrypted2, decrypted2);

            Assert.Equal(data, decrypted1);
            Assert.Equal(data, decrypted2);
            Assert.NotEqual(data, encrypted1);
            Assert.NotEqual(data, encrypted2);
            Assert.NotEqual(encrypted1, encrypted2);
        }

        [Theory]
        [InlineData(new byte[] { 0x39, 0x7b, 0xe9, 0x5a, 0x12, 0x2e, 0xfb, 0x21, 0xc4, 0xe3, 0xf9, 0x0c, 0x3d, 0xc5, 0xee, 0xba, 0x3d, 0x91, 0xed, 0xef, 0x18, 0xb6, 0x75, 0xe9, 0xb9, 0x22, 0x1c, 0xc8, 0x34, 0xd7, 0xcb, 0x97 }, new byte[] { 0x9e, 0x34, 0xae, 0xf5, 0x0b, 0xa3, 0xfd, 0x90, 0x36, 0xfc, 0x4c, 0x86, 0xc2, 0xa1, 0x2d }, (uint)3173162193, new byte[] { 0xca, 0xff, 0x39, 0x69, 0x58, 0xde, 0x91, 0x56, 0x1b, 0x47, 0x75, 0xdd, 0x05, 0xa7, 0x4d, 0xfd, 0xa8, 0x49, 0xa1, 0x1a, 0x66, 0xb7, 0x7b, 0x96, 0x4e, 0x7d, 0x4a, 0xa5, 0xe0, 0xc9, 0x57, 0x96, 0x0b }, new byte[] { 0xa6, 0x8f, 0x7a, 0x1f, 0x0b, 0xb6, 0x07, 0x14, 0xee, 0xf1, 0x6b, 0x64, 0x04, 0x7d, 0x39, 0x3d, 0x69, 0xd4, 0x63, 0xc1, 0xe0, 0x6b, 0xbc, 0x03, 0x03, 0x40, 0xd2, 0x46, 0x9f, 0xf7, 0x6f, 0xd3, 0x31 })]
        [InlineData(new byte[] { 0x1c, 0xca, 0x08, 0x90, 0x52, 0x85, 0xab, 0x98, 0x6e, 0x29, 0x8f, 0xdc, 0x8d, 0xfe, 0x33, 0x18, 0x02, 0xec, 0x6d, 0x13, 0x3d, 0xb7, 0x7f, 0x13, 0xb0, 0x15, 0xaf, 0xc0, 0x17, 0x4a, 0xc2, 0xc0 }, new byte[] { 0xb6, 0xa5, 0xc8, 0xdb, 0xaf }, (uint)931433447, new byte[] { 0x3c, 0xca, 0xd3, 0xb5, 0xa9, 0x55, 0xed, 0x20, 0x59, 0x17, 0xb2, 0x87, 0x19, 0x40, 0x1f, 0x84 }, new byte[] { 0x15, 0xd8, 0xe3, 0x89, 0xe9, 0x9c, 0xd8, 0xa3, 0xb2, 0x97, 0x3e, 0xd7, 0x7c, 0xe6, 0xad, 0x39 })]
        [InlineData(new byte[] { 0x97, 0x82, 0x62, 0x0c, 0x07, 0x38, 0xfe, 0xd9, 0x78, 0x49, 0x7f, 0x33, 0x53, 0xae, 0xe1, 0xb8 }, new byte[] { 0x36, 0xf8, 0x00, 0x03, 0x1d }, (uint)3967114010, new byte[] { 0x0c, 0xd6, 0x54, 0x81, 0x7f, 0x4c, 0xbd, 0x68, 0xb3, 0xc5, 0xde, 0xa6, 0x37, 0x2a, 0x28, 0x11 }, new byte[] { 0xb2, 0xdd, 0x50, 0x7d, 0xb1, 0x95, 0x4d, 0xe6, 0x73, 0x7f, 0x32, 0x28, 0x5a, 0x27, 0xaa, 0xcf })]
        [InlineData(new byte[] { 0xd9, 0x6e, 0xcd, 0x7c, 0xad, 0xad, 0x13, 0xcd, 0x1b, 0xae, 0xc8, 0x7f, 0xe7, 0x86, 0xe9, 0x2d }, new byte[] { 0x27, 0x17, 0x8b, 0x97, 0x1e, 0xbe, 0xfe, 0x3c, 0xf1, 0x72, 0x88, 0xc5, 0x94, 0x7c, 0x74 }, (uint)3191842719, new byte[] { 0x53, 0xfb, 0x9f, 0x3f, 0xf2, 0x7d, 0x0c, 0x40, 0x44, 0xe5, 0x7a, 0x9e, 0x4a, 0x54, 0x35, 0x45 }, new byte[] { 0x31, 0xd0, 0x86, 0x45, 0xd4, 0x3f, 0x53, 0x22, 0xc9, 0xfe, 0x88, 0x5e, 0x5f, 0x80, 0x02, 0xc5 })]
        [InlineData(new byte[] { 0xf5, 0xfa, 0xa1, 0x1c, 0x4e, 0x42, 0x49, 0x68, 0x6c, 0xb7, 0x86, 0xf3, 0x5b, 0xda, 0x5e, 0x0f }, new byte[] { 0xef, 0xb6, 0x6a, 0x85, 0x37, 0xd2, 0xb4, 0xab, 0xee, 0x37, 0x5c, 0x9b, 0x9f, 0x28, 0x6d, 0xd3 }, (uint)388854445, new byte[] { 0x78, 0xbd, 0x09, 0x82, 0x29, 0xea, 0xe2, 0xdf, 0x76, 0xfc, 0xa0, 0xb6, 0x8c, 0x4e, 0x7f, 0xaa }, new byte[] { 0x7c, 0x40, 0x4e, 0x03, 0x29, 0x1e, 0x7c, 0x81, 0xfd, 0x76, 0x10, 0x08, 0x50, 0x92, 0x20, 0x8a })]
        [InlineData(new byte[] { 0xbf, 0xc2, 0x48, 0x42, 0x0d, 0xce, 0x6c, 0x79, 0xd7, 0x70, 0x0b, 0x70, 0xd5, 0xfc, 0x25, 0x11, 0xe9, 0x33, 0xfb, 0x71, 0x6b, 0x57, 0x7a, 0x86, 0xf4, 0x9d, 0xa6, 0xda, 0x5b, 0x38, 0x9a, 0xb4 }, new byte[] { 0xd7, 0x77, 0xb0, 0xc2, 0x52, 0x7e, 0x99, 0x60, 0x20, 0x3a, 0x00, 0x53, 0x49, 0x3a, 0x30, 0x0d }, (uint)725153228, new byte[] { 0xe0, 0x20, 0x6a, 0xd9, 0x05, 0xc8, 0x62, 0x33, 0x63, 0xdd, 0xd9, 0x8e, 0x5e, 0x84, 0xa1, 0xd6 }, new byte[] { 0xfe, 0xdd, 0x43, 0x8e, 0x8e, 0x13, 0x39, 0x0d, 0x66, 0x77, 0xfc, 0x7d, 0x3d, 0x98, 0x92, 0x94 })]
        [InlineData(new byte[] { 0x85, 0x9d, 0xd6, 0xf8, 0xe9, 0x03, 0x20, 0x7a, 0xc3, 0xb7, 0x00, 0x30, 0x88, 0x80, 0x56, 0x63 }, new byte[] { 0x84, 0x3e, 0xee, 0x8f, 0xf3 }, (uint)1770159958, new byte[] { 0xbd, 0x06, 0xba, 0x68, 0x89, 0xda, 0xc1, 0xec, 0x85, 0x15, 0x1d, 0xf2, 0x57, 0xb5, 0xa7, 0xcc, 0xa0, 0x05, 0x5e, 0x45, 0x05, 0x5c, 0x27, 0x85, 0xd2, 0xc3, 0x06, 0x79, 0x9b, 0x00, 0x41, 0xd2, 0x96 }, new byte[] { 0x1e, 0xa0, 0x4b, 0xe2, 0xa7, 0xab, 0x73, 0xe6, 0xbb, 0xe6, 0x65, 0x23, 0xf1, 0x45, 0xfe, 0x2e, 0x23, 0x40, 0x6b, 0x9e, 0x6e, 0xb8, 0x79, 0xdb, 0x66, 0xd3, 0x7c, 0x53, 0xe4, 0xb7, 0xa8, 0x47, 0x15 })]
        [InlineData(new byte[] { 0xf7, 0xa2, 0xba, 0x46, 0x93, 0x94, 0xad, 0x7e, 0xbe, 0x0a, 0x25, 0x3b, 0x67, 0xb5, 0xc3, 0x71, 0x75, 0x83, 0x91, 0xa0, 0x36, 0xd1, 0xdb, 0x42, 0x34, 0x1b, 0x98, 0xd6, 0xca, 0x6a, 0x71, 0x10 }, new byte[] { 0xa2, 0x53, 0x9c, 0x5f, 0x34 }, (uint)3919656388, new byte[] { 0xfc, 0xb6, 0xc3, 0x24, 0x15, 0x86, 0xfb, 0x8f, 0xe7, 0x63, 0xfd, 0x87, 0xaf, 0x09, 0x90, 0x50, 0x9c, 0xf3, 0x5c, 0xcd, 0x98, 0xd2, 0x59, 0xdf, 0xfb, 0xe7, 0x30, 0x3e, 0x85, 0x1d, 0x5c, 0x3a, 0x47 }, new byte[] { 0x18, 0x44, 0xb1, 0x5f, 0xa2, 0xec, 0x96, 0x24, 0x49, 0xcf, 0xaf, 0x62, 0xa2, 0x2f, 0x8e, 0x4c, 0x6a, 0xa4, 0x3f, 0x7b, 0xde, 0x8b, 0x10, 0x74, 0x64, 0x89, 0x70, 0xc3, 0x23, 0x9d, 0x51, 0x96, 0xeb })]
        [InlineData(new byte[] { 0x40, 0x85, 0x7f, 0x3c, 0xc8, 0x67, 0x8c, 0x31, 0xac, 0xce, 0xdd, 0x2c, 0x63, 0x3c, 0xbb, 0x96 }, new byte[] { 0xbd, 0xd4, 0xd2, 0x05, 0x40, 0x47, 0xab, 0xd0, 0x6a, 0x2e, 0xab, 0x87, 0xc6, 0x9a, 0xf3 }, (uint)4081687214, new byte[] { 0x69, 0x86, 0x93, 0x3f, 0xf7, 0x17, 0x24, 0xdb, 0x84, 0x12, 0xf5, 0x98, 0xce, 0xfd, 0x80, 0x80, 0xaf, 0x88, 0xe3, 0x47, 0x2b, 0x8d, 0xf9, 0x6a, 0x3e, 0x93, 0x54, 0xa4, 0xa3, 0x4b, 0x87, 0x30, 0x92 }, new byte[] { 0x41, 0x72, 0x58, 0x60, 0x77, 0xcf, 0xae, 0x65, 0xc6, 0x60, 0xd1, 0x7f, 0xd4, 0x68, 0x5f, 0x3d, 0x03, 0x9c, 0xc5, 0x07, 0x4b, 0xc3, 0x9b, 0x5b, 0x8f, 0x9d, 0x35, 0x21, 0x41, 0xbb, 0x43, 0xd6, 0x36 })]
        [InlineData(new byte[] { 0x6c, 0x39, 0x61, 0xb9, 0x33, 0x5b, 0xc6, 0xea, 0xa7, 0x42, 0xd2, 0xc0, 0x32, 0xee, 0xe0, 0x06, 0xc3, 0x3e, 0x50, 0x9d, 0x36, 0xfd, 0xf1, 0xf9, 0x33, 0xcc, 0x12, 0x29, 0xad, 0x5b, 0xdf, 0x24 }, new byte[] { 0xeb, 0x17, 0xb5, 0xe9, 0xe7, 0xa2, 0xd2, 0x03, 0x09, 0xf9, 0x11, 0xf8, 0x10, 0x50, 0x56 }, (uint)1953841336, new byte[] { 0xe4, 0xae, 0xeb, 0xe7, 0x83, 0x6b, 0xb8, 0x92, 0xb2, 0xc6, 0xf0, 0xce, 0x5f, 0x87, 0x0c, 0xf2 }, new byte[] { 0x8e, 0x13, 0x24, 0x89, 0x2d, 0x62, 0xb6, 0x75, 0x07, 0xef, 0x3c, 0x79, 0x32, 0x96, 0x1c, 0xf4 })]
        public void ReferenceTest(byte[] key, byte[] iv, uint generation, byte[] data, byte[] expected)
        {
            ModulatingCipher cipher = new ModulatingCipher();
            cipher.Initialize(key, iv);

            byte[] output = new byte[expected.Length];
            cipher.Process(generation, data, output);
            
            var _key = string.Join(", ", key.Select(b => $"0x{b:x2}"));
            var _iv = string.Join(", ", iv.Select(b => $"0x{b:x2}"));
            var _data = string.Join(", ", data.Select(b => $"0x{b:x2}"));
            var _expected = string.Join(", ", output.Select(b => $"0x{b:x2}"));
            Log.Verbose($"[InlineData(new byte[] {{{_key}}}, new byte[] {{{_iv}}}, (uint){generation}, new byte[] {{{_data}}}, new byte[] {{{_expected}}})]");

            Assert.Equal(expected, output);
        }
    }
}