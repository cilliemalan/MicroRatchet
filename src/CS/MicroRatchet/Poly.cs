using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace MicroRatchet
{
    internal class Poly : IMac
    {
        private int _macSize;
        private IAesFactory _aesFactory;

        private uint r0, r1, r2, r3, r4;
        private uint s1, s2, s3, s4;
        private uint k0, k1, k2, k3;
        private uint h0, h1, h2, h3, h4;
        private byte[] partialBlock;
        private int partialBlockBytes;

        public Poly(IAesFactory aesFactory)
        {
            _aesFactory = aesFactory;
        }

        public void Init(byte[] key, ArraySegment<byte> iv, int macSize)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (iv == null) throw new ArgumentNullException(nameof(iv));
            if (macSize != 96 && macSize != 112 && macSize != 128)
            {
                throw new InvalidOperationException("The Poly1305 MAC must be 96, 112, or 128 bits");
            }

            _macSize = macSize / 8;
            if (iv.Count != 16)
            {
                byte[] newIv = new byte[16];
                Array.Copy(iv.Array, iv.Offset, newIv, 0, Math.Min(iv.Count, 16));
                iv = new ArraySegment<byte>(newIv);
            }
            InitInternal(key, iv);

            Log.Verbose($"--maccing--");
            Log.Verbose($"   IV:      {Log.ShowBytes(iv)}");
            Log.Verbose($"   KEY:     {Log.ShowBytes(key)}");
        }

        private void InitInternal(byte[] key, ArraySegment<byte> nonce)
        {
            // Extract r portion of key (and "clamp" the values)
            var a0 = key[+0] | (uint)key[+1] << 8 | (uint)key[+2] << 16 | (uint)key[+3] << 24;
            var a1 = key[+4] | (uint)key[+5] << 8 | (uint)key[+6] << 16 | (uint)key[+7] << 24;
            var a2 = key[+8] | (uint)key[+9] << 8 | (uint)key[+10] << 16 | (uint)key[+11] << 24;
            var a3 = key[+12] | (uint)key[+13] << 8 | (uint)key[+14] << 16 | (uint)key[+15] << 24;
            r0 = a0;
            r1 = (a0 >> 26) | (a1 << 6);
            r2 = (a1 >> 20) | (a2 << 12);
            r3 = (a2 >> 14) | (a3 << 18);
            r4 = a3 >> 8;
            r0 &= 0x03FFFFFFU;
            r1 &= 0x03FFFF03U;
            r2 &= 0x03FFC0FFU;
            r3 &= 0x03F03FFFU;
            r4 &= 0x000FFFFFU;
            s1 = r1 * 5;
            s2 = r2 * 5;
            s3 = r3 * 5;
            s4 = r4 * 5;

            byte[] k = new byte[16];
            Array.Copy(key, 16, k, 0, 16);
            var aes = _aesFactory.GetAes(true, k);
            aes.Process(nonce, new ArraySegment<byte>(k));

            k0 = k[0] | (uint)k[1] << 8 | (uint)k[2] << 16 | (uint)k[3] << 24;
            k1 = k[4] | (uint)k[5] << 8 | (uint)k[6] << 16 | (uint)k[7] << 24;
            k2 = k[8] | (uint)k[9] << 8 | (uint)k[10] << 16 | (uint)k[11] << 24;
            k3 = k[12] | (uint)k[13] << 8 | (uint)k[14] << 16 | (uint)k[15] << 24;

            h0 = 0;
            h1 = 0;
            h2 = 0;
            h3 = 0;
            h4 = 0;
            partialBlock = null;
            partialBlockBytes = 0;
        }

        public void Process(ArraySegment<byte> data)
        {
            if (data.Count == 0) return;
            Log.Verbose($"   MAC INPUT:     {Log.ShowBytes(data.Array, data.Offset, data.Count)}");

            if (partialBlockBytes > 0)
            {
                if (data.Count + partialBlockBytes < 16)
                {
                    Array.Copy(data.Array, data.Offset, partialBlock, partialBlockBytes, data.Count);
                    partialBlockBytes += data.Count;
                }
                else
                {
                    var left = 16 - partialBlockBytes;
                    Array.Copy(data.Array, data.Offset, partialBlock, partialBlockBytes, left);
                    ProcessBlock(new ArraySegment<byte>(partialBlock, 0, 16));
                    partialBlockBytes = 0;
                    Process(new ArraySegment<byte>(data.Array, data.Offset + left, data.Count - left));
                }
            }
            else
            {
                for (int i = 0; i < data.Count; i += 16)
                {
                    var left = data.Count - i;
                    if (left >= 16)
                    {
                        ProcessBlock(new ArraySegment<byte>(data.Array, data.Offset + i, data.Count - i));
                    }
                    else
                    {
                        partialBlock = new byte[16];
                        Array.Copy(data.Array, data.Offset + i, partialBlock, 0, left);
                        partialBlockBytes = left;
                    }
                }
            }
        }

        private void ProcessBlock(ArraySegment<byte> block_)
        {
            byte[] block = block_.Array;
            var offset = block_.Offset;
            var cnt = block_.Count;
            bool blockIsPadded;
            if (cnt < 16)
            {
                var newblock = new byte[16];
                Array.Copy(block, offset, newblock, 0, cnt);
                newblock[cnt] = 1;
                block = newblock;
                offset = 0;
                cnt = 16;
                blockIsPadded = true;
            }
            else
            {
                blockIsPadded = false;
            }

            ulong t0 = block[offset + 0] | (uint)block[offset + 1] << 8 | (uint)block[offset + 2] << 16 | (uint)block[offset + 3] << 24;
            ulong t1 = block[offset + 4] | (uint)block[offset + 5] << 8 | (uint)block[offset + 6] << 16 | (uint)block[offset + 7] << 24;
            ulong t2 = block[offset + 8] | (uint)block[offset + 9] << 8 | (uint)block[offset + 10] << 16 | (uint)block[offset + 11] << 24;
            ulong t3 = block[offset + 12] | (uint)block[offset + 13] << 8 | (uint)block[offset + 14] << 16 | (uint)block[offset + 15] << 24;

            h0 += (uint)(t0 & 0x3ffffffU);
            h1 += (uint)((((t1 << 32) | t0) >> 26) & 0x3ffffff);
            h2 += (uint)((((t2 << 32) | t1) >> 20) & 0x3ffffff);
            h3 += (uint)((((t3 << 32) | t2) >> 14) & 0x3ffffff);
            h4 += (uint)(t3 >> 8);

            if (!blockIsPadded)
            {
                h4 += 0x1000000;
            }

            ulong mul(uint i1, uint i2) => ((ulong)i1) * i2;
            var tp0 = mul(h0, r0) + mul(h1, s4) + mul(h2, s3) + mul(h3, s2) + mul(h4, s1);
            var tp1 = mul(h0, r1) + mul(h1, r0) + mul(h2, s4) + mul(h3, s3) + mul(h4, s2);
            var tp2 = mul(h0, r2) + mul(h1, r1) + mul(h2, r0) + mul(h3, s4) + mul(h4, s3);
            var tp3 = mul(h0, r3) + mul(h1, r2) + mul(h2, r1) + mul(h3, r0) + mul(h4, s4);
            var tp4 = mul(h0, r4) + mul(h1, r3) + mul(h2, r2) + mul(h3, r1) + mul(h4, r0);

            h0 = (uint)tp0 & 0x3ffffff;
            tp1 += tp0 >> 26;
            h1 = (uint)tp1 & 0x3ffffff;
            tp2 += tp1 >> 26;
            h2 = (uint)tp2 & 0x3ffffff;
            tp3 += tp2 >> 26;
            h3 = (uint)tp3 & 0x3ffffff;
            tp4 += tp3 >> 26;
            h4 = (uint)tp4 & 0x3ffffff;
            h0 += (uint)(tp4 >> 26) * 5;
            h1 += h0 >> 26;
            h0 &= 0x3ffffff;
        }

        public byte[] Compute()
        {
            byte[] output = new byte[_macSize];
            Compute(new ArraySegment<byte>(output));
            return output;
        }

        public void Compute(ArraySegment<byte> output)
        {
            if (partialBlockBytes > 0)
            {
                ProcessBlock(new ArraySegment<byte>(partialBlock, 0, partialBlockBytes));
            }

            h1 += h0 >> 26;
            h2 += h1 >> 26;
            h3 += h2 >> 26;
            h4 += h3 >> 26;
            h0 &= 0x3ffffff;
            h1 &= 0x3ffffff;
            h2 &= 0x3ffffff;
            h3 &= 0x3ffffff;
            h0 += (h4 >> 26) * 5;
            h1 += h0 >> 26;
            h4 &= 0x3ffffff;
            h0 &= 0x3ffffff;

            var g0 = h0 + 5;
            var b = g0 >> 26;
            g0 &= 0x3ffffff;
            var g1 = h1 + b;
            b = g1 >> 26;
            g1 &= 0x3ffffff;
            var g2 = h2 + b;
            b = g2 >> 26;
            g2 &= 0x3ffffff;
            var g3 = h3 + b;
            b = g3 >> 26;
            g3 &= 0x3ffffff;
            var g4 = h4 + b - (1 << 26);

            b = (g4 >> 31) - 1;
            uint nb = ~b;
            h0 = (h0 & nb) | (g0 & b);
            h1 = (h1 & nb) | (g1 & b);
            h2 = (h2 & nb) | (g2 & b);
            h3 = (h3 & nb) | (g3 & b);
            h4 = (h4 & nb) | (g4 & b);

            ulong f0, f1, f2, f3;
            f0 = ((h0) | (h1 << 26)) + (ulong)k0;
            f1 = ((h1 >> 6) | (h2 << 20)) + (ulong)k1;
            f2 = ((h2 >> 12) | (h3 << 14)) + (ulong)k2;
            f3 = ((h3 >> 18) | (h4 << 8)) + (ulong)k3;
            f1 += f0 >> 32;
            f2 += f1 >> 32;
            f3 += f2 >> 32;

            if (_macSize >= 12)
            {
                output.Array[output.Offset + 0] = (byte)f0;
                output.Array[output.Offset + 1] = (byte)(f0 >> 8);
                output.Array[output.Offset + 2] = (byte)(f0 >> 16);
                output.Array[output.Offset + 3] = (byte)(f0 >> 24);
                output.Array[output.Offset + 4] = (byte)f1;
                output.Array[output.Offset + 5] = (byte)(f1 >> 8);
                output.Array[output.Offset + 6] = (byte)(f1 >> 16);
                output.Array[output.Offset + 7] = (byte)(f1 >> 24);
                output.Array[output.Offset + 8] = (byte)f2;
                output.Array[output.Offset + 9] = (byte)(f2 >> 8);
                output.Array[output.Offset + 10] = (byte)(f2 >> 16);
                output.Array[output.Offset + 11] = (byte)(f2 >> 24);
            }
            if (_macSize >= 14)
            {
                output.Array[output.Offset + 12] = (byte)f3;
                output.Array[output.Offset + 13] = (byte)(f3 >> 8);
            }
            if (_macSize >= 16)
            {
                output.Array[output.Offset + 14] = (byte)(f3 >> 16);
                output.Array[output.Offset + 15] = (byte)(f3 >> 24);
            }
        }
    }
}
