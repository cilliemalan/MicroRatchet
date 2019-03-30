using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using System;
using System.Collections.Generic;
using System.Text;
using System.Diagnostics;

namespace MicroRatchet
{
    internal class Cipher : ICipher
    {
        SicBlockCipher cipher;

        public Cipher()
        {
        }

        public void Initialize(byte[] key, byte[] iv)
        {
            if (key == null && iv == null)
            {
                cipher = null;
            }
            else
            {
                if (key == null) throw new ArgumentNullException(nameof(key));
                if (iv == null) throw new ArgumentNullException(nameof(iv));

                Log.Verbose($"--crypting--");
                Log.Verbose($"   KEY:     {Log.ShowBytes(key)}");
                Log.Verbose($"   NONCE:   {Log.ShowBytes(iv ?? new byte[0])}");
                var notUsed = true;
                cipher = new SicBlockCipher(new AesEngine());
                cipher.Init(notUsed, new ParametersWithIV(new KeyParameter(key), FixIv(iv)));
            }
        }

        private byte[] FixIv(byte[] iv)
        {
            int l = Math.Min(Math.Max(8, iv.Length), 16);
            int c = Math.Min(iv.Length, l);
            var newIv = new byte[l];
            Array.Copy(iv, 0, newIv, 0, c);
            return newIv;
        }

        public byte[] Encrypt(ArraySegment<byte> data) => Process(data);
        public byte[] Decrypt(ArraySegment<byte> data) => Process(data);

        private byte[] Process(ArraySegment<byte> data)
        {
            Log.Verbose("Cipher Process");
            if (cipher == null) throw new ObjectDisposedException(nameof(Cipher));

            var blockSize = cipher.GetBlockSize();
            var outputBuffer = new byte[RoundUpToMultiple(data.Count, blockSize)];
            for (int i = 0; i < data.Count; i += blockSize)
            {
                int left = data.Count - i;
                if (left > blockSize)
                {
                    cipher.ProcessBlock(data.Array, data.Offset + i, outputBuffer, i);
                }
                else
                {
                    byte[] tempBuffer = new byte[blockSize];
                    Array.Copy(data.Array, data.Offset + i, tempBuffer, 0, left);
                    cipher.ProcessBlock(tempBuffer, 0, outputBuffer, i);
                }
            }
            var output = new byte[data.Count];
            Array.Copy(outputBuffer, output, data.Count);

            Log.Verbose($"   PAYLOAD: {Log.ShowBytes(data.Array, data.Offset, data.Count)}");
            Log.Verbose($"   OUTPUT:  {Log.ShowBytes(output)}");
            Log.Verbose($"--crypting--");

            return output;
        }

        private static int RoundUpToMultiple(int a, int multipleOf)
        {
            var remain = a % multipleOf;
            if (remain == 0) return a;
            else return a - remain + multipleOf;
        }
    }
}
