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
                //Debug.WriteLine($"--crypting--");
                //Debug.WriteLine($"   KEY:     {Convert.ToBase64String(key)}");
                //Debug.WriteLine($"   NONCE:   {Convert.ToBase64String(iv ?? new byte[0])}");
                var notUsed = true;
                cipher = new SicBlockCipher(new AesEngine());
                cipher.Init(notUsed, new ParametersWithIV(new KeyParameter(key), FixIv(iv) ?? new byte[cipher.GetBlockSize()]));
            }
        }

        private byte[] FixIv(byte[] iv)
        {
            if (iv == null) return null;

            Digest d = new Digest();
            var digest = d.ComputeDigest(iv);
            byte[] newiv = new byte[16];
            for (int i = 0; i < 16; i++) newiv[i] = digest[i];
            return newiv;
        }

        public byte[] Encrypt(ArraySegment<byte> data) => Process(data);
        public byte[] Decrypt(ArraySegment<byte> data) => Process(data);

        private byte[] Process(ArraySegment<byte> data)
        {
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

            //Debug.WriteLine($"--crypting--");
            //Debug.WriteLine($"   PAYLOAD: {Convert.ToBase64String(data.Array, data.Offset, data.Count)}");
            //Debug.WriteLine($"   OUTPUT:  {Convert.ToBase64String(output)}");
            //Debug.WriteLine($"--crypting--");

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
