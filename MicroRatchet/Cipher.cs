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
    internal class Cipher : IDisposable, ICipher
    {
        private byte[] iv;
        private byte[] key;

        public Cipher(byte[] key, byte[] iv)
        {
            this.iv = FixIv(iv);
            this.key = key;
        }

        private byte[] FixIv(byte[] iv)
        {
            if (iv == null) return null;

            Digest d = new Digest();
            var digest = d.ComputeDigest(iv);
            byte[] newiv = new byte[16];
            for (int i = 0; i < 16; i++) newiv[i] = (byte)(digest[i] ^ digest[i + 16]);
            return newiv;
        }

        public byte[] Encrypt(ArraySegment<byte> data) => Process(data, iv);
        public byte[] Decrypt(ArraySegment<byte> data) => Process(data, iv);

        private byte[] Process(ArraySegment<byte> data, byte[] iv)
        {
            if (key == null) throw new ObjectDisposedException(nameof(Cipher));

            var encryptor = new SicBlockCipher(new AesEngine());
            var blockSize = encryptor.GetBlockSize();
            encryptor.Init(true, new ParametersWithIV(new KeyParameter(key), iv ?? new byte[blockSize]));
            var outputBuffer = new byte[RoundUpToMultiple(data.Count, blockSize)];
            for (int i = 0; i < data.Count; i += blockSize)
            {
                int left = data.Count - i;
                if (left > blockSize)
                {
                    encryptor.ProcessBlock(data.Array, data.Offset + i, outputBuffer, i);
                }
                else
                {
                    byte[] tempBuffer = new byte[blockSize];
                    Array.Copy(data.Array, i, tempBuffer, 0, left);
                    encryptor.ProcessBlock(tempBuffer, 0, outputBuffer, i);
                }
            }
            var output = new byte[data.Count];
            Array.Copy(outputBuffer, output, data.Count);

            //Debug.WriteLine($"--crypting--");
            //Debug.WriteLine($"   KEY:     {Convert.ToBase64String(key)}");
            //Debug.WriteLine($"   NONCE:   {Convert.ToBase64String(iv ?? new byte[0])}");
            //Debug.WriteLine($"   PAYLOAD: {Convert.ToBase64String(data.Array, data.Offset, data.Count)}");
            //Debug.WriteLine($"   OUTPUT:  {Convert.ToBase64String(output)}");
            //Debug.WriteLine($"--crypting--");

            return output;
        }
        public void Dispose()
        {
            if (key != null)
            {
                Array.Clear(key, 0, key.Length);
                key = null;
            }
        }

        private static int RoundUpToMultiple(int a, int multipleOf)
        {
            var remain = a % multipleOf;
            if (remain == 0) return a;
            else return a - remain + multipleOf;
        }
    }
}
