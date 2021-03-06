﻿using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet
{
    ///<summary>
    /// An AES based key derivation function. It function is
    /// is based on the fact that an AES key cannot easily be recovered
    /// from given ciphertext (i.e with a block cipher key -> ciphertext
    /// is a one-way function). An AES encryptor is created with a given
    /// key and a nonce is seeded by processing context-specific information
    /// in a similar fashion as an OFB mode cipher. A pseudorandom stream
    /// of key material is the generated by monotinically incrementing and
    /// encrypting the nonce much like AES CTR mode.
    ///</summary>
    internal class AesKdf : IKeyDerivation
    {
        private IAesFactory _aesFactory;

        public AesKdf(IAesFactory aesFactory)
        {
            _aesFactory = aesFactory;
        }

        public byte[] GenerateBytes(byte[] key, byte[] info, int howManyBytes)
        {
            var aes = _aesFactory.GetAes(true, key);

            byte[] ctr = new byte[16];

            int infoBytesOffset = 0;
            if (info != null)
            {
                while (info.Length - infoBytesOffset > 0)
                {
                    for (int i = 0; i < 16 && i + infoBytesOffset < info.Length; i++)
                    {
                        ctr[i] ^= info[i + infoBytesOffset];
                    }

                    aes.Process(new ArraySegment<byte>(ctr), new ArraySegment<byte>(ctr));
                    infoBytesOffset += 16;
                }
            }

            byte[] output = new byte[howManyBytes];
            int outputOffset = 0;
            while (outputOffset < howManyBytes)
            {
                for (int z = 15; z >= 0 && ++ctr[z] == 0; z--) ;

                if (howManyBytes - outputOffset >= 16)
                {
                    aes.Process(new ArraySegment<byte>(ctr), new ArraySegment<byte>(output, outputOffset, 16));
                }
                else
                {
                    byte[] outbuf = new byte[16];
                    aes.Process(new ArraySegment<byte>(ctr), new ArraySegment<byte>(outbuf));
                    Array.Copy(outbuf, 0, output, outputOffset, howManyBytes - outputOffset);
                }
                outputOffset += 16;
            }

            return output;
        }
    }
}
