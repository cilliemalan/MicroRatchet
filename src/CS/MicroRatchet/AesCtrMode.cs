using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet
{
    internal class AesCtrMode
    {
        private IAes _aes;
        private byte[] _iv;

        public AesCtrMode(IAes aes, ArraySegment<byte> iv)
        {
            _iv = FixIv(iv);
            _aes = aes ?? throw new ArgumentNullException(nameof(aes));
            
            Log.Verbose($"--CTR CRYPTING--");
            Log.Verbose($"   NONCE:   {Log.ShowBytes(_iv)}");
        }

        private byte[] FixIv(ArraySegment<byte> iv)
        {
            if (iv.Array == null) throw new ArgumentNullException(nameof(iv));

            var newIv = new byte[16];
            Array.Copy(iv.Array, iv.Offset, newIv, 0, Math.Min(iv.Count, 16));
            return newIv;
        }
        
        public byte[] Process(ArraySegment<byte> data)
        {
            Log.Verbose("Cipher Process");

            byte[] ctrout = new byte[16];
            void ProcessBlock(
                byte[] input,
                int inputOffset,
                byte[] output,
                int outputOffset)
            {
                _aes.Process(new ArraySegment<byte>(_iv), new ArraySegment<byte>(ctrout));

                for (int i = 0; i < ctrout.Length; i++)
                {
                    output[outputOffset + i] = (byte)(ctrout[i] ^ input[inputOffset + i]);
                }

                // add 1 to the ctr (big endian)
                for (int z = 15; z >= 0 && ++_iv[z] == 0; z--) ;
            }
            
            var outputBuffer = new byte[RoundUpToMultiple(data.Count, 16)];
            for (int i = 0; i < data.Count; i += 16)
            {
                int left = data.Count - i;
                if (left > 16)
                {
                    ProcessBlock(data.Array, data.Offset + i, outputBuffer, i);
                }
                else
                {
                    byte[] tempBuffer = new byte[16];
                    Array.Copy(data.Array, data.Offset + i, tempBuffer, 0, left);
                    ProcessBlock(tempBuffer, 0, outputBuffer, i);
                }
            }

            var result = new byte[data.Count];
            Array.Copy(outputBuffer, result, data.Count);

            Log.Verbose($"   PAYLOAD: {Log.ShowBytes(data.Array, data.Offset, data.Count)}");
            Log.Verbose($"   OUTPUT:  {Log.ShowBytes(result)}");
            Log.Verbose($"--CTR CRYPTING--");

            return result;
        }

        private static int RoundUpToMultiple(int a, int multipleOf)
        {
            var remain = a % multipleOf;
            if (remain == 0) return a;
            else return a - remain + multipleOf;
        }
    }
}
