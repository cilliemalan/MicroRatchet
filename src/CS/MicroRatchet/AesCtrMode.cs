using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet
{
    internal class AesCtrMode
    {
        private IAes _aes;
        private byte[] _iv;
        bool burnt = false;

        public AesCtrMode(IAes aes, ArraySegment<byte> iv)
        {
            _iv = FixIv(iv);
            _aes = aes ?? throw new ArgumentNullException(nameof(aes));

            Log.Verbose($"--CTR CRYPTING--");
            Log.Verbose($"   NONCE:   {Log.ShowBytes(_iv)}");
        }

        public AesCtrMode(IAes aes, byte[] iv)
            : this(aes, new ArraySegment<byte>(iv))
        {
        }

        public AesCtrMode(IAes aes, byte[] iv, int offset, int length)
            : this(aes, new ArraySegment<byte>(iv, offset, length))
        {
        }

        private byte[] FixIv(ArraySegment<byte> iv)
        {
            if (iv.Array == null) throw new ArgumentNullException(nameof(iv));

            var newIv = new byte[16];
            Array.Copy(iv.Array, iv.Offset, newIv, 0, Math.Min(iv.Count, 16));
            return newIv;
        }

        public byte[] Process(byte[] data) => Process(new ArraySegment<byte>(data));
        public byte[] Process(byte[] data, int offset, int length) => Process(new ArraySegment<byte>(data, offset, length));
        public void Process(byte[] data, byte[] output) => Process(new ArraySegment<byte>(data), new ArraySegment<byte>(output));
        public void Process(byte[] data, int offset, int length, byte[] output) => Process(new ArraySegment<byte>(data, offset, length), new ArraySegment<byte>(output));
        public void Process(byte[] data, int doffset, int dlength, byte[] output, int ooffset, int olength) => Process(new ArraySegment<byte>(data, doffset, dlength), new ArraySegment<byte>(output, ooffset, olength));

        public byte[] Process(ArraySegment<byte> data)
        {
            byte[] output = new byte[data.Count];
            Process(data, new ArraySegment<byte>(output));
            return output;
        }

        public void Process(ArraySegment<byte> data, ArraySegment<byte> output)
        {
            if (burnt) throw new NotSupportedException("AesCtrMode can only be used once");
            burnt = true;

            Log.Verbose("Cipher Process");

            byte[] ctrout = new byte[16];
            void ProcessBlock(
                byte[] inbytes,
                int inoffset,
                int numBytesToProcess,
                byte[] outbytes,
                int outoffset)
            {
                _aes.Process(new ArraySegment<byte>(_iv), new ArraySegment<byte>(ctrout));

                for (int i = 0; i < ctrout.Length && i < numBytesToProcess; i++)
                {
                    outbytes[outoffset + i] = (byte)(ctrout[i] ^ inbytes[inoffset + i]);
                }

                // add 1 to the ctr (big endian)
                for (int z = 15; z >= 0 && ++_iv[z] == 0; z--) ;
            }

            for (int i = 0; i < data.Count; i += 16)
            {
                var toProcess = Math.Min(16, data.Count - i);
                ProcessBlock(
                    data.Array, data.Offset + i, toProcess,
                    output.Array, output.Offset + i);
            }
            
            Log.Verbose($"   PAYLOAD: {Log.ShowBytes(data)}");
            Log.Verbose($"   OUTPUT:  {Log.ShowBytes(output)}");
            Log.Verbose($"--CTR CRYPTING--");
        }
    }
}
