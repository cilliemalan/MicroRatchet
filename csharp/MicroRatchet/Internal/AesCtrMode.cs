using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet
{
    ///<summary>
    /// AES counter mode implementation. The plaintext stream
    /// is XORed with a pseudorandom stream of 16 byte blocks generated
    /// by AES encrypting monotonically increasing 16 byte numbers, starting
    /// with a given nonce/iv.
    ///</summary>
    internal class AesCtrMode
    {
        private IAes _aes;
        private byte[] _iv;
        private byte[] _ctrout;
        private int _off;

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
            Log.Verbose("Cipher Process");

            if (data.Array == null) throw new ArgumentNullException(nameof(data));
            if (output.Array == null) throw new ArgumentNullException(nameof(output));
            if (data.Count == 0) return;
            if (output.Count < data.Count) throw new InvalidOperationException("output does not have enough space");

            int offset = 0;
            while (offset < data.Count)
            {
                // create a cipherstream block if needed
                if (_ctrout == null || _off == 16)
                {
                    // push the counter through AES
                    if (_ctrout == null) _ctrout = new byte[16];
                    _aes.Process(new ArraySegment<byte>(_iv), new ArraySegment<byte>(_ctrout));
                    _off = 0;

                    // increment counter
                    for (int z = 15; z >= 0 && ++_iv[z] == 0; z--) ;
                }

                // transform the input with the cipherstream block
                int bytesToTransform = Math.Min(data.Count - offset, 16 - _off);
                for (int i = 0; i < bytesToTransform; i++)
                {
                    output.Array[output.Offset + i + offset] = (byte)(_ctrout[i + _off] ^ data.Array[data.Offset + i + offset]);
                }

                _off += bytesToTransform;
                offset += bytesToTransform;
            }

            Log.Verbose($"   PAYLOAD: {Log.ShowBytes(data)}");
            Log.Verbose($"   OUTPUT:  {Log.ShowBytes(output)}");
            Log.Verbose($"--CTR CRYPTING--");
        }
    }
}
