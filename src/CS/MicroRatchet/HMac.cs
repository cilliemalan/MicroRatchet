using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet
{
    internal class HMac
    {
        private IDigest _digest;
        private const int digestBytes = 32;
        private const int blockBytes = 64;

        private readonly byte[] inputBuf;
        private readonly byte[] outputBuf;

        public HMac(IDigest digest)
        {
            _digest = digest;
            if (_digest.DigestSize != digestBytes * 8)
            {
                throw new InvalidOperationException("The digest had the incorrect size");
            }
            inputBuf = new byte[blockBytes];
            outputBuf = new byte[blockBytes];
        }

        public void Init(byte[] key)
        {
            _digest.Reset();

            int keyLength = key.Length;

            if (keyLength > blockBytes)
            {
                _digest.Process(new ArraySegment<byte>(key));
                var _inputPad = _digest.Compute();
                Array.Copy(_inputPad, inputBuf, _inputPad.Length);
                keyLength = 32;
            }
            else
            {
                Array.Copy(key, 0, inputBuf, 0, keyLength);
            }

            Array.Clear(inputBuf, keyLength, blockBytes - keyLength);
            Array.Copy(inputBuf, 0, outputBuf, 0, blockBytes);
            
            for (int i = 0; i < blockBytes; i++) inputBuf[i] ^= 0x36;
            for (int i = 0; i < blockBytes; i++) outputBuf[i] ^= 0x5C;

            _digest.Process(new ArraySegment<byte>(inputBuf, 0, inputBuf.Length));
        }

        public void Process(ArraySegment<byte> data)
        {
            _digest.Process(data);
        }

        public byte[] Compute()
        {
            var _output = _digest.Compute();
            _digest.Process(new ArraySegment<byte>(outputBuf));
            _digest.Process(new ArraySegment<byte>(_output));

            _output = _digest.Compute();
            _digest.Process(new ArraySegment<byte>(inputBuf, 0, inputBuf.Length));

            return _output;
        }

    }
}
