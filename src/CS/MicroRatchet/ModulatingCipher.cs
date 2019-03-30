using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace MicroRatchet
{
    public class ModulatingCipher : IModulatingCipher
    {
        AesEngine aes = new AesEngine();
        byte[] _iv;
        private int _oldKeysToRetain;
        private LinkedList<(int kg, byte[] k)> oldkeys;
        private int _modulationInterval;
        private int _currentKeyGeneration;

        public ModulatingCipher()
            : this(1, 16)
        {
        }

        public ModulatingCipher(int modulationInterval = 16, int oldKeysToRetain = 1)
        {
            _oldKeysToRetain = oldKeysToRetain;
            _modulationInterval = modulationInterval;
            if (oldKeysToRetain > 0) oldkeys = new LinkedList<(int, byte[])>();
        }

        public void Initialize(byte[] key, byte[] iv = null)
        {
            var generation = 0;
            if (key == null) throw new ArgumentNullException(nameof(iv));
            if (key.Length != 16 && key.Length != 32) throw new ArgumentException("The key must be 16 or 32 bytes", nameof(key));

            _iv = new byte[16];
            if (iv != null)
            {
                _iv = new byte[16];
                Array.Copy(iv, 0, _iv, 0, Math.Min(16, iv.Length));
            }
            

            Log.Verbose($"--creating modulating cipher--");
            Log.Verbose($"   KEY:     {Log.ShowBytes(key)}");
            Log.Verbose($"   GEN:     {generation}");
            aes.Init(true, new KeyParameter(key));
            _currentKeyGeneration = generation / _modulationInterval;

            if(oldkeys != null)
            {
                oldkeys.Clear();
                oldkeys.AddFirst((_currentKeyGeneration, key));
            }
        }

        private void ModulateTo(uint generation)
        {
            var kg = generation / _modulationInterval;
            var ourkg = _currentKeyGeneration;
            byte[] newkey = null;
            if (kg != ourkg)
            {
                if (kg > ourkg)
                {
                    while (kg > ourkg)
                    {
                        ourkg++;
                        newkey = new byte[16];
                        aes.ProcessBlock(_iv, 0, newkey, 0);
                        if (oldkeys != null)
                        {
                            oldkeys.AddFirst((ourkg, newkey));
                        }
                    }
                }
                
                if (oldkeys != null)
                {
                    while (oldkeys.Count > _oldKeysToRetain) oldkeys.RemoveLast();
                }
            }
        }

        public void Process(uint generation, ArraySegment<byte> data, ArraySegment<byte> output)
        {
            Log.Verbose($"   IV:     {Log.ShowBytes(_iv)}");
            Log.Verbose($"   DATA:   {Log.ShowBytes(data.Array, data.Offset, data.Count)}");

            ModulateTo(generation);

            if (data == null) throw new ArgumentNullException(nameof(data));
            if (output == null) throw new ArgumentNullException(nameof(output));
            if (data.Count == 0) return;
            if (output.Count < data.Count) throw new InvalidOperationException("The output doesn't have enough space for the input.");

            // add generation to the iv as big endian (lsb is first)
            byte[] iv = (byte[])_iv.Clone();
            uint bctr = unchecked((iv[15] | ((uint)iv[14] << 8) | ((uint)iv[13] << 16) | (uint)iv[12] << 24) + generation);
            iv[15] = (byte)bctr;
            iv[14] = (byte)(bctr >> 8);
            iv[13] = (byte)(bctr >> 16);
            iv[12] = (byte)(bctr >> 24);

            // transform the IV to give us a new IV for the stream cipher used to encrypt the data
            byte[] ctr = new byte[16];
            aes.ProcessBlock(iv, 0, ctr, 0);

            byte[] transform = new byte[16];
            for (int i = 0; i < data.Count; i += 16)
            {
                // add 1 to the ctr (big endian)
                for (int z = 15; z >= 0 && ++ctr[z] == 0; z--) ;

                // process the ctr to get transform
                aes.ProcessBlock(ctr, 0, transform, 0);

                // modulate the data with transform
                int left = data.Offset + data.Count - i;
                for (int j = 0; j < 16 && j + i < data.Count; j++)
                {
                    output.Array[output.Offset + j + i] = (byte)(transform[j] ^ data.Array[data.Offset + j + i]);
                }
            }

            Log.Verbose($"   OUTPUT: {Log.ShowBytes(output.Array, output.Offset, data.Count)}");
            Log.Verbose($"--modulating--");
        }
    }
}
