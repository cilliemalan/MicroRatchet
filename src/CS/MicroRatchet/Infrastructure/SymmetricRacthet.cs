using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace MicroRatchet
{
    internal struct SymmetricRacthet
    {
        public static readonly byte[] ChainContext = new byte[16] { 0x7d, 0x93, 0x96, 0x05, 0xf5, 0xb6, 0xd2, 0xe2, 0x65, 0xd0, 0xde, 0xe6, 0xe4, 0x5d, 0x7a, 0x2c };

        public int Generation;
        public byte[] ChainKey;

        public int OldGeneration;
        public byte[] OldChainKey;

        public void Initialize(byte[] chainKey)
        {
            if (chainKey != null && chainKey.Length != 32) throw new InvalidOperationException("All keys sizes must be equal to the set key size");

            Log.Verbose($"  C Key Chain:    {Log.ShowBytes(chainKey)}");

            Generation = 0;
            ChainKey = chainKey;
            OldGeneration = 0;
            OldChainKey = null;
        }

        public void Reset()
        {
            Generation = 0;
            ChainKey = null;
            OldGeneration = 0;
            OldChainKey = null;
        }

        public (byte[] key, int generation) RatchetForSending(IKeyDerivation kdf)
        {
            // message keys are 128 bit
            var nextKeyBytes = kdf.GenerateBytes(ChainKey, ChainContext, 32 + 16);
            byte[] nextChainKey = new byte[32];
            Array.Copy(nextKeyBytes, nextChainKey, 32);
            byte[] messageKey = new byte[16];
            Array.Copy(nextKeyBytes, 32, messageKey, 0, 16);

            Log.Verbose($"      RTC  #:      {Generation + 1}");
            Log.Verbose($"      RTC IN:      {Log.ShowBytes(ChainKey)}");
            Log.Verbose($"      RTC CK:      {Log.ShowBytes(nextChainKey)}");
            Log.Verbose($"      RTC OK:      {Log.ShowBytes(messageKey)}");

            Generation++;
            ChainKey = nextChainKey;
            return (messageKey, Generation);
        }

        public (byte[] key, int generation) RatchetForReceiving(IKeyDerivation kdf, int toGeneration)
        {
            int gen;
            byte[] chain;
            if (toGeneration > Generation)
            {
                gen = Generation;
                chain = ChainKey;
            }
            else if (toGeneration > OldGeneration && OldChainKey != null)
            {
                gen = OldGeneration;
                chain = OldChainKey;
            }
            else
            {
                throw new InvalidOperationException("Could not ratchet to the generation because the old keys have been lost");
            }

            bool mustSkip = toGeneration > Generation && toGeneration - Generation > 1;
            bool incrementOld = toGeneration > OldGeneration && OldChainKey != null && toGeneration == OldGeneration + 1;

            byte[] key = null;
            while (gen < toGeneration)
            {
                Log.Verbose($"      RTC  #:      {gen + 1}");
                Log.Verbose($"      RTC IN:      {Log.ShowBytes(chain)}");

                // message keys are 128 bit
                var nextKeyBytes = kdf.GenerateBytes(chain, ChainContext, 32 + 16);
                byte[] nextChainKey = new byte[32];
                Array.Copy(nextKeyBytes, nextChainKey, 32);
                byte[] messageKey = new byte[16];
                Array.Copy(nextKeyBytes, 32, messageKey, 0, 16);

                gen++;
                chain = nextChainKey;
                key = messageKey;

                Log.Verbose($"      RTC CK:      {Log.ShowBytes(nextChainKey)}");
                Log.Verbose($"      RTC OK:      {Log.ShowBytes(messageKey)}");
            }

            if (mustSkip && OldChainKey == null)
            {
                OldChainKey = ChainKey;
                OldGeneration = Generation;
            }

            if (toGeneration > Generation)
            {
                Generation = gen;
                ChainKey = chain;
            }

            if (incrementOld)
            {
                OldGeneration++;
                OldChainKey = chain;
            }

            return (key, gen);
        }
    }
}
