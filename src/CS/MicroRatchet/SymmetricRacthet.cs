using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace MicroRatchet
{
    internal struct SymmetricRacthet
    {
        public byte[] HeaderKey;
        public byte[] NextHeaderKey;
        public Dictionary<int, byte[]> LostKeys;

        public int Generation;
        public byte[] ChainKey;

        public void Initialize(byte[] headerKey, byte[] chainKey, byte[] nextHeaderKey)
        {
            if ((headerKey != null && headerKey.Length != 32) ||
                (chainKey != null && chainKey.Length != 32) ||
                (nextHeaderKey != null && nextHeaderKey.Length != 32)) throw new InvalidOperationException("All keys sizes must be equal to the set key size");

            Log.Verbose($"  C Key HK:       {Log.ShowBytes(headerKey)}");
            Log.Verbose($"  C Key Chain:    {Log.ShowBytes(chainKey)}");
            Log.Verbose($"  C Key NHK:      {Log.ShowBytes(nextHeaderKey)}");
            
            HeaderKey = headerKey;
            NextHeaderKey = nextHeaderKey;
            LostKeys = new Dictionary<int, byte[]>();
            Generation = 0;
            ChainKey = chainKey;
        }

        public void Reset()
        {
            HeaderKey = null;
            NextHeaderKey = null;
            LostKeys = null;
            Generation = 0;
            ChainKey = null;
        }

        public (byte[] key, int generation) RatchetForSending(IKeyDerivation kdf)
        {
            // message keys are 128 bit
            var (gen, chain) = GetLastGeneration();
            var nextKeyBytes = kdf.GenerateBytes(chain, default, 32 + 16);
            byte[] nextChainKey = new byte[32];
            Array.Copy(nextKeyBytes, nextChainKey, 32);
            byte[] messageKey = new byte[16];
            Array.Copy(nextKeyBytes, 32, messageKey, 0, 16);
            var nextGen = gen + 1;

            Log.Verbose($"      RTC  #:      {nextGen}");
            Log.Verbose($"      RTC IN:      {Log.ShowBytes(chain)}");
            Log.Verbose($"      RTC CK:      {Log.ShowBytes(nextChainKey)}");
            Log.Verbose($"      RTC OK:      {Log.ShowBytes(messageKey)}");
            
            Generation = nextGen;
            ChainKey = nextChainKey;
            return (messageKey, nextGen);
        }

        public (byte[], int) RatchetForReceiving(IKeyDerivation kdf, int toGeneration)
        {
            // check lost keys
            if (LostKeys.TryGetValue(toGeneration, out var lostKey))
            {
                var result = (lostKey, toGeneration);
                LostKeys.Remove(toGeneration);
                return result;
            }

            // get the latest chain key we have that is smaller than the requested generation
            var (gen, chain) = GetLastGenerationBefore(toGeneration);

            if (chain == null)
            {
                throw new InvalidOperationException("Could not ratchet to the required generation because the keys have been deleted.");
            }


            byte[] key = null;
            while (gen < toGeneration)
            {
                Log.Verbose($"      RTC  #:      {gen + 1}");
                Log.Verbose($"      RTC IN:      {Log.ShowBytes(chain)}");

                // message keys are 128 bit
                var nextKeyBytes = kdf.GenerateBytes(chain, default, 32 + 16);
                byte[] nextChainKey = new byte[32];
                Array.Copy(nextKeyBytes, nextChainKey, 32);
                byte[] messageKey = new byte[16];
                Array.Copy(nextKeyBytes, 32, messageKey, 0, 16);
                gen++;
                chain = nextChainKey;
                key = messageKey;

                if (gen != toGeneration)
                {
                    LostKeys[gen] = key;
                }

                Log.Verbose($"      RTC CK:      {Log.ShowBytes(nextChainKey)}");
                Log.Verbose($"      RTC OK:      {Log.ShowBytes(messageKey)}");
            }
            
            Generation = gen;
            ChainKey = chain;
            return (key, gen);
        }

        private (int generation, byte[] chain) GetLastGeneration()
        {
            return (Generation, ChainKey);
        }

        private (int generation, byte[] chain) GetLastGenerationBefore(int generation)
        {
            if (generation <= Generation)
            {
                return default;
            }
            else
            {
                return (Generation, ChainKey);
            }
        }
    }
}
