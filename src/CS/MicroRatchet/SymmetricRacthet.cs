using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace MicroRatchet
{
    internal struct SymmetricRacthet
    {
        public int KeySize { get; set; }

        public byte[] HeaderKey;
        public byte[] NextHeaderKey;
        public Dictionary<int, byte[]> LostKeys;

        public int Generation;
        public byte[] ChainKey;

        public void Initialize(int keySize, byte[] headerKey, byte[] chainKey, byte[] nextHeaderKey)
        {
            if (keySize != 32 && keySize != 16) throw new InvalidOperationException("Invalid key size. Must be 16 or 32 bytes.");
            if ((headerKey != null && headerKey.Length != keySize) ||
                (chainKey != null && chainKey.Length != keySize) ||
                (nextHeaderKey != null && nextHeaderKey.Length != keySize)) throw new InvalidOperationException("All keys sizes must be equal to the set key size");

            Log.Verbose($"  C Key HK:       {Log.ShowBytes(headerKey)}");
            Log.Verbose($"  C Key Chain:    {Log.ShowBytes(chainKey)}");
            Log.Verbose($"  C Key NHK:      {Log.ShowBytes(nextHeaderKey)}");

            KeySize = keySize;
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
            var (gen, chain) = GetLastGeneration();
            var nextKeys = kdf.GenerateKeys(chain, null, 2, KeySize);
            var nextGen = gen + 1;

            Log.Verbose($"      RTC  #:      {nextGen}");
            Log.Verbose($"      RTC IN:      {Log.ShowBytes(chain)}");
            Log.Verbose($"      RTC CK:      {Log.ShowBytes(nextKeys[0])}");
            Log.Verbose($"      RTC OK:      {Log.ShowBytes(nextKeys[1])}");
            
            Generation = nextGen;
            ChainKey = nextKeys[0];
            return (nextKeys[1], nextGen);
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

                var nextKeys = kdf.GenerateKeys(chain, null, 2, KeySize);
                gen++;
                chain = nextKeys[0];
                key = nextKeys[1];

                if (gen != toGeneration)
                {
                    LostKeys[gen] = key;
                }

                Log.Verbose($"      RTC CK:      {Log.ShowBytes(nextKeys[0])}");
                Log.Verbose($"      RTC OK:      {Log.ShowBytes(nextKeys[1])}");
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
