using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace MicroRatchet
{
    internal struct SymmetricRacthet
    {
        public const int NumLostKeysToStore = 10;

        public byte[] HeaderKey;
        public byte[] NextHeaderKey;
        private Dictionary<int, byte[]> LostKeys;

        private int Generation;
        private byte[] ChainKey;

        public void Initialize(byte[] headerKey, byte[] chainKey, byte[] nextHeaderKey)
        {
            //Debug.WriteLine($"  C Key HK:       {Convert.ToBase64String(headerKey)}");
            //Debug.WriteLine($"  C Key Chain:    {Convert.ToBase64String(chainKey)}");
            //Debug.WriteLine($"  C Key NHK:      {Convert.ToBase64String(nextHeaderKey)}");

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
            var nextKeys = kdf.GenerateKeys(chain, null, 2);
            var nextGen = gen + 1;
            SetSingleGeneration(nextGen, nextKeys[0]);

            //Debug.WriteLine($"      RTC  #:      {nextGen}");
            //Debug.WriteLine($"      RTC IN:      {Convert.ToBase64String(chain)}");
            //Debug.WriteLine($"      RTC CK:      {Convert.ToBase64String(nextKeys[0])}");
            //Debug.WriteLine($"      RTC OK:      {Convert.ToBase64String(nextKeys[1])}");

            return (nextKeys[1], nextGen);
        }

        public (byte[], int) RatchetForReceiving(IKeyDerivation kdf, int toGeneration)
        {
            // check lost keys
            if (LostKeys.TryGetValue(toGeneration, out var lostKey))
            {
                return (lostKey, toGeneration);
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
                //Debug.WriteLine($"      RTC  #:      {gen + 1}");
                //Debug.WriteLine($"      RTC IN:      {Convert.ToBase64String(chain)}");

                var nextKeys = kdf.GenerateKeys(chain, null, 2);
                gen++;
                chain = nextKeys[0];
                key = nextKeys[1];

                if (gen != toGeneration)
                {
                    LostKeys[gen] = key;
                }

                //Debug.WriteLine($"      RTC CK:      {Convert.ToBase64String(nextKeys[0])}");
                //Debug.WriteLine($"      RTC OK:      {Convert.ToBase64String(nextKeys[1])}");
            }

            SetSingleGeneration(gen, chain);
            return (key, gen);
        }

        private void SetSingleGeneration(int gen, byte[] chain)
        {
            Generation = gen;
            ChainKey = chain;
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

        public void Serialize(BinaryWriter bw, bool isSendingChain)
        {
            WriteBuffer(bw, HeaderKey);
            WriteBuffer(bw, NextHeaderKey);
            bw.Write(Generation);
            WriteBuffer(bw, ChainKey);
            if (!isSendingChain)
            {
                if (LostKeys == null)
                {
                    bw.Write(-1);
                }
                else
                {
                    bw.Write(Math.Min(LostKeys.Count, NumLostKeysToStore));
                    foreach (var kvp in LostKeys.OrderByDescending(x => x.Key).Take(NumLostKeysToStore))
                    {
                        bw.Write(kvp.Key);
                        WriteBuffer(bw, kvp.Value);
                    }
                }
            }
        }

        public void Deserialize(BinaryReader br, bool isSendingChain)
        {
            HeaderKey = ReadBuffer(br);
            NextHeaderKey = ReadBuffer(br);
            Generation = br.ReadInt32();
            ChainKey = ReadBuffer(br);
            if (!isSendingChain)
            {
                int numLostKeys = br.ReadInt32();
                if (numLostKeys >= 0)
                {
                    LostKeys = new Dictionary<int, byte[]>();
                    for (int i = 0; i < numLostKeys; i++)
                    {
                        LostKeys[br.ReadInt32()] = ReadBuffer(br);
                    }
                }
            }
        }

        private static void WriteBuffer(BinaryWriter bw, byte[] data)
        {
            if (data == null)
            {
                bw.Write((byte)255);
            }
            else
            {
                if (data.Length >= 255) throw new InvalidOperationException("The data is too big");
                bw.Write((byte)data.Length);
                if (data.Length != 0) bw.Write(data);
            }
        }

        private static byte[] ReadBuffer(BinaryReader br)
        {
            int c = br.ReadByte();
            if (c == 255) return null;
            if (c > 0) return br.ReadBytes(c);
            else return new byte[0];
        }
    }
}
