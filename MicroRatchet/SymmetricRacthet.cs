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
        private List<(int generation, byte[] chain)> ChainKeys;

        public void Initialize(byte[] headerKey, byte[] chainKey, byte[] nextHeaderKey)
        {
            //Debug.WriteLine($"  C Key HK:       {Convert.ToBase64String(headerKey)}");
            //Debug.WriteLine($"  C Key Chain:    {Convert.ToBase64String(chainKey)}");
            //Debug.WriteLine($"  C Key NHK:      {Convert.ToBase64String(nextHeaderKey)}");

            HeaderKey = headerKey;
            NextHeaderKey = nextHeaderKey;
            ChainKeys = new List<(int generation, byte[] chain)>
            {
                (0, chainKey)
            };
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
            // get the latest chain key we have that is smaller than the requested generation
            var (gen, chain) = GetLastGenerationBefore(toGeneration);

            if (chain == null) throw new InvalidOperationException("Could not ratchet to the required generation because the keys have been deleted.");

            byte[] key = null;
            while (gen < toGeneration)
            {
                //Debug.WriteLine($"      RTC  #:      {gen + 1}");
                //Debug.WriteLine($"      RTC IN:      {Convert.ToBase64String(chain)}");

                var nextKeys = kdf.GenerateKeys(chain, null, 2);
                gen++;
                chain = nextKeys[0];
                key = nextKeys[1];
                AddGeneration(gen, chain);

                //Debug.WriteLine($"      RTC CK:      {Convert.ToBase64String(nextKeys[0])}");
                //Debug.WriteLine($"      RTC OK:      {Convert.ToBase64String(nextKeys[1])}");
            }

            return (key, gen);
        }

        private void AddGeneration(int gen, byte[] key)
        {
            ChainKeys.Add((gen, key));
        }

        private void SetSingleGeneration(int gen, byte[] key)
        {
            ChainKeys[0] = (gen, key);
        }

        private (int generation, byte[] chain) GetLastGeneration()
        {
            return ChainKeys.Last();
        }

        private (int generation, byte[] chain) GetLastGenerationBefore(int generation)
        {
            return ChainKeys.OrderByDescending(x => x.generation)
                            .Where(x => x.generation < generation)
                            .FirstOrDefault();
        }

        public void Serialize(BinaryWriter bw, bool isSendingChain)
        {
            WriteBuffer(bw, HeaderKey);
            WriteBuffer(bw, NextHeaderKey);
            if (isSendingChain)
            {
                var (generation, chain) = ChainKeys[0];
                bw.Write(generation);
                WriteBuffer(bw, chain);
            }
            else
            {
                if (ChainKeys == null)
                {
                    bw.Write(-1);
                }
                else
                {
                    bw.Write(ChainKeys.Count);
                    foreach (var (generation, chain) in ChainKeys)
                    {
                        bw.Write(generation);
                        WriteBuffer(bw, chain);
                    }
                }
            }
        }

        public void Deserialize(BinaryReader br, bool isSendingChain)
        {
            HeaderKey = ReadBuffer(br);
            NextHeaderKey = ReadBuffer(br);
            if (isSendingChain)
            {
                ChainKeys = new List<(int, byte[])>
                {
                    (br.ReadInt32(), ReadBuffer(br))
                };
            }
            else
            {
                int numChainKeys = br.ReadInt32();
                if (numChainKeys >= 0)
                {
                    ChainKeys = new List<(int, byte[])>();
                    for (int i = 0; i < numChainKeys; i++)
                    {
                        ChainKeys.Add((br.ReadInt32(), ReadBuffer(br)));
                    }
                }
            }
        }

        private static void WriteBuffer(BinaryWriter bw, byte[] data)
        {
            if (data == null)
            {
                bw.Write(-1);
            }
            else
            {
                bw.Write(data.Length);
                if (data.Length != 0) bw.Write(data);
            }
        }

        private static byte[] ReadBuffer(BinaryReader br)
        {
            int c = br.ReadInt32();
            if (c < 0) return null;
            if (c > 0) return br.ReadBytes(c);
            else return new byte[0];
        }
    }
}
