using System;
using System.Collections.Generic;
using System.Linq;

namespace MicroRatchet
{
    internal struct SymmetricRacthet
    {
        public byte[] HeaderKey;
        public byte[] NextHeaderKey;
        public List<(int generation, byte[] chain)> ChainKeys;

        public (byte[] key, int generation) RatchetAndTrim(IKeyDerivation kdf)
        {
            var (gen, chain) = ChainKeys.Last();
            var nextKeys = kdf.GenerateKeys(chain, null, 2);
            var nextGen = gen + 1;
            ChainKeys.Add((nextGen, nextKeys[0]));


            //Debug.WriteLine($"      RTC  #:      {nextGen}");
            //Debug.WriteLine($"      RTC IN:      {Convert.ToBase64String(chain)}");
            //Debug.WriteLine($"      RTC CK:      {Convert.ToBase64String(nextKeys[0])}");
            //Debug.WriteLine($"      RTC OK:      {Convert.ToBase64String(nextKeys[1])}");

            TrimChain();
            return (nextKeys[1], nextGen);
        }

        public (byte[], int) RetrieveAndTrim(IKeyDerivation kdf, int step)
        {
            // get the latest chain key we have that is smaller than the requested generation
            var (gen, chain) = ChainKeys.OrderByDescending(x => x.generation)
                .Where(x => x.generation < step)
                .FirstOrDefault();

            if (chain == null) throw new InvalidOperationException("Could not ratchet to the required generation because the keys have been deleted.");

            byte[] key = null;
            while (gen < step)
            {
                //Debug.WriteLine($"      RTC  #:      {gen + 1}");
                //Debug.WriteLine($"      RTC IN:      {Convert.ToBase64String(chain)}");

                var nextKeys = kdf.GenerateKeys(chain, null, 2);
                gen++;
                chain = nextKeys[0];
                key = nextKeys[1];

                //Debug.WriteLine($"      RTC CK:      {Convert.ToBase64String(nextKeys[0])}");
                //Debug.WriteLine($"      RTC OK:      {Convert.ToBase64String(nextKeys[1])}");
            }

            // store the key as the latest key we've generated
            ChainKeys.Add((gen, chain));

            TrimChain();
            return (key, gen);
        }

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

        private void TrimChain()
        {
            // skipping the last chain key, move from the back
            // and remove all consecutive ratchet keys. When a discontinuity
            // is found, don't delete it

            if (ChainKeys.Count == 1) return;
            else if (ChainKeys.Count == 2)
            {
                if (ChainKeys[0].generation == ChainKeys[1].generation - 1)
                {
                    ChainKeys.RemoveAt(0);
                }
            }
            else
            {
                var toRetain = new List<(int generation, byte[] chain)>();

                int lastGeneration = int.MaxValue;
                foreach (var ck in ChainKeys.AsEnumerable().OrderByDescending(x => x.generation))
                {
                    if (toRetain.Count > 45) break;

                    if (toRetain.Count == 0)
                    {
                        toRetain.Add(ck);
                    }
                    else
                    {

                        if (lastGeneration - ck.generation > 1)
                        {
                            toRetain.Add(ck);
                        }

                        lastGeneration = ck.generation;
                    }
                }

                if (toRetain[toRetain.Count - 1] != ChainKeys[0])
                {
                    toRetain.Add(ChainKeys[0]);
                }
                toRetain.Reverse();
                ChainKeys = toRetain;
            }
        }
    }
}
