using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;

namespace MicroRatchet
{
    internal class EcdhRatchetStep
    {
        public struct Chain
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

        public int Generation;
        public byte[] PublicKey;
        public byte[] PrivateKey;
        public Chain ReceivingChain;
        public Chain SendingChain;
        public byte[] NextRootKey;

        private EcdhRatchetStep() { }

        public static EcdhRatchetStep InitializeServer(IKeyDerivation kdf,
            IKeyAgreement previousKeyPair,
            byte[] rootKey, byte[] publicKey, IKeyAgreement keyPair,
            byte[] receiveHeaderKey, byte[] sendHeaderKey)
        {
            //Debug.WriteLine($"--Initialize ECDH Ratchet");
            //Debug.WriteLine($"Root Key:           {Convert.ToBase64String(rootKey)}");
            //Debug.WriteLine($"Prev ECDH Private: ({Convert.ToBase64String(previousKeyPair.GetPublicKey())})");
            //Debug.WriteLine($"ECDH Public:        {Convert.ToBase64String(publicKey ?? new byte[0])}");
            //Debug.WriteLine($"Curr ECDH Private: ({Convert.ToBase64String(keyPair.GetPublicKey())})");

            var e = new EcdhRatchetStep
            {
                Generation = 0,
                PublicKey = publicKey,
                PrivateKey = keyPair.Serialize(),
            };

            // receive chain
            //Debug.WriteLine("  --Receiving Chain");
            var rcinfo = previousKeyPair.DeriveKey(publicKey);
            //Debug.WriteLine($"  C Input Key:    {Convert.ToBase64String(rootKey)}");
            //Debug.WriteLine($"  C Key Info:     {Convert.ToBase64String(rcinfo)}");
            var rckeys = kdf.GenerateKeys(rootKey, rcinfo, 3);
            //Debug.WriteLine($"  C Key Out 0:    {Convert.ToBase64String(rckeys[0])}");
            //Debug.WriteLine($"  C Key Out 1:    {Convert.ToBase64String(rckeys[1])}");
            //Debug.WriteLine($"  C Key Out 2:    {Convert.ToBase64String(rckeys[2])}");
            rootKey = rckeys[0];
            e.ReceivingChain.Initialize(receiveHeaderKey, rckeys[1], rckeys[2]);

            // send chain
            //Debug.WriteLine("  --Sending Chain");
            var scinfo = keyPair.DeriveKey(publicKey);
            //Debug.WriteLine($"  C Input Key:    {Convert.ToBase64String(rootKey)}");
            //Debug.WriteLine($"  C Key Info:     {Convert.ToBase64String(scinfo)}");
            var sckeys = kdf.GenerateKeys(rootKey, scinfo, 3);
            //Debug.WriteLine($"  C Key Out 0:    {Convert.ToBase64String(sckeys[0])}");
            //Debug.WriteLine($"  C Key Out 1:    {Convert.ToBase64String(sckeys[1])}");
            //Debug.WriteLine($"  C Key Out 2:    {Convert.ToBase64String(sckeys[2])}");
            rootKey = sckeys[0];
            e.SendingChain.Initialize(sendHeaderKey, sckeys[1], sckeys[2]);

            // next root key

            //Debug.WriteLine($"Next Root Key:     ({Convert.ToBase64String(rootKey)})");
            e.NextRootKey = rootKey;
            return e;
        }

        public static EcdhRatchetStep[] InitializeClient(IKeyDerivation kdf,
            byte[] rootKey, byte[] publicKey0, byte[] publicKey1, IKeyAgreement keyPair,
            byte[] receiveHeaderKey, byte[] sendHeaderKey,
            IKeyAgreement nextKeyPair)
        {
            //Debug.WriteLine($"--Initialize ECDH Ratchet CLIENT");
            //Debug.WriteLine($"Root Key:           {Convert.ToBase64String(rootKey)}");
            //Debug.WriteLine($"ECDH Public 0:      {Convert.ToBase64String(publicKey0)}");
            //Debug.WriteLine($"ECDH Public 1:      {Convert.ToBase64String(publicKey1)}");
            //Debug.WriteLine($"ECDH Private:      ({Convert.ToBase64String(keyPair.GetPublicKey())})");

            var e0 = new EcdhRatchetStep
            {
                Generation = 0,
                PublicKey = publicKey0,
                PrivateKey = keyPair.Serialize(),
            };

            // receive chain doesn't exist
            //Debug.WriteLine("  --Receiving Chain");

            // send chain
            //Debug.WriteLine("  --Sending Chain");
            var scinfo = keyPair.DeriveKey(publicKey0);
            //Debug.WriteLine($"  C Input Key:    {Convert.ToBase64String(rootKey)}");
            //Debug.WriteLine($"  C Key Info:     {Convert.ToBase64String(scinfo)}");
            var sckeys = kdf.GenerateKeys(rootKey, scinfo, 3);
            //Debug.WriteLine($"  C Key Out 0:    {Convert.ToBase64String(sckeys[0])}");
            //Debug.WriteLine($"  C Key Out 1:    {Convert.ToBase64String(sckeys[1])}");
            //Debug.WriteLine($"  C Key Out 2:    {Convert.ToBase64String(sckeys[2])}");
            rootKey = sckeys[0];
            e0.SendingChain.Initialize(sendHeaderKey, sckeys[1], sckeys[2]);

            // next root key
            //Debug.WriteLine($"Next Root Key:     ({Convert.ToBase64String(rootKey)})");
            e0.NextRootKey = rootKey;

            var e1 = EcdhRatchetStep.InitializeServer(kdf,
                keyPair,
                rootKey,
                publicKey1,
                nextKeyPair,
                receiveHeaderKey,
                e0.SendingChain.NextHeaderKey);

            return new[] { e0, e1 };
        }

        public EcdhRatchetStep Ratchet(IKeyAgreementFactory factory, IKeyDerivation kdf, byte[] publicKey, IKeyAgreement keyPair)
        {
            return EcdhRatchetStep.InitializeServer(kdf,
                factory.Deserialize(PrivateKey),
                NextRootKey,
                publicKey,
                keyPair,
                ReceivingChain.NextHeaderKey,
                SendingChain.NextHeaderKey);
        }

        public void Serialize(BinaryWriter bw)
        {
            void SerializeChain(ref Chain se)
            {
                WriteBuffer(bw, se.HeaderKey);
                WriteBuffer(bw, se.NextHeaderKey);
                if (se.ChainKeys == null)
                {
                    bw.Write(-1);
                }
                else
                {
                    bw.Write(se.ChainKeys.Count);
                    foreach (var (generation, chain) in se.ChainKeys)
                    {
                        bw.Write(generation);
                        WriteBuffer(bw, chain);
                    }
                }
            }

            bw.Write(Generation);
            WriteBuffer(bw, PublicKey);
            WriteBuffer(bw, PrivateKey);
            SerializeChain(ref SendingChain);
            SerializeChain(ref ReceivingChain);
            WriteBuffer(bw, NextRootKey);
        }

        public static EcdhRatchetStep Deserialize(BinaryReader br)
        {
            void DeserializeChain(ref Chain se)
            {
                se.HeaderKey = ReadBuffer(br);
                se.NextHeaderKey = ReadBuffer(br);
                int numChainKeys = br.ReadInt32();
                if (numChainKeys >= 0)
                {
                    se.ChainKeys = new List<(int, byte[])>();
                    for (int i = 0; i < numChainKeys; i++)
                    {
                        se.ChainKeys.Add((br.ReadInt32(), ReadBuffer(br)));
                    }
                }
            }

            var step = new EcdhRatchetStep();
            step.Generation = br.ReadInt32();
            step.PublicKey = ReadBuffer(br);
            step.PrivateKey = ReadBuffer(br);
            DeserializeChain(ref step.SendingChain);
            DeserializeChain(ref step.ReceivingChain);
            step.NextRootKey = ReadBuffer(br);

            return step;
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
