using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;

namespace MicroRatchet
{
    internal abstract class State
    {
        protected abstract int Version { get; }

        // after init
        public EcdhRatchet Ratchets = new EcdhRatchet();

        protected State()
        {
        }

        public static State Initialize(bool isClient)
        {
            if (isClient)
            {
                var state = new ClientState();
                return state;
            }
            else
            {
                var state = new ServerState();
                return state;
            }
        }

        public abstract void Store(IStorageProvider storage);

        protected void ReadRatchet(Stream stream)
        {
            List<EcdhRatchetStep> steps = new List<EcdhRatchetStep>();
            bool last = true;
            bool secondToLast = false;
            for (; ; )
            {
                // check if this is still a ratchet record
                var b = stream.ReadByte();
                stream.Seek(-1, SeekOrigin.Current);
                if ((b & 0b1110_0000) == 0) break;

                if (last)
                {
                    var genbytes = new byte[8];
                    stream.Read(genbytes, 0, 8);
                    genbytes[0] &= 0b0001_1111;
                    var rgeneration = BigEndianBitConverter.ToInt32(genbytes, 0);
                    var sgeneration = BigEndianBitConverter.ToInt32(genbytes, 4);

                    var ecdh = KeyAgreement.Deserialize(stream);
                    var nextRootKey = new byte[32];
                    var sHeaderKey = new byte[32];
                    var sNextHeaderKey = new byte[32];
                    var sChainKey = new byte[32];
                    var rHeaderKey = new byte[32];
                    var rNextHeaderKey = new byte[32];
                    var rChainKey = new byte[32];
                    stream.Read(nextRootKey, 0, 32);
                    stream.Read(sHeaderKey, 0, 32);
                    stream.Read(sNextHeaderKey, 0, 32);
                    stream.Read(sChainKey, 0, 32);
                    stream.Read(rHeaderKey, 0, 32);
                    stream.Read(rNextHeaderKey, 0, 32);
                    stream.Read(rChainKey, 0, 32);
                    steps.Add(EcdhRatchetStep.Create(ecdh, nextRootKey, rgeneration, rHeaderKey, rNextHeaderKey, rChainKey,
                        sgeneration, sHeaderKey, sNextHeaderKey, sChainKey));
                }
                else if (secondToLast)
                {
                    if ((b & 0b1000_0000) != 0)
                    {
                        var genbytes = new byte[8];
                        stream.Read(genbytes, 0, 8);
                        genbytes[0] &= 0b0001_1111;
                        var rgeneration = BigEndianBitConverter.ToInt32(genbytes, 0);
                        var sgeneration = BigEndianBitConverter.ToInt32(genbytes, 4);

                        var sHeaderKey = new byte[32];
                        var sChainKey = new byte[32];
                        var rHeaderKey = new byte[32];
                        var rChainKey = new byte[32];
                        stream.Read(sHeaderKey, 0, 32);
                        stream.Read(sChainKey, 0, 32);
                        stream.Read(rHeaderKey, 0, 32);
                        stream.Read(rChainKey, 0, 32);
                        steps.Add(EcdhRatchetStep.Create(null, null, rgeneration, rHeaderKey, null, rChainKey,
                            sgeneration, sHeaderKey, null, sChainKey));
                    }
                    else
                    {
                        var genbytes = new byte[4];
                        stream.Read(genbytes, 0, 4);
                        genbytes[0] &= 0b0001_1111;
                        var sgeneration = BigEndianBitConverter.ToInt32(genbytes, 0);

                        var sHeaderKey = new byte[32];
                        var sChainKey = new byte[32];
                        stream.Read(sHeaderKey, 0, 32);
                        stream.Read(sChainKey, 0, 32);
                        steps.Add(EcdhRatchetStep.Create(null, null, 0, null, null, null,
                            sgeneration, sHeaderKey, null, sChainKey));
                    }
                }
                else
                {
                    var genbytes = new byte[4];
                    stream.Read(genbytes, 0, 4);
                    genbytes[0] &= 0b0001_1111;
                    var rgeneration = BigEndianBitConverter.ToInt32(genbytes, 0);

                    var rHeaderKey = new byte[32];
                    var rChainKey = new byte[32];
                    stream.Read(rHeaderKey, 0, 32);
                    stream.Read(rChainKey, 0, 32);
                    steps.Add(EcdhRatchetStep.Create(null, null, rgeneration, rHeaderKey, null, rChainKey,
                        0, null, null, null));
                }

                if (secondToLast) { secondToLast = false; }
                if (last) { last = false; secondToLast = true; }
            }

            for (; ; )
            {
                // check if this is still a lost record
                long spaceleft = stream.Length - stream.Position;
                if (spaceleft < 33) break;
                var b = stream.ReadByte();
                if (b == 0) break;
                stream.Seek(-1, SeekOrigin.Current);


                byte[] genbytes = new byte[4];
                byte[] keybytes = new byte[32];
                stream.Read(genbytes, 0, 4);
                stream.Read(keybytes, 0, 32);
                var compoundgen = BigEndianBitConverter.ToUInt32(genbytes, 0);
                int gen = (int)((compoundgen & 0b11111111_00000000_00000000_00000000) >> 24);
                int kgen = (int)(compoundgen & 0b00000000_11111111_11111111_11111111);
                steps[gen - 1].ReceivingChain.LostKeys.Add(kgen, keybytes);
            }

            if (!Ratchets.IsEmpty) Ratchets = new EcdhRatchet();
            Ratchets = new EcdhRatchet();

            foreach (var step in Enumerable.Reverse(steps)) Ratchets.Add(step);
        }

        protected void WriteRatchet(Stream stream)
        {
            bool last = true;
            bool secondToLast = false;
            // store ratchets from newest to oldest
            var reverseRatchets = Ratchets.AsEnumerable().Reverse().ToArray();
            foreach (var ratchet in reverseRatchets)
            {
                if (last)
                {
                    if (ratchet.EcdhKey == null) throw new InvalidOperationException("The last ratchet must have an ecdh private key");
                    if (ratchet.NextRootKey == null) throw new InvalidOperationException("The last ratchet must have the next root key");
                    if (ratchet.SendingChain.NextHeaderKey == null) throw new InvalidOperationException("The last ratchet must have the sending next header key");
                    if (ratchet.SendingChain.HeaderKey == null) throw new InvalidOperationException("The last ratchet must have the sending header key");
                    if (ratchet.SendingChain.ChainKey == null) throw new InvalidOperationException("The last ratchet must have the sending chain key");
                    if (ratchet.ReceivingChain.NextHeaderKey == null) throw new InvalidOperationException("The last ratchet must have the receiving next header key");
                    if (ratchet.ReceivingChain.HeaderKey == null) throw new InvalidOperationException("The last ratchet must have the receiving header key");
                    if (ratchet.ReceivingChain.ChainKey == null) throw new InvalidOperationException("The last ratchet must have the receiving chain key");

                    if (ratchet.NextRootKey.Length != 32) throw new InvalidOperationException("ratchet.NextRootKey must be 32 bytes");
                    if (ratchet.SendingChain.HeaderKey.Length != 32) throw new InvalidOperationException("ratchet.NextRootKey must be 32 bytes");
                    if (ratchet.SendingChain.NextHeaderKey.Length != 32) throw new InvalidOperationException("ratchet.NextRootKey must be 32 bytes");
                    if (ratchet.SendingChain.ChainKey.Length != 32) throw new InvalidOperationException("ratchet.NextRootKey must be 32 bytes");
                    if (ratchet.ReceivingChain.HeaderKey.Length != 32) throw new InvalidOperationException("ratchet.NextRootKey must be 32 bytes");
                    if (ratchet.ReceivingChain.NextHeaderKey.Length != 32) throw new InvalidOperationException("ratchet.NextRootKey must be 32 bytes");
                    if (ratchet.ReceivingChain.ChainKey.Length != 32) throw new InvalidOperationException("ratchet.NextRootKey must be 32 bytes");

                    var rgeneration = BigEndianBitConverter.GetBytes(ratchet.ReceivingChain.Generation);
                    var sgeneration = BigEndianBitConverter.GetBytes(ratchet.SendingChain.Generation);
                    rgeneration[0] |= 0b1110_0000;
                    stream.Write(rgeneration, 0, 4);
                    stream.Write(sgeneration, 0, 4);

                    ratchet.EcdhKey.Serialize(stream);
                    stream.Write(ratchet.NextRootKey, 0, 32);
                    stream.Write(ratchet.SendingChain.HeaderKey, 0, 32);
                    stream.Write(ratchet.SendingChain.NextHeaderKey, 0, 32);
                    stream.Write(ratchet.SendingChain.ChainKey, 0, 32);
                    stream.Write(ratchet.ReceivingChain.HeaderKey, 0, 32);
                    stream.Write(ratchet.ReceivingChain.NextHeaderKey, 0, 32);
                    stream.Write(ratchet.ReceivingChain.ChainKey, 0, 32);
                }
                else if (secondToLast)
                {
                    //if (ratchet.EcdhKey != null) throw new InvalidOperationException("The second last ratchet must NOT have an ecdh private key");
                    if (ratchet.NextRootKey != null) throw new InvalidOperationException("The second last ratchet must NOT have the next root key");
                    if (ratchet.SendingChain.NextHeaderKey != null) throw new InvalidOperationException("The second last ratchet must NOT have the sending next header key");
                    if (ratchet.SendingChain.HeaderKey == null) throw new InvalidOperationException("The second last ratchet must have the sending header key");
                    if (ratchet.SendingChain.ChainKey == null) throw new InvalidOperationException("The second last ratchet must have the sending chain key");
                    if (ratchet.ReceivingChain.ChainKey != null)
                    {
                        if (ratchet.ReceivingChain.NextHeaderKey != null) throw new InvalidOperationException("The second last ratchet must NOT have the receiving next header key");
                        if (ratchet.ReceivingChain.HeaderKey == null) throw new InvalidOperationException("The second last ratchet must have the receiving header key");
                        if (ratchet.ReceivingChain.ChainKey == null) throw new InvalidOperationException("The second last ratchet must have the receiving chain key");

                        if (ratchet.SendingChain.HeaderKey.Length != 32) throw new InvalidOperationException("ratchet.NextRootKey must be 32 bytes");
                        if (ratchet.SendingChain.ChainKey.Length != 32) throw new InvalidOperationException("ratchet.NextRootKey must be 32 bytes");
                        if (ratchet.ReceivingChain.HeaderKey.Length != 32) throw new InvalidOperationException("ratchet.NextRootKey must be 32 bytes");
                        if (ratchet.ReceivingChain.ChainKey.Length != 32) throw new InvalidOperationException("ratchet.NextRootKey must be 32 bytes");

                        var rgeneration = BigEndianBitConverter.GetBytes(ratchet.ReceivingChain.Generation);
                        var sgeneration = BigEndianBitConverter.GetBytes(ratchet.SendingChain.Generation);
                        rgeneration[0] |= 0b1100_0000;
                        stream.Write(rgeneration, 0, 4);
                        stream.Write(sgeneration, 0, 4);

                        stream.Write(ratchet.SendingChain.HeaderKey, 0, 32);
                        stream.Write(ratchet.SendingChain.ChainKey, 0, 32);
                        stream.Write(ratchet.ReceivingChain.HeaderKey, 0, 32);
                        stream.Write(ratchet.ReceivingChain.ChainKey, 0, 32);
                    }
                    else
                    {
                        if (ratchet.ReceivingChain.NextHeaderKey != null) throw new InvalidOperationException("The second last send only ratchet must NOT have the receiving next header key");
                        if (ratchet.ReceivingChain.HeaderKey != null) throw new InvalidOperationException("The second last send only ratchet must NOT have the receiving header key");
                        if (ratchet.ReceivingChain.ChainKey != null) throw new InvalidOperationException("The second last send only ratchet must NOT have the receiving chain key");

                        if (ratchet.SendingChain.HeaderKey.Length != 32) throw new InvalidOperationException("ratchet.NextRootKey must be 32 bytes");
                        if (ratchet.SendingChain.ChainKey.Length != 32) throw new InvalidOperationException("ratchet.NextRootKey must be 32 bytes");

                        var sgeneration = BigEndianBitConverter.GetBytes(ratchet.SendingChain.Generation);
                        sgeneration[0] |= 0b0100_0000;
                        stream.Write(sgeneration, 0, 4);

                        stream.Write(ratchet.SendingChain.HeaderKey, 0, 32);
                        stream.Write(ratchet.SendingChain.ChainKey, 0, 32);
                    }
                }
                else if (ratchet.ReceivingChain.ChainKey != null)
                {
                    if (ratchet.EcdhKey != null) throw new InvalidOperationException("The third last ratchet must NOT have an ecdh private key");
                    if (ratchet.NextRootKey != null) throw new InvalidOperationException("The third last ratchet must NOT have the next root key");
                    if (ratchet.SendingChain.NextHeaderKey != null) throw new InvalidOperationException("The third last ratchet must NOT have the sending next header key");
                    if (ratchet.SendingChain.HeaderKey != null) throw new InvalidOperationException("The third last ratchet must NOT have the sending header key");
                    if (ratchet.SendingChain.ChainKey != null) throw new InvalidOperationException("The third last ratchet must NOT have the sending chain key");
                    if (ratchet.ReceivingChain.NextHeaderKey != null) throw new InvalidOperationException("The third last ratchet must NOT have the receiving next header key");
                    if (ratchet.ReceivingChain.HeaderKey == null) throw new InvalidOperationException("The third last ratchet must have the receiving header key");
                    if (ratchet.ReceivingChain.ChainKey == null) throw new InvalidOperationException("The third last ratchet must have the receiving chain key");

                    if (ratchet.ReceivingChain.HeaderKey.Length != 32) throw new InvalidOperationException("ratchet.NextRootKey must be 32 bytes");
                    if (ratchet.ReceivingChain.ChainKey.Length != 32) throw new InvalidOperationException("ratchet.NextRootKey must be 32 bytes");

                    var rgeneration = BigEndianBitConverter.GetBytes(ratchet.ReceivingChain.Generation);
                    rgeneration[0] |= 0b1000_0000;
                    stream.Write(rgeneration, 0, 4);

                    stream.Write(ratchet.ReceivingChain.HeaderKey, 0, 32);
                    stream.Write(ratchet.ReceivingChain.ChainKey, 0, 32);
                }


                if (secondToLast) { secondToLast = false; }
                if (last) { last = false; secondToLast = true; }
            }

            var lostKeys = reverseRatchets
                .Select((x, i) => (gen: i + 1, ratchet: x))
                .Where(x => x.ratchet.ReceivingChain.LostKeys != null)
                .SelectMany(x => x.ratchet.ReceivingChain.LostKeys.OrderByDescending(k => k.Key).Select((k, ki) => (nkey: ki, x.gen, kgen: k.Key, key: k.Value)))
                .OrderBy(x => (x.nkey, -x.gen))
                .Take(SymmetricRacthet.NumLostKeysToStore)
                .Select((a) => (a.gen, a.kgen, a.key))
                .ToArray();

            int numLostKeysStored = 0;
            foreach (var (gen, kgen, key) in lostKeys)
            {
                if (key.Length != 32) throw new InvalidOperationException("keys must be 32 bytes");

                long spaceleft = stream.Length - stream.Position;
                if (spaceleft < 33)
                {
                    break;
                }

                if (numLostKeysStored > SymmetricRacthet.NumLostKeysToStore)
                {
                    stream.WriteByte(0);
                    break;
                }

                // store 1 bit indicator, 7 bits rgen, 24 bits cgen
                var compoundkgen = (uint)gen << 24 | ((uint)kgen & 0b00000000_11111111_11111111_11111111);
                compoundkgen &= 0b01111111_11111111_11111111_11111111;
                var genbytes = BigEndianBitConverter.GetBytes(compoundkgen);
                stream.Write(genbytes, 0, 4);
                stream.Write(key, 0, 32);

                numLostKeysStored++;
            }

            if (stream.Length - stream.Position >= 1)
            {
                stream.WriteByte(0);
            }
        }
    }
}
