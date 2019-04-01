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
        protected int KeySizeInBytes { get; }

        protected abstract int Version { get; }

        public virtual bool IsInitialized => (Ratchets?.Count ?? 0) != 0;
        
        public EcdhRatchet Ratchets = new EcdhRatchet();

        protected State(int keySizeInBytes)
        {
            KeySizeInBytes = keySizeInBytes;
        }

        public static State Initialize(bool isClient, int keySizeInBytes)
        {
            if (isClient)
            {
                var state = new ClientState(keySizeInBytes);
                return state;
            }
            else
            {
                var state = new ServerState(keySizeInBytes);
                return state;
            }
        }

        public abstract void Store(IStorageProvider storage, int numberOfRatchetsToStore, int numLostKeysToStore);

        protected void ReadRatchet(Stream stream, IKeyAgreementFactory kexFac)
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
                    var rgeneration = BigEndianBitConverter.ToInt32(genbytes, 0); // hot
                    var sgeneration = BigEndianBitConverter.ToInt32(genbytes, 4); // hot and important

                    var ecdh = kexFac.Deserialize(stream);
                    var nextRootKey = new byte[KeySizeInBytes];
                    var sHeaderKey = new byte[KeySizeInBytes];
                    var sNextHeaderKey = new byte[KeySizeInBytes];
                    var sChainKey = new byte[KeySizeInBytes];
                    var rHeaderKey = new byte[KeySizeInBytes];
                    var rNextHeaderKey = new byte[KeySizeInBytes];
                    var rChainKey = new byte[KeySizeInBytes];
                    stream.Read(nextRootKey, 0, KeySizeInBytes); // cold
                    stream.Read(sHeaderKey, 0, KeySizeInBytes); // cold
                    stream.Read(sNextHeaderKey, 0, KeySizeInBytes); // cold
                    stream.Read(sChainKey, 0, KeySizeInBytes); // hot and important
                    stream.Read(rHeaderKey, 0, KeySizeInBytes); // cold
                    stream.Read(rNextHeaderKey, 0, KeySizeInBytes); // cold
                    stream.Read(rChainKey, 0, KeySizeInBytes); // hot
                    steps.Add(EcdhRatchetStep.Create(ecdh, nextRootKey, rgeneration, rHeaderKey, rNextHeaderKey, rChainKey,
                        sgeneration, sHeaderKey, sNextHeaderKey, sChainKey));
                }
                else if (secondToLast)
                {
                    if ((b & 0b1000_0000) != 0)
                    {
                        // send and receive chain
                        var genbytes = new byte[8];
                        stream.Read(genbytes, 0, 8);
                        genbytes[0] &= 0b0001_1111;
                        var rgeneration = BigEndianBitConverter.ToInt32(genbytes, 0); // hot
                        var sgeneration = BigEndianBitConverter.ToInt32(genbytes, 4); // hot and important

                        var sHeaderKey = new byte[KeySizeInBytes];
                        var sChainKey = new byte[KeySizeInBytes];
                        var rHeaderKey = new byte[KeySizeInBytes];
                        var rChainKey = new byte[KeySizeInBytes];
                        stream.Read(sHeaderKey, 0, KeySizeInBytes); // cold
                        stream.Read(sChainKey, 0, KeySizeInBytes); // hot and important
                        stream.Read(rHeaderKey, 0, KeySizeInBytes); // cold
                        stream.Read(rChainKey, 0, KeySizeInBytes); // hot
                        steps.Add(EcdhRatchetStep.Create(null, null, rgeneration, rHeaderKey, null, rChainKey,
                            sgeneration, sHeaderKey, null, sChainKey));
                    }
                    else
                    {
                        // only sending chain - the client starts with only a sending chain as the first generation
                        var genbytes = new byte[4];
                        stream.Read(genbytes, 0, 4);
                        genbytes[0] &= 0b0001_1111;
                        var sgeneration = BigEndianBitConverter.ToInt32(genbytes, 0); // hot and important

                        var sHeaderKey = new byte[KeySizeInBytes];
                        var sChainKey = new byte[KeySizeInBytes];
                        stream.Read(sHeaderKey, 0, KeySizeInBytes); // cold
                        stream.Read(sChainKey, 0, KeySizeInBytes); // hot and important
                        steps.Add(EcdhRatchetStep.Create(null, null, 0, null, null, null,
                            sgeneration, sHeaderKey, null, sChainKey));
                    }
                }
                else
                {
                    var genbytes = new byte[4];
                    stream.Read(genbytes, 0, 4);
                    genbytes[0] &= 0b0001_1111;
                    var rgeneration = BigEndianBitConverter.ToInt32(genbytes, 0); // hot

                    var rHeaderKey = new byte[KeySizeInBytes];
                    var rChainKey = new byte[KeySizeInBytes];
                    stream.Read(rHeaderKey, 0, KeySizeInBytes); // cold
                    stream.Read(rChainKey, 0, KeySizeInBytes); // hot
                    steps.Add(EcdhRatchetStep.Create(null, null, rgeneration, rHeaderKey, null, rChainKey,
                        0, null, null, null));
                }

                if (secondToLast) { secondToLast = false; }
                if (last) { last = false; secondToLast = true; }
            }

            for (; ; ) // 36 bytes per key
            {
                // check if this is still a lost record
                long spaceleft = stream.Length - stream.Position;
                if (spaceleft < 33) break;
                var b = stream.ReadByte();
                if (b == 0) break;
                stream.Seek(-1, SeekOrigin.Current);


                byte[] genbytes = new byte[4];
                byte[] keybytes = new byte[KeySizeInBytes];
                stream.Read(genbytes, 0, 4);
                stream.Read(keybytes, 0, KeySizeInBytes);
                var compoundgen = BigEndianBitConverter.ToUInt32(genbytes, 0);
                int gen = (int)((compoundgen & 0b11111111_00000000_00000000_00000000) >> 24);
                int kgen = (int)(compoundgen & 0b00000000_11111111_11111111_11111111);
                steps[gen - 1].ReceivingChain.LostKeys.Add(kgen, keybytes);
            }

            if (!Ratchets.IsEmpty) Ratchets = new EcdhRatchet();
            Ratchets = new EcdhRatchet();

            foreach (var step in Enumerable.Reverse(steps)) Ratchets.Add(step);
        }

        protected void WriteRatchet(Stream stream, int numberOfRatchetsToStore, int numLostKeysToStore)
        {
            bool last = true;
            bool secondToLast = false;
            // store ratchets from newest to oldest
            var reverseRatchets = Ratchets.AsEnumerable().Reverse().Take(numberOfRatchetsToStore).ToArray();
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

                    if (ratchet.NextRootKey.Length != KeySizeInBytes) throw new InvalidOperationException($"ratchet.NextRootKey must be {KeySizeInBytes} bytes");
                    if (ratchet.SendingChain.HeaderKey.Length != KeySizeInBytes) throw new InvalidOperationException($"ratchet.NextRootKey must be {KeySizeInBytes} bytes");
                    if (ratchet.SendingChain.NextHeaderKey.Length != KeySizeInBytes) throw new InvalidOperationException($"ratchet.NextRootKey must be {KeySizeInBytes} bytes");
                    if (ratchet.SendingChain.ChainKey.Length != KeySizeInBytes) throw new InvalidOperationException($"ratchet.NextRootKey must be {KeySizeInBytes} bytes");
                    if (ratchet.ReceivingChain.HeaderKey.Length != KeySizeInBytes) throw new InvalidOperationException($"ratchet.NextRootKey must be {KeySizeInBytes} bytes");
                    if (ratchet.ReceivingChain.NextHeaderKey.Length != KeySizeInBytes) throw new InvalidOperationException($"ratchet.NextRootKey must be {KeySizeInBytes} bytes");
                    if (ratchet.ReceivingChain.ChainKey.Length != KeySizeInBytes) throw new InvalidOperationException($"ratchet.NextRootKey must be {KeySizeInBytes} bytes");

                    var rgeneration = BigEndianBitConverter.GetBytes(ratchet.ReceivingChain.Generation);
                    var sgeneration = BigEndianBitConverter.GetBytes(ratchet.SendingChain.Generation);
                    rgeneration[0] |= 0b1110_0000;
                    stream.Write(rgeneration, 0, 4);
                    stream.Write(sgeneration, 0, 4);

                    ratchet.EcdhKey.Serialize(stream);
                    stream.Write(ratchet.NextRootKey, 0, KeySizeInBytes);
                    stream.Write(ratchet.SendingChain.HeaderKey, 0, KeySizeInBytes);
                    stream.Write(ratchet.SendingChain.NextHeaderKey, 0, KeySizeInBytes);
                    stream.Write(ratchet.SendingChain.ChainKey, 0, KeySizeInBytes);
                    stream.Write(ratchet.ReceivingChain.HeaderKey, 0, KeySizeInBytes);
                    stream.Write(ratchet.ReceivingChain.NextHeaderKey, 0, KeySizeInBytes);
                    stream.Write(ratchet.ReceivingChain.ChainKey, 0, KeySizeInBytes);
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

                        if (ratchet.SendingChain.HeaderKey.Length != KeySizeInBytes) throw new InvalidOperationException($"ratchet.NextRootKey must be {KeySizeInBytes} bytes");
                        if (ratchet.SendingChain.ChainKey.Length != KeySizeInBytes) throw new InvalidOperationException($"ratchet.NextRootKey must be {KeySizeInBytes} bytes");
                        if (ratchet.ReceivingChain.HeaderKey.Length != KeySizeInBytes) throw new InvalidOperationException($"ratchet.NextRootKey must be {KeySizeInBytes} bytes");
                        if (ratchet.ReceivingChain.ChainKey.Length != KeySizeInBytes) throw new InvalidOperationException($"ratchet.NextRootKey must be {KeySizeInBytes} bytes");

                        var rgeneration = BigEndianBitConverter.GetBytes(ratchet.ReceivingChain.Generation);
                        var sgeneration = BigEndianBitConverter.GetBytes(ratchet.SendingChain.Generation);
                        rgeneration[0] |= 0b1100_0000;
                        stream.Write(rgeneration, 0, 4);
                        stream.Write(sgeneration, 0, 4);

                        stream.Write(ratchet.SendingChain.HeaderKey, 0, KeySizeInBytes);
                        stream.Write(ratchet.SendingChain.ChainKey, 0, KeySizeInBytes);
                        stream.Write(ratchet.ReceivingChain.HeaderKey, 0, KeySizeInBytes);
                        stream.Write(ratchet.ReceivingChain.ChainKey, 0, KeySizeInBytes);
                    }
                    else
                    {
                        if (ratchet.ReceivingChain.NextHeaderKey != null) throw new InvalidOperationException("The second last send only ratchet must NOT have the receiving next header key");
                        if (ratchet.ReceivingChain.HeaderKey != null) throw new InvalidOperationException("The second last send only ratchet must NOT have the receiving header key");
                        if (ratchet.ReceivingChain.ChainKey != null) throw new InvalidOperationException("The second last send only ratchet must NOT have the receiving chain key");

                        if (ratchet.SendingChain.HeaderKey.Length != KeySizeInBytes) throw new InvalidOperationException($"ratchet.SendingChain.HeaderKey must be {KeySizeInBytes} bytes");
                        if (ratchet.SendingChain.ChainKey.Length != KeySizeInBytes) throw new InvalidOperationException($"ratchet.SendingChain.ChainKey must be {KeySizeInBytes} bytes");

                        var sgeneration = BigEndianBitConverter.GetBytes(ratchet.SendingChain.Generation);
                        sgeneration[0] |= 0b0100_0000;
                        stream.Write(sgeneration, 0, 4);

                        stream.Write(ratchet.SendingChain.HeaderKey, 0, KeySizeInBytes);
                        stream.Write(ratchet.SendingChain.ChainKey, 0, KeySizeInBytes);
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

                    if (ratchet.ReceivingChain.HeaderKey.Length != KeySizeInBytes) throw new InvalidOperationException($"ratchet.ReceivingChain.HeaderKey must be {KeySizeInBytes} bytes");
                    if (ratchet.ReceivingChain.ChainKey.Length != KeySizeInBytes) throw new InvalidOperationException($"ratchet.ReceivingChain.ChainKey must be {KeySizeInBytes} bytes");

                    var rgeneration = BigEndianBitConverter.GetBytes(ratchet.ReceivingChain.Generation);
                    rgeneration[0] |= 0b1000_0000;
                    stream.Write(rgeneration, 0, 4);

                    stream.Write(ratchet.ReceivingChain.HeaderKey, 0, KeySizeInBytes);
                    stream.Write(ratchet.ReceivingChain.ChainKey, 0, KeySizeInBytes);
                }


                if (secondToLast) { secondToLast = false; }
                if (last) { last = false; secondToLast = true; }
            }

            var lostKeys = reverseRatchets
                .Select((x, i) => (gen: i + 1, ratchet: x))
                .Where(x => x.ratchet.ReceivingChain.LostKeys != null)
                .SelectMany(x => x.ratchet.ReceivingChain.LostKeys.OrderByDescending(k => k.Key).Select((k, ki) => (nkey: ki, x.gen, kgen: k.Key, key: k.Value)))
                .OrderBy(x => (x.nkey, -x.gen))
                .Take(numLostKeysToStore)
                .Select((a) => (a.gen, a.kgen, a.key))
                .ToArray();

            int numLostKeysStored = 0;
            foreach (var (gen, kgen, key) in lostKeys)
            {
                if (key.Length != KeySizeInBytes) throw new InvalidOperationException($"keys must be {KeySizeInBytes} bytes");

                long spaceleft = stream.Length - stream.Position;
                if (spaceleft < (KeySizeInBytes + 1))
                {
                    break;
                }

                if (numLostKeysStored > numLostKeysToStore)
                {
                    stream.WriteByte(0);
                    break;
                }

                // store 1 bit indicator, 7 bits rgen, 24 bits cgen
                var compoundkgen = (uint)gen << 24 | ((uint)kgen & 0b00000000_11111111_11111111_11111111);
                compoundkgen &= 0b01111111_11111111_11111111_11111111;
                var genbytes = BigEndianBitConverter.GetBytes(compoundkgen);
                stream.Write(genbytes, 0, 4);
                stream.Write(key, 0, KeySizeInBytes);

                numLostKeysStored++;
            }

            if (stream.Length - stream.Position >= 1)
            {
                stream.WriteByte(0);
            }
        }
    }
}
