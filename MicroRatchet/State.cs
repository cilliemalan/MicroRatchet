using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace MicroRatchet
{
    internal abstract class State
    {
        protected abstract int Version { get; }
        protected abstract bool IsClient { get; }

        // shared fields
        public long MessageCounter;
        public byte[] RemotePublicKey;
        public byte[] LocalEcdhForInit;
        public byte[] RemoteEcdhForInit;
        public byte[] RootKey;
        public byte[] FirstSendHeaderKey;
        public byte[] FirstReceiveHeaderKey;
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

        public static State Deserialize(byte[] data)
        {
            if (data == null || data.Length == 0) return null;
            
            var isClient = (data[0] & 0x80) != 0;
            var state = isClient ? (State)new ClientState() : new ServerState();

            var version = data[0] & 0x7F;
            if (version != state.Version) throw new Exception("Unsupported version");

            using (MemoryStream ms = new MemoryStream(data, 1, data.Length - 1, false))
            {
                using (BinaryReader br = new BinaryReader(ms))
                {
                    state.ReadPayload(br);
                }
            }

            return state;
        }

        public byte[] Serialize()
        {
            using (var ms = new MemoryStream())
            {
                using (BinaryWriter bw = new BinaryWriter(ms))
                {
                    byte version = (byte)Version;
                    if (IsClient) version |= 0x80;
                    bw.Write(version);

                    WritePayload(bw);

                    Debug.WriteLine($"Serialized {ms.Length} bytes of state");
                    return ms.ToArray();
                }
            }
        }

        public void Burn()
        {
            foreach (var f in GetType().GetFields())
            {
                if (typeof(Array).IsAssignableFrom(f.FieldType))
                {
                    Array.Clear((Array)f.GetValue(this), 0, ((Array)f.GetValue(this)).Length);
                }
            }
        }

        protected virtual void ReadPayload(BinaryReader br)
        {
            MessageCounter = br.ReadInt64();
            RemotePublicKey = ReadBuffer(br);
            LocalEcdhForInit = ReadBuffer(br);
            RemoteEcdhForInit = ReadBuffer(br);
            RootKey = ReadBuffer(br);
            FirstSendHeaderKey = ReadBuffer(br);
            FirstReceiveHeaderKey = ReadBuffer(br);
            Ratchets = EcdhRatchet.Deserialize(br);
        }

        protected virtual void WritePayload(BinaryWriter bw)
        {
            bw.Write(MessageCounter);
            WriteBuffer(bw, RemotePublicKey);
            WriteBuffer(bw, LocalEcdhForInit);
            WriteBuffer(bw, RemoteEcdhForInit);
            WriteBuffer(bw, RootKey);
            WriteBuffer(bw, FirstSendHeaderKey);
            WriteBuffer(bw, FirstReceiveHeaderKey);
            Ratchets.Serialize(bw);
        }

        protected static void WriteBuffer(BinaryWriter bw, byte[] data)
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

        protected static byte[] ReadBuffer(BinaryReader br)
        {
            int c = br.ReadInt32();
            if (c < 0) return null;
            if (c > 0) return br.ReadBytes(c);
            else return new byte[0];
        }
    }
}
