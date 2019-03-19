using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace MicroRatchet
{
    internal class ClientState : State
    {
        protected override int Version => 1;

        public override bool IsInitialized => base.IsInitialized && InitializationNonce == null;

        internal ClientState(int keySizeInBytes)
            : base(keySizeInBytes)
        {

        }

        // used throughout init
        public byte[] InitializationNonce;

        // used twice
        public IKeyAgreement LocalEcdhForInit;

        private long StoreInternal(IStorageProvider storage, int numberOfRatchetsToStore, int numLostKeysToStore)
        {
            using (var memory = storage.LockCold())
            {
                byte versionByte = (byte)Version;

                bool hasInit = InitializationNonce != null;
                bool hasRatchet = Ratchets != null && Ratchets.Count != 0;
                bool hasEcdh = LocalEcdhForInit != null;

                if (hasInit) versionByte |= 0b0001_0000;
                if (hasRatchet) versionByte |= 0b0010_0000;
                if (hasEcdh) versionByte |= 0b0100_0000;
                memory.WriteByte(versionByte);

                if (hasInit)
                {
                    if (InitializationNonce.Length != 32) throw new InvalidOperationException($"InitializationNonce must be 32 bytes");

                    if (InitializationNonce != null) memory.Write(InitializationNonce, 0, 32); else memory.Seek(32, SeekOrigin.Current);
                }

                if (hasEcdh)
                {
                    LocalEcdhForInit.Serialize(memory);
                }

                if (hasRatchet)
                {
                    WriteRatchet(memory, numberOfRatchetsToStore, numLostKeysToStore);
                }

                Debug.WriteLine($"Wrote {memory.Position} bytes of client state");
                return memory.Position;
            }
        }

        public override void Store(IStorageProvider storage, int numberOfRatchetsToStore, int numLostKeysToStore)
        {
            StoreInternal(storage, numberOfRatchetsToStore, numLostKeysToStore);
        }

        private long LoadInternal(IStorageProvider storage, IKeyAgreementFactory kexFac)
        {
            using (var memory = storage.LockCold())
            {
                var versionInt = memory.ReadByte();
                if (versionInt < 0) throw new EndOfStreamException();
                var versionByte = (byte)versionInt;

                bool hasInit = (versionByte & 0b0001_0000) != 0;
                bool hasRatchet = (versionByte & 0b0010_0000) != 0;
                bool hasEcdh = (versionByte & 0b0100_0000) != 0;

                if (hasInit)
                {
                    if (InitializationNonce == null || InitializationNonce.Length != 32) InitializationNonce = new byte[32];

                    memory.Read(InitializationNonce, 0, 32);
                }

                if (hasEcdh)
                {
                    LocalEcdhForInit = KeyAgreement.Deserialize(memory);
                }

                if (hasRatchet)
                {
                    ReadRatchet(memory, kexFac);
                }

                Debug.WriteLine($"Read {memory.Position} bytes of client state");
                return memory.Position;
            }
        }

        public static ClientState Load(IStorageProvider storage, IKeyAgreementFactory kexFac, int keySize)
        {
            var state = new ClientState(keySize);
            state.LoadInternal(storage, kexFac);
            return state;
        }
    }
}
