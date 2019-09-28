using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace MicroRatchet
{
    /// <summary>
    /// 
    /// </summary>
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

        private long StoreInternal(IStorageProvider storage, int numberOfRatchetsToStore)
        {
            using (var memory = storage.Lock())
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
                    if (InitializationNonce.Length != MicroRatchetClient.InitializationNonceSize) throw new InvalidOperationException($"InitializationNonce must be {MicroRatchetClient.InitializationNonceSize} bytes");

                    if (InitializationNonce != null) memory.Write(InitializationNonce, 0, MicroRatchetClient.InitializationNonceSize); else memory.Seek(MicroRatchetClient.InitializationNonceSize, SeekOrigin.Current);
                }

                if (hasEcdh)
                {
                    LocalEcdhForInit.Serialize(memory);
                }

                if (hasRatchet)
                {
                    WriteRatchet(memory, numberOfRatchetsToStore);
                }

                Log.Verbose($"Wrote {memory.Position} bytes of client state");
                return memory.Position;
            }
        }

        public override void Store(IStorageProvider storage, int numberOfRatchetsToStore)
        {
            StoreInternal(storage, numberOfRatchetsToStore);
        }

        private long LoadInternal(IStorageProvider storage, IKeyAgreementFactory kexFac)
        {
            using (var memory = storage.Lock())
            {
                var versionInt = memory.ReadByte();
                if (versionInt < 0) throw new EndOfStreamException();
                var versionByte = (byte)versionInt;

                bool hasInit = (versionByte & 0b0001_0000) != 0;
                bool hasRatchet = (versionByte & 0b0010_0000) != 0;
                bool hasEcdh = (versionByte & 0b0100_0000) != 0;

                if (hasInit)
                {
                    if (InitializationNonce == null || InitializationNonce.Length != MicroRatchetClient.InitializationNonceSize) InitializationNonce = new byte[MicroRatchetClient.InitializationNonceSize];

                    memory.Read(InitializationNonce, 0, MicroRatchetClient.InitializationNonceSize);
                }

                if (hasEcdh)
                {
                    
                    LocalEcdhForInit = kexFac.Deserialize(memory);
                }

                if (hasRatchet)
                {
                    ReadRatchet(memory, kexFac);
                }

                Log.Verbose($"Read {memory.Position} bytes of client state");
                return memory.Position;
            }
        }

        public static ClientState Load(IStorageProvider storage, IKeyAgreementFactory kexFac, int keySize = 32)
        {
            if (keySize != 32) throw new InvalidOperationException("Invalid key size");
            var state = new ClientState(keySize);
            state.LoadInternal(storage, kexFac);
            return state;
        }
    }
}
