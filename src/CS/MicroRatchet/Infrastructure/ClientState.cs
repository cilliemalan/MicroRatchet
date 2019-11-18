﻿using System;
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

        public override void Store(Stream memory, int numberOfRatchetsToStore)
        {
            if (memory == null) throw new ArgumentNullException(nameof(memory));

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
        }

        private void LoadInternal(Stream memory, IKeyAgreementFactory kexFac)
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
        }

        public static ClientState Load(byte[] source, IKeyAgreementFactory kexFac, int keySize = 32)
        {
            if (source == null) throw new ArgumentNullException(nameof(source));
            if (kexFac == null) throw new ArgumentNullException(nameof(kexFac));

            using var ms = new MemoryStream(source);
            return Load(ms, kexFac, keySize);
        }

        public static ClientState Load(Stream source, IKeyAgreementFactory kexFac, int keySize = 32)
        {
            if (source == null) throw new ArgumentNullException(nameof(source));
            if (kexFac == null) throw new ArgumentNullException(nameof(kexFac));

            if (keySize != 32) throw new InvalidOperationException("Invalid key size");
            var state = new ClientState(keySize);
            state.LoadInternal(source, kexFac);
            return state;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                InitializationNonce?.Shred();
                InitializationNonce = null;

                (LocalEcdhForInit as IDisposable)?.Dispose();
                LocalEcdhForInit = null;
            }
        }
    }
}
