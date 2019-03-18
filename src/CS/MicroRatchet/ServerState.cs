﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace MicroRatchet
{
    internal class ServerState : State
    {
        protected override int Version => 1;

        // used only once
        public byte[] RootKey;
        public byte[] FirstSendHeaderKey;
        public byte[] FirstReceiveHeaderKey;
        public IKeyAgreement LocalEcdhRatchetStep0;
        public IKeyAgreement LocalEcdhRatchetStep1;

        internal ServerState(int keySize)
            : base(keySize)
        {

        }

        // used a few times
        public byte[] NextInitializationNonce;

        public override void Store(IStorageProvider storage, int numberOfRatchetsToStore, int numLostKeysToStore)
        {
            using (var memory = storage.LockCold())
            {
                byte versionByte = (byte)Version;

                bool hasInit = NextInitializationNonce != null;
                bool hasRatchet = Ratchets != null && Ratchets.Count != 0;
                bool hasEcdh = LocalEcdhRatchetStep0 != null && LocalEcdhRatchetStep1 != null;

                if (hasInit) versionByte |= 0b0001_0000;
                if (hasRatchet) versionByte |= 0b0010_0000;
                if (hasEcdh) versionByte |= 0b0100_0000;
                memory.WriteByte(versionByte);

                if (hasInit)
                {
                    if (RootKey != null && RootKey.Length != KeySizeInBytes) throw new InvalidOperationException($"RootKey must be {KeySizeInBytes} bytes");
                    if (FirstSendHeaderKey != null && FirstSendHeaderKey.Length != KeySizeInBytes) throw new InvalidOperationException($"FirstSendHeaderKey must be {KeySizeInBytes} bytes");
                    if (FirstReceiveHeaderKey != null && FirstReceiveHeaderKey.Length != KeySizeInBytes) throw new InvalidOperationException($"FirstReceiveHeaderKey must be {KeySizeInBytes} bytes");
                    if (NextInitializationNonce != null && NextInitializationNonce.Length != 32) throw new InvalidOperationException($"NextInitializationNonce must be 32 bytes");

                    if (RootKey != null) memory.Write(RootKey, 0, KeySizeInBytes); else memory.Seek(KeySizeInBytes, SeekOrigin.Current);
                    if (FirstSendHeaderKey != null) memory.Write(FirstSendHeaderKey, 0, KeySizeInBytes); else memory.Seek(KeySizeInBytes, SeekOrigin.Current);
                    if (FirstReceiveHeaderKey != null) memory.Write(FirstReceiveHeaderKey, 0, KeySizeInBytes); else memory.Seek(KeySizeInBytes, SeekOrigin.Current);
                    if (NextInitializationNonce != null) memory.Write(NextInitializationNonce, 0, 32); else memory.Seek(32, SeekOrigin.Current);
                }
                if (hasEcdh)
                {
                    LocalEcdhRatchetStep0.Serialize(memory);
                    LocalEcdhRatchetStep1.Serialize(memory);
                }

                if (hasRatchet)
                {
                    WriteRatchet(memory, numberOfRatchetsToStore, numLostKeysToStore);
                }
                Debug.WriteLine($"Wrote {memory.Position} bytes of server state");
            }
        }

        private void LoadInternal(IStorageProvider storage, IKeyAgreementFactory kexFac)
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
                    if (RootKey == null || RootKey.Length != KeySizeInBytes) RootKey = new byte[KeySizeInBytes];
                    if (FirstSendHeaderKey == null || FirstSendHeaderKey.Length != KeySizeInBytes) FirstSendHeaderKey = new byte[KeySizeInBytes];
                    if (FirstReceiveHeaderKey == null || FirstReceiveHeaderKey.Length != KeySizeInBytes) FirstReceiveHeaderKey = new byte[KeySizeInBytes];
                    if (NextInitializationNonce == null || NextInitializationNonce.Length != 32) NextInitializationNonce = new byte[32];

                    memory.Read(RootKey, 0, KeySizeInBytes);
                    memory.Read(FirstSendHeaderKey, 0, KeySizeInBytes);
                    memory.Read(FirstReceiveHeaderKey, 0, KeySizeInBytes);
                    memory.Read(NextInitializationNonce, 0, 32);
                }

                if (hasEcdh)
                {
                    LocalEcdhRatchetStep0 = KeyAgreement.Deserialize(memory);
                    LocalEcdhRatchetStep1 = KeyAgreement.Deserialize(memory);
                }

                if (hasRatchet)
                {
                    ReadRatchet(memory, kexFac);
                }
                Debug.WriteLine($"Read {memory.Position} bytes of server state");
            }
        }

        public static ServerState Load(IStorageProvider storage, IKeyAgreementFactory kexFac, int keySize)
        {
            var state = new ServerState(keySize);
            state.LoadInternal(storage, kexFac);
            return state;
        }
    }
}