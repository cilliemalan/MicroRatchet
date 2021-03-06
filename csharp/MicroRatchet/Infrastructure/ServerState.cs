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

        public byte[] ClientInitializationNonce;
        public byte[] RootKey;
        public byte[] FirstSendHeaderKey;
        public byte[] FirstReceiveHeaderKey;
        public IKeyAgreement LocalEcdhRatchetStep0;
        public IKeyAgreement LocalEcdhRatchetStep1;
        public byte[] ClientPublicKey;

        internal ServerState(int keySize)
            : base(keySize)
        {

        }

        // used a few times
        public byte[] NextInitializationNonce;

        public override void Store(Stream memory, int numberOfRatchetsToStore)
        {
            if (memory == null) throw new ArgumentNullException(nameof(memory));

            byte versionByte = (byte)Version;

            bool hasInit = NextInitializationNonce != null;
            bool hasRatchet = Ratchets != null && Ratchets.Count != 0;
            bool hasEcdh = LocalEcdhRatchetStep0 != null && LocalEcdhRatchetStep1 != null;
            bool hasClientPublicKey = ClientPublicKey != null;

            if (hasInit) versionByte |= 0b0001_0000;
            if (hasRatchet) versionByte |= 0b0010_0000;
            if (hasEcdh) versionByte |= 0b0100_0000;
            if (hasClientPublicKey) versionByte |= 0b1000_0000;
            memory.WriteByte(versionByte);

            if (hasInit)
            {
                if (ClientInitializationNonce != null && ClientInitializationNonce.Length != MicroRatchetContext.InitializationNonceSize) throw new InvalidOperationException($"ClientInitializationNonce must be {MicroRatchetContext.InitializationNonceSize} bytes");
                if (RootKey != null && RootKey.Length != KeySizeInBytes) throw new InvalidOperationException($"RootKey must be {KeySizeInBytes} bytes");
                if (FirstSendHeaderKey != null && FirstSendHeaderKey.Length != KeySizeInBytes) throw new InvalidOperationException($"FirstSendHeaderKey must be {KeySizeInBytes} bytes");
                if (FirstReceiveHeaderKey != null && FirstReceiveHeaderKey.Length != KeySizeInBytes) throw new InvalidOperationException($"FirstReceiveHeaderKey must be {KeySizeInBytes} bytes");
                if (NextInitializationNonce != null && NextInitializationNonce.Length != MicroRatchetContext.InitializationNonceSize) throw new InvalidOperationException($"NextInitializationNonce must be {MicroRatchetContext.InitializationNonceSize} bytes");

                if (ClientInitializationNonce != null) memory.Write(ClientInitializationNonce, 0, MicroRatchetContext.InitializationNonceSize); else memory.Seek(MicroRatchetContext.InitializationNonceSize, SeekOrigin.Current);
                if (RootKey != null) memory.Write(RootKey, 0, KeySizeInBytes); else memory.Seek(KeySizeInBytes, SeekOrigin.Current);
                if (FirstSendHeaderKey != null) memory.Write(FirstSendHeaderKey, 0, KeySizeInBytes); else memory.Seek(KeySizeInBytes, SeekOrigin.Current);
                if (FirstReceiveHeaderKey != null) memory.Write(FirstReceiveHeaderKey, 0, KeySizeInBytes); else memory.Seek(KeySizeInBytes, SeekOrigin.Current);
                if (NextInitializationNonce != null) memory.Write(NextInitializationNonce, 0, MicroRatchetContext.InitializationNonceSize); else memory.Seek(MicroRatchetContext.InitializationNonceSize, SeekOrigin.Current);
            }
            if (hasEcdh)
            {
                LocalEcdhRatchetStep0.Serialize(memory);
                LocalEcdhRatchetStep1.Serialize(memory);
            }
            if (hasClientPublicKey)
            {
                if (ClientPublicKey.Length != 32) throw new InvalidOperationException("Client public key must be 32 bytes");
                memory.Write(ClientPublicKey, 0, 32);
            }
            if (hasRatchet)
            {
                WriteRatchet(memory, numberOfRatchetsToStore);
            }
            Log.Verbose($"Wrote {memory.Position} bytes of server state");
        }

        private void LoadInternal(Stream memory, IKeyAgreementFactory kexFac)
        {
            var versionInt = memory.ReadByte();
            if (versionInt < 0) throw new EndOfStreamException();
            var versionByte = (byte)versionInt;

            bool isClient = (versionByte & 0b0000_1000) != 0;
            bool hasInit = (versionByte & 0b0001_0000) != 0;
            bool hasRatchet = (versionByte & 0b0010_0000) != 0;
            bool hasEcdh = (versionByte & 0b0100_0000) != 0;
            bool hasClientPublicKey = (versionByte & 0b1000_0000) != 0;

            if (isClient) throw new InvalidOperationException("The provided state is not server state");

            if (hasInit)
            {
                if (ClientInitializationNonce == null || ClientInitializationNonce.Length != MicroRatchetContext.InitializationNonceSize) ClientInitializationNonce = new byte[MicroRatchetContext.InitializationNonceSize];
                if (RootKey == null || RootKey.Length != KeySizeInBytes) RootKey = new byte[KeySizeInBytes];
                if (FirstSendHeaderKey == null || FirstSendHeaderKey.Length != KeySizeInBytes) FirstSendHeaderKey = new byte[KeySizeInBytes];
                if (FirstReceiveHeaderKey == null || FirstReceiveHeaderKey.Length != KeySizeInBytes) FirstReceiveHeaderKey = new byte[KeySizeInBytes];
                if (NextInitializationNonce == null || NextInitializationNonce.Length != MicroRatchetContext.InitializationNonceSize) NextInitializationNonce = new byte[MicroRatchetContext.InitializationNonceSize];

                memory.Read(ClientInitializationNonce, 0, MicroRatchetContext.InitializationNonceSize);
                memory.Read(RootKey, 0, KeySizeInBytes);
                memory.Read(FirstSendHeaderKey, 0, KeySizeInBytes);
                memory.Read(FirstReceiveHeaderKey, 0, KeySizeInBytes);
                memory.Read(NextInitializationNonce, 0, MicroRatchetContext.InitializationNonceSize);
            }

            if (hasEcdh)
            {
                LocalEcdhRatchetStep0 = kexFac.Deserialize(memory);
                LocalEcdhRatchetStep1 = kexFac.Deserialize(memory);
            }

            if (hasClientPublicKey)
            {
                if (ClientPublicKey == null || ClientPublicKey.Length != KeySizeInBytes) ClientPublicKey = new byte[32];
                memory.Read(ClientPublicKey, 0, 32);
            }

            if (hasRatchet)
            {
                ReadRatchet(memory, kexFac);
            }

            Log.Verbose($"Read {memory.Position} bytes of server state");
        }

        public static new ServerState Load(byte[] source, IKeyAgreementFactory kexFac, int keySize = 32)
        {
            if (source == null) throw new ArgumentNullException(nameof(source));
            if (kexFac == null) throw new ArgumentNullException(nameof(kexFac));

            using var ms = new MemoryStream(source);
            return Load(ms, kexFac, keySize);
        }

        public static new ServerState Load(Stream source, IKeyAgreementFactory kexFac, int keySize = 32)
        {
            if (source == null) throw new ArgumentNullException(nameof(source));
            if (kexFac == null) throw new ArgumentNullException(nameof(kexFac));

            if (keySize != 32) throw new InvalidOperationException("Invalid key size");
            var state = new ServerState(keySize);
            state.LoadInternal(source, kexFac);
            return state;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                ClientInitializationNonce?.Shred();
                ClientInitializationNonce = null;
                RootKey?.Shred();
                RootKey = null;
                FirstSendHeaderKey?.Shred();
                FirstSendHeaderKey = null;
                FirstReceiveHeaderKey?.Shred();
                FirstReceiveHeaderKey = null;
                ClientPublicKey?.Shred();
                ClientPublicKey = null;

                (LocalEcdhRatchetStep0 as IDisposable)?.Dispose();
                LocalEcdhRatchetStep0 = null;
                (LocalEcdhRatchetStep1 as IDisposable)?.Dispose();
                LocalEcdhRatchetStep1 = null;
            }
        }
    }
}
