using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace MicroRatchet
{
    internal class ServerState : State
    {
        protected override int Version => 1;
        protected override bool IsClient => false;

        // not used at all
        //public byte[] RemotePublicKey;

        // used transiently
        //public byte[] InitializationNonce;
        //public byte[] RemoteEcdhForInit;

        // used only once
        public byte[] RootKey;
        public byte[] FirstSendHeaderKey;
        public byte[] FirstReceiveHeaderKey;
        public byte[] LocalEcdhRatchetStep0;
        public byte[] LocalEcdhRatchetStep1;
        public byte[] NextInitializationNonce;

        protected override void ReadPayload(BinaryReader br)
        {
            base.ReadPayload(br);
            RootKey = ReadBuffer(br);
            FirstSendHeaderKey = ReadBuffer(br);
            FirstReceiveHeaderKey = ReadBuffer(br);
            LocalEcdhRatchetStep0 = ReadBuffer(br);
            LocalEcdhRatchetStep1 = ReadBuffer(br);
            NextInitializationNonce = ReadBuffer(br);
        }

        protected override void WritePayload(BinaryWriter bw)
        {
            base.WritePayload(bw);
            WriteBuffer(bw, RootKey);
            WriteBuffer(bw, FirstSendHeaderKey);
            WriteBuffer(bw, FirstReceiveHeaderKey);
            WriteBuffer(bw, LocalEcdhRatchetStep0);
            WriteBuffer(bw, LocalEcdhRatchetStep1);
            WriteBuffer(bw, NextInitializationNonce);
        }
    }
}
