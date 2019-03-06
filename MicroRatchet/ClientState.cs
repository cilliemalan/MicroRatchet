using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace MicroRatchet
{
    internal class ClientState : State
    {
        protected override int Version => 1;
        protected override bool IsClient => true;

        // used throughout init
        public byte[] InitializationNonce;

        // used twice
        public byte[] LocalEcdhForInit;

        protected override void ReadPayload(BinaryReader br)
        {
            base.ReadPayload(br);
            InitializationNonce = ReadBuffer(br);
            LocalEcdhForInit = ReadBuffer(br);
        }

        protected override void WritePayload(BinaryWriter bw)
        {
            base.WritePayload(bw);
            WriteBuffer(bw, InitializationNonce);
            WriteBuffer(bw, LocalEcdhForInit);
        }
    }
}
