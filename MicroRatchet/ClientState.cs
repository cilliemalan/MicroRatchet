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
        
        public byte[] InitializationNonce;
        public byte[] publicKeySignature;

        protected override void ReadPayload(BinaryReader br)
        {
            base.ReadPayload(br);
            InitializationNonce = ReadBuffer(br);
            publicKeySignature = ReadBuffer(br);
        }

        protected override void WritePayload(BinaryWriter bw)
        {
            base.WritePayload(bw);
            WriteBuffer(bw, InitializationNonce);
            WriteBuffer(bw, publicKeySignature);
        }
    }
}
