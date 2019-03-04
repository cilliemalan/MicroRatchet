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
        
        public byte[] InitializationNonce;
        public byte[] NextInitializationNonce;

        public byte[] LocalEcdhRatchetStep0;
        public byte[] LocalEcdhRatchetStep1;

        protected override void ReadPayload(BinaryReader br)
        {
            base.ReadPayload(br);
            InitializationNonce = ReadBuffer(br);
            NextInitializationNonce = ReadBuffer(br);
            LocalEcdhRatchetStep0 = ReadBuffer(br);
            LocalEcdhRatchetStep1 = ReadBuffer(br);
        }

        protected override void WritePayload(BinaryWriter bw)
        {
            base.WritePayload(bw);
            WriteBuffer(bw, InitializationNonce);
            WriteBuffer(bw, NextInitializationNonce);
            WriteBuffer(bw, LocalEcdhRatchetStep0);
            WriteBuffer(bw, LocalEcdhRatchetStep1);
        }
    }
}
