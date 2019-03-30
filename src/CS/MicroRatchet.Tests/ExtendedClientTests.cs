﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Xunit;

namespace MicroRatchet.Tests
{
    public class ExtendedClientTests
    {
        [Fact]
        public void SendSomeMessagesBothDirectionsWithEcdhMultiTest()
        {
            var (client, server) = Common.CreateAndInitialize();

            RandomNumberGenerator rng = new RandomNumberGenerator();
            byte[] cmessage1 = rng.Generate(32);
            byte[] cmessage2 = rng.Generate(32);
            byte[] cmessage3 = rng.Generate(32);
            byte[] cmessage4 = rng.Generate(32);
            byte[] cmessage5 = rng.Generate(32);
            byte[] cmessage6 = rng.Generate(32);
            byte[] smessage1 = rng.Generate(32);
            byte[] smessage2 = rng.Generate(32);
            byte[] smessage3 = rng.Generate(32);
            byte[] smessage4 = rng.Generate(32);
            byte[] smessage5 = rng.Generate(32);
            byte[] smessage6 = rng.Generate(32);

            var cp1 = client.Send(cmessage1).Message;
            var cp2 = client.Send(cmessage2).Message;
            var sr1 = server.Receive(cp1).Payload;
            var sr2 = server.Receive(cp2).Payload;
            Assert.Equal(cmessage1, sr1);
            Assert.Equal(cmessage2, sr2);

            var sp1 = server.Send(smessage1).Message;
            var sp2 = server.Send(smessage2).Message;
            var cr1 = client.Receive(sp1).Payload;
            var cr2 = client.Receive(sp2).Payload;
            Assert.Equal(smessage1, cr1);
            Assert.Equal(smessage2, cr2);

            var cp3 = client.Send(cmessage3).Message;
            var cp4 = client.Send(cmessage4).Message;
            var sr3 = server.Receive(cp3).Payload;
            var sr4 = server.Receive(cp4).Payload;
            Assert.Equal(cmessage3, sr3);
            Assert.Equal(cmessage4, sr4);

            var sp3 = server.Send(smessage3).Message;
            var sp4 = server.Send(smessage4).Message;
            var cr3 = client.Receive(sp3).Payload;
            var cr4 = client.Receive(sp4).Payload;
            Assert.Equal(smessage3, cr3);
            Assert.Equal(smessage4, cr4);

            var cp5 = client.Send(cmessage5).Message;
            var cp6 = client.Send(cmessage6).Message;
            var sr5 = server.Receive(cp5).Payload;
            var sr6 = server.Receive(cp6).Payload;
            Assert.Equal(cmessage5, sr5);
            Assert.Equal(cmessage6, sr6);

            var sp5 = server.Send(smessage5).Message;
            var sp6 = server.Send(smessage6).Message;
            var cr5 = client.Receive(sp5).Payload;
            var cr6 = client.Receive(sp6).Payload;
            Assert.Equal(smessage5, cr5);
            Assert.Equal(smessage6, cr6);

            client.SaveState();
            server.SaveState();
            var cs = ClientState.Load(client.Services.Storage, DefaultKexFactory.Instance, client.Configuration.UseAes256 ? 32 : 16);
            var ss = ServerState.Load(server.Services.Storage, DefaultKexFactory.Instance, server.Configuration.UseAes256 ? 32 : 16);
            Assert.Equal(4, cs.Ratchets.Count);
            Assert.Equal(4, ss.Ratchets.Count);
        }
    }
}