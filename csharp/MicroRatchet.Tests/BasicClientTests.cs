﻿using MicroRatchet.BouncyCastle;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Xunit;

namespace MicroRatchet.Tests
{
    public class BasicClientTests
    {
        [Fact]
        public void ClientMessagesReinstantiation()
        {
            var clientServices = new BouncyCastleServices(KeyGeneration.GeneratePrivateKey());
            var serverServices = new BouncyCastleServices(KeyGeneration.GeneratePrivateKey());

            RandomNumberGenerator rng = new RandomNumberGenerator();
            byte[] message1 = rng.Generate(64);
            byte[] message2 = rng.Generate(64);
            byte[] message3 = rng.Generate(64);

            byte[] s, c;

            var client = new MicroRatchetContext(clientServices, true);
            var clientInitPacket = client.InitiateInitialization();
            c = client.SaveStateAsByteArray();
            var server = new MicroRatchetContext(serverServices, false);
            var responsePacket = server.Receive(clientInitPacket).ToSendBack;
            s = server.SaveStateAsByteArray();
            client = new MicroRatchetContext(clientServices, true, stateBytes: c);
            var firstPacket = client.Receive(responsePacket).ToSendBack;
            c = client.SaveStateAsByteArray();
            server = new MicroRatchetContext(serverServices, false, stateBytes: s);
            var firstResponse = server.Receive(firstPacket).ToSendBack;
            s = server.SaveStateAsByteArray();
            client = new MicroRatchetContext(clientServices, true, stateBytes: c);
            var lastResult = client.Receive(firstResponse).ToSendBack;
            c = client.SaveStateAsByteArray();

            client = new MicroRatchetContext(clientServices, true, 80, stateBytes: c);
            var pl1 = client.Send(message1);
            c = client.SaveStateAsByteArray();
            client = new MicroRatchetContext(clientServices, true, 80, stateBytes: c);
            var pl2 = client.Send(message2);
            c = client.SaveStateAsByteArray();
            client = new MicroRatchetContext(clientServices, true, 80, stateBytes: c);
            var pl3 = client.Send(message3);
            c = client.SaveStateAsByteArray();

            server = new MicroRatchetContext(serverServices, false, 80, stateBytes: s);
            var r1 = server.Receive(pl1).Payload;
            s = server.SaveStateAsByteArray();
            server = new MicroRatchetContext(serverServices, false, 80, stateBytes: s);
            var r2 = server.Receive(pl2).Payload;
            s = server.SaveStateAsByteArray();
            server = new MicroRatchetContext(serverServices, false, 80, stateBytes: s);
            var r3 = server.Receive(pl3).Payload;
            s = server.SaveStateAsByteArray();

            Assert.Equal(message1, r1);
            Assert.Equal(message2, r2);
            Assert.Equal(message3, r3);

            Assert.Null(lastResult);
        }

        [Fact]
        public void SendSomeMessagesFromClientTest()
        {
            var (client, server) = Common.CreateAndInitialize();

            RandomNumberGenerator rng = new RandomNumberGenerator();
            byte[] message1 = rng.Generate(64);
            byte[] message2 = rng.Generate(64);
            byte[] message3 = rng.Generate(64);

            var pl1 = client.Send(message1);
            var pl2 = client.Send(message2);
            var pl3 = client.Send(message3);

            var r1 = server.Receive(pl1).Payload;
            var r2 = server.Receive(pl2).Payload;
            var r3 = server.Receive(pl3).Payload;

            Assert.Equal(message1, r1);
            Assert.Equal(message2, r2);
            Assert.Equal(message3, r3);
        }

        [Fact]
        public void SendSomeMessagesFromClientOutOfOrderTest()
        {
            var (client, server) = Common.CreateAndInitialize();

            RandomNumberGenerator rng = new RandomNumberGenerator();
            byte[] message1 = rng.Generate(64);
            byte[] message2 = rng.Generate(64);
            byte[] message3 = rng.Generate(64);
            byte[] message4 = rng.Generate(64);
            byte[] message5 = rng.Generate(64);

            var pl1 = client.Send(message1);
            var pl2 = client.Send(message2);
            var pl3 = client.Send(message3);
            var pl4 = client.Send(message4);
            var pl5 = client.Send(message5);

            var r5 = server.Receive(pl5).Payload;
            var r1 = server.Receive(pl1).Payload;
            var r3 = server.Receive(pl3).Payload;
            var r4 = server.Receive(pl4).Payload;
            var r2 = server.Receive(pl2).Payload;

            Assert.Equal(message1, r1);
            Assert.Equal(message2, r2);
            Assert.Equal(message3, r3);
            Assert.Equal(message4, r4);
            Assert.Equal(message5, r5);
        }

        [Fact]
        public void SendSomeMessagesFromClientOutOfOrderWithDropsTest()
        {
            var (client, server) = Common.CreateAndInitialize();

            RandomNumberGenerator rng = new RandomNumberGenerator();
            byte[] message1 = rng.Generate(64);
            byte[] message2 = rng.Generate(64);
            byte[] message3 = rng.Generate(64);
            byte[] message4 = rng.Generate(64);
            byte[] message5 = rng.Generate(64);

            var pl1 = client.Send(message1);
            var pl2 = client.Send(message2);
            var pl3 = client.Send(message3);
            var pl4 = client.Send(message4);
            var pl5 = client.Send(message5);

            var r5 = server.Receive(pl5).Payload;
            var r1 = server.Receive(pl1).Payload;
            //var r3 = server.Receive(pl3).Payload;
            var r4 = server.Receive(pl4).Payload;
            var r2 = server.Receive(pl2).Payload;

            Assert.Equal(message1, r1);
            Assert.Equal(message2, r2);
            //Assert.Equal(message3, r3);
            Assert.Equal(message4, r4);
            Assert.Equal(message5, r5);
        }

        [Fact]
        public void SendSomeMessagesBothDirectionsTest()
        {
            var (client, server) = Common.CreateAndInitialize();

            RandomNumberGenerator rng = new RandomNumberGenerator();
            byte[] cmessage1 = rng.Generate(64);
            byte[] cmessage2 = rng.Generate(64);
            byte[] cmessage3 = rng.Generate(64);
            byte[] smessage1 = rng.Generate(64);
            byte[] smessage2 = rng.Generate(64);
            byte[] smessage3 = rng.Generate(64);

            var cp1 = client.Send(cmessage1);
            var sr1 = server.Receive(cp1).Payload;

            var sp1 = server.Send(smessage1);
            var cr1 = client.Receive(sp1).Payload;

            var cp2 = client.Send(cmessage2);
            var sr2 = server.Receive(cp2).Payload;

            var sp2 = server.Send(smessage2);
            var cr2 = client.Receive(sp2).Payload;

            var cp3 = client.Send(cmessage3);
            var sr3 = server.Receive(cp3).Payload;

            var sp3 = server.Send(smessage3);
            var cr3 = client.Receive(sp3).Payload;

            Assert.Equal(cmessage1, sr1);
            Assert.Equal(cmessage2, sr2);
            Assert.Equal(cmessage3, sr3);
            Assert.Equal(smessage1, cr1);
            Assert.Equal(smessage2, cr2);
            Assert.Equal(smessage3, cr3);
        }

        [Fact]
        public void SendSomeMessagesBothDirectionsWithDropsTest()
        {
            var (client, server) = Common.CreateAndInitialize();

            RandomNumberGenerator rng = new RandomNumberGenerator();
            byte[] cmessage1 = rng.Generate(64);
            byte[] cmessage2 = rng.Generate(64);
            byte[] cmessage3 = rng.Generate(64);
            byte[] smessage1 = rng.Generate(64);
            byte[] smessage2 = rng.Generate(64);
            byte[] smessage3 = rng.Generate(64);

            var cp1 = client.Send(cmessage1);
            var sr1 = server.Receive(cp1).Payload;

            var sp1 = server.Send(smessage1);
            var cr1 = client.Receive(sp1).Payload;

            //var cp2 = client.Send(cmessage2);
            //var sr2 = server.Receive(cp2).Payload;

            //var sp2 = server.Send(smessage2);
            //var cr2 = client.Receive(sp2).Payload;

            var cp3 = client.Send(cmessage3);
            var sr3 = server.Receive(cp3).Payload;

            var sp3 = server.Send(smessage3);
            var cr3 = client.Receive(sp3).Payload;

            Assert.Equal(cmessage1, sr1);
            //Assert.Equal(cmessage2, sr2);
            Assert.Equal(cmessage3, sr3);
            Assert.Equal(smessage1, cr1);
            //Assert.Equal(smessage2, cr2);
            Assert.Equal(smessage3, cr3);
        }

        [Fact]
        public void SendSomeMessagesBothDirectionsOutOfOrderTest()
        {
            var (client, server) = Common.CreateAndInitialize();

            RandomNumberGenerator rng = new RandomNumberGenerator();
            byte[] cmessage1 = rng.Generate(64);
            byte[] cmessage2 = rng.Generate(64);
            byte[] cmessage3 = rng.Generate(64);
            byte[] cmessage4 = rng.Generate(64);
            byte[] cmessage5 = rng.Generate(64);
            byte[] smessage1 = rng.Generate(64);
            byte[] smessage2 = rng.Generate(64);
            byte[] smessage3 = rng.Generate(64);
            byte[] smessage4 = rng.Generate(64);
            byte[] smessage5 = rng.Generate(64);

            var cp1 = client.Send(cmessage1);
            var sr1 = server.Receive(cp1).Payload;
            var sp1 = server.Send(smessage1);
            var cr1 = client.Receive(sp1).Payload;
            var sp4 = server.Send(smessage4);
            var cp3 = client.Send(cmessage3);
            var cp2 = client.Send(cmessage2);
            var sr3 = server.Receive(cp3).Payload;
            var cp5 = client.Send(cmessage5);
            var cp4 = client.Send(cmessage4);
            var cr4 = client.Receive(sp4).Payload;
            var sp3 = server.Send(smessage3);
            var sr5 = server.Receive(cp5).Payload;
            var sp2 = server.Send(smessage2);
            var cr3 = client.Receive(sp3).Payload;
            var sr2 = server.Receive(cp2).Payload;
            var cr2 = client.Receive(sp2).Payload;
            var sr4 = server.Receive(cp4).Payload;
            var sp5 = server.Send(smessage5);
            var cr5 = client.Receive(sp5).Payload;

            Assert.Equal(cmessage1, sr1);
            Assert.Equal(cmessage2, sr2);
            Assert.Equal(cmessage3, sr3);
            Assert.Equal(cmessage4, sr4);
            Assert.Equal(cmessage5, sr5);
            Assert.Equal(smessage1, cr1);
            Assert.Equal(smessage2, cr2);
            Assert.Equal(smessage3, cr3);
            Assert.Equal(smessage4, cr4);
            Assert.Equal(smessage5, cr5);
        }

        [Fact]
        public void SendSomeMessagesBothDirectionsWithEcdhTest()
        {
            var (client, server) = Common.CreateAndInitialize();

            RandomNumberGenerator rng = new RandomNumberGenerator();
            byte[] cmessage1 = rng.Generate(32);
            byte[] cmessage2 = rng.Generate(32);
            byte[] cmessage3 = rng.Generate(32);
            byte[] smessage1 = rng.Generate(32);
            byte[] smessage2 = rng.Generate(32);
            byte[] smessage3 = rng.Generate(32);

            var cp1 = client.Send(cmessage1);
            var sr1 = server.Receive(cp1).Payload;
            Assert.Equal(cmessage1, sr1);

            var sp1 = server.Send(smessage1);
            var cr1 = client.Receive(sp1).Payload;
            Assert.Equal(smessage1, cr1);

            var cp2 = client.Send(cmessage2);
            var sr2 = server.Receive(cp2).Payload;
            Assert.Equal(cmessage2, sr2);

            var sp2 = server.Send(smessage2);
            var cr2 = client.Receive(sp2).Payload;
            Assert.Equal(smessage2, cr2);

            var cp3 = client.Send(cmessage3);
            var sr3 = server.Receive(cp3).Payload;
            Assert.Equal(cmessage3, sr3);

            var sp3 = server.Send(smessage3);
            var cr3 = client.Receive(sp3).Payload;
            Assert.Equal(smessage3, cr3);

            using var cms = new MemoryStream();
            using var sms = new MemoryStream();
            client.SaveState(cms); cms.Position = 0;
            server.SaveState(sms); sms.Position = 0;
            var cs = ClientState.Load(cms, DefaultKexFactory.Instance);
            var ss = ServerState.Load(sms, DefaultKexFactory.Instance);
            Assert.Equal(4, cs.Ratchets.Count);
            Assert.Equal(4, ss.Ratchets.Count);
        }
    }
}
