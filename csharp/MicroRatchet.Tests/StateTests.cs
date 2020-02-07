using MicroRatchet.BouncyCastle;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Xunit;

namespace MicroRatchet.Tests
{
    public class StateTests
    {
        private const int ks = 32;

        [Fact]
        public void ClientInitStateTest()
        {
            var clientServices = new BouncyCastleServices(KeyGeneration.GeneratePrivateKey());
            var serverServices = new BouncyCastleServices(KeyGeneration.GeneratePrivateKey());

            byte[] cs, ss;

            RandomNumberGenerator rng = new RandomNumberGenerator();
            byte[] message1 = rng.Generate(64);
            byte[] message2 = rng.Generate(64);
            byte[] message3 = rng.Generate(64);

            var client = new MicroRatchetContext(clientServices, true);
            var kex = clientServices.KeyAgreementFactory;

            var clientInitPacket = client.InitiateInitialization();
            cs = client.SaveStateAsByteArray();
            {
                var ts = ClientState.Load(cs, kex, ks).StoreAsByteArray(5);
                Assert.Equal(ts, cs);
            }

            var server = new MicroRatchetContext(serverServices, false);
            var responsePacket = server.Receive(clientInitPacket).ToSendBack;
            ss = server.SaveStateAsByteArray();
            {
                var ts = ServerState.Load(ss, kex, ks).StoreAsByteArray(5);
                Assert.Equal(ts, ss);
            }


            client = new MicroRatchetContext(clientServices, true, stateBytes: cs);
            var firstPacket = client.Receive(responsePacket).ToSendBack;
            cs = client.SaveStateAsByteArray();
            {
                var ts = ClientState.Load(cs, kex, ks).StoreAsByteArray(5);
                Assert.Equal(ts, cs);
            }

            server = new MicroRatchetContext(serverServices, false, stateBytes: ss);
            var firstResponse = server.Receive(firstPacket).ToSendBack;
            ss = server.SaveStateAsByteArray();
            {
                var ts = ServerState.Load(ss, kex, ks).StoreAsByteArray(5);
                Assert.Equal(ts, ss);
            }

            client = new MicroRatchetContext(clientServices, true, stateBytes: cs);
            var lastResult = client.Receive(firstResponse).ToSendBack;
            cs = client.SaveStateAsByteArray();
            {
                var ts = ClientState.Load(cs, kex, ks).StoreAsByteArray(5);
                Assert.Equal(ts, cs);
            }


            client = new MicroRatchetContext(clientServices, true, 80, stateBytes: cs);
            var pl1 = client.Send(message1);
            cs = client.SaveStateAsByteArray();
            {
                var ts = ClientState.Load(cs, kex, ks).StoreAsByteArray(5);
                Assert.Equal(ts, cs);
            }

            client = new MicroRatchetContext(clientServices, true, 80, stateBytes: cs);
            var pl2 = client.Send(message2);
            cs = client.SaveStateAsByteArray();
            {
                var ts = ClientState.Load(cs, kex, ks).StoreAsByteArray(5);
                Assert.Equal(ts, cs);
            }

            client = new MicroRatchetContext(clientServices, true, 80, stateBytes: cs);
            var pl3 = client.Send(message3);
            cs = client.SaveStateAsByteArray();
            {
                var ts = ClientState.Load(cs, kex, ks).StoreAsByteArray(5);
                Assert.Equal(ts, cs);
            }


            server = new MicroRatchetContext(serverServices, false, 80, stateBytes: ss);
            var r1 = server.Receive(pl1).Payload;
            ss = server.SaveStateAsByteArray();
            {
                var ts = ServerState.Load(ss, kex, ks).StoreAsByteArray(5);
                Assert.Equal(ts, ss);
            }

            server = new MicroRatchetContext(serverServices, false, 80, stateBytes: ss);
            var r2 = server.Receive(pl2).Payload;
            ss = server.SaveStateAsByteArray();
            {
                var ts = ServerState.Load(ss, kex, ks).StoreAsByteArray(5);
                Assert.Equal(ts, ss);
            }

            server = new MicroRatchetContext(serverServices, false, 80, stateBytes: ss);
            var r3 = server.Receive(pl3).Payload;
            ss = server.SaveStateAsByteArray();
            {
                var ts = ServerState.Load(ss, kex, ks).StoreAsByteArray(5);
                Assert.Equal(ts, ss);
            }


            Assert.Equal(message1, r1);
            Assert.Equal(message2, r2);
            Assert.Equal(message3, r3);

            Assert.Null(lastResult);
        }
    }
}
