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
        private class InMemoryStorage : IStorageProvider
        {
            public byte[] hot;
            public byte[] cold;

            public InMemoryStorage()
            {
                hot = new byte[1024];
                cold = new byte[1024];
            }

            public Stream LockHot() => new MemoryStream(hot);
            public Stream LockCold() => new MemoryStream(cold);
        }

        [Fact]
        public void ClientInitStateTest()
        {
            DefaultServices clientServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());
            DefaultServices serverServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());
            var cstorage = new InMemoryStorage();
            var sstorage = new InMemoryStorage();
            clientServices.Storage = cstorage;
            serverServices.Storage = sstorage;

            RandomNumberGenerator rng = new RandomNumberGenerator();
            byte[] message1 = rng.Generate(64);
            byte[] message2 = rng.Generate(64);
            byte[] message3 = rng.Generate(64);

            var client = new MicroRatchetClient(clientServices, true);
            var kex = clientServices.KeyAgreementFactory;

            var clientInitPacket = client.InitiateInitialization();
            client.SaveState();
            {
                var oldState = cstorage.cold.Clone();
                ClientState.Load(cstorage, kex, ks).Store(cstorage, 5);
                Assert.Equal(oldState, cstorage.cold);
            }

            var server = new MicroRatchetClient(serverServices, false);
            var responsePacket = server.Receive(clientInitPacket.Message).ToSendBack;
            server.SaveState();
            {
                var oldState = sstorage.cold.Clone();
                ServerState.Load(sstorage, kex, ks).Store(sstorage, 5);
                Assert.Equal(oldState, sstorage.cold);
            }


            client = new MicroRatchetClient(clientServices, true);
            var firstPacket = client.Receive(responsePacket.Message).ToSendBack;
            client.SaveState();
            {
                var oldState = cstorage.cold.Clone();
                ClientState.Load(cstorage, kex, ks).Store(cstorage, 5);
                Assert.Equal(oldState, cstorage.cold);
            }

            server = new MicroRatchetClient(serverServices, false);
            var firstResponse = server.Receive(firstPacket.Message).ToSendBack;
            server.SaveState();
            {
                var oldState = sstorage.cold.Clone();
                ServerState.Load(sstorage, kex, ks).Store(sstorage, 5);
                Assert.Equal(oldState, sstorage.cold);
            }

            client = new MicroRatchetClient(clientServices, true);
            var lastResult = client.Receive(firstResponse.Message).ToSendBack;
            client.SaveState();
            {
                var oldState = cstorage.cold.Clone();
                ClientState.Load(cstorage, kex, ks).Store(cstorage, 5);
                Assert.Equal(oldState, cstorage.cold);
            }


            client = new MicroRatchetClient(clientServices, true, 80);
            var pl1 = client.Send(message1).Message;
            client.SaveState();
            {
                var oldState = cstorage.cold.Clone();
                ClientState.Load(cstorage, kex, ks).Store(cstorage, 5);
                Assert.Equal(oldState, cstorage.cold);
            }

            client = new MicroRatchetClient(clientServices, true, 80);
            var pl2 = client.Send(message2).Message;
            client.SaveState();
            {
                var oldState = cstorage.cold.Clone();
                ClientState.Load(cstorage, kex, ks).Store(cstorage, 5);
                Assert.Equal(oldState, cstorage.cold);
            }

            client = new MicroRatchetClient(clientServices, true, 80);
            var pl3 = client.Send(message3).Message;
            client.SaveState();
            {
                var oldState = cstorage.cold.Clone();
                ClientState.Load(cstorage, kex, ks).Store(cstorage, 5);
                Assert.Equal(oldState, cstorage.cold);
            }


            server = new MicroRatchetClient(serverServices, false, 80);
            var r1 = server.Receive(pl1).Payload;
            server.SaveState();
            {
                var oldState = sstorage.cold.Clone();
                ServerState.Load(sstorage, kex, ks).Store(sstorage, 5);
                Assert.Equal(oldState, sstorage.cold);
            }

            server = new MicroRatchetClient(serverServices, false, 80);
            var r2 = server.Receive(pl2).Payload;
            server.SaveState();
            {
                var oldState = sstorage.cold.Clone();
                ServerState.Load(sstorage, kex, ks).Store(sstorage, 5);
                Assert.Equal(oldState, sstorage.cold);
            }

            server = new MicroRatchetClient(serverServices, false, 80);
            var r3 = server.Receive(pl3).Payload;
            server.SaveState();
            {
                var oldState = sstorage.cold.Clone();
                ServerState.Load(sstorage, kex, ks).Store(sstorage, 5);
                Assert.Equal(oldState, sstorage.cold);
            }


            Assert.Equal(message1, r1);
            Assert.Equal(message2, r2);
            Assert.Equal(message3, r3);

            Assert.Null(lastResult);
        }
    }
}
