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
            public byte[] memory;

            public InMemoryStorage()
            {
                memory = new byte[1024];
            }

            public Stream Lock() => new MemoryStream(memory);
        }

        [Fact]
        public void ClientInitStateTest()
        {
            BouncyCastleServices clientServices = new BouncyCastleServices(KeyGeneration.GeneratePrivateKey(), new InMemoryStorage());
            BouncyCastleServices serverServices = new BouncyCastleServices(KeyGeneration.GeneratePrivateKey(), new InMemoryStorage());
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
                var oldState = cstorage.memory.Clone();
                ClientState.Load(cstorage.Lock(), kex, ks).Store(cstorage, 5);
                Assert.Equal(oldState, cstorage.memory);
            }

            var server = new MicroRatchetClient(serverServices, false);
            var responsePacket = server.Receive(clientInitPacket).ToSendBack;
            server.SaveState();
            {
                var oldState = sstorage.memory.Clone();
                ServerState.Load(sstorage.Lock(), kex, ks).Store(sstorage, 5);
                Assert.Equal(oldState, sstorage.memory);
            }


            client = new MicroRatchetClient(clientServices, true);
            var firstPacket = client.Receive(responsePacket).ToSendBack;
            client.SaveState();
            {
                var oldState = cstorage.memory.Clone();
                ClientState.Load(cstorage.Lock(), kex, ks).Store(cstorage, 5);
                Assert.Equal(oldState, cstorage.memory);
            }

            server = new MicroRatchetClient(serverServices, false);
            var firstResponse = server.Receive(firstPacket).ToSendBack;
            server.SaveState();
            {
                var oldState = sstorage.memory.Clone();
                ServerState.Load(sstorage.Lock(), kex, ks).Store(sstorage, 5);
                Assert.Equal(oldState, sstorage.memory);
            }

            client = new MicroRatchetClient(clientServices, true);
            var lastResult = client.Receive(firstResponse).ToSendBack;
            client.SaveState();
            {
                var oldState = cstorage.memory.Clone();
                ClientState.Load(cstorage.Lock(), kex, ks).Store(cstorage, 5);
                Assert.Equal(oldState, cstorage.memory);
            }


            client = new MicroRatchetClient(clientServices, true, 80);
            var pl1 = client.Send(message1);
            client.SaveState();
            {
                var oldState = cstorage.memory.Clone();
                ClientState.Load(cstorage.Lock(), kex, ks).Store(cstorage, 5);
                Assert.Equal(oldState, cstorage.memory);
            }

            client = new MicroRatchetClient(clientServices, true, 80);
            var pl2 = client.Send(message2);
            client.SaveState();
            {
                var oldState = cstorage.memory.Clone();
                ClientState.Load(cstorage.Lock(), kex, ks).Store(cstorage, 5);
                Assert.Equal(oldState, cstorage.memory);
            }

            client = new MicroRatchetClient(clientServices, true, 80);
            var pl3 = client.Send(message3);
            client.SaveState();
            {
                var oldState = cstorage.memory.Clone();
                ClientState.Load(cstorage.Lock(), kex, ks).Store(cstorage, 5);
                Assert.Equal(oldState, cstorage.memory);
            }


            server = new MicroRatchetClient(serverServices, false, 80);
            var r1 = server.Receive(pl1).Payload;
            server.SaveState();
            {
                var oldState = sstorage.memory.Clone();
                ServerState.Load(sstorage.Lock(), kex, ks).Store(sstorage, 5);
                Assert.Equal(oldState, sstorage.memory);
            }

            server = new MicroRatchetClient(serverServices, false, 80);
            var r2 = server.Receive(pl2).Payload;
            server.SaveState();
            {
                var oldState = sstorage.memory.Clone();
                ServerState.Load(sstorage.Lock(), kex, ks).Store(sstorage, 5);
                Assert.Equal(oldState, sstorage.memory);
            }

            server = new MicroRatchetClient(serverServices, false, 80);
            var r3 = server.Receive(pl3).Payload;
            server.SaveState();
            {
                var oldState = sstorage.memory.Clone();
                ServerState.Load(sstorage.Lock(), kex, ks).Store(sstorage, 5);
                Assert.Equal(oldState, sstorage.memory);
            }


            Assert.Equal(message1, r1);
            Assert.Equal(message2, r2);
            Assert.Equal(message3, r3);

            Assert.Null(lastResult);
        }
    }

    internal static class StateExtensions
    {
        public static void Store(this State state, IStorageProvider storage, int nr)
        {
            using var stream = storage.Lock();
            state.Store(stream, nr);
        }
    }
}
