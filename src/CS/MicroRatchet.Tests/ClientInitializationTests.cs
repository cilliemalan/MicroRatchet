using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Xunit;

namespace MicroRatchet.Tests
{
    public class ClientInitializationTests
    {
        [Fact]
        public void ClientInitialization1MessageTest()
        {
            DefaultServices clientServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());

            var client = new MicroRatchetClient(clientServices, true);

            var clientInitPacket = client.InitiateInitialization();
            client.SaveState();
            ClientState clientState = ClientState.Load(clientServices.Storage, DefaultKexFactory.Instance);

            Assert.NotNull(clientState.LocalEcdhForInit);
            Assert.NotNull(clientState.InitializationNonce);

            Assert.Equal(4, clientState.InitializationNonce.Length);
        }

        [Fact]
        public void ClientInitialization2ProcessTest()
        {
            DefaultServices clientServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());
            DefaultServices serverServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());

            var client = new MicroRatchetClient(clientServices, true);
            var server = new MicroRatchetClient(serverServices, false);

            var clientInitPacket = client.InitiateInitialization();
            var responsePacket = server.Receive(clientInitPacket.Message).ToSendBack;
            client.SaveState();
            server.SaveState();
            ClientState clientState = ClientState.Load(clientServices.Storage, DefaultKexFactory.Instance);
            ServerState serverState = ServerState.Load(serverServices.Storage, DefaultKexFactory.Instance);
        }

        [Fact]
        public void ClientInitialization3ProcessResponseTest()
        {
            DefaultServices clientServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());
            DefaultServices serverServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());

            var client = new MicroRatchetClient(clientServices, true);
            var server = new MicroRatchetClient(serverServices, false);

            var clientInitPacket = client.InitiateInitialization();
            var responsePacket = server.Receive(clientInitPacket.Message).ToSendBack;
            var firstPacket = client.Receive(responsePacket.Message).ToSendBack;
            client.SaveState();
            server.SaveState();
            ClientState clientState = ClientState.Load(clientServices.Storage, DefaultKexFactory.Instance);
            ServerState serverState = ServerState.Load(serverServices.Storage, DefaultKexFactory.Instance);

            Assert.Equal(clientState.Ratchets[0].SendingChain.HeaderKey, serverState.FirstReceiveHeaderKey);
            Assert.Equal(clientState.Ratchets[1].ReceivingChain.HeaderKey, serverState.FirstSendHeaderKey);
        }

        [Fact]
        public void ClientInitialization4ProcessFirstPacketSendTest()
        {
            DefaultServices clientServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());
            DefaultServices serverServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());

            var client = new MicroRatchetClient(clientServices, true);
            var server = new MicroRatchetClient(serverServices, false);

            var clientInitPacket = client.InitiateInitialization();
            var responsePacket = server.Receive(clientInitPacket.Message).ToSendBack;
            var firstPacket = client.Receive(responsePacket.Message).ToSendBack;
            var firstResponse = server.Receive(firstPacket.Message).ToSendBack;
            client.SaveState();
            server.SaveState();
            ClientState clientState = ClientState.Load(clientServices.Storage, DefaultKexFactory.Instance);
            ServerState serverState = ServerState.Load(serverServices.Storage, DefaultKexFactory.Instance);

            Assert.NotNull(firstResponse);
            Assert.Equal(2, clientState.Ratchets.Count);
            Assert.Equal(1, serverState.Ratchets.Count);
        }

        [Fact]
        public void ClientInitialization5ProcessComplete()
        {
            DefaultServices clientServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());
            DefaultServices serverServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());

            var client = new MicroRatchetClient(clientServices, true);
            var server = new MicroRatchetClient(serverServices, false);

            var clientInitPacket = client.InitiateInitialization();
            var responsePacket = server.Receive(clientInitPacket.Message).ToSendBack;
            var firstPacket = client.Receive(responsePacket.Message).ToSendBack;
            var firstResponse = server.Receive(firstPacket.Message).ToSendBack;
            var lastResult = client.Receive(firstResponse.Message).ToSendBack;
            client.SaveState();
            server.SaveState();
            ClientState clientState = ClientState.Load(clientServices.Storage, DefaultKexFactory.Instance);
            ServerState serverState = ServerState.Load(serverServices.Storage, DefaultKexFactory.Instance);

            Assert.Null(lastResult);
        }

        [Fact]
        public void ClientInitializationClientReinstantiation()
        {
            DefaultServices clientServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());
            DefaultServices serverServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());

            var client = new MicroRatchetClient(clientServices, true);
            var clientInitPacket = client.InitiateInitialization();
            client.SaveState();
            var server = new MicroRatchetClient(serverServices, false);
            var responsePacket = server.Receive(clientInitPacket.Message).ToSendBack;
            server.SaveState();
            client = new MicroRatchetClient(clientServices, true);
            var firstPacket = client.Receive(responsePacket.Message).ToSendBack;
            client.SaveState();
            server = new MicroRatchetClient(serverServices, false);
            var firstResponse = server.Receive(firstPacket.Message).ToSendBack;
            server.SaveState();
            client = new MicroRatchetClient(clientServices, true);
            var lastResult = client.Receive(firstResponse.Message).ToSendBack;
            client.SaveState();

            Assert.Null(lastResult);
        }

        [Fact]
        public void ClientLargeInit1MessageTest()
        {
            DefaultServices clientServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());

            var client = new MicroRatchetClient(clientServices, true, 80);

            var clientInitPacket = client.InitiateInitialization();
            client.SaveState();
            ClientState clientState = ClientState.Load(clientServices.Storage, DefaultKexFactory.Instance);

            Assert.NotNull(clientState.LocalEcdhForInit);
            Assert.NotNull(clientState.InitializationNonce);

            Assert.Equal(4, clientState.InitializationNonce.Length);
            Assert.True(clientInitPacket.IsMultipartMessage);
            Assert.Equal(2, clientInitPacket.Messages.Length);
        }

        [Fact]
        public void ClientLargeInit2ProcessTest()
        {
            DefaultServices clientServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());
            DefaultServices serverServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());

            var client = new MicroRatchetClient(clientServices, true, 80);
            var server = new MicroRatchetClient(serverServices, false, 80);

            var clientInitPacket = client.InitiateInitialization();
            var responsePacket = server.ReceiveMultiple(clientInitPacket).ToSendBack;
            client.SaveState();
            server.SaveState();
            ClientState clientState = ClientState.Load(clientServices.Storage, DefaultKexFactory.Instance);
            ServerState serverState = ServerState.Load(serverServices.Storage, DefaultKexFactory.Instance);
        }

        [Fact]
        public void ClientLargeInit3ProcessResponseTest()
        {
            DefaultServices clientServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());
            DefaultServices serverServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());

            var client = new MicroRatchetClient(clientServices, true, 80);
            var server = new MicroRatchetClient(serverServices, false, 80);

            var clientInitPacket = client.InitiateInitialization();
            var responsePacket = server.ReceiveMultiple(clientInitPacket).ToSendBack;
            var firstPacket = client.ReceiveMultiple(responsePacket).ToSendBack;
            client.SaveState();
            server.SaveState();
            ClientState clientState = ClientState.Load(clientServices.Storage, DefaultKexFactory.Instance);
            ServerState serverState = ServerState.Load(serverServices.Storage, DefaultKexFactory.Instance);

            Assert.Equal(clientState.Ratchets[0].SendingChain.HeaderKey, serverState.FirstReceiveHeaderKey);
            Assert.Equal(clientState.Ratchets[1].ReceivingChain.HeaderKey, serverState.FirstSendHeaderKey);
        }

        [Fact]
        public void ClientLargeInit4ProcessFirstPacketSendTest()
        {
            DefaultServices clientServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());
            DefaultServices serverServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());

            var client = new MicroRatchetClient(clientServices, true, 80);
            var server = new MicroRatchetClient(serverServices, false, 80);

            var clientInitPacket = client.InitiateInitialization();
            var responsePacket = server.ReceiveMultiple(clientInitPacket).ToSendBack;
            var firstPacket = client.ReceiveMultiple(responsePacket).ToSendBack;
            var firstResponse = server.Receive(firstPacket.Message).ToSendBack;
            client.SaveState();
            server.SaveState();
            ClientState clientState = ClientState.Load(clientServices.Storage, DefaultKexFactory.Instance);
            ServerState serverState = ServerState.Load(serverServices.Storage, DefaultKexFactory.Instance);

            Assert.NotNull(firstResponse);
            Assert.Equal(2, clientState.Ratchets.Count);
            Assert.Equal(1, serverState.Ratchets.Count);
        }

        [Fact]
        public void ClientLargeInit5ProcessComplete()
        {
            DefaultServices clientServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());
            DefaultServices serverServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());

            var client = new MicroRatchetClient(clientServices, true, 80);
            var server = new MicroRatchetClient(serverServices, false, 80);

            var clientInitPacket = client.InitiateInitialization();
            var responsePacket = server.ReceiveMultiple(clientInitPacket).ToSendBack;
            var firstPacket = client.ReceiveMultiple(responsePacket).ToSendBack;
            var firstResponse = server.Receive(firstPacket.Message).ToSendBack;
            var lastResult = client.Receive(firstResponse.Message).ToSendBack;
            client.SaveState();
            server.SaveState();
            ClientState clientState = ClientState.Load(clientServices.Storage, DefaultKexFactory.Instance);
            ServerState serverState = ServerState.Load(serverServices.Storage, DefaultKexFactory.Instance);

            Assert.Null(lastResult);
        }

        [Fact]
        public void HotReinitialization()
        {
            DefaultServices clientServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());
            DefaultServices serverServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());

            var client = new MicroRatchetClient(clientServices, true, 1000);
            var server = new MicroRatchetClient(serverServices, false, 1000);

            // initialize
            {
                var clientInitPacket = client.InitiateInitialization();
                var responsePacket = server.Receive(clientInitPacket.Message).ToSendBack;
                var firstPacket = client.Receive(responsePacket.Message).ToSendBack;
                var firstResponse = server.Receive(firstPacket.Message).ToSendBack;
                var lastResult = client.Receive(firstResponse.Message).ToSendBack;
                client.SaveState();
                server.SaveState();
            }

            // now we're hot
            client = new MicroRatchetClient(clientServices, true, 80);
            server = new MicroRatchetClient(serverServices, false, 80);
            {
                RandomNumberGenerator rng = new RandomNumberGenerator();
                byte[] message1 = rng.Generate(32);
                byte[] message2 = rng.Generate(32);
                byte[] message3 = rng.Generate(32);

                var pl1 = client.Send(message1).Message;
                var pl2 = client.Send(message2).Message;
                var pl3 = client.Send(message3).Message;

                var r1 = server.Receive(pl1).Payload;
                var r2 = server.Receive(pl2).Payload;
                var r3 = server.Receive(pl3).Payload;

                Assert.Equal(message1, r1);
                Assert.Equal(message2, r2);
                Assert.Equal(message3, r3);

                client.SaveState();
                server.SaveState();
            }

            // oh noes! Client fail! reinitialize
            clientServices.Storage = new InMemoryStorage(1024, 8192);
            client = new MicroRatchetClient(clientServices, true, 80);
            server = new MicroRatchetClient(serverServices, false, 80);
            {
                var clientInitPacket = client.InitiateInitialization();
                var responsePacket = server.ReceiveMultiple(clientInitPacket).ToSendBack;
                var firstPacket = client.ReceiveMultiple(responsePacket).ToSendBack;
                var firstResponse = server.Receive(firstPacket.Message).ToSendBack;
                var lastResult = client.Receive(firstResponse.Message).ToSendBack;
                client.SaveState();
                server.SaveState();
            }

            // now we're hot AGAIN
            client = new MicroRatchetClient(clientServices, true, 80);
            server = new MicroRatchetClient(serverServices, false, 80);
            {
                RandomNumberGenerator rng = new RandomNumberGenerator();
                byte[] message1 = rng.Generate(32);
                byte[] message2 = rng.Generate(32);
                byte[] message3 = rng.Generate(32);

                var pl1 = client.Send(message1).Message;
                var pl2 = client.Send(message2).Message;
                var pl3 = client.Send(message3).Message;

                var r1 = server.Receive(pl1).Payload;
                var r2 = server.Receive(pl2).Payload;
                var r3 = server.Receive(pl3).Payload;

                Assert.Equal(message1, r1);
                Assert.Equal(message2, r2);
                Assert.Equal(message3, r3);

                client.SaveState();
                server.SaveState();
            }
        }


        private class InMemoryStorage : IStorageProvider
        {
            private byte[] hot;
            private byte[] cold;

            public InMemoryStorage(int hotSpace, int coldSpace)
            {
                hot = new byte[hotSpace];
                cold = new byte[coldSpace];
            }

            public Stream LockHot() => new MemoryStream(hot);
            public Stream LockCold() => new MemoryStream(cold);
        }
    }
}
