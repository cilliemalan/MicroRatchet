using MicroRatchet.BouncyCastle;
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
            BouncyCastleServices clientServices = new BouncyCastleServices(KeyGeneration.GeneratePrivateKey(), new InMemoryStorage());

            var client = new MicroRatchetClient(clientServices, true);

            var clientInitPacket = client.InitiateInitialization();
            client.SaveState();
            ClientState clientState = ClientState.Load(clientServices.Storage, DefaultKexFactory.Instance);

            Assert.NotNull(clientState.LocalEcdhForInit);
            Assert.NotNull(clientState.InitializationNonce);

            Assert.Equal(MicroRatchetClient.InitializationNonceSize, clientState.InitializationNonce.Length);
        }

        [Fact]
        public void ClientInitialization2ProcessTest()
        {
            BouncyCastleServices clientServices = new BouncyCastleServices(KeyGeneration.GeneratePrivateKey(), new InMemoryStorage());
            BouncyCastleServices serverServices = new BouncyCastleServices(KeyGeneration.GeneratePrivateKey(), new InMemoryStorage());

            var client = new MicroRatchetClient(clientServices, true);
            var server = new MicroRatchetClient(serverServices, false);

            var clientInitPacket = client.InitiateInitialization();
            var responsePacket = server.Receive(clientInitPacket).ToSendBack;
            client.SaveState();
            server.SaveState();
            ClientState clientState = ClientState.Load(clientServices.Storage, DefaultKexFactory.Instance);
            ServerState serverState = ServerState.Load(serverServices.Storage, DefaultKexFactory.Instance);
        }

        [Fact]
        public void ClientInitialization3ProcessResponseTest()
        {
            BouncyCastleServices clientServices = new BouncyCastleServices(KeyGeneration.GeneratePrivateKey(), new InMemoryStorage());
            BouncyCastleServices serverServices = new BouncyCastleServices(KeyGeneration.GeneratePrivateKey(), new InMemoryStorage());

            var client = new MicroRatchetClient(clientServices, true);
            var server = new MicroRatchetClient(serverServices, false);

            var clientInitPacket = client.InitiateInitialization();
            var responsePacket = server.Receive(clientInitPacket).ToSendBack;
            var firstPacket = client.Receive(responsePacket).ToSendBack;
            client.SaveState();
            server.SaveState();
            ClientState clientState = ClientState.Load(clientServices.Storage, DefaultKexFactory.Instance);
            ServerState serverState = ServerState.Load(serverServices.Storage, DefaultKexFactory.Instance);

            Assert.Equal(clientState.Ratchets[0].SendHeaderKey, serverState.FirstReceiveHeaderKey);
            Assert.Equal(clientState.Ratchets[1].ReceiveHeaderKey, serverState.FirstSendHeaderKey);
        }

        [Fact]
        public void ClientInitialization4ProcessFirstPacketSendTest()
        {
            BouncyCastleServices clientServices = new BouncyCastleServices(KeyGeneration.GeneratePrivateKey(), new InMemoryStorage());
            BouncyCastleServices serverServices = new BouncyCastleServices(KeyGeneration.GeneratePrivateKey(), new InMemoryStorage());

            var client = new MicroRatchetClient(clientServices, true);
            var server = new MicroRatchetClient(serverServices, false);

            var clientInitPacket = client.InitiateInitialization();
            var responsePacket = server.Receive(clientInitPacket).ToSendBack;
            var firstPacket = client.Receive(responsePacket).ToSendBack;
            var firstResponse = server.Receive(firstPacket).ToSendBack;
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
            BouncyCastleServices clientServices = new BouncyCastleServices(KeyGeneration.GeneratePrivateKey(), new InMemoryStorage());
            BouncyCastleServices serverServices = new BouncyCastleServices(KeyGeneration.GeneratePrivateKey(), new InMemoryStorage());

            var client = new MicroRatchetClient(clientServices, true);
            var server = new MicroRatchetClient(serverServices, false);

            var clientInitPacket = client.InitiateInitialization();
            var responsePacket = server.Receive(clientInitPacket).ToSendBack;
            var firstPacket = client.Receive(responsePacket).ToSendBack;
            var firstResponse = server.Receive(firstPacket).ToSendBack;
            var lastResult = client.Receive(firstResponse).ToSendBack;
            client.SaveState();
            server.SaveState();
            ClientState clientState = ClientState.Load(clientServices.Storage, DefaultKexFactory.Instance);
            ServerState serverState = ServerState.Load(serverServices.Storage, DefaultKexFactory.Instance);

            Assert.Null(lastResult);
        }

        [Fact]
        public void ClientCanSendLargeMessageAfterInitialization()
        {
            BouncyCastleServices clientServices = new BouncyCastleServices(KeyGeneration.GeneratePrivateKey(), new InMemoryStorage());
            BouncyCastleServices serverServices = new BouncyCastleServices(KeyGeneration.GeneratePrivateKey(), new InMemoryStorage());

            var client = new MicroRatchetClient(clientServices, true);
            var server = new MicroRatchetClient(serverServices, false);

            var clientInitPacket = client.InitiateInitialization();
            var responsePacket = server.Receive(clientInitPacket).ToSendBack;
            var firstPacket = client.Receive(responsePacket).ToSendBack;
            var firstResponse = server.Receive(firstPacket).ToSendBack;
            var lastResult = client.Receive(firstResponse).ToSendBack;
            client.SaveState();
            server.SaveState();

            byte[] payload = new byte[server.Configuration.MaximumMessageSize - MicroRatchetClient.MinimumOverhead];
            clientServices.RandomNumberGenerator.Generate(payload);
            byte[] message = client.Send(payload);
            byte[] received = server.Receive(message).Payload;
            Assert.Equal(payload, received);
        }

        [Fact]
        public void ServerCanSendLargeMessageAfterInitialization()
        {
            BouncyCastleServices clientServices = new BouncyCastleServices(KeyGeneration.GeneratePrivateKey(), new InMemoryStorage());
            BouncyCastleServices serverServices = new BouncyCastleServices(KeyGeneration.GeneratePrivateKey(), new InMemoryStorage());

            var client = new MicroRatchetClient(clientServices, true);
            var server = new MicroRatchetClient(serverServices, false);

            var clientInitPacket = client.InitiateInitialization();
            var responsePacket = server.Receive(clientInitPacket).ToSendBack;
            var firstPacket = client.Receive(responsePacket).ToSendBack;
            var firstResponse = server.Receive(firstPacket).ToSendBack;
            var lastResult = client.Receive(firstResponse).ToSendBack;
            client.SaveState();
            server.SaveState();

            byte[] payload = new byte[server.Configuration.MaximumMessageSize - MicroRatchetClient.MinimumOverhead];
            clientServices.RandomNumberGenerator.Generate(payload);
            byte[] message = server.Send(payload);
            byte[] received = client.Receive(message).Payload;
            Assert.Equal(payload, received);
        }

        [Fact]
        public void ClientInitializationClientReinstantiation()
        {
            BouncyCastleServices clientServices = new BouncyCastleServices(KeyGeneration.GeneratePrivateKey(), new InMemoryStorage());
            BouncyCastleServices serverServices = new BouncyCastleServices(KeyGeneration.GeneratePrivateKey(), new InMemoryStorage());

            var client = new MicroRatchetClient(clientServices, true);
            var clientInitPacket = client.InitiateInitialization();
            client.SaveState();
            var server = new MicroRatchetClient(serverServices, false);
            var responsePacket = server.Receive(clientInitPacket).ToSendBack;
            server.SaveState();
            client = new MicroRatchetClient(clientServices, true);
            var firstPacket = client.Receive(responsePacket).ToSendBack;
            client.SaveState();
            server = new MicroRatchetClient(serverServices, false);
            var firstResponse = server.Receive(firstPacket).ToSendBack;
            server.SaveState();
            client = new MicroRatchetClient(clientServices, true);
            var lastResult = client.Receive(firstResponse).ToSendBack;
            client.SaveState();

            Assert.Null(lastResult);
        }

        [Fact]
        public void HotReinitialization()
        {
            BouncyCastleServices clientServices = new BouncyCastleServices(KeyGeneration.GeneratePrivateKey(), new InMemoryStorage());
            BouncyCastleServices serverServices = new BouncyCastleServices(KeyGeneration.GeneratePrivateKey(), new InMemoryStorage());

            var client = new MicroRatchetClient(clientServices, true, 1000);
            var server = new MicroRatchetClient(serverServices, false, 1000);

            // initialize
            {
                var clientInitPacket = client.InitiateInitialization();
                var responsePacket = server.Receive(clientInitPacket).ToSendBack;
                var firstPacket = client.Receive(responsePacket).ToSendBack;
                var firstResponse = server.Receive(firstPacket).ToSendBack;
                var lastResult = client.Receive(firstResponse).ToSendBack;
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

                var pl1 = client.Send(message1);
                var pl2 = client.Send(message2);
                var pl3 = client.Send(message3);

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
            clientServices.Storage = new InMemoryStorage(8192);
            client = new MicroRatchetClient(clientServices, true, 1000);
            server = new MicroRatchetClient(serverServices, false, 1000);
            {
                var clientInitPacket = client.InitiateInitialization();
                var responsePacket = server.Receive(clientInitPacket).ToSendBack;
                var firstPacket = client.Receive(responsePacket).ToSendBack;
                var firstResponse = server.Receive(firstPacket).ToSendBack;
                var lastResult = client.Receive(firstResponse).ToSendBack;
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

                var pl1 = client.Send(message1);
                var pl2 = client.Send(message2);
                var pl3 = client.Send(message3);

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

        [Fact]
        public void ClientInitializationRetransmitThrowsTest()
        {
            // this test makes sure that during the initialization process
            // any retransmitted packet will cause an exception. However,
            // the initialization process will not be affected and a client
            // and server can still process non-repeated messages.

            BouncyCastleServices clientServices = new BouncyCastleServices(KeyGeneration.GeneratePrivateKey(), new InMemoryStorage());
            BouncyCastleServices serverServices = new BouncyCastleServices(KeyGeneration.GeneratePrivateKey(), new InMemoryStorage());

            var client = new MicroRatchetClient(clientServices, true);
            var server = new MicroRatchetClient(serverServices, false);

            var clientInitPacket = client.InitiateInitialization();
            var responsePacket = server.Receive(clientInitPacket.ToArray()).ToSendBack;
            Assert.Throws<InvalidOperationException>(() => server.Receive(clientInitPacket.ToArray()));
            var firstPacket = client.Receive(responsePacket.ToArray()).ToSendBack;
            Assert.Throws<InvalidOperationException>(() => client.Receive(responsePacket.ToArray()));
            var firstResponse = server.Receive(firstPacket.ToArray()).ToSendBack;
            Assert.Throws<InvalidOperationException>(() => server.Receive(firstPacket.ToArray()));
            var lastResult = client.Receive(firstResponse.ToArray()).ToSendBack;
            Assert.Throws<InvalidOperationException>(() => client.Receive(firstResponse.ToArray()));
            client.SaveState();
            server.SaveState();
            ClientState clientState = ClientState.Load(clientServices.Storage, DefaultKexFactory.Instance);
            ServerState serverState = ServerState.Load(serverServices.Storage, DefaultKexFactory.Instance);

            var rng = new RandomNumberGenerator();
            byte[] message1 = rng.Generate(32);
            byte[] message2 = rng.Generate(32);
            var m1 = client.Send(message1);
            var p1 = server.Receive(m1).Payload;
            var m2 = server.Send(message2);
            var p2 = client.Receive(m2).Payload;
            Assert.Equal(message1, p1);
            Assert.Equal(message2, p2);
        }

        [Fact]
        public void ClientInitializationRestartTest()
        {
            // this test simulates a client timeout during initialization. When this
            // happens the client will restart initialization. The test checks that
            // the server and client will behave properly no matter at what point
            // during initialization the packet was dropped.

            BouncyCastleServices clientServices = new BouncyCastleServices(KeyGeneration.GeneratePrivateKey(), new InMemoryStorage());
            BouncyCastleServices serverServices = new BouncyCastleServices(KeyGeneration.GeneratePrivateKey(), new InMemoryStorage());


            for (int i = 0; i < 4; i++)
            {
                var client = new MicroRatchetClient(clientServices, true);
                var server = new MicroRatchetClient(serverServices, false);

                {
                    var clientInitPacket = client.InitiateInitialization();
                    if (i == 0) goto restart;
                    var responsePacket = server.Receive(clientInitPacket).ToSendBack;
                    if (i == 1) goto restart;
                    var firstPacket = client.Receive(responsePacket).ToSendBack;
                    if (i == 2) goto restart;
                    var firstResponse = server.Receive(firstPacket).ToSendBack;
                    if (i == 3) goto restart;
                    client.Receive(firstResponse);
                }

                restart:
                {
                    var clientInitPacket = client.InitiateInitialization();
                    var responsePacket = server.Receive(clientInitPacket).ToSendBack;
                    var firstPacket = client.Receive(responsePacket).ToSendBack;
                    var firstResponse = server.Receive(firstPacket).ToSendBack;
                    var lastResult = client.Receive(firstResponse).ToSendBack;

                    Assert.Null(lastResult);
                }

                var rng = new RandomNumberGenerator();
                byte[] message1 = rng.Generate(32);
                byte[] message2 = rng.Generate(32);
                var m1 = client.Send(message1);
                var p1 = server.Receive(m1).Payload;
                var m2 = server.Send(message2);
                var p2 = client.Receive(m2).Payload;
                Assert.Equal(message1, p1);
                Assert.Equal(message2, p2);
            }
        }
    }
}
