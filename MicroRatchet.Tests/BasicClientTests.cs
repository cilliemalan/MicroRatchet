using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Xunit;

namespace MicroRatchet.Tests
{
    public class BasicClientTests
    {
        [Fact]
        public void ClientInitializationMessageTest()
        {
            DefaultServices clientServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());

            var client = new MicroRatchetClient(clientServices, true);

            var clientInitPacket = client.ProcessInitialization();
            client.SaveState();
            ClientState clientState = ClientState.Load(clientServices.Storage, DefaultKexFactory.Instance);

            Assert.NotNull(clientState.LocalEcdhForInit);
            Assert.NotNull(clientState.InitializationNonce);
            
            Assert.Equal(32, clientState.InitializationNonce.Length);
        }

        [Fact]
        public void ClientInitializationProcessTest()
        {
            DefaultServices clientServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());
            DefaultServices serverServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());

            var client = new MicroRatchetClient(clientServices, true);
            var server = new MicroRatchetClient(serverServices, false);

            var clientInitPacket = client.ProcessInitialization();
            var responsePacket = server.ProcessInitialization(clientInitPacket);
            client.SaveState();
            server.SaveState();
            ClientState clientState = ClientState.Load(clientServices.Storage, DefaultKexFactory.Instance);
            ServerState serverState = ServerState.Load(serverServices.Storage, DefaultKexFactory.Instance);
            
        }

        [Fact]
        public void ClientInitializationProcessResponseTest()
        {
            DefaultServices clientServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());
            DefaultServices serverServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());

            var client = new MicroRatchetClient(clientServices, true);
            var server = new MicroRatchetClient(serverServices, false);

            var clientInitPacket = client.ProcessInitialization();
            var responsePacket = server.ProcessInitialization(clientInitPacket);
            var firstPacket = client.ProcessInitialization(responsePacket);
            client.SaveState();
            server.SaveState();
            ClientState clientState = ClientState.Load(clientServices.Storage, DefaultKexFactory.Instance);
            ServerState serverState = ServerState.Load(serverServices.Storage, DefaultKexFactory.Instance);
            
            Assert.Equal(clientState.Ratchets[0].SendingChain.HeaderKey, serverState.FirstReceiveHeaderKey);
            Assert.Equal(clientState.Ratchets[1].ReceivingChain.HeaderKey, serverState.FirstSendHeaderKey);
        }

        [Fact]
        public void ClientInitializationProcessFirstPacketSendTest()
        {
            DefaultServices clientServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());
            DefaultServices serverServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());

            var client = new MicroRatchetClient(clientServices, true);
            var server = new MicroRatchetClient(serverServices, false);

            var clientInitPacket = client.ProcessInitialization();
            var responsePacket = server.ProcessInitialization(clientInitPacket);
            var firstPacket = client.ProcessInitialization(responsePacket);
            var firstResponse = server.ProcessInitialization(firstPacket);
            client.SaveState();
            server.SaveState();
            ClientState clientState = ClientState.Load(clientServices.Storage, DefaultKexFactory.Instance);
            ServerState serverState = ServerState.Load(serverServices.Storage, DefaultKexFactory.Instance);

            Assert.NotNull(firstResponse);
            Assert.Equal(2, clientState.Ratchets.Count);
            Assert.Equal(1, serverState.Ratchets.Count);
        }

        [Fact]
        public void ClientInitializationProcessComplete()
        {
            DefaultServices clientServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());
            DefaultServices serverServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());

            var client = new MicroRatchetClient(clientServices, true);
            var server = new MicroRatchetClient(serverServices, false);

            var clientInitPacket = client.ProcessInitialization();
            var responsePacket = server.ProcessInitialization(clientInitPacket);
            var firstPacket = client.ProcessInitialization(responsePacket);
            var firstResponse = server.ProcessInitialization(firstPacket);
            var lastResult = client.ProcessInitialization(firstResponse);
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
            var clientInitPacket = client.ProcessInitialization();
            client.SaveState();
            var server = new MicroRatchetClient(serverServices, false);
            var responsePacket = server.ProcessInitialization(clientInitPacket);
            server.SaveState();
            client = new MicroRatchetClient(clientServices, true);
            var firstPacket = client.ProcessInitialization(responsePacket);
            client.SaveState();
            server = new MicroRatchetClient(serverServices, false);
            var firstResponse = server.ProcessInitialization(firstPacket);
            server.SaveState();
            client = new MicroRatchetClient(clientServices, true);
            var lastResult = client.ProcessInitialization(firstResponse);
            client.SaveState();

            Assert.Null(lastResult);
        }

        [Fact]
        public void ClientMessagesReinstantiation()
        {
            DefaultServices clientServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());
            DefaultServices serverServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());

            RandomNumberGenerator rng = new RandomNumberGenerator();
            byte[] message1 = rng.Generate(64);
            byte[] message2 = rng.Generate(64);
            byte[] message3 = rng.Generate(64);

            var client = new MicroRatchetClient(clientServices, true);
            var clientInitPacket = client.ProcessInitialization();
            client.SaveState();
            var server = new MicroRatchetClient(serverServices, false);
            var responsePacket = server.ProcessInitialization(clientInitPacket);
            server.SaveState();
            client = new MicroRatchetClient(clientServices, true);
            var firstPacket = client.ProcessInitialization(responsePacket);
            client.SaveState();
            server = new MicroRatchetClient(serverServices, false);
            var firstResponse = server.ProcessInitialization(firstPacket);
            server.SaveState();
            client = new MicroRatchetClient(clientServices, true);
            var lastResult = client.ProcessInitialization(firstResponse);
            client.SaveState();

            client = new MicroRatchetClient(clientServices, true, 80);
            var pl1 = client.Send(message1);
            client.SaveState();
            client = new MicroRatchetClient(clientServices, true, 80);
            var pl2 = client.Send(message2);
            client.SaveState();
            client = new MicroRatchetClient(clientServices, true, 80);
            var pl3 = client.Send(message3);
            client.SaveState();

            server = new MicroRatchetClient(serverServices, false, 80);
            var r1 = server.Receive(pl1);
            server.SaveState();
            server = new MicroRatchetClient(serverServices, false, 80);
            var r2 = server.Receive(pl2);
            server.SaveState();
            server = new MicroRatchetClient(serverServices, false, 80);
            var r3 = server.Receive(pl3);
            server.SaveState();

            Assert.Equal(message1, r1);
            Assert.Equal(message2, r2);
            Assert.Equal(message3, r3);

            Assert.Null(lastResult);
        }

        [Fact]
        public void SendSomeMessagesFromClientTest()
        {
            var (client, server) = CreateAndInitialize();

            RandomNumberGenerator rng = new RandomNumberGenerator();
            byte[] message1 = rng.Generate(64);
            byte[] message2 = rng.Generate(64);
            byte[] message3 = rng.Generate(64);

            var pl1 = client.Send(message1);
            var pl2 = client.Send(message2);
            var pl3 = client.Send(message3);

            var r1 = server.Receive(pl1);
            var r2 = server.Receive(pl2);
            var r3 = server.Receive(pl3);

            Assert.Equal(message1, r1);
            Assert.Equal(message2, r2);
            Assert.Equal(message3, r3);
        }

        [Fact]
        public void SendSomeMessagesFromClientOutOfOrderTest()
        {
            var (client, server) = CreateAndInitialize();

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

            var r5 = server.Receive(pl5);
            var r1 = server.Receive(pl1);
            var r3 = server.Receive(pl3);
            var r4 = server.Receive(pl4);
            var r2 = server.Receive(pl2);

            Assert.Equal(message1, r1);
            Assert.Equal(message2, r2);
            Assert.Equal(message3, r3);
            Assert.Equal(message4, r4);
            Assert.Equal(message5, r5);
        }

        [Fact]
        public void SendSomeMessagesFromClientOutOfOrderWithDropsTest()
        {
            var (client, server) = CreateAndInitialize();

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

            var r5 = server.Receive(pl5);
            var r1 = server.Receive(pl1);
            //var r3 = server.Receive(pl3);
            var r4 = server.Receive(pl4);
            var r2 = server.Receive(pl2);

            Assert.Equal(message1, r1);
            Assert.Equal(message2, r2);
            //Assert.Equal(message3, r3);
            Assert.Equal(message4, r4);
            Assert.Equal(message5, r5);
        }

        [Fact]
        public void SendSomeMessagesBothDirectionsTest()
        {
            var (client, server) = CreateAndInitialize();

            RandomNumberGenerator rng = new RandomNumberGenerator();
            byte[] cmessage1 = rng.Generate(64);
            byte[] cmessage2 = rng.Generate(64);
            byte[] cmessage3 = rng.Generate(64);
            byte[] smessage1 = rng.Generate(64);
            byte[] smessage2 = rng.Generate(64);
            byte[] smessage3 = rng.Generate(64);

            var cp1 = client.Send(cmessage1);
            var sr1 = server.Receive(cp1);

            var sp1 = server.Send(smessage1);
            var cr1 = client.Receive(sp1);

            var cp2 = client.Send(cmessage2);
            var sr2 = server.Receive(cp2);

            var sp2 = server.Send(smessage2);
            var cr2 = client.Receive(sp2);

            var cp3 = client.Send(cmessage3);
            var sr3 = server.Receive(cp3);

            var sp3 = server.Send(smessage3);
            var cr3 = client.Receive(sp3);

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
            var (client, server) = CreateAndInitialize();

            RandomNumberGenerator rng = new RandomNumberGenerator();
            byte[] cmessage1 = rng.Generate(64);
            byte[] cmessage2 = rng.Generate(64);
            byte[] cmessage3 = rng.Generate(64);
            byte[] smessage1 = rng.Generate(64);
            byte[] smessage2 = rng.Generate(64);
            byte[] smessage3 = rng.Generate(64);

            var cp1 = client.Send(cmessage1);
            var sr1 = server.Receive(cp1);

            var sp1 = server.Send(smessage1);
            var cr1 = client.Receive(sp1);

            //var cp2 = client.Send(cmessage2);
            //var sr2 = server.Receive(cp2);

            //var sp2 = server.Send(smessage2);
            //var cr2 = client.Receive(sp2);

            var cp3 = client.Send(cmessage3);
            var sr3 = server.Receive(cp3);

            var sp3 = server.Send(smessage3);
            var cr3 = client.Receive(sp3);

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
            var (client, server) = CreateAndInitialize();

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
            var sr1 = server.Receive(cp1);
            var sp1 = server.Send(smessage1);
            var cr1 = client.Receive(sp1);
            var sp4 = server.Send(smessage4);
            var cp3 = client.Send(cmessage3);
            var cp2 = client.Send(cmessage2);
            var sr3 = server.Receive(cp3);
            var cp5 = client.Send(cmessage5);
            var cp4 = client.Send(cmessage4);
            var cr4 = client.Receive(sp4);
            var sp3 = server.Send(smessage3);
            var sr5 = server.Receive(cp5);
            var sp2 = server.Send(smessage2);
            var cr3 = client.Receive(sp3);
            var sr2 = server.Receive(cp2);
            var cr2 = client.Receive(sp2);
            var sr4 = server.Receive(cp4);
            var sp5 = server.Send(smessage5);
            var cr5 = client.Receive(sp5);

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
            var (client, server) = CreateAndInitialize();

            RandomNumberGenerator rng = new RandomNumberGenerator();
            byte[] cmessage1 = rng.Generate(32);
            byte[] cmessage2 = rng.Generate(32);
            byte[] cmessage3 = rng.Generate(32);
            byte[] smessage1 = rng.Generate(32);
            byte[] smessage2 = rng.Generate(32);
            byte[] smessage3 = rng.Generate(32);

            var cp1 = client.Send(cmessage1);
            var sr1 = server.Receive(cp1);
            Assert.Equal(cmessage1, sr1);

            var sp1 = server.Send(smessage1);
            var cr1 = client.Receive(sp1);
            Assert.Equal(smessage1, cr1);

            var cp2 = client.Send(cmessage2);
            var sr2 = server.Receive(cp2);
            Assert.Equal(cmessage2, sr2);

            var sp2 = server.Send(smessage2);
            var cr2 = client.Receive(sp2);
            Assert.Equal(smessage2, cr2);

            var cp3 = client.Send(cmessage3);
            var sr3 = server.Receive(cp3);
            Assert.Equal(cmessage3, sr3);

            var sp3 = server.Send(smessage3);
            var cr3 = client.Receive(sp3);
            Assert.Equal(smessage3, cr3);

            client.SaveState();
            server.SaveState();
            var cs = ClientState.Load(client.Services.Storage, DefaultKexFactory.Instance);
            var ss = ServerState.Load(server.Services.Storage, DefaultKexFactory.Instance);
            Assert.Equal(4, cs.Ratchets.Count);
            Assert.Equal(4, ss.Ratchets.Count);
        }

        private static (MicroRatchetClient client, MicroRatchetClient server) CreateAndInitialize()
        {
            DefaultServices clientServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());
            DefaultServices serverServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());

            var client = new MicroRatchetClient(clientServices, true);
            var server = new MicroRatchetClient(serverServices, false);

            var clientInitPacket = client.ProcessInitialization();
            var responsePacket = server.ProcessInitialization(clientInitPacket);
            var firstPacket = client.ProcessInitialization(responsePacket);
            var firstResponse = server.ProcessInitialization(firstPacket);
            var lastResult = client.ProcessInitialization(firstResponse);

            Assert.Null(lastResult);

            client.SaveState();
            server.SaveState();
            return (new MicroRatchetClient(clientServices, true, 80), new MicroRatchetClient(serverServices, false, 80));
        }
    }
}
