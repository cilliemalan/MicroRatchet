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

            var clientInitPacket = client.InitiateInitialization();
            client.SaveState();
            ClientState clientState = ClientState.Load(clientServices.Storage, DefaultKexFactory.Instance, client.Configuration.UseAes256 ? 32 : 16);

            Assert.NotNull(clientState.LocalEcdhForInit);
            Assert.NotNull(clientState.InitializationNonce);
            
            Assert.Equal(4, clientState.InitializationNonce.Length);
        }

        [Fact]
        public void ClientInitializationProcessTest()
        {
            DefaultServices clientServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());
            DefaultServices serverServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());

            var client = new MicroRatchetClient(clientServices, true);
            var server = new MicroRatchetClient(serverServices, false);

            var clientInitPacket = client.InitiateInitialization();
            var responsePacket = server.Receive(clientInitPacket).ToSendBack;
            client.SaveState();
            server.SaveState();
            ClientState clientState = ClientState.Load(clientServices.Storage, DefaultKexFactory.Instance, client.Configuration.UseAes256 ? 32 : 16);
            ServerState serverState = ServerState.Load(serverServices.Storage, DefaultKexFactory.Instance, server.Configuration.UseAes256 ? 32 : 16);
            
        }

        [Fact]
        public void ClientInitializationProcessResponseTest()
        {
            DefaultServices clientServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());
            DefaultServices serverServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());

            var client = new MicroRatchetClient(clientServices, true);
            var server = new MicroRatchetClient(serverServices, false);

            var clientInitPacket = client.InitiateInitialization();
            var responsePacket = server.Receive(clientInitPacket).ToSendBack;
            var firstPacket = client.Receive(responsePacket).ToSendBack;
            client.SaveState();
            server.SaveState();
            ClientState clientState = ClientState.Load(clientServices.Storage, DefaultKexFactory.Instance, client.Configuration.UseAes256 ? 32 : 16);
            ServerState serverState = ServerState.Load(serverServices.Storage, DefaultKexFactory.Instance, server.Configuration.UseAes256 ? 32 : 16);
            
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

            var clientInitPacket = client.InitiateInitialization();
            var responsePacket = server.Receive(clientInitPacket).ToSendBack;
            var firstPacket = client.Receive(responsePacket).ToSendBack;
            var firstResponse = server.Receive(firstPacket).ToSendBack;
            client.SaveState();
            server.SaveState();
            ClientState clientState = ClientState.Load(clientServices.Storage, DefaultKexFactory.Instance, client.Configuration.UseAes256 ? 32 : 16);
            ServerState serverState = ServerState.Load(serverServices.Storage, DefaultKexFactory.Instance, server.Configuration.UseAes256 ? 32 : 16);

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

            var clientInitPacket = client.InitiateInitialization();
            var responsePacket = server.Receive(clientInitPacket).ToSendBack;
            var firstPacket = client.Receive(responsePacket).ToSendBack;
            var firstResponse = server.Receive(firstPacket).ToSendBack;
            var lastResult = client.Receive(firstResponse).ToSendBack;
            client.SaveState();
            server.SaveState();
            ClientState clientState = ClientState.Load(clientServices.Storage, DefaultKexFactory.Instance, client.Configuration.UseAes256 ? 32 : 16);
            ServerState serverState = ServerState.Load(serverServices.Storage, DefaultKexFactory.Instance, server.Configuration.UseAes256 ? 32 : 16);

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
        public void ClientMessagesReinstantiation()
        {
            DefaultServices clientServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());
            DefaultServices serverServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());

            RandomNumberGenerator rng = new RandomNumberGenerator();
            byte[] message1 = rng.Generate(64);
            byte[] message2 = rng.Generate(64);
            byte[] message3 = rng.Generate(64);

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

            client = new MicroRatchetClient(clientServices, true, 80);
            var pl1 = client.Send(message1).Message;
            client.SaveState();
            client = new MicroRatchetClient(clientServices, true, 80);
            var pl2 = client.Send(message2).Message;
            client.SaveState();
            client = new MicroRatchetClient(clientServices, true, 80);
            var pl3 = client.Send(message3).Message;
            client.SaveState();

            server = new MicroRatchetClient(serverServices, false, 80);
            var r1 = server.Receive(pl1).Payload;
            server.SaveState();
            server = new MicroRatchetClient(serverServices, false, 80);
            var r2 = server.Receive(pl2).Payload;
            server.SaveState();
            server = new MicroRatchetClient(serverServices, false, 80);
            var r3 = server.Receive(pl3).Payload;
            server.SaveState();

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

            var pl1 = client.Send(message1).Message;
            var pl2 = client.Send(message2).Message;
            var pl3 = client.Send(message3).Message;

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

            var pl1 = client.Send(message1).Message;
            var pl2 = client.Send(message2).Message;
            var pl3 = client.Send(message3).Message;
            var pl4 = client.Send(message4).Message;
            var pl5 = client.Send(message5).Message;

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

            var pl1 = client.Send(message1).Message;
            var pl2 = client.Send(message2).Message;
            var pl3 = client.Send(message3).Message;
            var pl4 = client.Send(message4).Message;
            var pl5 = client.Send(message5).Message;

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

            var cp1 = client.Send(cmessage1).Message;
            var sr1 = server.Receive(cp1).Payload;

            var sp1 = server.Send(smessage1).Message;
            var cr1 = client.Receive(sp1).Payload;

            var cp2 = client.Send(cmessage2).Message;
            var sr2 = server.Receive(cp2).Payload;

            var sp2 = server.Send(smessage2).Message;
            var cr2 = client.Receive(sp2).Payload;

            var cp3 = client.Send(cmessage3).Message;
            var sr3 = server.Receive(cp3).Payload;

            var sp3 = server.Send(smessage3).Message;
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

            var cp1 = client.Send(cmessage1).Message;
            var sr1 = server.Receive(cp1).Payload;

            var sp1 = server.Send(smessage1).Message;
            var cr1 = client.Receive(sp1).Payload;

            //var cp2 = client.Send(cmessage2).Message;
            //var sr2 = server.Receive(cp2).Payload;

            //var sp2 = server.Send(smessage2).Message;
            //var cr2 = client.Receive(sp2).Payload;

            var cp3 = client.Send(cmessage3).Message;
            var sr3 = server.Receive(cp3).Payload;

            var sp3 = server.Send(smessage3).Message;
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

            var cp1 = client.Send(cmessage1).Message;
            var sr1 = server.Receive(cp1).Payload;
            var sp1 = server.Send(smessage1).Message;
            var cr1 = client.Receive(sp1).Payload;
            var sp4 = server.Send(smessage4).Message;
            var cp3 = client.Send(cmessage3).Message;
            var cp2 = client.Send(cmessage2).Message;
            var sr3 = server.Receive(cp3).Payload;
            var cp5 = client.Send(cmessage5).Message;
            var cp4 = client.Send(cmessage4).Message;
            var cr4 = client.Receive(sp4).Payload;
            var sp3 = server.Send(smessage3).Message;
            var sr5 = server.Receive(cp5).Payload;
            var sp2 = server.Send(smessage2).Message;
            var cr3 = client.Receive(sp3).Payload;
            var sr2 = server.Receive(cp2).Payload;
            var cr2 = client.Receive(sp2).Payload;
            var sr4 = server.Receive(cp4).Payload;
            var sp5 = server.Send(smessage5).Message;
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

            var cp1 = client.Send(cmessage1).Message;
            var sr1 = server.Receive(cp1).Payload;
            Assert.Equal(cmessage1, sr1);

            var sp1 = server.Send(smessage1).Message;
            var cr1 = client.Receive(sp1).Payload;
            Assert.Equal(smessage1, cr1);

            var cp2 = client.Send(cmessage2).Message;
            var sr2 = server.Receive(cp2).Payload;
            Assert.Equal(cmessage2, sr2);

            var sp2 = server.Send(smessage2).Message;
            var cr2 = client.Receive(sp2).Payload;
            Assert.Equal(smessage2, cr2);

            var cp3 = client.Send(cmessage3).Message;
            var sr3 = server.Receive(cp3).Payload;
            Assert.Equal(cmessage3, sr3);

            var sp3 = server.Send(smessage3).Message;
            var cr3 = client.Receive(sp3).Payload;
            Assert.Equal(smessage3, cr3);

            client.SaveState();
            server.SaveState();
            var cs = ClientState.Load(client.Services.Storage, DefaultKexFactory.Instance, client.Configuration.UseAes256 ? 32 : 16);
            var ss = ServerState.Load(server.Services.Storage, DefaultKexFactory.Instance, server.Configuration.UseAes256 ? 32 : 16);
            Assert.Equal(4, cs.Ratchets.Count);
            Assert.Equal(4, ss.Ratchets.Count);
        }
    }
}
