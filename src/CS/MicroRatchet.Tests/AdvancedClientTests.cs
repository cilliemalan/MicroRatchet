using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Xunit;

namespace MicroRatchet.Tests
{
    public class AdvancedClientTests
    {
        [Fact]
        public void SendSomeMessagesBothDirectionsWithEcdhMultiTest()
        {
            var (client, server) = CreateAndInitialize();

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

        [Fact]
        public void SendLargeMessageTest()
        {
            var (client, server) = CreateAndInitialize();

            RandomNumberGenerator rng = new RandomNumberGenerator();
            byte[] message = rng.Generate(client.MultipartMessageSize * 7);

            var toSend = client.SendMultipart(message);
            Assert.True(toSend.IsMultipartMessage);
            Assert.Equal(7, toSend.Messages.Length);
        }

        [Fact]
        public void ReceiveLargeMessageTest()
        {
            var (client, server) = CreateAndInitialize();

            RandomNumberGenerator rng = new RandomNumberGenerator();
            byte[] message = rng.Generate(client.MultipartMessageSize * 7);

            var toSend = client.SendMultipart(message);
            Assert.True(toSend.IsMultipartMessage);
            Assert.Equal(7, toSend.Messages.Length);

            for (int i = 0; i < 6; i++)
            {
                var rr = server.Receive(toSend.Messages[i]);
                Assert.Equal(ReceivedDataType.Partial, rr.ReceivedDataType);
                Assert.Equal(client.MultipartMessageSize, rr.Payload.Length);
                Assert.Equal(i, rr.MessageNumber);
                Assert.Equal(7, rr.TotalMessages);
            }

            var lr = server.Receive(toSend.Messages[6]);
            Assert.Equal(ReceivedDataType.Normal, lr.ReceivedDataType);
            Assert.Equal(message.Length, lr.Payload.Length);
            Assert.Equal(6, lr.MessageNumber);
            Assert.Equal(7, lr.TotalMessages);
            Assert.Equal(message, lr.Payload);
        }

        [Fact]
        public void ReceiveLargeMessageWithABitLeftOverTest()
        {
            var (client, server) = CreateAndInitialize();

            RandomNumberGenerator rng = new RandomNumberGenerator();
            byte[] message = rng.Generate(client.MultipartMessageSize * 7 + 10);

            var toSend = client.SendMultipart(message);
            Assert.True(toSend.IsMultipartMessage);
            Assert.Equal(8, toSend.Messages.Length);

            for (int i = 0; i < 7; i++)
            {
                var rr = server.Receive(toSend.Messages[i]);
                Assert.Equal(ReceivedDataType.Partial, rr.ReceivedDataType);
                Assert.Equal(client.MultipartMessageSize, rr.Payload.Length);
                Assert.Equal(i, rr.MessageNumber);
                Assert.Equal(8, rr.TotalMessages);
            }

            var lr = server.Receive(toSend.Messages[7]);
            Assert.Equal(ReceivedDataType.Normal, lr.ReceivedDataType);
            Assert.Equal(message.Length, lr.Payload.Length);
            Assert.Equal(7, lr.MessageNumber);
            Assert.Equal(8, lr.TotalMessages);
            Assert.Equal(message, lr.Payload);
        }

        [Fact]
        public void ReceiveLargeMessageOverlappingTest()
        {
            var (client, server) = CreateAndInitialize();

            RandomNumberGenerator rng = new RandomNumberGenerator();
            byte[] message1 = rng.Generate(client.MultipartMessageSize * 2);
            byte[] message2 = rng.Generate(client.MultipartMessageSize * 2);

            var toSend1 = client.SendMultipart(message1);
            var toSend2 = client.SendMultipart(message2);
            Assert.True(toSend1.IsMultipartMessage);
            Assert.Equal(2, toSend1.Messages.Length);
            Assert.True(toSend2.IsMultipartMessage);
            Assert.Equal(2, toSend2.Messages.Length);

            var rr1 = server.Receive(toSend1.Messages[0]);
            var rr2 = server.Receive(toSend2.Messages[0]);
            var lr1 = server.Receive(toSend1.Messages[1]);
            var lr2 = server.Receive(toSend2.Messages[1]);

            Assert.Equal(ReceivedDataType.Partial, rr1.ReceivedDataType);
            Assert.Equal(client.MultipartMessageSize, rr1.Payload.Length);
            Assert.Equal(0, rr1.MessageNumber);
            Assert.Equal(2, rr1.TotalMessages);
            Assert.NotEqual(rr1.MultipartSequence, rr2.MultipartSequence);
            Assert.Equal(rr1.MultipartSequence, lr1.MultipartSequence);
            Assert.Equal(ReceivedDataType.Partial, rr2.ReceivedDataType);
            Assert.Equal(client.MultipartMessageSize, rr2.Payload.Length);
            Assert.Equal(0, rr2.MessageNumber);
            Assert.Equal(2, rr2.TotalMessages);

            Assert.Equal(ReceivedDataType.Normal, lr1.ReceivedDataType);
            Assert.Equal(message1.Length, lr1.Payload.Length);
            Assert.Equal(1, lr1.MessageNumber);
            Assert.Equal(2, lr1.TotalMessages);
            Assert.Equal(message1, lr1.Payload);
            Assert.Equal(ReceivedDataType.Normal, lr2.ReceivedDataType);
            Assert.Equal(message1.Length, lr2.Payload.Length);
            Assert.Equal(1, lr2.MessageNumber);
            Assert.Equal(2, lr2.TotalMessages);
            Assert.Equal(message2, lr2.Payload);
        }

        [Fact]
        public void ReceiveLargeMessageOutOfOrderTest()
        {
            var (client, server) = CreateAndInitialize();

            RandomNumberGenerator rng = new RandomNumberGenerator();
            byte[] message1 = rng.Generate(client.MultipartMessageSize * 2);
            byte[] message2 = rng.Generate(client.MultipartMessageSize * 2);

            var toSend1 = client.SendMultipart(message1);
            var toSend2 = client.SendMultipart(message2);
            Assert.True(toSend1.IsMultipartMessage);
            Assert.Equal(2, toSend1.Messages.Length);
            Assert.True(toSend2.IsMultipartMessage);
            Assert.Equal(2, toSend2.Messages.Length);

            var rr2 = server.Receive(toSend2.Messages[1]);
            var rr1 = server.Receive(toSend1.Messages[1]);
            var lr1 = server.Receive(toSend1.Messages[0]);
            var lr2 = server.Receive(toSend2.Messages[0]);

            Assert.Equal(ReceivedDataType.Partial, rr1.ReceivedDataType);
            Assert.Equal(client.MultipartMessageSize, rr1.Payload.Length);
            Assert.Equal(1, rr1.MessageNumber);
            Assert.Equal(2, rr1.TotalMessages);
            Assert.NotEqual(rr1.MultipartSequence, rr2.MultipartSequence);
            Assert.Equal(rr1.MultipartSequence, lr1.MultipartSequence);
            Assert.Equal(ReceivedDataType.Partial, rr2.ReceivedDataType);
            Assert.Equal(client.MultipartMessageSize, rr2.Payload.Length);
            Assert.Equal(1, rr2.MessageNumber);
            Assert.Equal(2, rr2.TotalMessages);

            Assert.Equal(ReceivedDataType.Normal, lr1.ReceivedDataType);
            Assert.Equal(message1.Length, lr1.Payload.Length);
            Assert.Equal(0, lr1.MessageNumber);
            Assert.Equal(2, lr1.TotalMessages);
            Assert.Equal(message1, lr1.Payload);
            Assert.Equal(ReceivedDataType.Normal, lr2.ReceivedDataType);
            Assert.Equal(message1.Length, lr2.Payload.Length);
            Assert.Equal(0, lr2.MessageNumber);
            Assert.Equal(2, lr2.TotalMessages);
            Assert.Equal(message2, lr2.Payload);
        }

        [InlineData(100, 10)]
        [InlineData(10, 100)]
        [InlineData(100, 100)]
        [InlineData(100, 100, 0.1, 0.1)]
        [InlineData(100, 100, 0.5, 0.5)]
        [InlineData(100, 100, 0.1, 0.5)]
        [InlineData(100, 100, 0.5, 0.1)]
        [InlineData(100, 100, 0.5, 0.0)]
        [InlineData(100, 100, 0.0, 0.5)]
        [InlineData(100, 100, 0.5, 0.1, true)]
        [InlineData(100, 100, 0.5, 0.0, true)]
        [InlineData(100, 100, 0.0, 0.5, true)]
        [InlineData(1000, 100, 0.1, 0.1)]
        [InlineData(1000, 100, 0.5, 0.5)]
        [InlineData(1000, 100, 0.1, 0.5)]
        [InlineData(1000, 100, 0.5, 0.1)]
        [InlineData(1000, 100, 0.5, 0.0)]
        [InlineData(1000, 100, 0.0, 0.5)]
        [InlineData(1000, 100, 0.5, 0.1, true)]
        [InlineData(1000, 100, 0.5, 0.0, true)]
        [InlineData(1000, 100, 0.0, 0.5, true)]
        [Theory]
        public void LargeVolumeTest(int clientMessagesCount, int serverMessagesCount, double clientDropChance = 0, double serverDropChance = 0, bool outOfOrder = false, int minsize = 16, int maxsize = 32)
        {
            var (client, server) = CreateAndInitialize();
            var cservices = client.Services;
            var sservices = server.Services;

            RandomNumberGenerator rng = new RandomNumberGenerator();
            Random r = new Random();
            var clientMessages = new HashSet<byte[]>(Enumerable.Range(0, clientMessagesCount).Select(_ => rng.Generate(r.Next(minsize, maxsize))));
            var serverMessages = new HashSet<byte[]>(Enumerable.Range(0, serverMessagesCount).Select(_ => rng.Generate(r.Next(minsize, maxsize))));
            Queue<byte[]> clientMessagesToSend = new Queue<byte[]>(clientMessages);
            Queue<byte[]> serverMessagesToSend = new Queue<byte[]>(serverMessages);
            var messagesSentFromClient = new List<byte[]>();
            var messagesSentFromServer = new List<byte[]>();
            HashSet<byte[]> messagesReceivedByClient = new HashSet<byte[]>();
            HashSet<byte[]> messagesReceivedByServer = new HashSet<byte[]>();

            byte[] DoubleInSize(byte[] payload) => payload.Concat(payload).ToArray();

            byte[] Dequeue(List<byte[]> l)
            {
                if (outOfOrder)
                {
                    if (l.Count == 0) return null;
                    else if (l.Count < 10)
                    {
                        var m = l[r.Next(l.Count)];
                        l.Remove(m);
                        return m;
                    }
                }

                {
                    var m = l.FirstOrDefault();
                    l.Remove(m);
                    return m;
                }
            }

            for (; ; )
            {
                if (!messagesSentFromClient.Any() && !messagesSentFromServer.Any() &&
                    !clientMessagesToSend.TryPeek(out var _) && !serverMessagesToSend.TryPeek(out var _))
                {
                    break;
                }

                var n = r.Next(4);

                if (n == 0) // send from client
                {
                    clientMessagesToSend.TryDequeue(out var payload);
                    if (payload != null)
                    {
                        payload = r.Next(10) > 7 ? DoubleInSize(payload) : payload;
                        var message = client.Send(payload);
                        if (r.NextDouble() > clientDropChance)
                        {
                            messagesSentFromClient.AddRange(message.Messages);
                        }
                    }
                    else n = 1;
                }
                if (n == 1) // send from server
                {
                    serverMessagesToSend.TryDequeue(out var payload);
                    if (payload != null)
                    {
                        payload = r.Next(10) > 7 ? DoubleInSize(payload) : payload;
                        var message = server.Send(payload);
                        if (r.NextDouble() > serverDropChance)
                        {
                            messagesSentFromServer.AddRange(message.Messages);
                        }
                    }
                    else n = 2;
                }
                if (n == 2) // receive by client
                {
                    var message = Dequeue(messagesSentFromServer);
                    if (message != null)
                    {
                        var received = client.Receive(message);
                        if (received.ReceivedDataType == ReceivedDataType.Normal)
                        {
                            messagesReceivedByClient.Add(received.Payload);
                        }
                    }
                    else n = 3;
                }
                if (n == 3) // receive by server
                {
                    var message = Dequeue(messagesSentFromClient);
                    if (message != null)
                    {
                        var received = server.Receive(message);
                        if (received.ReceivedDataType == ReceivedDataType.Normal)
                        {
                            messagesReceivedByServer.Add(received.Payload);
                        }
                    }
                }
            }

            Assert.All(messagesReceivedByClient, message => serverMessages.Contains(message));
            Assert.All(messagesReceivedByServer, message => clientMessages.Contains(message));
        }

        private static (MicroRatchetClient client, MicroRatchetClient server) CreateAndInitialize()
        {
            DefaultServices clientServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());
            DefaultServices serverServices = new DefaultServices(KeyGeneration.GeneratePrivateKey());

            var client = new MicroRatchetClient(clientServices, true);
            var server = new MicroRatchetClient(serverServices, false);

            var packet = client.InitiateInitialization();

            while (!client.IsInitialized || !server.IsInitialized)
            {
                packet = server.Receive(packet).ToSendBack;
                if (packet != null) packet = client.Receive(packet).ToSendBack;
            }

            client.SaveState();
            server.SaveState();
            return (new MicroRatchetClient(clientServices, true, 80), new MicroRatchetClient(serverServices, false, 80));
        }
    }
}
