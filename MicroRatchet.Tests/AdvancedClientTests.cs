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

            var cp1 = client.Send(cmessage1);
            var cp2 = client.Send(cmessage2);
            var sr1 = server.Receive(cp1);
            var sr2 = server.Receive(cp2);
            Assert.Equal(cmessage1, sr1);
            Assert.Equal(cmessage2, sr2);

            var sp1 = server.Send(smessage1);
            var sp2 = server.Send(smessage2);
            var cr1 = client.Receive(sp1);
            var cr2 = client.Receive(sp2);
            Assert.Equal(smessage1, cr1);
            Assert.Equal(smessage2, cr2);

            var cp3 = client.Send(cmessage3);
            var cp4 = client.Send(cmessage4);
            var sr3 = server.Receive(cp3);
            var sr4 = server.Receive(cp4);
            Assert.Equal(cmessage3, sr3);
            Assert.Equal(cmessage4, sr4);

            var sp3 = server.Send(smessage3);
            var sp4 = server.Send(smessage4);
            var cr3 = client.Receive(sp3);
            var cr4 = client.Receive(sp4);
            Assert.Equal(smessage3, cr3);
            Assert.Equal(smessage4, cr4);

            var cp5 = client.Send(cmessage5);
            var cp6 = client.Send(cmessage6);
            var sr5 = server.Receive(cp5);
            var sr6 = server.Receive(cp6);
            Assert.Equal(cmessage5, sr5);
            Assert.Equal(cmessage6, sr6);

            var sp5 = server.Send(smessage5);
            var sp6 = server.Send(smessage6);
            var cr5 = client.Receive(sp5);
            var cr6 = client.Receive(sp6);
            Assert.Equal(smessage5, cr5);
            Assert.Equal(smessage6, cr6);

            var cs = State.Deserialize(client.Services.SecureStorage.LoadAsync());
            var ss = State.Deserialize(server.Services.SecureStorage.LoadAsync());
            Assert.Equal(5, cs.Ratchets.Count);
            Assert.Equal(4, ss.Ratchets.Count);
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
        public void LargeVolumeTest(int clientMessagesCount, int serverMessagesCount, double clientDropChance = 0, double serverDropChance = 0, bool outOfOrder = false)
        {
            var (client, server) = CreateAndInitialize();
            RandomNumberGenerator rng = new RandomNumberGenerator();
            Random r = new Random();
            var clientMessages = new HashSet<byte[]>(Enumerable.Range(0, clientMessagesCount).Select(_ => rng.Generate(32)));
            var serverMessages = new HashSet<byte[]>(Enumerable.Range(0, serverMessagesCount).Select(_ => rng.Generate(32)));
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
                            messagesSentFromClient.Add(message);
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
                            messagesSentFromServer.Add(message);
                        }
                    }
                    else n = 2;
                }
                if (n == 2) // receive by client
                {
                    var message = Dequeue(messagesSentFromServer);
                    if (message != null)
                    {
                        var payload = client.Receive(message);
                        messagesReceivedByClient.Add(payload);
                    }
                    else n = 3;
                }
                if (n == 3) // receive by server
                {
                    var message = Dequeue(messagesSentFromClient);
                    if (message != null)
                    {
                        var payload = server.Receive(message);
                        messagesReceivedByServer.Add(payload);
                    }
                }
            }

            var clientState = State.Deserialize(client.Services.SecureStorage.LoadAsync());
            var serverState = State.Deserialize(server.Services.SecureStorage.LoadAsync());
            Assert.All(messagesReceivedByClient, message => serverMessages.Contains(message));
            Assert.All(messagesReceivedByServer, message => clientMessages.Contains(message));
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

            return (new MicroRatchetClient(clientServices, true, 80), new MicroRatchetClient(serverServices, false, 80));
        }
    }
}
