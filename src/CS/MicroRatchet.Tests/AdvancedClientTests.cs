using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Xunit;

namespace MicroRatchet.Tests
{
    public class AdvancedClientTests
    {
        [InlineData(100, 10)]
        [InlineData(10, 100)]
        [InlineData(100, 100)]
        [InlineData(100, 1000)]
        [InlineData(1000, 100)]
        [InlineData(1000, 1000)]
        [Theory]
        public void LargeVolumeTestBasic(int clientMessagesCount, int serverMessagesCount, double clientDropChance = 0, double serverDropChance = 0, bool outOfOrder = false, int minsize = 16, int maxsize = 32)
        {
            AdvancedTestInternal(clientMessagesCount, serverMessagesCount, clientDropChance, serverDropChance, outOfOrder, minsize, maxsize);
        }

        [InlineData(100, 100, 0.1, 0.1)]
        [InlineData(100, 100, 0.5, 0.5)]
        [InlineData(100, 100, 0.1, 0.5)]
        [InlineData(100, 100, 0.5, 0.1)]
        [InlineData(100, 100, 0.5, 0.0)]
        [InlineData(100, 100, 0.0, 0.5)]
        [Theory]
        public void LargeVolumeTestDrops(int clientMessagesCount, int serverMessagesCount, double clientDropChance = 0, double serverDropChance = 0, bool outOfOrder = false, int minsize = 16, int maxsize = 32)
        {
            AdvancedTestInternal(clientMessagesCount, serverMessagesCount, clientDropChance, serverDropChance, outOfOrder, minsize, maxsize);
        }

        [InlineData(100, 100, 0.5, 0.1, true)]
        [InlineData(100, 100, 0.5, 0.0, true)]
        [InlineData(100, 100, 0.0, 0.5, true)]
        [Theory]
        public void LargeVolumeTestDropsAndReorders(int clientMessagesCount, int serverMessagesCount, double clientDropChance = 0, double serverDropChance = 0, bool outOfOrder = false, int minsize = 16, int maxsize = 32)
        {
            AdvancedTestInternal(clientMessagesCount, serverMessagesCount, clientDropChance, serverDropChance, outOfOrder, minsize, maxsize);
        }

        [InlineData(1000, 100, 0.1, 0.1)]
        [InlineData(1000, 100, 0.5, 0.5)]
        [InlineData(1000, 100, 0.1, 0.5)]
        [InlineData(1000, 100, 0.5, 0.1)]
        [InlineData(1000, 100, 0.5, 0.0)]
        [InlineData(1000, 100, 0.0, 0.5)]
        [Theory]
        public void LargeVolumeTestMoreDrops(int clientMessagesCount, int serverMessagesCount, double clientDropChance = 0, double serverDropChance = 0, bool outOfOrder = false, int minsize = 16, int maxsize = 32)
        {
            AdvancedTestInternal(clientMessagesCount, serverMessagesCount, clientDropChance, serverDropChance, outOfOrder, minsize, maxsize);
        }

        [InlineData(1000, 100, 0.5, 0.1, true)]
        [InlineData(1000, 100, 0.5, 0.0, true)]
        [InlineData(1000, 100, 0.0, 0.5, true)]
        [Theory]
        public void LargeVolumeTestMoreDropsAndReorders(int clientMessagesCount, int serverMessagesCount, double clientDropChance = 0, double serverDropChance = 0, bool outOfOrder = false, int minsize = 16, int maxsize = 32)
        {
            AdvancedTestInternal(clientMessagesCount, serverMessagesCount, clientDropChance, serverDropChance, outOfOrder, minsize, maxsize);
        }

        [InlineData(100, 10, 0.0, 0.0, false, 32, 192)]
        [InlineData(100, 100, 0.0, 0.0, false, 32, 192)]
        [InlineData(1000, 1000, 0.0, 0.0, false, 32, 192)]
        [Theory]
        public void LargeVolumeTestLargeMessages(int clientMessagesCount, int serverMessagesCount, double clientDropChance = 0, double serverDropChance = 0, bool outOfOrder = false, int minsize = 16, int maxsize = 32)
        {
            AdvancedTestInternal(clientMessagesCount, serverMessagesCount, clientDropChance, serverDropChance, outOfOrder, minsize, maxsize);
        }

        [InlineData(100, 10, 0.0, 0.0, true, 32, 192)]
        [InlineData(100, 100, 0.0, 0.0, true, 32, 192)]
        [InlineData(1000, 1000, 0.0, 0.0, true, 32, 192)]
        [Theory]
        public void LargeVolumeTestLargeMessagesReorders(int clientMessagesCount, int serverMessagesCount, double clientDropChance = 0, double serverDropChance = 0, bool outOfOrder = false, int minsize = 16, int maxsize = 32)
        {
            AdvancedTestInternal(clientMessagesCount, serverMessagesCount, clientDropChance, serverDropChance, outOfOrder, minsize, maxsize);
        }

        [InlineData(100, 100, 0.0, 0.1, false, 32, 192)]
        [InlineData(100, 100, 0.1, 0.0, false, 32, 192)]
        [InlineData(100, 100, 0.5, 0.5, false, 32, 192)]
        [InlineData(100, 100, 0.1, 0.5, false, 32, 192)]
        [InlineData(100, 100, 0.5, 0.1, false, 32, 192)]
        [InlineData(100, 100, 0.5, 0.0, false, 32, 192)]
        [InlineData(100, 100, 0.0, 0.5, false, 32, 192)]
        [Theory]
        public void LargeVolumeTestLargeMessagesDrops(int clientMessagesCount, int serverMessagesCount, double clientDropChance = 0, double serverDropChance = 0, bool outOfOrder = false, int minsize = 16, int maxsize = 32)
        {
            AdvancedTestInternal(clientMessagesCount, serverMessagesCount, clientDropChance, serverDropChance, outOfOrder, minsize, maxsize);
        }

        [InlineData(100, 100, 0.0, 0.1, true, 32, 192)]
        [InlineData(100, 100, 0.1, 0.0, true, 32, 192)]
        [InlineData(100, 100, 0.5, 0.1, true, 32, 192)]
        [InlineData(100, 100, 0.5, 0.0, true, 32, 192)]
        [InlineData(100, 100, 0.0, 0.5, true, 32, 192)]
        [Theory]
        public void LargeVolumeTestLargeMessagesDropsAndReorders(int clientMessagesCount, int serverMessagesCount, double clientDropChance = 0, double serverDropChance = 0, bool outOfOrder = false, int minsize = 16, int maxsize = 32)
        {
            AdvancedTestInternal(clientMessagesCount, serverMessagesCount, clientDropChance, serverDropChance, outOfOrder, minsize, maxsize);
        }

        [InlineData(1, 0)]
        [InlineData(5, 0)]
        [InlineData(5, 1)]
        [InlineData(5, 5)]
        [Theory]
        public void VeryLargeVolumeTestBasic(int clientMessagesCount, int serverMessagesCount, double clientDropChance = 0, double serverDropChance = 0, bool outOfOrder = false, int minsize = 1024, int maxsize = 8192)
        {
            AdvancedTestInternal(clientMessagesCount, serverMessagesCount, clientDropChance, serverDropChance, outOfOrder, minsize, maxsize);
        }

        [InlineData(1, 0)]
        [InlineData(5, 0)]
        [InlineData(5, 1)]
        [InlineData(5, 5)]
        [Theory]
        public void VeryVeryLargeVolumeTestBasic(int clientMessagesCount, int serverMessagesCount, double clientDropChance = 0, double serverDropChance = 0, bool outOfOrder = false, int minsize = 8 * 1024, int maxsize = 128 * 1024)
        {
            AdvancedTestInternal(clientMessagesCount, serverMessagesCount, clientDropChance, serverDropChance, outOfOrder, minsize, maxsize);
        }

        private static void AdvancedTestInternal(int clientMessagesCount, int serverMessagesCount, double clientDropChance, double serverDropChance, bool outOfOrder, int minsize, int maxsize)
        {
            var (client, server) = Common.CreateAndInitialize(allowImplicitMultipart: true, maximumBufferedPartialMessageSize: maxsize * 10);
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

            var serverExpects = new HashSet<byte[]>();
            var clientExpects = new HashSet<byte[]>();

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
                        var message = client.Send(payload);

                        bool dropped = false;
                        foreach (var p in message.Messages)
                        {
                            if (r.NextDouble() > clientDropChance)
                            {
                                messagesSentFromClient.Add(p);
                            }
                            else
                            {
                                dropped = true;
                            }
                        }

                        if (dropped == false)
                        {
                            serverExpects.Add(payload);
                        }
                    }
                    else n = 1;
                }
                if (n == 1) // send from server
                {
                    serverMessagesToSend.TryDequeue(out var payload);
                    if (payload != null)
                    {
                        var message = server.Send(payload);

                        bool dropped = false;
                        foreach (var p in message.Messages)
                        {
                            if (r.NextDouble() > serverDropChance)
                            {
                                messagesSentFromServer.Add(p);
                            }
                            else
                            {
                                dropped = true;
                            }
                        }

                        if (dropped == false)
                        {
                            clientExpects.Add(payload);
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
            Assert.All(serverExpects, message => messagesReceivedByServer.Contains(message));
            Assert.All(clientExpects, message => messagesReceivedByClient.Contains(message));
            Assert.All(messagesReceivedByServer, message => serverExpects.Contains(message));
            Assert.All(messagesReceivedByClient, message => clientExpects.Contains(message));
            Assert.Equal(serverExpects.Count, messagesReceivedByServer.Count);
            Assert.Equal(clientExpects.Count, messagesReceivedByClient.Count);
        }
    }
}
