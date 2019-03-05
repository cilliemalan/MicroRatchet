using System;
using System.Collections.Generic;
using System.Linq;

namespace MicroRatchet.Performance
{
    class Program
    {
        static void Main(string[] args)
        {
            int clientMessagesCount = 100000;
            int serverMessagesCount = 1000;
            double clientDropChance = 0.1;
            double serverDropChance = 0.1;


            var (client, server) = CreateAndInitialize();
            RandomNumberGenerator rng = new RandomNumberGenerator();
            Random r = new Random();
            var clientMessages = new HashSet<byte[]>(Enumerable.Range(0, clientMessagesCount).Select(_ => rng.Generate(32)));
            var serverMessages = new HashSet<byte[]>(Enumerable.Range(0, serverMessagesCount).Select(_ => rng.Generate(32)));
            Queue<byte[]> clientMessagesToSend = new Queue<byte[]>(clientMessages);
            Queue<byte[]> serverMessagesToSend = new Queue<byte[]>(serverMessages);
            var messagesSentFromClient = new Queue<byte[]>();
            var messagesSentFromServer = new Queue<byte[]>();
            HashSet<byte[]> messagesReceivedByClient = new HashSet<byte[]>();
            HashSet<byte[]> messagesReceivedByServer = new HashSet<byte[]>();

            byte[] DoubleInSize(byte[] payload) => payload.Concat(payload).ToArray();

            int clientSent = 0, serverSent = 0, clientReceived = 0, serverReceived = 0, clientDropped = 0, serverDropped = 0;
            Console.WriteLine($"Sending {clientMessagesCount}/{clientDropChance:P0} and {serverMessagesCount}/{serverDropChance:P0}");
            for (int i = 0; ; i++)
            {
                bool anyMessagesToReceive = messagesSentFromClient.TryPeek(out var _) || messagesSentFromServer.TryPeek(out var _);
                bool anyMessagesToSend = clientMessagesToSend.TryPeek(out var _) || serverMessagesToSend.TryPeek(out var _);
                if (!anyMessagesToReceive && !anyMessagesToSend)
                {
                    break;
                }

                if (i % 5 == 0)
                {
                    var totalReceived = clientReceived + serverReceived + clientDropped + serverDropped;
                    var totalAll = clientMessagesCount + serverMessagesCount;
                    var percentage = (double)totalReceived / totalAll;
                    Console.Write($"\r{percentage:P0} - c: {clientSent}/{clientDropped} -> {serverReceived}  s: {serverSent}/{serverDropped} -> {clientReceived}   ");
                }

                var clientOrServer = r.Next(2);
                var sendOrReceive = r.Next(2);
                double ratio = (double)clientMessagesCount / serverMessagesCount / 10;
                int maxClient = (int)(10 * ratio);
                int maxServer = (int)(20 / ratio);
                var maxMessages = r.Next(clientOrServer == 0 ? maxClient : maxServer) + 1;

                if (anyMessagesToSend && (sendOrReceive == 0 || !anyMessagesToReceive))
                {
                    if (clientOrServer == 0) // send from client
                    {
                        while (maxMessages-- > 0)
                        {
                            clientMessagesToSend.TryDequeue(out var payload);
                            if (payload != null)
                            {
                                payload = r.Next(10) > 7 ? DoubleInSize(payload) : payload;
                                var message = client.Send(payload);
                                if (r.NextDouble() > clientDropChance)
                                {
                                    clientSent++;
                                    messagesSentFromClient.Enqueue(message);
                                }
                                else
                                {
                                    clientDropped++;
                                }
                            }
                        }
                    }
                    else
                    {
                        while (maxMessages-- > 0)
                        {
                            serverMessagesToSend.TryDequeue(out var payload);
                            if (payload != null)
                            {
                                payload = r.Next(10) > 7 ? DoubleInSize(payload) : payload;
                                var message = server.Send(payload);
                                if (r.NextDouble() > serverDropChance)
                                {
                                    serverSent++;
                                    messagesSentFromServer.Enqueue(message);
                                }
                                else
                                {
                                    serverDropped++;
                                }
                            }
                        }
                    }
                }
                else
                {
                    if (clientOrServer != 0)  // receive by client
                    {
                        while (maxMessages-- > 0)
                        {
                            messagesSentFromServer.TryDequeue(out var message);
                            if (message != null)
                            {
                                var payload = client.Receive(message);
                                messagesReceivedByClient.Add(payload);
                                clientReceived++;
                            }
                        }
                    }
                    else // receive by server
                    {
                        while (maxMessages-- > 0)
                        {
                            messagesSentFromClient.TryDequeue(out var message);
                            if (message != null)
                            {
                                var payload = server.Receive(message);
                                messagesReceivedByServer.Add(payload);
                                serverReceived++;
                            }
                        }
                    }
                }
            }

            Console.WriteLine("Done");
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

            return (new MicroRatchetClient(clientServices, true, 80), new MicroRatchetClient(serverServices, false, 80));
        }
    }
}
