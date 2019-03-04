using System;
using System.Collections.Generic;
using System.Linq;

namespace MicroRatchet.Performance
{
    class Program
    {
        static void Main(string[] args)
        {
            int clientMessagesCount = 10000;
            int serverMessagesCount = 10000;
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
                if (!messagesSentFromClient.TryPeek(out var _) && !messagesSentFromServer.TryPeek(out var _) &&
                    !clientMessagesToSend.TryPeek(out var _) && !serverMessagesToSend.TryPeek(out var _))
                {
                    break;
                }
                
                if (i % 100 == 0)
                {
                    var totalReceived = clientReceived + serverReceived + clientDropped + serverDropped;
                    var totalAll = clientMessagesCount + serverMessagesCount;
                    var percentage = (double)totalReceived / totalAll;
                    Console.Write($"\r{percentage:P0} - c: {clientSent}/{clientDropped} -> {serverReceived}  s: {serverSent}/{serverDropped} -> {clientReceived}   ");
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
                            clientSent++;
                            messagesSentFromClient.Enqueue(message);
                        }
                        else
                        {
                            clientDropped++;
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
                            serverSent++;
                            messagesSentFromServer.Enqueue(message);
                        }
                        else
                        {
                            serverDropped++;
                        }
                    }
                    else n = 2;
                }
                if (n == 2) // receive by client
                {
                    messagesSentFromServer.TryDequeue(out var message);
                    if (message != null)
                    {
                        var payload = client.Receive(message);
                        messagesReceivedByClient.Add(payload);
                        clientReceived++;
                    }
                    else n = 3;
                }
                if (n == 3) // receive by server
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
