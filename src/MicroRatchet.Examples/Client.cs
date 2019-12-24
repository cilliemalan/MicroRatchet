using MicroRatchet.BouncyCastle;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace MicroRatchet.Examples
{
    static class Client
    {
        const int PORT = 3422;

        public static async Task Run(CancellationToken cancellationToken)
        {
            byte[] privateKey = KeyGeneration.GeneratePrivateKey();
            byte[] publicKey = KeyGeneration.GetPublicKeyFromPrivateKey(privateKey);

            var config = new MicroRatchetConfiguration
            {
                ApplicationKey = new byte[16],
                IsClient = true,
                MaximumMessageSize = 256,
                MinimumMessageSize = 256,
                NumberOfRatchetsToKeep = 3
            };

            var services = new BouncyCastleServices(privateKey);
            using var context = new MicroRatchetClient(services, config, null);

            Console.WriteLine($"Starting Client with public key: {publicKey.ToHexString()}");


            using var udp = new UdpClient(PORT);
            var serverEndpoint = new IPEndPoint(IPAddress.Loopback, PORT);

            // Step 1: Initialize
            while (!context.IsInitialized && !cancellationToken.IsCancellationRequested)
            {
                try
                {
                    // 1.1 Send initialization request
                    Console.WriteLine("Sending initialization request");
                    byte[] msg = context.InitiateInitialization();
                    await udp.SendAsync(msg, serverEndpoint, cancellationToken);

                    // 1.2 Receive initialization response
                    var timeout = CancellationTokenSource.CreateLinkedTokenSource(
                        cancellationToken,
                        new CancellationTokenSource(15000).Token).Token;
                    var receivedData = await udp.ReceiveAsync(timeout);
                    var res = context.Receive(receivedData.Buffer);

                    if (res.ToSendBack != null)
                    {
                        Console.WriteLine("Received initialization response.");
                        Console.WriteLine($"Server public key: {context.GetRemotePublicKey().ToHexString()}");
                        Console.WriteLine("Sending first message");
                        // 1.3 Send first request
                        await udp.SendAsync(res.ToSendBack, serverEndpoint, cancellationToken);

                        // 1.4 Receive first response
                        timeout = CancellationTokenSource.CreateLinkedTokenSource(
                            cancellationToken,
                            new CancellationTokenSource(15000).Token).Token;
                        receivedData = await udp.ReceiveAsync(timeout);
                        res = context.Receive(receivedData.Buffer);
                    }
                }
                catch (Exception)
                {
                }
            }

            if (!cancellationToken.IsCancellationRequested)
            {
                Console.WriteLine("Client initialized");
                Console.WriteLine("Type stuff in and press enter to send to the server.\n\n");

                // in order to get the console, udp stuff, and MR stuff to work
                // together even though nothing was written for async, we need
                // some synchronization.
                // A background thread reads from the console and pushes messages
                // into a queue which then in turn get sent to the server by the
                // Send task.
                // A receive task handles messages from the server

                var messages = new ConcurrentQueue<string>();
                var semaphore = new SemaphoreSlim(0);
                async Task ReceiveTask()
                {
                    while (!cancellationToken.IsCancellationRequested)
                    {
                        var received = await udp.ReceiveAsync(cancellationToken);

                        var message = context.Receive(received.Buffer);
                        if (message.Payload != null)
                        {
                            Console.WriteLine(Encoding.UTF8.GetString(message.Payload));
                        }
                    }
                }

                async Task SendTask()
                {
                    while (!cancellationToken.IsCancellationRequested)
                    {
                        await semaphore.WaitAsync();
                        messages.TryDequeue(out var payload);

                        var message = context.Send(Encoding.UTF8.GetBytes(payload));

                        await udp.SendAsync(message, serverEndpoint, cancellationToken);
                    }
                }

                var consoleReadThread = new Thread(_ =>
                {
                    for(; ;)
                    {
                        messages.Enqueue(Console.ReadLine());
                        semaphore.Release();
                    }
                });
                consoleReadThread.IsBackground = true;
                consoleReadThread.Start();

                await Task.WhenAll(ReceiveTask(), SendTask());
            }
        }
    }
}
