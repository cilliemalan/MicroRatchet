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
            // generate a key pair
            byte[] privateKey = KeyGeneration.GeneratePrivateKey();
            byte[] publicKey = KeyGeneration.GetPublicKeyFromPrivateKey(privateKey);

            // configuring as a client with the default application key.
            // messages will be padded to 64 bytes and cannot exceed
            // 256 bytes.
            var config = new MicroRatchetConfiguration
            {
                ApplicationKey = new byte[16],
                IsClient = true,
                MaximumMessageSize = 256,
                MinimumMessageSize = 64
            };

            // create the MicroRatchet context
            var services = new BouncyCastleServices(privateKey);
            using var context = new MicroRatchetContext(services, config, null);

            Console.WriteLine($"Starting Client with public key: {publicKey.ToHexString()}");

            // Create UDP client. No connection since UDP is a
            // connectionless message based protocol. For the client
            // we don't specify a local endpoint.
            using var udp = new UdpClient();
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
                    Console.WriteLine($"SENT {msg.Length} bytes INITIALIZATION REQUEST");

                    // 1.2 Receive initialization response
                    var timeout = CancellationTokenSource.CreateLinkedTokenSource(
                        cancellationToken,
                        new CancellationTokenSource(15000).Token).Token;
                    var receivedData = await udp.ReceiveAsync(timeout);
                    Console.WriteLine($"RECEIVED {receivedData.Buffer.Length} bytes FROM SERVER");
                    var res = context.Receive(receivedData.Buffer);

                    if (res.ToSendBack != null)
                    {
                        Console.WriteLine("Received initialization response.");
                        Console.WriteLine($"Server public key: {context.GetRemotePublicKey().ToHexString()}");
                        Console.WriteLine("Sending first message");
                        // 1.3 Send first request
                        await udp.SendAsync(res.ToSendBack, serverEndpoint, cancellationToken);
                        Console.WriteLine($"SENT BACK {res.ToSendBack} bytes");

                        // 1.4 Receive first response
                        timeout = CancellationTokenSource.CreateLinkedTokenSource(
                            cancellationToken,
                            new CancellationTokenSource(15000).Token).Token;
                        receivedData = await udp.ReceiveAsync(timeout);
                        Console.WriteLine($"RECEIVED {receivedData.Buffer.Length} bytes FROM SERVER");
                        res = context.Receive(receivedData.Buffer);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"An exception was encountered: {ex.Message}");
                }
            }

            // the context is now initialized and message can be sent back and forth
            // as needed. Messages being dropped or received out of order does not
            // affect subsequent messages.
            if (!cancellationToken.IsCancellationRequested)
            {
                Console.WriteLine("Client initialized");
                Console.WriteLine("Type stuff in and press enter to send to the server.\n\n");

                // in order to get the console, udp stuff, and MR stuff to work
                // together (even though nothing was written for async), we need
                // some synchronization.
                // A background thread reads from the console and pushes messages
                // into a queue which then in turn get sent to the server by the
                // Send task.
                // A receive task handles messages from the server


                // The receive task handles incoming UDP messages.
                var messages = new ConcurrentQueue<string>();
                var semaphore = new SemaphoreSlim(0);
                async Task ReceiveTask()
                {
                    while (!cancellationToken.IsCancellationRequested)
                    {
                        var received = await udp.ReceiveAsync(cancellationToken);
                        Console.WriteLine($"RECEIVED {received.Buffer.Length} bytes");

                        try
                        {
                            // pass the received data to the MR context
                            var message = context.Receive(received.Buffer);

                            // The message is always padded to the minimum message size, 
                            // so read the incoming message as a null-terminated
                            // string.
                            string msg = message.Payload.DecodeNullTerminatedString();

                            // Print the decrypted and decoded message to the console
                            Console.WriteLine($"RECEIVED MESSAGE: {msg}");
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"An exception was encountered when receiving a message: {ex}");
                        }
                    }
                }

                // the send task dequeues messages, encrypts, and sends
                // them to the server endpoint as UDP messages.
                async Task SendTask()
                {
                    while (!cancellationToken.IsCancellationRequested)
                    {
                        // wait for a message
                        await semaphore.WaitAsync();
                        messages.TryDequeue(out var payload);

                        // encrypt the message using the context. The message
                        // will be padded to the minimum configured message size.
                        var payloadBytes = Encoding.UTF8.GetBytes(payload);
                        var message = context.Send(payloadBytes);

                        // send as UDP message to the server endpoint.
                        await udp.SendAsync(message, serverEndpoint, cancellationToken);
                        Console.WriteLine($"SENT {payloadBytes} bytes PAYLOAD, resulting in {message.Length} bytes ENCRYPTED MESSAGE");
                    }
                }

                // The console thread reades lines one at a time and
                // enqueues them for sending.
                var consoleReadThread = new Thread(_ =>
                {
                    for (; ; )
                    {
                        messages.Enqueue(Console.ReadLine());
                        semaphore.Release();
                    }
                });
                // background threads are terminated when the program exits
                consoleReadThread.IsBackground = true;
                consoleReadThread.Start();

                await Task.WhenAll(ReceiveTask(), SendTask());
            }
        }
    }
}
