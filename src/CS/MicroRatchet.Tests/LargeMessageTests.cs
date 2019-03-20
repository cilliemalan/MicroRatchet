using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Xunit;

namespace MicroRatchet.Tests
{
    public class LargeMessageTests
    {
        [Fact]
        public void SendLargeMessageTest()
        {
            var (client, server) = Common.CreateAndInitialize(allowImplicitMultipart: true);

            RandomNumberGenerator rng = new RandomNumberGenerator();
            byte[] message = rng.Generate(client.MultipartMessageSize * 7);

            var toSend = client.Send(message);
            Assert.True(toSend.IsMultipartMessage);
            Assert.Equal(7, toSend.Messages.Length);
        }

        [Fact]
        public void ReceiveLargeMessageTest()
        {
            var (client, server) = Common.CreateAndInitialize(allowImplicitMultipart: true);

            RandomNumberGenerator rng = new RandomNumberGenerator();
            byte[] message = rng.Generate(client.MultipartMessageSize * 7);

            var toSend = client.Send(message);
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
            var (client, server) = Common.CreateAndInitialize(allowImplicitMultipart: true);

            RandomNumberGenerator rng = new RandomNumberGenerator();
            byte[] message = rng.Generate(client.MultipartMessageSize * 7 + 10);

            var toSend = client.Send(message);
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
            var (client, server) = Common.CreateAndInitialize(allowImplicitMultipart: true);

            RandomNumberGenerator rng = new RandomNumberGenerator();
            byte[] message1 = rng.Generate(client.MultipartMessageSize * 2);
            byte[] message2 = rng.Generate(client.MultipartMessageSize * 2);

            var toSend1 = client.Send(message1);
            var toSend2 = client.Send(message2);
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
            var (client, server) = Common.CreateAndInitialize(allowImplicitMultipart: true);

            RandomNumberGenerator rng = new RandomNumberGenerator();
            byte[] message1 = rng.Generate(client.MultipartMessageSize * 2);
            byte[] message2 = rng.Generate(client.MultipartMessageSize * 2);

            var toSend1 = client.Send(message1);
            var toSend2 = client.Send(message2);
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

        [Fact]
        public void CantSendMultipartAccidentally()
        {
            var (client, server) = Common.CreateAndInitialize(allowImplicitMultipart: false);

            Assert.Throws<InvalidOperationException>(() => client.Send(new byte[client.MaximumMessageSize + 1]));
        }
    }
}
