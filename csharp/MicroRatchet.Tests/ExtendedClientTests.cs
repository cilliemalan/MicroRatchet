using MicroRatchet.BouncyCastle;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Xunit;

namespace MicroRatchet.Tests
{
    public class ExtendedClientTests
    {
        [Fact]
        public void SendSomeMessagesBothDirectionsWithEcdhMultiTest()
        {
            var (client, server) = Common.CreateAndInitialize();

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
            var sr1 = server.Receive(cp1).Payload;
            var sr2 = server.Receive(cp2).Payload;
            Assert.Equal(cmessage1, sr1);
            Assert.Equal(cmessage2, sr2);

            var sp1 = server.Send(smessage1);
            var sp2 = server.Send(smessage2);
            var cr1 = client.Receive(sp1).Payload;
            var cr2 = client.Receive(sp2).Payload;
            Assert.Equal(smessage1, cr1);
            Assert.Equal(smessage2, cr2);

            var cp3 = client.Send(cmessage3);
            var cp4 = client.Send(cmessage4);
            var sr3 = server.Receive(cp3).Payload;
            var sr4 = server.Receive(cp4).Payload;
            Assert.Equal(cmessage3, sr3);
            Assert.Equal(cmessage4, sr4);

            var sp3 = server.Send(smessage3);
            var sp4 = server.Send(smessage4);
            var cr3 = client.Receive(sp3).Payload;
            var cr4 = client.Receive(sp4).Payload;
            Assert.Equal(smessage3, cr3);
            Assert.Equal(smessage4, cr4);

            var cp5 = client.Send(cmessage5);
            var cp6 = client.Send(cmessage6);
            var sr5 = server.Receive(cp5).Payload;
            var sr6 = server.Receive(cp6).Payload;
            Assert.Equal(cmessage5, sr5);
            Assert.Equal(cmessage6, sr6);

            var sp5 = server.Send(smessage5);
            var sp6 = server.Send(smessage6);
            var cr5 = client.Receive(sp5).Payload;
            var cr6 = client.Receive(sp6).Payload;
            Assert.Equal(smessage5, cr5);
            Assert.Equal(smessage6, cr6);

            var css = client.SaveStateAsByteArray();
            var sss = server.SaveStateAsByteArray();
            var cs = ClientState.Load(css, DefaultKexFactory.Instance);
            var ss = ServerState.Load(sss, DefaultKexFactory.Instance);
            Assert.Equal(4, cs.Ratchets.Count);
            Assert.Equal(4, ss.Ratchets.Count);
        }

        [Fact]
        public void SmallMessageTest()
        {
            var (client, server) = Common.CreateAndInitialize();
            var rng = new RandomNumberGenerator();
            var msg1 = rng.Generate(1);
            var msg2 = rng.Generate(2);
            var msg3 = rng.Generate(3);
            var msg4 = rng.Generate(4);

            var cmsg1 = client.Send(msg1);
            var rmsg1 = server.Receive(cmsg1);
            PrefixMatch(msg1, rmsg1.Payload);

            var cmsg2 = server.Send(msg2);
            var rmsg2 = client.Receive(cmsg2);
            PrefixMatch(msg2, rmsg2.Payload);

            var cmsg3 = client.Send(msg3);
            var rmsg3 = server.Receive(cmsg3);
            PrefixMatch(msg3, rmsg3.Payload);

            var cmsg4 = server.Send(msg4);
            var rmsg4 = client.Receive(cmsg4);
            PrefixMatch(msg4, rmsg4.Payload);
        }

        [Fact]
        public void RetransmissionFailTest1()
        {
            var (client, server) = Common.CreateAndInitialize();
            var rng = new RandomNumberGenerator();
            var msg1 = rng.Generate(16);
            var msg2 = rng.Generate(26);
            var msg3 = rng.Generate(36);
            var msg4 = rng.Generate(46);

            var cmsg1 = client.Send(msg1);
            var rmsg1 = server.Receive(cmsg1);
            Assert.ThrowsAny<Exception>(() => server.Receive(cmsg1));
            Assert.Equal(msg1, rmsg1.Payload);

            var cmsg2 = server.Send(msg2);
            var rmsg2 = client.Receive(cmsg2);
            Assert.ThrowsAny<Exception>(() => client.Receive(cmsg2));
            Assert.Equal(msg2, rmsg2.Payload);

            var cmsg3 = client.Send(msg3);
            var rmsg3 = server.Receive(cmsg3);
            Assert.ThrowsAny<Exception>(() => server.Receive(cmsg3));
            Assert.Equal(msg3, rmsg3.Payload);

            var cmsg4 = server.Send(msg4);
            var rmsg4 = client.Receive(cmsg4);
            Assert.ThrowsAny<Exception>(() => client.Receive(cmsg4));
            Assert.Equal(msg4, rmsg4.Payload);
        }

        [Fact]
        public void RetransmissionFailTest2()
        {
            var (client, server) = Common.CreateAndInitialize();
            var rng = new RandomNumberGenerator();
            var msg1 = rng.Generate(16);
            var msg2 = rng.Generate(26);
            var msg3 = rng.Generate(36);
            var msg4 = rng.Generate(46);

            var cmsg1 = client.Send(msg1);
            var rmsg1 = server.Receive(cmsg1);
            Assert.ThrowsAny<Exception>(() => server.Receive(cmsg1));
            Assert.Equal(msg1, rmsg1.Payload);

            var cmsg2 = server.Send(msg2);
            var rmsg2 = client.Receive(cmsg2);
            Assert.ThrowsAny<Exception>(() => client.Receive(cmsg2));
            Assert.Equal(msg2, rmsg2.Payload);

            var cmsg3 = client.Send(msg3);
            var rmsg3 = server.Receive(cmsg3);
            Assert.ThrowsAny<Exception>(() => server.Receive(cmsg1));
            Assert.ThrowsAny<Exception>(() => server.Receive(cmsg3));
            Assert.ThrowsAny<Exception>(() => server.Receive(cmsg1));
            Assert.Equal(msg3, rmsg3.Payload);

            var cmsg4 = server.Send(msg4);
            var rmsg4 = client.Receive(cmsg4);
            Assert.ThrowsAny<Exception>(() => client.Receive(cmsg2));
            Assert.ThrowsAny<Exception>(() => client.Receive(cmsg4));
            Assert.ThrowsAny<Exception>(() => client.Receive(cmsg2));
            Assert.Equal(msg4, rmsg4.Payload);
        }

        [Fact]
        public void RetransmissionFailTest3()
        {
            var (client, server) = Common.CreateAndInitialize();
            var rng = new RandomNumberGenerator();
            var msg1 = rng.Generate(16);
            var msg2 = rng.Generate(26);
            var msg3 = rng.Generate(36);
            var msg4 = rng.Generate(46);

            var cmsg1 = client.Send(msg1);
            var cmsg2 = client.Send(msg2);
            var cmsg3 = client.Send(msg3);
            var cmsg4 = client.Send(msg4);

            var rmsg1 = server.Receive(cmsg1);
            var rmsg3 = server.Receive(cmsg3);
            Assert.ThrowsAny<Exception>(() => server.Receive(cmsg3));
            var rmsg2 = server.Receive(cmsg2);
            var rmsg4 = server.Receive(cmsg4);

            Assert.Equal(msg1, rmsg1.Payload);
            Assert.Equal(msg2, rmsg2.Payload);
            Assert.Equal(msg3, rmsg3.Payload);
            Assert.Equal(msg4, rmsg4.Payload);
        }

        [Fact]
        public void RetransmissionFailTest4()
        {
            var (client, server) = Common.CreateAndInitialize();
            var rng = new RandomNumberGenerator();
            var msg1 = rng.Generate(16);
            var msg2 = rng.Generate(26);
            var msg3 = rng.Generate(36);
            var msg4 = rng.Generate(46);
            var msg5 = rng.Generate(25);
            var msg6 = rng.Generate(34);
            var msg7 = rng.Generate(43);
            var msg8 = rng.Generate(52);

            var cmsg1 = client.Send(msg1);
            var cmsg2 = client.Send(msg2);
            var cmsg3 = client.Send(msg3);
            var cmsg4 = client.Send(msg4);
            var cmsg5 = client.Send(msg5);
            var cmsg6 = client.Send(msg6);
            var cmsg7 = client.Send(msg7);
            var cmsg8 = client.Send(msg8);

            var rmsg1 = server.Receive(cmsg1);
            var rmsg2 = server.Receive(cmsg2);
            var rmsg7 = server.Receive(cmsg7);
            var rmsg5 = server.Receive(cmsg5);
            Assert.ThrowsAny<Exception>(() => server.Receive(cmsg5));
            var rmsg6 = server.Receive(cmsg6);
            Assert.ThrowsAny<Exception>(() => server.Receive(cmsg6));
            var rmsg8 = server.Receive(cmsg8);
            var rmsg3 = server.Receive(cmsg3);
            var rmsg4 = server.Receive(cmsg4);
            Assert.ThrowsAny<Exception>(() => server.Receive(cmsg4));

            Assert.Equal(msg1, rmsg1.Payload);
            Assert.Equal(msg2, rmsg2.Payload);
            Assert.Equal(msg3, rmsg3.Payload);
            Assert.Equal(msg4, rmsg4.Payload);
            Assert.Equal(msg5, rmsg5.Payload);
            Assert.Equal(msg6, rmsg6.Payload);
            Assert.Equal(msg7, rmsg7.Payload);
            Assert.Equal(msg8, rmsg8.Payload);
        }

        [Fact]
        public void ReflectFailTest()
        {
            var (client, server) = Common.CreateAndInitialize();
            var rng = new RandomNumberGenerator();
            var msg1 = rng.Generate(16);
            var msg2 = rng.Generate(26);
            var msg3 = rng.Generate(36);
            var msg4 = rng.Generate(46);

            var cmsg1 = client.Send(msg1);
            var rmsg1 = server.Receive(cmsg1);
            Assert.ThrowsAny<Exception>(() => client.Receive(cmsg1));
            Assert.Equal(msg1, rmsg1.Payload);

            var cmsg2 = server.Send(msg2);
            var rmsg2 = client.Receive(cmsg2);
            Assert.ThrowsAny<Exception>(() => server.Receive(cmsg2));
            Assert.Equal(msg2, rmsg2.Payload);

            var cmsg3 = client.Send(msg3);
            var rmsg3 = server.Receive(cmsg3);
            Assert.ThrowsAny<Exception>(() => client.Receive(cmsg3));
            Assert.Equal(msg3, rmsg3.Payload);

            var cmsg4 = server.Send(msg4);
            var rmsg4 = client.Receive(cmsg4);
            Assert.ThrowsAny<Exception>(() => server.Receive(cmsg4));
            Assert.Equal(msg4, rmsg4.Payload);
        }

        private static void PrefixMatch(byte[] a, byte[] b)
        {
            var t = new byte[a.Length];
            Array.Copy(b, 0, t, 0, a.Length);
            Assert.Equal(a, t);
        }
    }
}
