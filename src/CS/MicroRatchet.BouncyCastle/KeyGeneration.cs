using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.Security;
#pragma warning disable CA1810 // Initialize reference type static fields inline

namespace MicroRatchet.BouncyCastle
{
    /// <summary>
    /// Functions for generating a ECDSA key pairs.
    /// </summary>
    public static class KeyGeneration
    {
        private static readonly ECDomainParameters domainParms;

        static KeyGeneration()
        {
            var curve = CustomNamedCurves.GetByName("secp256r1");
            domainParms = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
        }

        public static byte[] GeneratePrivateKey(SecureRandom random = null)
        {
            if (random == null) random = new SecureRandom();

            // generates a private key that will always
            // have 32 bits of info and have a a positive
            // public key Y coordinate

            BigInteger n = domainParms.N;
            BigInteger d;
            int minWeight = n.BitLength / 4;

            for (; ; )
            {
                var bytes = new byte[32];
                random.NextBytes(bytes);
                while (bytes[0] > 127 || bytes[0] == 0) bytes[0] = (byte)random.Next();
                d = new BigInteger(bytes);
                var dbytes = d.ToByteArray();

                var nafWeight = WNafUtilities.GetNafWeight(d);
                if (nafWeight < minWeight)
                    continue;

                var m = new FixedPointCombMultiplier();
                ECPoint q = m.Multiply(domainParms.G, d).Normalize();

                bool isOdd = q.AffineYCoord.TestBitZero();

                if (!isOdd)
                {
                    return dbytes;
                }
            }
        }

        public static bool IsPublicKeyAcceptable(AsymmetricCipherKeyPair ackp)
        {
            if (ackp?.Public is ECPublicKeyParameters pubkeyparm)
            {
                return IsPublicKeyAcceptable(pubkeyparm);
            }
            else
            {
                throw new InvalidOperationException("The key pair is not an EC key pair");
            }
        }

        public static bool IsPublicKeyAcceptable(ECPublicKeyParameters pubkey)
        {
            return !(pubkey?.Q?.AffineYCoord?.TestBitZero() ?? true);
        }

        public static byte[] GetPublicKeyFromPrivateKey(ArraySegment<byte> key) =>
            GetPublicKeyFromPrivateKey(new ECPrivateKeyParameters(new BigInteger(key.Array, key.Offset, key.Count), domainParms));

        public static byte[] GetPublicKeyFromPrivateKey(ECPrivateKeyParameters priv)
        {
            if (priv == null) throw new ObjectDisposedException(nameof(KeyAgreement));
            ECPoint q = new FixedPointCombMultiplier().Multiply(domainParms.G, priv.D).Normalize();
            var bytes = q.GetEncoded(true);
            System.Diagnostics.Debug.Assert(bytes[0] == 2, "All EC points must be even");
            var trimmed = new byte[32];
            Array.Copy(bytes, 1, trimmed, 0, 32);
            return trimmed;
        }

        public static ECPoint DecodePublicKey(ArraySegment<byte> key)
        {
            if (key.Count != 32) throw new ArgumentException("Public key must be 32 bytes long", nameof(key));

            byte[] pnt = new byte[33];
            pnt[0] = 0x02;
            Array.Copy(key.Array, key.Offset, pnt, 1, 32);
            return domainParms.Curve.DecodePoint(pnt);
        }
    }
}
