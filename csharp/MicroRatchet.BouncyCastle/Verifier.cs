using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
#pragma warning disable CA1810 // Initialize reference type static fields inline
#pragma warning disable CA1031 // Do not catch general exception types

namespace MicroRatchet.BouncyCastle
{
    public sealed class Verifier : IVerifier
    {
        private static readonly ECDomainParameters domainParms;

        static Verifier()
        {
            var curve = CustomNamedCurves.GetByName("secp256r1");
            domainParms = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
        }

        private ECPoint _pubkeypoint;

        public Verifier(ArraySegment<byte> publicKey)
        {
            _pubkeypoint = KeyGeneration.DecodePublicKey(publicKey);
        }

        public int SignatureSize => 64;

        public bool Verify(ArraySegment<byte> data, ArraySegment<byte> signature)
        {
            try
            {
                ECDsaSigner signer = new ECDsaSigner();
                signer.Init(false, new ECPublicKeyParameters(_pubkeypoint, domainParms));
                var hash = data.ToArray();
                var r = new BigInteger(1, signature.Array, signature.Offset, 32);
                var s = new BigInteger(1, signature.Array, signature.Offset + 32, 32);
                return signer.VerifySignature(hash, r, s);
            }
            catch { return false; }
        }
    }
}
