using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using System;
using System.Collections.Generic;
using System.Text;

namespace MicroRatchet
{
    internal class Verifier : IVerifier
    {
        protected static readonly ECDomainParameters domainParms;

        static Verifier()
        {
            var curve = ECNamedCurveTable.GetByName("secp256r1");
            domainParms = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
        }

        private byte[] _publicKey;
        private ECPoint _pubkeypoint;

        public Verifier(byte[] publicKey)
        {
            _publicKey = publicKey;
            _pubkeypoint = KeyGeneration.DecodePublicKey(_publicKey);
        }
        
        public int SignatureSize => 64;

        public byte[] PublicKey => _publicKey;

        public bool Verify(ArraySegment<byte> data, byte[] signature)
        {
            try
            {
                ECDsaSigner signer = new ECDsaSigner();
                signer.Init(false, new ECPublicKeyParameters(_pubkeypoint, domainParms));
                var hash = new Digest().ComputeDigest(data);
                var r = new BigInteger(1, signature, 0, 32);
                var s = new BigInteger(1, signature, 32, 32);
                return signer.VerifySignature(hash, r, s);
            }
            catch { return false; }
        }
    }
}
