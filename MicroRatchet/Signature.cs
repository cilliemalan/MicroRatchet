using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.Security;
using System.Diagnostics;

namespace MicroRatchet
{
    internal class Signature : Verifier, ISignature
    {
        private byte[] _key;
        
        public Signature(byte[] key)
            :base(KeyGeneration.GetPublicKeyFromPrivateKey(key))
        {
            _key = key;
        }

        public byte[] Sign(ArraySegment<byte> data)
        {
            ECDsaSigner signer = new ECDsaSigner();
            signer.Init(true, new ECPrivateKeyParameters(new BigInteger(_key), domainParms));
            byte[] hash = data.ToArray();
            var sig = signer.GenerateSignature(hash);
            var r = sig[0];
            var s = sig[1];
            var bytes1 = r.ToByteArray();
            var bytes2 = s.ToByteArray();

            byte[] signatureBytes = new byte[64];
            if (bytes1.Length == 33 && bytes1[0] == 0) Array.Copy(bytes1, 1, signatureBytes, 0, 32);
            else if (bytes1.Length <= 32) Array.Copy(bytes1, 0, signatureBytes, 32 - bytes1.Length, bytes1.Length);
            else throw new Exception("Unacceptable signature length");
            if (bytes2.Length == 33 && bytes2[0] == 0) Array.Copy(bytes2, 1, signatureBytes, 32, 32);
            else if (bytes2.Length <= 32) Array.Copy(bytes2, 0, signatureBytes, 64 - bytes2.Length, bytes2.Length);
            else throw new Exception("Unacceptable signature length");
            return signatureBytes;
        }
    }
}
