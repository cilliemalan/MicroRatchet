using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace MicroRatchet
{
    /// <summary>
    /// The state for an ECDH ratchet step.
    /// </summary>
    internal class EcdhRatchetStep
    {
        public IKeyAgreement EcdhKey;
        public byte[] NextRootKey;
        public byte[] SendHeaderKey;
        public byte[] NextSendHeaderKey;
        public byte[] ReceiveHeaderKey;
        public byte[] NextReceiveHeaderKey;
        public SymmetricRacthet ReceivingChain;
        public SymmetricRacthet SendingChain;

        private EcdhRatchetStep() { }

        public static EcdhRatchetStep InitializeServer(IKeyDerivation kdf, IDigest digest,
            IKeyAgreement previousKeyPair,
            byte[] rootKey, ArraySegment<byte> remotePublicKey, IKeyAgreement keyPair,
            byte[] receiveHeaderKey, byte[] sendHeaderKey)
        {
            if (receiveHeaderKey.Length != 32 || sendHeaderKey.Length != 32) throw new InvalidOperationException("Keys need to be 32 bytes.");
            Log.Verbose($"--Initialize ECDH Ratchet");
            Log.Verbose($"Root Key:           {Log.ShowBytes(rootKey)}");
            Log.Verbose($"Prev ECDH Private: ({Log.ShowBytes(previousKeyPair.GetPublicKey())})");
            Log.Verbose($"ECDH Public:        {Log.ShowBytes(remotePublicKey)}");
            Log.Verbose($"Curr ECDH Private: ({Log.ShowBytes(keyPair.GetPublicKey())})");

            var e = new EcdhRatchetStep
            {
                EcdhKey = keyPair,
                ReceiveHeaderKey = receiveHeaderKey,
                SendHeaderKey = sendHeaderKey
            };

            // receive chain
            Log.Verbose("  --Receiving Chain");
            var rcderived = previousKeyPair.DeriveKey(remotePublicKey);
            rcderived = digest.ComputeDigest(rcderived);
            Log.Verbose($"  C Input Key:    {Log.ShowBytes(rootKey)}");
            Log.Verbose($"  C Key Info:     {Log.ShowBytes(rcderived)}");
            var rckeys = kdf.GenerateKeys(rcderived, rootKey, 3, 32);
            Log.Verbose($"  C Key Out 0:    {Log.ShowBytes(rckeys[0])}");
            Log.Verbose($"  C Key Out 1:    {Log.ShowBytes(rckeys[1])}");
            Log.Verbose($"  C Key Out 2:    {Log.ShowBytes(rckeys[2])}");
            rootKey = rckeys[0];
            e.ReceivingChain.Initialize(rckeys[1]);
            e.NextReceiveHeaderKey = rckeys[2];

            // send chain
            Log.Verbose("  --Sending Chain");
            var scderived = keyPair.DeriveKey(remotePublicKey);
            scderived = digest.ComputeDigest(scderived);
            Log.Verbose($"  C Input Key:    {Log.ShowBytes(rootKey)}");
            Log.Verbose($"  C Key Info:     {Log.ShowBytes(scderived)}");
            var sckeys = kdf.GenerateKeys(scderived, rootKey, 3, 32);
            Log.Verbose($"  C Key Out 0:    {Log.ShowBytes(sckeys[0])}");
            Log.Verbose($"  C Key Out 1:    {Log.ShowBytes(sckeys[1])}");
            Log.Verbose($"  C Key Out 2:    {Log.ShowBytes(sckeys[2])}");
            rootKey = sckeys[0];
            e.SendingChain.Initialize(sckeys[1]);
            e.NextSendHeaderKey = sckeys[2];

            // next root key
            Log.Verbose($"Next Root Key:     ({Log.ShowBytes(rootKey)})");
            e.NextRootKey = rootKey;
            return e;
        }

        public byte[] GetPublicKey(IKeyAgreementFactory kexfac) => EcdhKey.GetPublicKey();

        public static EcdhRatchetStep[] InitializeClient(IKeyDerivation kdf, IDigest digest,
            byte[] rootKey, ArraySegment<byte> remotePublicKey0, ArraySegment<byte> remotePublicKey1, IKeyAgreement keyPair,
            byte[] receiveHeaderKey, byte[] sendHeaderKey,
            IKeyAgreement nextKeyPair)
        {
            if (receiveHeaderKey.Length != 32 || sendHeaderKey.Length != 32) throw new InvalidOperationException("Keys need to be 32 bytes.");
            Log.Verbose($"--Initialize ECDH Ratchet CLIENT");
            Log.Verbose($"Root Key:           {Log.ShowBytes(rootKey)}");
            Log.Verbose($"ECDH Public 0:      {Log.ShowBytes(remotePublicKey0)}");
            Log.Verbose($"ECDH Public 1:      {Log.ShowBytes(remotePublicKey1)}");
            Log.Verbose($"ECDH Private:      ({Log.ShowBytes(keyPair.GetPublicKey())})");

            var e0 = new EcdhRatchetStep
            {
                EcdhKey = keyPair,
                SendHeaderKey = sendHeaderKey
            };

            // receive chain doesn't exist
            Log.Verbose("  --Receiving Chain");

            // send chain
            Log.Verbose("  --Sending Chain");
            var scderived = keyPair.DeriveKey(remotePublicKey0);
            scderived = digest.ComputeDigest(scderived);
            Log.Verbose($"  C Input Key:    {Log.ShowBytes(rootKey)}");
            Log.Verbose($"  C Key Info:     {Log.ShowBytes(scderived)}");
            var sckeys = kdf.GenerateKeys(scderived, rootKey, 3, 32);
            Log.Verbose($"  C Key Out 0:    {Log.ShowBytes(sckeys[0])}");
            Log.Verbose($"  C Key Out 1:    {Log.ShowBytes(sckeys[1])}");
            Log.Verbose($"  C Key Out 2:    {Log.ShowBytes(sckeys[2])}");
            rootKey = sckeys[0];
            e0.SendingChain.Initialize(sckeys[1]);
            var nextSendHeaderKey = sckeys[2];
            
            var e1 = InitializeServer(kdf, digest,
                keyPair,
                rootKey,
                remotePublicKey1,
                nextKeyPair,
                receiveHeaderKey,
                nextSendHeaderKey);

            return new[] { e0, e1 };
        }

        public EcdhRatchetStep Ratchet(IKeyAgreementFactory factory, IKeyDerivation kdf, IDigest digest, ArraySegment<byte> remotePublicKey, IKeyAgreement keyPair)
        {
            var nextStep = InitializeServer(kdf, digest,
                EcdhKey,
                NextRootKey,
                remotePublicKey,
                keyPair,
                NextReceiveHeaderKey,
                NextSendHeaderKey);

            NextRootKey = null;
            EcdhKey = null;
            NextSendHeaderKey = null;
            NextReceiveHeaderKey = null;

            return nextStep;
        }

        public static EcdhRatchetStep Create(IKeyAgreement EcdhKey, byte[] NextRootKey,
            int receivingGeneration, byte[] receivingHeaderKey, byte[] receivingNextHeaderKey, byte[] receivingChainKey,
            int sendingGeneration, byte[] sendingHeaderKey, byte[] sendingNextHeaderKey, byte[] sendingChainKey)
        {
            if (NextRootKey != null && NextRootKey.Length != 32) throw new InvalidOperationException("The next root key size needs to be 32 bytes");
            if (receivingHeaderKey != null && receivingHeaderKey.Length != 32) throw new InvalidOperationException("The receiving header key size needs to be 32 bytes");
            if (receivingNextHeaderKey != null && receivingNextHeaderKey.Length != 32) throw new InvalidOperationException("The next receiving header key size needs to be 32 bytes");
            if (receivingChainKey != null && receivingChainKey.Length != 32) throw new InvalidOperationException("The receiving chain key size needs to be 32 bytes");
            if (sendingHeaderKey != null && sendingHeaderKey.Length != 32) throw new InvalidOperationException("The sending header key size needs to be 32 bytes");
            if (sendingNextHeaderKey != null && sendingNextHeaderKey.Length != 32) throw new InvalidOperationException("The next sending header key size needs to be 32 bytes");
            if (sendingChainKey != null && sendingChainKey.Length != 32) throw new InvalidOperationException("The sending chain key size needs to be 32 bytes");

            var step = new EcdhRatchetStep()
            {
                EcdhKey = EcdhKey,
                NextRootKey = NextRootKey,
                ReceiveHeaderKey = receivingHeaderKey,
                NextReceiveHeaderKey = receivingNextHeaderKey,
                SendHeaderKey = sendingHeaderKey,
                NextSendHeaderKey = sendingNextHeaderKey
            };

            step.ReceivingChain.Initialize(receivingChainKey);
            step.ReceivingChain.Generation = receivingGeneration;
            step.SendingChain.Initialize(sendingChainKey);
            step.SendingChain.Generation = sendingGeneration;

            return step;
        }
    }
}
