using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace MicroRatchet
{
    internal class EcdhRatchetStep
    {
        public IKeyAgreement EcdhKey;
        public byte[] NextRootKey;
        public SymmetricRacthet ReceivingChain;
        public SymmetricRacthet SendingChain;

        private EcdhRatchetStep() { }

        public static EcdhRatchetStep InitializeServer(IKeyDerivation kdf,
            IKeyAgreement previousKeyPair,
            byte[] rootKey, byte[] remotePublicKey, IKeyAgreement keyPair,
            byte[] receiveHeaderKey, byte[] sendHeaderKey)
        {
            int keySize = rootKey.Length;
            if (keySize != 32 && keySize != 16) throw new InvalidOperationException("Invalid key size. Must be 16 or 32 bytes.");
            if(receiveHeaderKey.Length != keySize || sendHeaderKey.Length != keySize) throw new InvalidOperationException("All keys sizes were not consistent.");
            Log.Verbose($"--Initialize ECDH Ratchet");
            Log.Verbose($"Root Key:           {Log.ShowBytes(rootKey)}");
            Log.Verbose($"Prev ECDH Private: ({Log.ShowBytes(previousKeyPair.GetPublicKey())})");
            Log.Verbose($"ECDH Public:        {Log.ShowBytes(remotePublicKey ?? new byte[0])}");
            Log.Verbose($"Curr ECDH Private: ({Log.ShowBytes(keyPair.GetPublicKey())})");

            var e = new EcdhRatchetStep
            {
                EcdhKey = keyPair,
            };

            // receive chain
            Log.Verbose("  --Receiving Chain");
            var rcderived = previousKeyPair.DeriveKey(remotePublicKey);
            Log.Verbose($"  C Input Key:    {Log.ShowBytes(rootKey)}");
            Log.Verbose($"  C Key Info:     {Log.ShowBytes(rcderived)}");
            var rckeys = kdf.GenerateKeys(rcderived, rootKey, 3, keySize);
            Log.Verbose($"  C Key Out 0:    {Log.ShowBytes(rckeys[0])}");
            Log.Verbose($"  C Key Out 1:    {Log.ShowBytes(rckeys[1])}");
            Log.Verbose($"  C Key Out 2:    {Log.ShowBytes(rckeys[2])}");
            rootKey = rckeys[0];
            e.ReceivingChain.Initialize(keySize, receiveHeaderKey, rckeys[1], rckeys[2]);

            // send chain
            Log.Verbose("  --Sending Chain");
            var scderived = keyPair.DeriveKey(remotePublicKey);
            Log.Verbose($"  C Input Key:    {Log.ShowBytes(rootKey)}");
            Log.Verbose($"  C Key Info:     {Log.ShowBytes(scderived)}");
            var sckeys = kdf.GenerateKeys(scderived, rootKey, 3, keySize);
            Log.Verbose($"  C Key Out 0:    {Log.ShowBytes(sckeys[0])}");
            Log.Verbose($"  C Key Out 1:    {Log.ShowBytes(sckeys[1])}");
            Log.Verbose($"  C Key Out 2:    {Log.ShowBytes(sckeys[2])}");
            rootKey = sckeys[0];
            e.SendingChain.Initialize(keySize, sendHeaderKey, sckeys[1], sckeys[2]);

            // next root key

            Log.Verbose($"Next Root Key:     ({Log.ShowBytes(rootKey)})");
            e.NextRootKey = rootKey;
            return e;
        }

        public byte[] GetPublicKey(IKeyAgreementFactory kexfac) => EcdhKey.GetPublicKey();

        public static EcdhRatchetStep[] InitializeClient(IKeyDerivation kdf,
            byte[] rootKey, byte[] remotePublicKey0, byte[] remotePublicKey1, IKeyAgreement keyPair,
            byte[] receiveHeaderKey, byte[] sendHeaderKey,
            IKeyAgreement nextKeyPair)
        {
            int keySize = rootKey.Length;
            if (keySize != 32 && keySize != 16) throw new InvalidOperationException("Invalid key size. Must be 16 or 32 bytes.");
            if (receiveHeaderKey.Length != keySize || sendHeaderKey.Length != keySize) throw new InvalidOperationException("All keys sizes were not consistent.");
            Log.Verbose($"--Initialize ECDH Ratchet CLIENT");
            Log.Verbose($"Root Key:           {Log.ShowBytes(rootKey)}");
            Log.Verbose($"ECDH Public 0:      {Log.ShowBytes(remotePublicKey0)}");
            Log.Verbose($"ECDH Public 1:      {Log.ShowBytes(remotePublicKey1)}");
            Log.Verbose($"ECDH Private:      ({Log.ShowBytes(keyPair.GetPublicKey())})");

            var e0 = new EcdhRatchetStep
            {
                EcdhKey = keyPair
            };
            e0.SendingChain.KeySize = keySize;
            e0.SendingChain.KeySize = keySize;

            // receive chain doesn't exist
            Log.Verbose("  --Receiving Chain");

            // send chain
            Log.Verbose("  --Sending Chain");
            var scderived = keyPair.DeriveKey(remotePublicKey0);
            Log.Verbose($"  C Input Key:    {Log.ShowBytes(rootKey)}");
            Log.Verbose($"  C Key Info:     {Log.ShowBytes(scderived)}");
            var sckeys = kdf.GenerateKeys(scderived, rootKey, 3, keySize);
            Log.Verbose($"  C Key Out 0:    {Log.ShowBytes(sckeys[0])}");
            Log.Verbose($"  C Key Out 1:    {Log.ShowBytes(sckeys[1])}");
            Log.Verbose($"  C Key Out 2:    {Log.ShowBytes(sckeys[2])}");
            rootKey = sckeys[0];
            e0.SendingChain.Initialize(keySize, sendHeaderKey, sckeys[1], sckeys[2]);

            var nextSendHeaderKey = e0.SendingChain.NextHeaderKey;
            e0.SendingChain.NextHeaderKey = null;
            var e1 = InitializeServer(kdf,
                keyPair,
                rootKey,
                remotePublicKey1,
                nextKeyPair,
                receiveHeaderKey,
                nextSendHeaderKey);

            return new[] { e0, e1 };
        }

        public EcdhRatchetStep Ratchet(IKeyAgreementFactory factory, IKeyDerivation kdf, byte[] remotePublicKey, IKeyAgreement keyPair)
        {
            var nextStep = InitializeServer(kdf,
                EcdhKey,
                NextRootKey,
                remotePublicKey,
                keyPair,
                ReceivingChain.NextHeaderKey,
                SendingChain.NextHeaderKey);
            
            NextRootKey = null;
            EcdhKey = null;
            ReceivingChain.NextHeaderKey = null;
            SendingChain.NextHeaderKey = null;

            return nextStep;
        }
        
        public static EcdhRatchetStep Create(IKeyAgreement EcdhKey, byte[] NextRootKey,
            int receivingGeneration, byte[] receivingHeaderKey, byte[] receivingNextHeaderKey, byte[] receivingChainKey,
            int sendingGeneration, byte[] sendingHeaderKey, byte[] sendingNextHeaderKey, byte[] sendingChainKey)
        {
            int keySize = (NextRootKey ?? sendingHeaderKey ?? receivingHeaderKey).Length;
            var step = new EcdhRatchetStep()
            {
                EcdhKey = EcdhKey,
                NextRootKey = NextRootKey
            };

            step.ReceivingChain.Initialize(keySize, receivingHeaderKey, receivingChainKey, receivingNextHeaderKey);
            step.ReceivingChain.Generation = receivingGeneration;
            step.SendingChain.Initialize(keySize, sendingHeaderKey, sendingChainKey, sendingNextHeaderKey);
            step.SendingChain.Generation = sendingGeneration;

            return step;
        }
    }
}
