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
            //Debug.WriteLine($"--Initialize ECDH Ratchet");
            //Debug.WriteLine($"Root Key:           {Convert.ToBase64String(rootKey)}");
            //Debug.WriteLine($"Prev ECDH Private: ({Convert.ToBase64String(previousKeyPair.GetPublicKey())})");
            //Debug.WriteLine($"ECDH Public:        {Convert.ToBase64String(remotePublicKey ?? new byte[0])}");
            //Debug.WriteLine($"Curr ECDH Private: ({Convert.ToBase64String(keyPair.GetPublicKey())})");

            var e = new EcdhRatchetStep
            {
                EcdhKey = keyPair,
            };

            // receive chain
            //Debug.WriteLine("  --Receiving Chain");
            var rcinfo = previousKeyPair.DeriveKey(remotePublicKey);
            //Debug.WriteLine($"  C Input Key:    {Convert.ToBase64String(rootKey)}");
            //Debug.WriteLine($"  C Key Info:     {Convert.ToBase64String(rcinfo)}");
            var rckeys = kdf.GenerateKeys(rootKey, rcinfo, 3, keySize);
            //Debug.WriteLine($"  C Key Out 0:    {Convert.ToBase64String(rckeys[0])}");
            //Debug.WriteLine($"  C Key Out 1:    {Convert.ToBase64String(rckeys[1])}");
            //Debug.WriteLine($"  C Key Out 2:    {Convert.ToBase64String(rckeys[2])}");
            rootKey = rckeys[0];
            e.ReceivingChain.Initialize(keySize, receiveHeaderKey, rckeys[1], rckeys[2]);

            // send chain
            //Debug.WriteLine("  --Sending Chain");
            var scinfo = keyPair.DeriveKey(remotePublicKey);
            //Debug.WriteLine($"  C Input Key:    {Convert.ToBase64String(rootKey)}");
            //Debug.WriteLine($"  C Key Info:     {Convert.ToBase64String(scinfo)}");
            var sckeys = kdf.GenerateKeys(rootKey, scinfo, 3, keySize);
            //Debug.WriteLine($"  C Key Out 0:    {Convert.ToBase64String(sckeys[0])}");
            //Debug.WriteLine($"  C Key Out 1:    {Convert.ToBase64String(sckeys[1])}");
            //Debug.WriteLine($"  C Key Out 2:    {Convert.ToBase64String(sckeys[2])}");
            rootKey = sckeys[0];
            e.SendingChain.Initialize(keySize, sendHeaderKey, sckeys[1], sckeys[2]);

            // next root key

            //Debug.WriteLine($"Next Root Key:     ({Convert.ToBase64String(rootKey)})");
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
            //Debug.WriteLine($"--Initialize ECDH Ratchet CLIENT");
            //Debug.WriteLine($"Root Key:           {Convert.ToBase64String(rootKey)}");
            //Debug.WriteLine($"ECDH Public 0:      {Convert.ToBase64String(remotePublicKey0)}");
            //Debug.WriteLine($"ECDH Public 1:      {Convert.ToBase64String(remotePublicKey1)}");
            //Debug.WriteLine($"ECDH Private:      ({Convert.ToBase64String(keyPair.GetPublicKey())})");

            var e0 = new EcdhRatchetStep
            {
                EcdhKey = keyPair
            };
            e0.SendingChain.KeySize = keySize;
            e0.SendingChain.KeySize = keySize;

            // receive chain doesn't exist
            //Debug.WriteLine("  --Receiving Chain");

            // send chain
            //Debug.WriteLine("  --Sending Chain");
            var scinfo = keyPair.DeriveKey(remotePublicKey0);
            //Debug.WriteLine($"  C Input Key:    {Convert.ToBase64String(rootKey)}");
            //Debug.WriteLine($"  C Key Info:     {Convert.ToBase64String(scinfo)}");
            var sckeys = kdf.GenerateKeys(rootKey, scinfo, 3, keySize);
            //Debug.WriteLine($"  C Key Out 0:    {Convert.ToBase64String(sckeys[0])}");
            //Debug.WriteLine($"  C Key Out 1:    {Convert.ToBase64String(sckeys[1])}");
            //Debug.WriteLine($"  C Key Out 2:    {Convert.ToBase64String(sckeys[2])}");
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
