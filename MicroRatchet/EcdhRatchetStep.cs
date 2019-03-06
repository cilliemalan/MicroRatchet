using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace MicroRatchet
{
    internal class EcdhRatchetStep
    {
        private byte[] _publicKey;
        private byte[] KeyData;
        private byte[] NextRootKey;
        public SymmetricRacthet ReceivingChain;
        public SymmetricRacthet SendingChain;

        private EcdhRatchetStep() { }

        public static EcdhRatchetStep InitializeServer(IKeyDerivation kdf,
            IKeyAgreement previousKeyPair,
            byte[] rootKey, byte[] remotePublicKey, IKeyAgreement keyPair,
            byte[] receiveHeaderKey, byte[] sendHeaderKey)
        {
            //Debug.WriteLine($"--Initialize ECDH Ratchet");
            //Debug.WriteLine($"Root Key:           {Convert.ToBase64String(rootKey)}");
            //Debug.WriteLine($"Prev ECDH Private: ({Convert.ToBase64String(previousKeyPair.GetPublicKey())})");
            //Debug.WriteLine($"ECDH Public:        {Convert.ToBase64String(remotePublicKey ?? new byte[0])}");
            //Debug.WriteLine($"Curr ECDH Private: ({Convert.ToBase64String(keyPair.GetPublicKey())})");

            var e = new EcdhRatchetStep
            {
                KeyData = keyPair.Serialize(),
                _publicKey = keyPair.GetPublicKey()
            };

            // receive chain
            //Debug.WriteLine("  --Receiving Chain");
            var rcinfo = previousKeyPair.DeriveKey(remotePublicKey);
            //Debug.WriteLine($"  C Input Key:    {Convert.ToBase64String(rootKey)}");
            //Debug.WriteLine($"  C Key Info:     {Convert.ToBase64String(rcinfo)}");
            var rckeys = kdf.GenerateKeys(rootKey, rcinfo, 3);
            //Debug.WriteLine($"  C Key Out 0:    {Convert.ToBase64String(rckeys[0])}");
            //Debug.WriteLine($"  C Key Out 1:    {Convert.ToBase64String(rckeys[1])}");
            //Debug.WriteLine($"  C Key Out 2:    {Convert.ToBase64String(rckeys[2])}");
            rootKey = rckeys[0];
            e.ReceivingChain.Initialize(receiveHeaderKey, rckeys[1], rckeys[2]);

            // send chain
            //Debug.WriteLine("  --Sending Chain");
            var scinfo = keyPair.DeriveKey(remotePublicKey);
            //Debug.WriteLine($"  C Input Key:    {Convert.ToBase64String(rootKey)}");
            //Debug.WriteLine($"  C Key Info:     {Convert.ToBase64String(scinfo)}");
            var sckeys = kdf.GenerateKeys(rootKey, scinfo, 3);
            //Debug.WriteLine($"  C Key Out 0:    {Convert.ToBase64String(sckeys[0])}");
            //Debug.WriteLine($"  C Key Out 1:    {Convert.ToBase64String(sckeys[1])}");
            //Debug.WriteLine($"  C Key Out 2:    {Convert.ToBase64String(sckeys[2])}");
            rootKey = sckeys[0];
            e.SendingChain.Initialize(sendHeaderKey, sckeys[1], sckeys[2]);

            // next root key

            //Debug.WriteLine($"Next Root Key:     ({Convert.ToBase64String(rootKey)})");
            e.NextRootKey = rootKey;
            return e;
        }

        public byte[] GetPublicKey(IKeyAgreementFactory kexfac)
        {
            if (_publicKey == null)
            {
                _publicKey = kexfac.Deserialize(KeyData).GetPublicKey();
            }

            return _publicKey;
        }

        public static EcdhRatchetStep[] InitializeClient(IKeyDerivation kdf,
            byte[] rootKey, byte[] remotePublicKey0, byte[] remotePublicKey1, IKeyAgreement keyPair,
            byte[] receiveHeaderKey, byte[] sendHeaderKey,
            IKeyAgreement nextKeyPair)
        {
            //Debug.WriteLine($"--Initialize ECDH Ratchet CLIENT");
            //Debug.WriteLine($"Root Key:           {Convert.ToBase64String(rootKey)}");
            //Debug.WriteLine($"ECDH Public 0:      {Convert.ToBase64String(remotePublicKey0)}");
            //Debug.WriteLine($"ECDH Public 1:      {Convert.ToBase64String(remotePublicKey1)}");
            //Debug.WriteLine($"ECDH Private:      ({Convert.ToBase64String(keyPair.GetPublicKey())})");

            var e0 = new EcdhRatchetStep
            {
                KeyData = keyPair.Serialize(),
                _publicKey = keyPair.GetPublicKey()
            };

            // receive chain doesn't exist
            //Debug.WriteLine("  --Receiving Chain");

            // send chain
            //Debug.WriteLine("  --Sending Chain");
            var scinfo = keyPair.DeriveKey(remotePublicKey0);
            //Debug.WriteLine($"  C Input Key:    {Convert.ToBase64String(rootKey)}");
            //Debug.WriteLine($"  C Key Info:     {Convert.ToBase64String(scinfo)}");
            var sckeys = kdf.GenerateKeys(rootKey, scinfo, 3);
            //Debug.WriteLine($"  C Key Out 0:    {Convert.ToBase64String(sckeys[0])}");
            //Debug.WriteLine($"  C Key Out 1:    {Convert.ToBase64String(sckeys[1])}");
            //Debug.WriteLine($"  C Key Out 2:    {Convert.ToBase64String(sckeys[2])}");
            rootKey = sckeys[0];
            e0.SendingChain.Initialize(sendHeaderKey, sckeys[1], sckeys[2]);

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
                factory.Deserialize(KeyData),
                NextRootKey,
                remotePublicKey,
                keyPair,
                ReceivingChain.NextHeaderKey,
                SendingChain.NextHeaderKey);
            
            NextRootKey = null;
            KeyData = null;
            ReceivingChain.NextHeaderKey = null;
            SendingChain.NextHeaderKey = null;

            return nextStep;
        }

        public void Serialize(BinaryWriter bw)
        {
            WriteBuffer(bw, KeyData);
            SendingChain.Serialize(bw, true);
            ReceivingChain.Serialize(bw, false);
            WriteBuffer(bw, NextRootKey);
        }

        public static EcdhRatchetStep Deserialize(BinaryReader br)
        {

            var step = new EcdhRatchetStep();
            step.KeyData = ReadBuffer(br);
            step.SendingChain.Deserialize(br, true);
            step.ReceivingChain.Deserialize(br, false);
            step.NextRootKey = ReadBuffer(br);

            return step;
        }

        private static void WriteBuffer(BinaryWriter bw, byte[] data)
        {
            if (data == null)
            {
                bw.Write(-1);
            }
            else
            {
                bw.Write(data.Length);
                if (data.Length != 0) bw.Write(data);
            }
        }

        private static byte[] ReadBuffer(BinaryReader br)
        {
            int c = br.ReadInt32();
            if (c < 0) return null;
            if (c > 0) return br.ReadBytes(c);
            else return new byte[0];
        }
    }
}
