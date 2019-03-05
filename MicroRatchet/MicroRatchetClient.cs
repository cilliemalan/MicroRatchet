using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;

namespace MicroRatchet
{
    public class MicroRatchetClient
    {
        IDigest Digest => Services.Digest;
        ISignature Signature => Services.Signature;
        IRandomNumberGenerator RandomNumberGenerator => Services.RandomNumberGenerator;
        ISecureStorage SecureStorage => Services.SecureStorage;
        IKeyAgreementFactory KeyAgreementFactory => Services.KeyAgreementFactory;
        ICipherFactory CipherFactory => Services.CipherFactory;
        IKeyDerivation KeyDerivation;
        IVerifierFactory VerifierFactory => Services.VerifierFactory;

        public IServices Services { get; }
        public int Mtu { get; }
        public bool IsClient { get; }

        public MicroRatchetClient(IServices services, bool isClient, int Mtu = 1000)
        {
            Services = services ?? throw new ArgumentException(nameof(services));
            IsClient = isClient;
            this.Mtu = Mtu;

            KeyDerivation = new KeyDerivation(Services.Digest);
        }

        private byte[] SendInitializationRequest(State _state)
        {
            if (!(_state is ClientState state)) throw new InvalidOperationException("Only the client can send init request.");

            // 32 bytes nonce
            state.InitializationNonce = RandomNumberGenerator.Generate(32);
            state.InitializationNonce[0] &= 0b0001_1111;
            state.InitializationNonce[0] |= 0b0110_0000;

            // get the public key
            var pubkey = Signature.PublicKey;

            // generate new ECDH keypair for init message and root key
            var clientEcdh = KeyAgreementFactory.GenerateNew();
            state.LocalEcdhForInit = clientEcdh.Serialize();

            // nonce(32), pubkey(32), ecdh(32), signature(64) (total: 160 bytes)
            using (MemoryStream ms = new MemoryStream())
            {
                using (BinaryWriter bw = new BinaryWriter(ms))
                {
                    bw.Write(state.InitializationNonce);
                    bw.Write(pubkey);
                    bw.Write(clientEcdh.GetPublicKey());
                    ms.TryGetBuffer(out var msbuffer);
                    bw.Write(Signature.Sign(msbuffer));

                    SaveState(state);
                    if (ms.Length > Mtu) throw new InvalidOperationException("The MTU was too small to create the message");
                    return ms.ToArray();
                }
            }
        }

        private void ReceiveInitializationRequest(State _state, byte[] data)
        {
            if (!(_state is ServerState state)) throw new InvalidOperationException("Only the server can receive an init request.");

            // nonce(32), pubkey(32), ecdh(32), signature(64) (total: 160 bytes)
            using (var ms = new MemoryStream(data))
            {
                using (var br = new BinaryReader(ms))
                {
                    // read stuff
                    state.InitializationNonce = br.ReadBytes(32);
                    state.RemotePublicKey = br.ReadBytes(32);
                    state.RemoteEcdhForInit = br.ReadBytes(32);

                    var verifier = VerifierFactory.Create(state.RemotePublicKey);
                    if (!verifier.VerifySignedMessage(data))
                    {
                        throw new InvalidOperationException("The signature was invalid");
                    }

                    SaveState(state);
                }
            }
        }

        private byte[] SendInitializationResponse(State _state)
        {
            if (!(_state is ServerState state)) throw new InvalidOperationException("Only the server can send init response.");

            if (state == null || state.RemotePublicKey == null) throw new InvalidOperationException("Could not send initialization response because the state has not been initialized.");
            if (state.RemoteEcdhForInit == null) throw new InvalidOperationException("Could not send initialization response because the ephemeral key has been deleted. Perhaps the initialization response has already been sent.");
            if (state.InitializationNonce == null) throw new InvalidOperationException("Could not send initialization response because the ephemeral nonce has been deleted. Perhaps the initialization response has already been sent.");


            // generate a nonce and new ecdh parms
            var serverNonce = RandomNumberGenerator.Generate(32);
            serverNonce[0] &= 0b0001_1111;
            serverNonce[0] |= 0b1110_0000;
            state.NextInitializationNonce = serverNonce;
            var tempEcdh = KeyAgreementFactory.GenerateNew();
            var tempEcdhPubkey = tempEcdh.GetPublicKey();
            var sharedSecret = tempEcdh.DeriveKey(state.RemoteEcdhForInit);

            // generate server ECDH for root key and root key
            var serverEcdh = KeyAgreementFactory.GenerateNew();
            state.LocalEcdhForInit = serverEcdh.Serialize();
            var rootPreKey = serverEcdh.DeriveKey(state.RemoteEcdhForInit);
            var genKeys = KeyDerivation.GenerateKeys(rootPreKey, null, 3);
            state.RootKey = genKeys[0];
            state.FirstSendHeaderKey = genKeys[1];
            state.FirstReceiveHeaderKey = genKeys[2];

            // generate two server ECDH. One for ratchet 0 sending key and one for the next
            // this is enough for the server to generate a receiving chain key and sending
            // chain key as soon as the client sends a sending chain key
            var serverEcdhRatchet0 = KeyAgreementFactory.GenerateNew();
            state.LocalEcdhRatchetStep0 = serverEcdhRatchet0.Serialize();
            var serverEcdhRatchet1 = KeyAgreementFactory.GenerateNew();
            state.LocalEcdhRatchetStep1 = serverEcdhRatchet1.Serialize();

            // generate client's pubkey signature
            byte[] clientKeySignature = Signature.Sign(state.RemotePublicKey);

            // new nonce(32), ecdh pubkey(32), [nonce(32), server pubkey(32), 
            // server pubkey signature(64), client pubkey signature(64), 
            // new ecdh pubkey(32) x3, signature(64)], mac(16)

            using (MemoryStream messageStream = new MemoryStream())
            {
                using (BinaryWriter messageWriter = new BinaryWriter(messageStream))
                {
                    messageWriter.Write(serverNonce);
                    messageWriter.Write(tempEcdhPubkey);

                    // create the payload
                    byte[] payload;
                    using (MemoryStream payloadStream = new MemoryStream())
                    {
                        using (BinaryWriter payloadWriter = new BinaryWriter(payloadStream))
                        {
                            payloadWriter.Write(state.InitializationNonce);
                            payloadWriter.Write(Signature.PublicKey);
                            payloadWriter.Write(new byte[64]); // TODO: public key signature
                            payloadWriter.Write(clientKeySignature);
                            payloadWriter.Write(serverEcdh.GetPublicKey());
                            payloadWriter.Write(serverEcdhRatchet0.GetPublicKey());
                            payloadWriter.Write(serverEcdhRatchet1.GetPublicKey());

                            // sign the message
                            payloadStream.TryGetBuffer(out var buffer);
                            payloadWriter.Write(Signature.Sign(buffer));
                            payload = payloadStream.ToArray();
                        }
                    }

                    // write the encrypted payload
                    var cipher = CipherFactory.GetAeadCipher(sharedSecret);
                    messageWriter.Write(cipher.Encrypt(serverNonce, payload));

                    SaveState(state);
                    if (messageStream.Length > Mtu) throw new InvalidOperationException("The MTU was too small to create the message");
                    return messageStream.ToArray();
                }
            }
        }

        private void ReceiveInitializationResponse(State _state, byte[] data)
        {
            if (!(_state is ClientState state)) throw new InvalidOperationException("Only the client can receive an init response.");

            // new nonce(32), ecdh pubkey(32), [nonce(32), server pubkey(32), 
            // server pubkey signature(64), client pubkey signature(64), 
            // new ecdh pubkey(32) x3, signature(64)], mac(16)

            using (var ms = new MemoryStream(data))
            {
                using (var br = new BinaryReader(ms))
                {
                    var nonce = br.ReadBytes(32);
                    var ecdh = br.ReadBytes(32);
                    IKeyAgreement localEcdh = KeyAgreementFactory.Deserialize(state.LocalEcdhForInit);
                    var tempSharedSecret = localEcdh.DeriveKey(ecdh);
                    var cipher = CipherFactory.GetAeadCipher(tempSharedSecret);
                    var payload = cipher.Decrypt(nonce, data, 64, data.Length - 64);

                    if (payload == null)
                    {
                        throw new InvalidOperationException("Could not decript payload");
                    }

                    using (var msp = new MemoryStream(payload))
                    {
                        using (var brp = new BinaryReader(msp))
                        {
                            var oldNonce = brp.ReadBytes(32);
                            var serverPubKey = brp.ReadBytes(32);
                            var serverPubKeySig = brp.ReadBytes(64);
                            var clientPubKeySig = brp.ReadBytes(64);
                            var rootEcdh = brp.ReadBytes(32);
                            var remoteRatchetEcdh0 = brp.ReadBytes(32);
                            var remoteRatchetEcdh1 = brp.ReadBytes(32);
                            var signature = brp.ReadBytes(64);

                            if (!oldNonce.Matches(state.InitializationNonce))
                            {
                                throw new InvalidOperationException("Nonce did not match");
                            }

                            var verifier = VerifierFactory.Create(serverPubKey);
                            if (!verifier.VerifySignedMessage(payload))
                            {
                                throw new InvalidOperationException("The signature was invalid");
                            }
                            // TODO check that the server public key is signed by a trusted signer
                            if (!verifier.Verify(Signature.PublicKey, clientPubKeySig))
                            {
                                throw new InvalidOperationException("The client public key was not signed by the server key");
                            }

                            // store the new nonce we got from the server
                            state.InitializationNonce = nonce;
                            Debug.WriteLine($"storing iniitlizaionta nonce: {Convert.ToBase64String(state.InitializationNonce)}");

                            // we now have enough information to construct our double ratchet
                            var localStep0EcdhRatchet = KeyAgreementFactory.GenerateNew();
                            var localStep1EcdhRatchet = KeyAgreementFactory.GenerateNew();

                            // initialize client root key and ecdh ratchet
                            state.RemoteEcdhForInit = rootEcdh;
                            state.publicKeySignature = clientPubKeySig;
                            var rootPreKey = localEcdh.DeriveKey(rootEcdh);
                            var genKeys = KeyDerivation.GenerateKeys(rootPreKey, null, 3);
                            var rootKey = state.RootKey = genKeys[0];
                            var receiveHeaderKey = state.FirstReceiveHeaderKey = genKeys[1];
                            var sendHeaderKey = state.FirstSendHeaderKey = genKeys[2];

                            state.Ratchets.Add(EcdhRatchetStep.InitializeClient(KeyDerivation, rootKey,
                                remoteRatchetEcdh0, remoteRatchetEcdh1, localStep0EcdhRatchet,
                                receiveHeaderKey, sendHeaderKey,
                                localStep1EcdhRatchet));

                            SaveState(state);
                        }
                    }
                }
            }
        }

        private byte[] SendFirstClientMessage(State _state)
        {
            if (!(_state is ClientState state)) throw new InvalidOperationException("Only the client can send the first client message.");

            return ConstructMessage(state, state.InitializationNonce, true, true, state.Ratchets.SecondToLast);
        }

        private void ReceiveFirstMessage(State _state, byte[] payload)
        {
            if (!(_state is ServerState state)) throw new InvalidOperationException("Only the server can receive the first client message.");

            // decrypt the outer payload with the AEAD cipher
            var cipher = CipherFactory.GetAeadCipher(state.FirstReceiveHeaderKey, 96);
            byte[] obfuscatedNonce = new byte[4];
            Array.Copy(payload, obfuscatedNonce, 4);
            byte[] encryptedPayload = new byte[payload.Length - 4];
            Array.Copy(payload, 4, encryptedPayload, 0, payload.Length - 4);
            var decryptedPayload = cipher.Decrypt(obfuscatedNonce, encryptedPayload);
            if (decryptedPayload == null) throw new InvalidOperationException("Could not decrypt the message");

            // get the unobfuscated nonce
            byte[] nonce = KeyDerivation.UnObfuscate(obfuscatedNonce, state.FirstReceiveHeaderKey, decryptedPayload);

            // get the new ecdh public from the decrypted payload
            var clientEcdhPublic = new byte[32];
            Array.Copy(decryptedPayload, clientEcdhPublic, 32);

            // initialize the ecdh ratchet
            var step = EcdhRatchetStep.InitializeServer(KeyDerivation,
                KeyAgreementFactory.Deserialize(state.LocalEcdhRatchetStep0),
                state.RootKey, clientEcdhPublic,
                KeyAgreementFactory.Deserialize(state.LocalEcdhRatchetStep1),
                state.FirstReceiveHeaderKey,
                state.FirstSendHeaderKey);
            state.Ratchets.Add(step);

            // get the inner payload key from the server receive chain
            var (key, nr) = step.ReceivingChain.Ratchet(KeyDerivation, 1);
            byte[] innerPayload = new byte[decryptedPayload.Length - 32];
            Array.Copy(decryptedPayload, 32, innerPayload, 0, innerPayload.Length);

            var innerCipher = CipherFactory.GetCipher(key, nonce);
            var decryptedInnerPayload = innerCipher.Decrypt(innerPayload);

            var innerNonce = new byte[32];
            Array.Copy(decryptedInnerPayload, innerNonce, 32);

            if (!innerNonce.Matches(state.NextInitializationNonce))
            {
                throw new InvalidOperationException("The inner encrypted nonce did not match the initialization nonce.");
            }

            SaveState(state);
        }

        private byte[] SendFirstResponse(State _state)
        {
            if (!(_state is ServerState state)) throw new InvalidOperationException("Only the server can send the first response.");

            return ConstructMessage(state, state.NextInitializationNonce, true, false, state.Ratchets.Last);
        }

        private void ReceiveFirstResponse(State _state, byte[] data)
        {
            if (!(_state is ClientState state)) throw new InvalidOperationException("Only the client can receive the first response.");

            var contents = DeconstructMessage(state, data);
            if (contents == null || contents.Length < 32)
            {
                throw new InvalidOperationException("The first response from the server was not valid");
            }
            var nonce = new byte[32];
            Array.Copy(contents, nonce, 32);
            if (!nonce.Matches(state.InitializationNonce))
            {
                throw new InvalidOperationException("The first response from the server did not contain the correct nonce");
            }
        }

        private byte[] ConstructMessage(State _state, byte[] message, bool pad, bool includeEcdh, EcdhRatchetStep step)
        {
            var state = _state;

            // select the ECDH ratchet step to use
            byte type;
            if (includeEcdh)
            {
                type = 0b0010_0000;
            }
            else
            {
                type = 0b0000_0000;
            }


            // get the payload key and nonce
            var ratchetPublicKey = KeyAgreementFactory.Deserialize(step.PrivateKey).GetPublicKey();
            var (payloadKey, messageNumber) = step.SendingChain.Ratchet(KeyDerivation);
            var nonce = BigEndianBitConverter.GetBytes(messageNumber);
            nonce[0] &= 0b0001_1111;
            nonce[0] |= type;

            // build the payload
            // <server nonce (32), padding (mtu - 80)>
            byte[] payload;
            using (var mspayload = new MemoryStream())
            {
                using (var bwpayload = new BinaryWriter(mspayload))
                {
                    bwpayload.Write(message);
                    if (pad)
                    {
                        int left = Mtu - 80;
                        if (left > 0)
                        {
                            bwpayload.Write(RandomNumberGenerator.Generate(left));
                        }
                    }

                    payload = mspayload.ToArray();
                }
            }

            // encrypt the payload
            var cipher = CipherFactory.GetCipher(payloadKey, nonce);
            var encryptedPayload = cipher.Encrypt(payload);

            // nonce (4), [ecdh (32), <payload>], mac (12)
            byte[] outerPayload;
            using (var ms = new MemoryStream())
            {
                using (var bw = new BinaryWriter(ms))
                {
                    if (includeEcdh)
                    {
                        bw.Write(ratchetPublicKey);
                    }
                    bw.Write(encryptedPayload);
                    outerPayload = ms.ToArray();
                }
            }

            // obfuscate the nonce
            var obfuscatedNonce = KeyDerivation.Obfuscate(nonce, step.SendingChain.HeaderKey, outerPayload);

            // encrypt the encrypted payload with the header key
            var aeadCipher = CipherFactory.GetAeadCipher(step.SendingChain.HeaderKey, 96);
            var encryptedOuterPayload = aeadCipher.Encrypt(obfuscatedNonce, outerPayload);

            using (var ms = new MemoryStream())
            {
                using (var bw = new BinaryWriter(ms))
                {
                    bw.Write(obfuscatedNonce);
                    bw.Write(encryptedOuterPayload);
                    var result = ms.ToArray();
                    if (result.Length > Mtu) throw new InvalidOperationException("Could not create message within MTU");
                    SaveState(state);
                    return result;
                }
            }
        }

        private byte[] DeconstructMessage(State _state, byte[] payload)
        {
            var state = _state;

            // extract the nonce
            byte[] obfuscatedNonce = new byte[4];
            Array.Copy(payload, obfuscatedNonce, 4);

            byte[] headerKey = null;
            byte[] decrypted = null;
            EcdhRatchetStep ratchetUsed = null;
            bool usedNextHeaderKey = false;
            int cnt = 0;
            foreach (var ratchet in state.Ratchets.Enumerate())
            {
                cnt++;
                headerKey = ratchet.ReceivingChain.HeaderKey;
                var cipher1 = CipherFactory.GetAeadCipher(headerKey, 96);
                decrypted = cipher1.Decrypt(obfuscatedNonce, payload, 4, payload.Length - 4);
                if (decrypted != null)
                {
                    ratchetUsed = ratchet;
                    break;
                }
                else
                {
                    headerKey = ratchet.ReceivingChain.NextHeaderKey;
                    var cipher2 = CipherFactory.GetAeadCipher(headerKey, 96);
                    decrypted = cipher2.Decrypt(obfuscatedNonce, payload, 4, payload.Length - 4);
                    if (decrypted != null)
                    {
                        usedNextHeaderKey = true;
                        ratchetUsed = ratchet;
                        break;
                    }
                }
            }

            if (decrypted == null)
            {
                throw new InvalidOperationException("Could not decrypt the incoming message");
            }

            byte[] noncebytes = KeyDerivation.UnObfuscate(obfuscatedNonce, headerKey, decrypted);
            int nonce = BigEndianBitConverter.ToInt32(noncebytes);
            int type = (int)((nonce & 0xE0000000) >> 29);
            int step = nonce & 0x1FFFFFFF;

            if (type == 0b001)
            {
                // the message contains ecdh parameters
                var clientEcdhPublic = new byte[32];
                Array.Copy(decrypted, clientEcdhPublic, 32);
                var newDecrypted = new byte[decrypted.Length - 32];
                Array.Copy(decrypted, 32, newDecrypted, 0, newDecrypted.Length);
                decrypted = newDecrypted;

                if (usedNextHeaderKey)
                {
                    // perform ecdh ratchet
                    var newEcdh = KeyAgreementFactory.GenerateNew();
                    EcdhRatchetStep newRatchet = ratchetUsed.Ratchet(KeyAgreementFactory, KeyDerivation, clientEcdhPublic, newEcdh);
                    state.Ratchets.Add(newRatchet);
                    ratchetUsed = newRatchet;
                }
            }

            // get the inner payload key from the server receive chain
            var (key, nr) = ratchetUsed.ReceivingChain.Ratchet(KeyDerivation, step);

            // decrypt the inner payload
            var innerCipher = CipherFactory.GetCipher(key, noncebytes);
            var decryptedInnerPayload = innerCipher.Decrypt(decrypted);
            SaveState(state);
            return decryptedInnerPayload;
        }

        public byte[] ProcessInitialization(byte[] dataReceived = null)
        {
            var _state = State.Deserialize(SecureStorage.LoadAsync());
            if (_state == null)
            {
                _state = State.Initialize(IsClient);
            }

            if (IsClient)
            {
                Debug.WriteLine("\n\n###CLIENT");
                if (dataReceived == null)
                {
                    // step 1: send first init request from client
                    return SendInitializationRequest(_state);
                }
                else
                {
                    var state = (ClientState)_state;


                    if (state.RemoteEcdhForInit == null)
                    {
                        var nonce = BigEndianBitConverter.ToUInt32(dataReceived);
                        var type = nonce >> 29;
                        if (type == 0b111)
                        {
                            // step 2: init response from server
                            ReceiveInitializationResponse(_state, dataReceived);
                            return SendFirstClientMessage(_state);
                        }
                        else
                        {
                            throw new InvalidOperationException("Expected an initialization response but got something else.");
                        }
                    }
                    else
                    {
                        // step 3: receive first message from server
                        ReceiveFirstResponse(_state, dataReceived);
                        // initialization completed successfully.
                        return null;
                    }

                    throw new InvalidOperationException("Unexpected message received during client initialization");
                }
            }
            else
            {
                Debug.WriteLine("\n\n###SERVER");
                var state = (ServerState)_state;

                if (dataReceived == null) throw new InvalidOperationException("Only the client can send initialization without having received a response first");

                var nonce = BigEndianBitConverter.ToUInt32(dataReceived);
                var type = nonce >> 29;

                if (state.InitializationNonce == null)
                {
                    if (type == 0b011)
                    {
                        // step 1: client init request
                        ReceiveInitializationRequest(_state, dataReceived);
                        return SendInitializationResponse(_state);
                    }
                    else
                    {
                        throw new InvalidOperationException("Expected initialization request but got something else.");
                    }
                }
                else
                {
                    // step 2: first message from client
                    ReceiveFirstMessage(_state, dataReceived);
                    return SendFirstResponse(_state);
                }

                throw new InvalidOperationException("Unexpected message received during server initialization");
            }
        }

        public byte[] Receive(byte[] data)
        {
            Debug.WriteLine($"\n\n###{(IsClient ? "CLIENT" : "SERVER")} RECEIVE");
            var state = State.Deserialize(SecureStorage.LoadAsync());

            if (state == null || state.Ratchets.IsEmpty)
            {
                throw new InvalidOperationException("The client has not been initialized.");
            }

            return DeconstructMessage(state, data);
        }

        public byte[] Send(byte[] payload)
        {
            Debug.WriteLine($"\n\n###{(IsClient ? "CLIENT" : "SERVER")} SEND");
            var state = State.Deserialize(SecureStorage.LoadAsync());

            if (state == null || state.Ratchets.IsEmpty)
            {
                throw new InvalidOperationException("The client has not been initialized.");
            }

            bool canIncludeEcdh = payload.Length <= Mtu - 48;
            EcdhRatchetStep step;
            if (canIncludeEcdh)
            {
                step = state.Ratchets.Last;
            }
            else
            {
                step = state.Ratchets.SecondToLast;
            }

            return ConstructMessage(state, payload, false, canIncludeEcdh, step);
        }

        private void SaveState(State state)
        {
            if (state != null)
            {
                SecureStorage.StoreAsync(state.Serialize());
            }
        }
    }
}
