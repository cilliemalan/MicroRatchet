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
        ICipher Cipher => Services.Cipher;
        IKeyDerivation KeyDerivation;
        IVerifierFactory VerifierFactory => Services.VerifierFactory;
        IMac Mac => Services.Mac;

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
            // message format:
            // nonce(32), pubkey(32), ecdh(32), signature(64) (total: 160 bytes)

            if (!(_state is ClientState state)) throw new InvalidOperationException("Only the client can send init request.");

            // 32 bytes nonce
            state.InitializationNonce = RandomNumberGenerator.Generate(32);
            state.InitializationNonce[0] = SetMessageType(state.InitializationNonce[0], MessageType.InitializationRequest);

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

        private (byte[] initializationNonce, byte[] remoteEcdhForInit, byte[] remotePublicKey) ReceiveInitializationRequest(State _state, byte[] data)
        {
            if (!(_state is ServerState state)) throw new InvalidOperationException("Only the server can receive an init request.");

            // nonce(32), pubkey(32), ecdh(32), signature(64) (total: 160 bytes)
            using (var ms = new MemoryStream(data))
            {
                using (var br = new BinaryReader(ms))
                {
                    // read stuff
                    var initializationNonce = br.ReadBytes(32);
                    var remotePublicKey = br.ReadBytes(32);
                    var remoteEcdhForInit = br.ReadBytes(32);

                    var verifier = VerifierFactory.Create(remotePublicKey);
                    if (!verifier.VerifySignedMessage(data))
                    {
                        throw new InvalidOperationException("The signature was invalid");
                    }

                    SaveState(state);

                    return (initializationNonce, remoteEcdhForInit, remotePublicKey);
                }
            }
        }

        private byte[] SendInitializationResponse(State _state, byte[] initializationNonce, byte[] remoteEcdhForInit)
        {
            // message format:
            // new nonce(32), ecdh pubkey(32),
            // <nonce from init request(32), server pubkey(32), 
            // new ecdh pubkey(32) x3, signature(64)>, mac(16)

            if (!(_state is ServerState state)) throw new InvalidOperationException("Only the server can send init response.");

            // generate a nonce and new ecdh parms
            var serverNonce = RandomNumberGenerator.Generate(32);
            serverNonce[0] = SetMessageType(serverNonce[0], MessageType.InitializationResponse);
            state.NextInitializationNonce = serverNonce;
            var tempEcdh = KeyAgreementFactory.GenerateNew();
            var tempEcdhPubkey = tempEcdh.GetPublicKey();
            var sharedSecret = tempEcdh.DeriveKey(remoteEcdhForInit);

            // generate server ECDH for root key and root key
            var serverEcdh = KeyAgreementFactory.GenerateNew();
            var LocalEcdhForInit = serverEcdh.Serialize();
            var rootPreKey = serverEcdh.DeriveKey(remoteEcdhForInit);
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

            // new nonce(32), ecdh pubkey(32),
            // [nonce(32), server pubkey(32), new ecdh pubkey(32) x3, signature(64)], mac(16)

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
                            payloadWriter.Write(initializationNonce);
                            payloadWriter.Write(Signature.PublicKey);
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
                    Cipher.Initialize(sharedSecret, serverNonce);
                    var encryptedPayload = Cipher.Encrypt(payload);
                    messageWriter.Write(encryptedPayload);

                    // calculate and write mac
                    Mac.Init(sharedSecret, serverNonce, 128);
                    Mac.Process(new ArraySegment<byte>(encryptedPayload));
                    var mac = Mac.Compute();
                    messageWriter.Write(mac);

                    SaveState(state);
                    if (messageStream.Length > Mtu) throw new InvalidOperationException("The MTU was too small to create the message");
                    return messageStream.ToArray();
                }
            }
        }

        private void ReceiveInitializationResponse(State _state, byte[] data)
        {
            if (!(_state is ClientState state)) throw new InvalidOperationException("Only the client can receive an init response.");

            // new nonce(32), ecdh pubkey(32), <nonce(32), server pubkey(32), 
            // new ecdh pubkey(32) x3, signature(64)>, mac(16)

            using (var ms = new MemoryStream(data))
            {
                using (var br = new BinaryReader(ms))
                {
                    // decrypt
                    var nonce = br.ReadBytes(32);
                    var ecdh = br.ReadBytes(32);
                    IKeyAgreement localEcdh = KeyAgreementFactory.Deserialize(state.LocalEcdhForInit);
                    var tempSharedSecret = localEcdh.DeriveKey(ecdh);
                    Cipher.Initialize(tempSharedSecret, nonce);
                    var payload = Cipher.Decrypt(data, 64, data.Length - 64 - 16);

                    // check mac
                    br.BaseStream.Seek(data.Length - 16, SeekOrigin.Begin);
                    var mac = br.ReadBytes(16);
                    Mac.Init(tempSharedSecret, nonce, 128);
                    Mac.Process(new ArraySegment<byte>(data, 64, data.Length - 64 - 16));
                    var checkMac = Mac.Compute();

                    if (!mac.Matches(checkMac))
                    {
                        throw new InvalidOperationException("Could not decript payload");
                    }

                    using (var msp = new MemoryStream(payload))
                    {
                        using (var brp = new BinaryReader(msp))
                        {
                            var oldNonce = brp.ReadBytes(32);
                            var serverPubKey = brp.ReadBytes(32);
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

                            // store the new nonce we got from the server
                            state.InitializationNonce = nonce;
                            //Debug.WriteLine($"storing iniitlizaionta nonce: {Convert.ToBase64String(state.InitializationNonce)}");

                            // we now have enough information to construct our double ratchet
                            var localStep0EcdhRatchet = KeyAgreementFactory.GenerateNew();
                            var localStep1EcdhRatchet = KeyAgreementFactory.GenerateNew();

                            // initialize client root key and ecdh ratchet
                            var RemoteEcdhForInit = rootEcdh;
                            var rootPreKey = localEcdh.DeriveKey(rootEcdh);
                            var genKeys = KeyDerivation.GenerateKeys(rootPreKey, null, 3);
                            var rootKey = genKeys[0];
                            var receiveHeaderKey = genKeys[1];
                            var sendHeaderKey = genKeys[2];

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

            var messageType = GetMessageType(payload[0]);
            if (messageType != MessageType.NormalWithEcdh)
            {
                throw new InvalidOperationException("The payload was invalid");
            }

            // extract the nonce
            byte[] nonce = new byte[4];
            Array.Copy(payload, nonce, nonce.Length);

            // use the header key we already agreed on
            byte[] headerKey = state.FirstReceiveHeaderKey;

            // double check the mac
            Mac.Init(headerKey, nonce, 96);
            Mac.Process(new ArraySegment<byte>(payload, nonce.Length, payload.Length - nonce.Length - 12));
            byte[] mac = Mac.Compute();
            if (!mac.Matches(new ArraySegment<byte>(payload, payload.Length - 12, 12)))
            {
                throw new InvalidOperationException("The first received message authentication code did not match");
            }

            // get the encrypted payload
            byte[] encryptedPayload;
            int headerSize = messageType == MessageType.NormalWithEcdh ? 36 : 4;
            encryptedPayload = new byte[payload.Length - headerSize - 12];
            Array.Copy(payload, headerSize, encryptedPayload, 0, encryptedPayload.Length);

            // decrypt the header
            var headerEncryptionKey = KeyDerivation.GenerateBytes(headerKey, encryptedPayload, 32);
            Cipher.Initialize(headerEncryptionKey, null);
            var decryptedHeader = Cipher.Decrypt(payload, 0, headerSize);
            decryptedHeader[0] = ClearMessageType(decryptedHeader[0]);

            // the message contains ecdh parameters
            var clientEcdhPublic = new byte[32];
            Array.Copy(decryptedHeader, 4, clientEcdhPublic, 0, 32);

            // initialize the ecdh ratchet
            var ratchetUsed = EcdhRatchetStep.InitializeServer(KeyDerivation,
                KeyAgreementFactory.Deserialize(state.LocalEcdhRatchetStep0),
                state.RootKey, clientEcdhPublic,
                KeyAgreementFactory.Deserialize(state.LocalEcdhRatchetStep1),
                state.FirstReceiveHeaderKey,
                state.FirstSendHeaderKey);
            state.Ratchets.Add(ratchetUsed);

            // get the inner payload key from the server receive chain
            var (key, nr) = ratchetUsed.ReceivingChain.RetrieveAndTrim(KeyDerivation, 1);

            // decrypt the inner payload
            var nonceBytes = new byte[4];
            Array.Copy(decryptedHeader, nonceBytes, 4);
            Cipher.Initialize(key, nonceBytes);
            var decryptedInnerPayload = Cipher.Decrypt(encryptedPayload);

            // check the inner payload
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
            // message format:
            // <nonce (4)>, <payload, padding>, mac(12)
            // <nonce (4), ecdh (32)>, <payload, padding>, mac(12)

            var state = _state;

            // this is the hottest line in the send process
            var ratchetPublicKey = step.GetPublicKey(KeyAgreementFactory);

            // get the payload key and nonce
            var (payloadKey, messageNumber) = step.SendingChain.RatchetAndTrim(KeyDerivation);
            var nonce = BigEndianBitConverter.GetBytes(messageNumber);
            var messageType = includeEcdh ? MessageType.NormalWithEcdh : MessageType.Normal;

            // calculate some sizes
            var headerSize = 4 + (includeEcdh ? 32 : 0);
            var overhead = headerSize + 12;
            var messageSize = message.Length;
            var maxMessageSize = Mtu - overhead;

            // build the payload: <payload, padding>
            byte[] payload;
            if (pad && messageSize < maxMessageSize)
            {
                payload = new byte[Mtu - overhead];
                Array.Copy(message, payload, message.Length);
            }
            else if (messageSize > maxMessageSize)
            {
                throw new InvalidOperationException("The message doesn't fit inside the MTU");
            }
            else
            {
                payload = message;
            }

            // encrypt the payload
            Cipher.Initialize(payloadKey, nonce);
            var encryptedPayload = Cipher.Encrypt(payload);

            // build the header: <nonce(4), ecdh(32)?>
            byte[] header = new byte[headerSize];
            Array.Copy(nonce, header, nonce.Length);
            if (includeEcdh)
            {
                Array.Copy(ratchetPublicKey, 0, header, nonce.Length, ratchetPublicKey.Length);
            }

            // encrypt the header
            var headerEncryptionKey = KeyDerivation.GenerateBytes(step.SendingChain.HeaderKey, encryptedPayload, 32);
            Cipher.Initialize(headerEncryptionKey, null);
            var encryptedHeader = Cipher.Encrypt(header);

            // set the message type (we can do this because we're using a CTR stream cipher)
            encryptedHeader[0] = SetMessageType(encryptedHeader[0], messageType);

            // mac the message: <header>, <payload>, mac(12)
            // the mac uses the first 4 encrypted bytes as iv and the rest (incl ecdh if there) as ad.
            byte[] iv;
            if (includeEcdh)
            {
                iv = new byte[4];
                Array.Copy(encryptedHeader, iv, 4);
                Mac.Init(step.SendingChain.HeaderKey, iv, 96);
                Mac.Process(new ArraySegment<byte>(encryptedHeader, 4, encryptedHeader.Length - 4));
            }
            else
            {
                iv = encryptedHeader;
                Mac.Init(step.SendingChain.HeaderKey, iv, 96);
            }
            Mac.Process(new ArraySegment<byte>(encryptedPayload));
            var mac = Mac.Compute();

            // construct the resulting message
            byte[] result = new byte[encryptedHeader.Length + encryptedPayload.Length + mac.Length];
            Array.Copy(encryptedHeader, 0, result, 0, encryptedHeader.Length);
            Array.Copy(encryptedPayload, 0, result, encryptedHeader.Length, encryptedPayload.Length);
            Array.Copy(mac, 0, result, encryptedHeader.Length + encryptedPayload.Length, mac.Length);
            if (result.Length > Mtu) throw new InvalidOperationException("Could not create message within MTU");
            SaveState(state);
            return result;
        }

        private byte[] DeconstructMessage(State _state, byte[] payload)
        {
            var state = _state;

            var messageType = GetMessageType(payload[0]);
            if (messageType != MessageType.Normal && messageType != MessageType.NormalWithEcdh)
            {
                throw new InvalidOperationException("The payload was invalid");
            }

            // extract the nonce
            byte[] nonce = new byte[4];
            Array.Copy(payload, nonce, nonce.Length);

            // find the header key by checking the mac
            byte[] headerKey = null;
            EcdhRatchetStep ratchetUsed = null;
            bool usedNextHeaderKey = false;
            int cnt = 0;
            foreach (var ratchet in state.Ratchets.Enumerate())
            {
                cnt++;
                headerKey = ratchet.ReceivingChain.HeaderKey;
                Mac.Init(headerKey, nonce, 96);
                Mac.Process(new ArraySegment<byte>(payload, nonce.Length, payload.Length - nonce.Length - 12));
                byte[] mac = Mac.Compute();
                if (mac.Matches(new ArraySegment<byte>(payload, payload.Length - mac.Length, mac.Length)))
                {
                    ratchetUsed = ratchet;
                    break;
                }
                else
                {
                    headerKey = ratchet.ReceivingChain.NextHeaderKey;
                    Mac.Init(headerKey, nonce, 96);
                    Mac.Process(new ArraySegment<byte>(payload, nonce.Length, payload.Length - nonce.Length - 12));
                    mac = Mac.Compute();
                    if (mac.Matches(new ArraySegment<byte>(payload, payload.Length - mac.Length, mac.Length)))
                    {
                        usedNextHeaderKey = true;
                        ratchetUsed = ratchet;
                        break;
                    }
                }
            }

            if (ratchetUsed == null)
            {
                throw new InvalidOperationException("Could not decrypt the incoming message");
            }

            // get the encrypted payload
            byte[] encryptedPayload;
            int headerSize = messageType == MessageType.NormalWithEcdh ? 36 : 4;
            encryptedPayload = new byte[payload.Length - headerSize - 12];
            Array.Copy(payload, headerSize, encryptedPayload, 0, encryptedPayload.Length);

            // decrypt the header
            var headerEncryptionKey = KeyDerivation.GenerateBytes(headerKey, encryptedPayload, 32);
            Cipher.Initialize(headerEncryptionKey, null);
            var decryptedHeader = Cipher.Decrypt(payload, 0, headerSize);
            decryptedHeader[0] = ClearMessageType(decryptedHeader[0]);
            int step = BigEndianBitConverter.ToInt32(decryptedHeader);

            if (messageType == MessageType.NormalWithEcdh)
            {
                // the message contains ecdh parameters
                var clientEcdhPublic = new byte[32];
                Array.Copy(decryptedHeader, 4, clientEcdhPublic, 0, 32);

                if (usedNextHeaderKey)
                {
                    // perform ecdh ratchet
                    var newEcdh = KeyAgreementFactory.GenerateNew();

                    // this is the hottest line in the deconstruct process:
                    EcdhRatchetStep newRatchet = ratchetUsed.Ratchet(KeyAgreementFactory, KeyDerivation, clientEcdhPublic, newEcdh);
                    state.Ratchets.Add(newRatchet);
                    ratchetUsed = newRatchet;
                }
            }

            // get the inner payload key from the server receive chain
            var (key, nr) = ratchetUsed.ReceivingChain.RetrieveAndTrim(KeyDerivation, step);

            // decrypt the inner payload
            var nonceBytes = new byte[4];
            Array.Copy(decryptedHeader, nonceBytes, 4);
            Cipher.Initialize(key, nonceBytes);
            var decryptedInnerPayload = Cipher.Decrypt(encryptedPayload);
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
                //Debug.WriteLine("\n\n###CLIENT");
                if (dataReceived == null)
                {
                    // step 1: send first init request from client
                    return SendInitializationRequest(_state);
                }
                else
                {
                    var state = (ClientState)_state;


                    if (state.Ratchets.Count == 0)
                    {
                        var nonce = BigEndianBitConverter.ToInt32(dataReceived);
                        var type = GetMessageType(nonce);
                        if (type == MessageType.InitializationResponse)
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
                //Debug.WriteLine("\n\n###SERVER");
                var state = (ServerState)_state;

                if (dataReceived == null) throw new InvalidOperationException("Only the client can send initialization without having received a response first");

                var nonce = BigEndianBitConverter.ToInt32(dataReceived);
                var type = GetMessageType(nonce);

                if (type == MessageType.InitializationRequest)
                {
                    // step 1: client init request
                    var (initializationNonce, remoteEcdhForInit, remotePublicKey) = ReceiveInitializationRequest(_state, dataReceived);
                    return SendInitializationResponse(_state, initializationNonce, remoteEcdhForInit);
                }
                else if (type == MessageType.NormalWithEcdh)
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
            //Debug.WriteLine($"\n\n###{(IsClient ? "CLIENT" : "SERVER")} RECEIVE");
            var state = State.Deserialize(SecureStorage.LoadAsync());

            if (state == null || state.Ratchets.IsEmpty)
            {
                throw new InvalidOperationException("The client has not been initialized.");
            }

            return DeconstructMessage(state, data);
        }

        public byte[] Send(byte[] payload)
        {
            //Debug.WriteLine($"\n\n###{(IsClient ? "CLIENT" : "SERVER")} SEND");
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

        private static MessageType GetMessageType(byte b) => (MessageType)((b & 0b1110_0000) >> 5);
        private static MessageType GetMessageType(int i) => (MessageType)((i & 0b11100000_00000000_00000000_00000000) >> 29);
        private static byte SetMessageType(byte b, MessageType type) => (byte)(b & 0b0001_1111 | ((int)type << 5));
        private static int SetMessageType(ref int i, MessageType type) => i & 0b00011111_11111111_11111111_11111111 | ((int)type << 29);
        private static byte ClearMessageType(byte b) => (byte)(b & 0b0001_1111);
        private static int ClearMessageType(int i) => i & 0b00011111_11111111_11111111_11111111;
    }
}
