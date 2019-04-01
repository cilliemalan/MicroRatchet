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
        public const int NonceSize = 4;
        public const int MacSize = 12;
        public const int EcdhSize = 32;
        public const int SignatureSize = 32;
        public const int MinimumMessageSize = 16;
        public const int MinimumOverhead = NonceSize + MacSize;
        public const int OverheadWithEcdh = MinimumOverhead + EcdhSize;
        public const int EncryptedMultipartHeaderOverhead = 6;

        IDigest Digest => Services.Digest;
        ISignature Signature => Services.Signature;
        IRandomNumberGenerator RandomNumberGenerator => Services.RandomNumberGenerator;
        IKeyAgreementFactory KeyAgreementFactory => Services.KeyAgreementFactory;
        IAesFactory AesFactory => Services.AesFactory;
        IKeyDerivation KeyDerivation;
        IVerifierFactory VerifierFactory => Services.VerifierFactory;
        IStorageProvider Storage => Services.Storage;

        private MultipartMessageReconstructor _multipart;
        private State _state;
        private List<(byte[], IAes)> _headerKeyCiphers = new List<(byte[], IAes)>();

        public IServices Services { get; }

        public MicroRatchetConfiguration Configuration { get; }

        public bool IsInitialized => LoadState().IsInitialized;
        public int MaximumMessageSize => Configuration.Mtu - MinimumOverhead;
        public int MaximumMessageSizeWithEcdh => Configuration.Mtu - OverheadWithEcdh;
        public int MultipartMessageSize => Configuration.Mtu - MinimumOverhead - EncryptedMultipartHeaderOverhead;
        public int MaxMultipartMessageTotalSize => MultipartMessageSize * 65536;
        public int InitRequestMessageSize => NonceSize + EcdhSize + EcdhSize + SignatureSize;
        public int InitResponseMessageSize => NonceSize * 2 + EcdhSize * 4 + SignatureSize + MacSize;

        public MicroRatchetClient(IServices services, MicroRatchetConfiguration config)
        {
            Services = services ?? throw new ArgumentNullException(nameof(services));
            Configuration = config ?? throw new ArgumentNullException(nameof(config));

            KeyDerivation = new AesKdf(Services.AesFactory);
            _multipart = new MultipartMessageReconstructor(MultipartMessageSize,
                config.MaximumBufferedPartialMessageSize,
                config.PartialMessageTimeout);

            CheckMtu();
        }

        public MicroRatchetClient(IServices services, bool isClient, int? Mtu = null)
        {
            Services = services ?? throw new ArgumentNullException(nameof(services));
            Configuration = new MicroRatchetConfiguration();
            Configuration.IsClient = isClient;
            if (Mtu.HasValue) Configuration.Mtu = Mtu.Value;
            KeyDerivation = new AesKdf(Services.AesFactory);
            _multipart = new MultipartMessageReconstructor(MultipartMessageSize,
                Configuration.MaximumBufferedPartialMessageSize,
                Configuration.PartialMessageTimeout);

            CheckMtu();
        }

        private void CheckMtu()
        {
            int mtu = Configuration.Mtu;
            if (!(LoadState()?.IsInitialized ?? false))
            {
                // minimum mtu is 52 bytes
                int maxInitMessageSize = (mtu - 1) * 4;
                if (InitResponseMessageSize > maxInitMessageSize) throw new InvalidOperationException("The MTU is not big enough to initialize the client");
            }

            // minimum mtu is 64 bytes
            if (mtu < OverheadWithEcdh + MinimumMessageSize) throw new InvalidOperationException("The MTU is not big enough to facilitate key exchange");
        }

        private IAes GetHeaderKeyCipher(byte[] key)
        {
            foreach (var hkc in _headerKeyCiphers)
            {
                if (hkc.Item1.Matches(key)) return hkc.Item2;
            }

            var cipher = AesFactory.GetAes(true, new ArraySegment<byte>(key));
            _headerKeyCiphers.Add((key, cipher));
            if (_headerKeyCiphers.Count > 3) _headerKeyCiphers.RemoveAt(0);
            return cipher;
        }

        private byte[] SendInitializationRequest(State state)
        {
            // message format:
            // nonce(4), pubkey(32), ecdh(32), signature(64) = 132 bytes

            if (!(state is ClientState clientState)) throw new InvalidOperationException("Only the client can send init request.");

            // 4 bytes nonce
            clientState.InitializationNonce = RandomNumberGenerator.Generate(NonceSize);
            clientState.InitializationNonce[0] = SetMessageType(clientState.InitializationNonce[0], MessageType.InitializationRequest);

            // get the public key
            var pubkey = Signature.PublicKey;

            // generate new ECDH keypair for init message and root key
            var clientEcdh = KeyAgreementFactory.GenerateNew();
            clientState.LocalEcdhForInit = clientEcdh;

            // nonce(4), pubkey(32), ecdh(32), signature(64)
            using (MemoryStream ms = new MemoryStream())
            {
                using (BinaryWriter bw = new BinaryWriter(ms))
                {
                    bw.Write(clientState.InitializationNonce);
                    bw.Write(pubkey);
                    bw.Write(clientEcdh.GetPublicKey());
                    ms.TryGetBuffer(out var msbuffer);
                    byte[] digest = Digest.ComputeDigest(msbuffer);
                    bw.Write(Signature.Sign(digest));

                    return ms.ToArray();
                }
            }
        }

        private (byte[] initializationNonce, byte[] remoteEcdhForInit) ReceiveInitializationRequest(State state, byte[] data)
        {
            if (!(state is ServerState serverState)) throw new InvalidOperationException("Only the server can receive an init request.");

            // nonce(4), pubkey(32), ecdh(32), signature(64)
            using (var ms = new MemoryStream(data))
            {
                using (var br = new BinaryReader(ms))
                {
                    // read stuff
                    var initializationNonce = br.ReadBytes(NonceSize);
                    var clientPublicKey = br.ReadBytes(EcdhSize);
                    var remoteEcdhForInit = br.ReadBytes(EcdhSize);

                    if (serverState.ClientPublicKey != null)
                    {
                        if (!serverState.ClientPublicKey.Matches(clientPublicKey))
                        {
                            throw new InvalidOperationException("The server was initialized before with a different public key");
                        }
                        else
                        {
                            // the client wants to reinitialize. Reset state.
                            serverState.RootKey = null;
                            serverState.FirstSendHeaderKey = null;
                            serverState.FirstReceiveHeaderKey = null;
                            serverState.LocalEcdhRatchetStep0 = null;
                            serverState.LocalEcdhRatchetStep1 = null;
                            serverState.Ratchets.Clear();
                        }
                    }

                    serverState.ClientPublicKey = clientPublicKey;
                    var verifier = VerifierFactory.Create(new ArraySegment<byte>(clientPublicKey));

                    if (!verifier.VerifySignedMessage(Digest, new ArraySegment<byte>(data)))
                    {
                        throw new InvalidOperationException("The signature was invalid");
                    }

                    return (initializationNonce, remoteEcdhForInit);
                }
            }
        }

        private byte[] SendInitializationResponse(State state, byte[] initializationNonce, byte[] remoteEcdhForInit)
        {
            // message format:
            // new nonce(4), ecdh pubkey(32),
            // <nonce from init request(4), server pubkey(32), 
            // new ecdh pubkey(32) x2, signature(64)>, mac(12) = 212 bytes

            if (!(state is ServerState serverState)) throw new InvalidOperationException("Only the server can send init response.");

            // generate a nonce and new ecdh parms
            var serverNonce = RandomNumberGenerator.Generate(NonceSize);
            serverNonce[0] = SetMessageType(serverNonce[0], MessageType.InitializationResponse);
            serverState.NextInitializationNonce = serverNonce;
            var rootPreEcdh = KeyAgreementFactory.GenerateNew();
            var rootPreEcdhPubkey = rootPreEcdh.GetPublicKey();

            // generate server ECDH for root key and root key
            var rootPreKey = rootPreEcdh.DeriveKey(new ArraySegment<byte>(remoteEcdhForInit));
            var genKeys = KeyDerivation.GenerateKeys(new ArraySegment<byte>(rootPreKey), new ArraySegment<byte>(serverNonce), 3, 32);
            serverState.RootKey = genKeys[0];
            serverState.FirstSendHeaderKey = genKeys[1];
            serverState.FirstReceiveHeaderKey = genKeys[2];

            // generate two server ECDH. One for ratchet 0 sending key and one for the next
            // this is enough for the server to generate a receiving chain key and sending
            // chain key as soon as the client sends a sending chain key
            var serverEcdhRatchet0 = KeyAgreementFactory.GenerateNew();
            serverState.LocalEcdhRatchetStep0 = serverEcdhRatchet0;
            var serverEcdhRatchet1 = KeyAgreementFactory.GenerateNew();
            serverState.LocalEcdhRatchetStep1 = serverEcdhRatchet1;

            using (MemoryStream messageStream = new MemoryStream())
            {
                using (BinaryWriter messageWriter = new BinaryWriter(messageStream))
                {
                    messageWriter.Write(serverNonce);
                    messageWriter.Write(rootPreEcdhPubkey);

                    // create the payload
                    byte[] payload;
                    using (MemoryStream payloadStream = new MemoryStream())
                    {
                        using (BinaryWriter payloadWriter = new BinaryWriter(payloadStream))
                        {
                            payloadWriter.Write(initializationNonce);
                            payloadWriter.Write(Signature.PublicKey);
                            payloadWriter.Write(serverEcdhRatchet0.GetPublicKey());
                            payloadWriter.Write(serverEcdhRatchet1.GetPublicKey());

                            // sign the message
                            payloadStream.TryGetBuffer(out var buffer);
                            byte[] digest = Digest.ComputeDigest(buffer);
                            payloadWriter.Write(Signature.Sign(digest));
                            payload = payloadStream.ToArray();
                        }
                    }

                    // encrypt the payload
                    AesCtrMode cipher = new AesCtrMode(AesFactory.GetAes(true, new ArraySegment<byte>(rootPreKey)), serverNonce);
                    var encryptedPayload = cipher.Process(new ArraySegment<byte>(payload));

                    // calculate mac
                    var Mac = new Poly(AesFactory);
                    Mac.Init(new ArraySegment<byte>(rootPreKey), new ArraySegment<byte>(serverNonce), MacSize * 8);
                    messageStream.TryGetBuffer(out var messageStreamBuffer);
                    Mac.Process(messageStreamBuffer);
                    Mac.Process(new ArraySegment<byte>(encryptedPayload));
                    var mac = Mac.Compute();

                    // write the encrypted payload
                    messageWriter.Write(encryptedPayload);

                    // write mac
                    messageWriter.Write(mac);

                    return messageStream.ToArray();
                }
            }
        }

        private void ReceiveInitializationResponse(State state, byte[] data)
        {
            if (!(state is ClientState clientState)) throw new InvalidOperationException("Only the client can receive an init response.");

            // new nonce(4), ecdh pubkey(32), <nonce(4), server pubkey(32), 
            // new ecdh pubkey(32) x2, signature(64)>, mac(12)
            using (var ms = new MemoryStream(data))
            {
                using (var br = new BinaryReader(ms))
                {
                    // decrypt
                    var nonce = br.ReadBytes(NonceSize);
                    var rootEcdhKey = br.ReadBytes(EcdhSize);
                    IKeyAgreement rootEcdh = clientState.LocalEcdhForInit;
                    var rootPreKey = rootEcdh.DeriveKey(new ArraySegment<byte>(rootEcdhKey));
                    AesCtrMode cipher = new AesCtrMode(AesFactory.GetAes(true, new ArraySegment<byte>(rootPreKey)), nonce);
                    var payload = cipher.Process(new ArraySegment<byte>(
                        data,
                        EcdhSize + NonceSize,
                        data.Length - EcdhSize - NonceSize - MacSize));

                    // check mac
                    var Mac = new Poly(AesFactory);
                    br.BaseStream.Seek(data.Length - MacSize, SeekOrigin.Begin);
                    var mac = br.ReadBytes(MacSize);
                    Mac.Init(new ArraySegment<byte>(rootPreKey), new ArraySegment<byte>(nonce), MacSize * 8);
                    Mac.Process(new ArraySegment<byte>(data, 0, data.Length - MacSize));
                    var checkMac = Mac.Compute();

                    if (!mac.Matches(checkMac))
                    {
                        throw new InvalidOperationException("Could not decript payload");
                    }

                    using (var msp = new MemoryStream(payload))
                    {
                        using (var brp = new BinaryReader(msp))
                        {
                            var oldNonce = brp.ReadBytes(NonceSize);
                            var serverPubKey = brp.ReadBytes(EcdhSize);
                            var remoteRatchetEcdh0 = brp.ReadBytes(EcdhSize);
                            var remoteRatchetEcdh1 = brp.ReadBytes(EcdhSize);
                            var signature = brp.ReadBytes(64);

                            if (!oldNonce.Matches(clientState.InitializationNonce))
                            {
                                throw new InvalidOperationException("Nonce did not match");
                            }

                            var verifier = VerifierFactory.Create(new ArraySegment<byte>(serverPubKey));
                            if (!verifier.VerifySignedMessage(Digest, new ArraySegment<byte>(payload)))
                            {
                                throw new InvalidOperationException("The signature was invalid");
                            }

                            // store the new nonce we got from the server
                            clientState.InitializationNonce = nonce;
                            Log.Verbose($"storing iniitlizaionta nonce: {Log.ShowBytes(nonce)}");

                            // we now have enough information to construct our double ratchet
                            var localStep0EcdhRatchet = KeyAgreementFactory.GenerateNew();
                            var localStep1EcdhRatchet = KeyAgreementFactory.GenerateNew();

                            // initialize client root key and ecdh ratchet
                            var genKeys = KeyDerivation.GenerateKeys(new ArraySegment<byte>(rootPreKey), new ArraySegment<byte>(nonce), 3, 32);
                            var rootKey = genKeys[0];
                            var receiveHeaderKey = genKeys[1];
                            var sendHeaderKey = genKeys[2];

                            clientState.Ratchets.Add(EcdhRatchetStep.InitializeClient(KeyDerivation, rootKey,
                                remoteRatchetEcdh0, remoteRatchetEcdh1, localStep0EcdhRatchet,
                                receiveHeaderKey, sendHeaderKey,
                                localStep1EcdhRatchet));

                            clientState.LocalEcdhForInit = null;
                        }
                    }
                }
            }
        }

        private byte[] SendFirstClientMessage(State state)
        {
            if (!(state is ClientState clientState)) throw new InvalidOperationException("Only the client can send the first client message.");

            return ConstructMessage(clientState, clientState.InitializationNonce, true, true, clientState.Ratchets.SecondToLast, MessageType.InitializationWithEcdh);
        }

        private void ReceiveFirstMessage(State state, byte[] payload)
        {
            if (!(state is ServerState serverState)) throw new InvalidOperationException("Only the server can receive the first client message.");

            var messageType = GetMessageType(payload[0]);
            if (messageType != MessageType.InitializationWithEcdh)
            {
                throw new InvalidOperationException("The message had an unexpected message type");
            }

            // extract the nonce
            byte[] nonce = new byte[NonceSize];
            Array.Copy(payload, nonce, nonce.Length);

            // extract other parts
            var messageSize = payload.Length;
            var headerSize = NonceSize + EcdhSize;
            var payloadSize = messageSize - MacSize - headerSize;
            byte[] encryptedPayload = new byte[payloadSize];
            byte[] encryptedHeader = new byte[headerSize];
            byte[] mac = new byte[MacSize];
            Array.Copy(payload, 0, encryptedHeader, 0, headerSize);
            Array.Copy(payload, headerSize, encryptedPayload, 0, payloadSize);
            Array.Copy(payload, headerSize + payloadSize, mac, 0, MacSize);

            // check the mac
            var Mac = new Poly(AesFactory);
            byte[] headerKey = serverState.FirstReceiveHeaderKey;
            Mac.Init(new ArraySegment<byte>(headerKey), new ArraySegment<byte>(nonce), MacSize * 8);
            Mac.Process(new ArraySegment<byte>(payload, 0, payload.Length - MacSize));
            byte[] compareMac = Mac.Compute();
            if (!mac.Matches(compareMac))
            {
                throw new InvalidOperationException("The first received message authentication code did not match");
            }

            // decrypt the header
            AesCtrMode hcipher = new AesCtrMode(GetHeaderKeyCipher(headerKey), encryptedPayload);
            var decryptedHeader = hcipher.Process(new ArraySegment<byte>(payload, 0, headerSize));
            decryptedHeader[0] = ClearMessageType(decryptedHeader[0]);
            int step = BigEndianBitConverter.ToInt32(decryptedHeader);

            // the message contains ecdh parameters
            var clientEcdhPublic = new byte[EcdhSize];
            Array.Copy(decryptedHeader, NonceSize, clientEcdhPublic, 0, EcdhSize);

            // initialize the ecdh ratchet
            var ratchetUsed = EcdhRatchetStep.InitializeServer(KeyDerivation,
                serverState.LocalEcdhRatchetStep0,
                serverState.RootKey, clientEcdhPublic,
                serverState.LocalEcdhRatchetStep1,
                serverState.FirstReceiveHeaderKey,
                serverState.FirstSendHeaderKey);
            serverState.Ratchets.Add(ratchetUsed);

            // get the inner payload key from the server receive chain
            var (key, nr) = ratchetUsed.ReceivingChain.RatchetForReceiving(KeyDerivation, step);

            // decrypt the inner payload
            var nonceBytes = new byte[NonceSize];
            Array.Copy(decryptedHeader, nonceBytes, NonceSize);
            AesCtrMode icipher = new AesCtrMode(AesFactory.GetAes(true, new ArraySegment<byte>(key)), nonceBytes);
            var decryptedInnerPayload = icipher.Process(new ArraySegment<byte>(encryptedPayload));

            // check the inner payload
            var innerNonce = new byte[NonceSize];
            Array.Copy(decryptedInnerPayload, innerNonce, NonceSize);
            if (!innerNonce.Matches(serverState.NextInitializationNonce))
            {
                throw new InvalidOperationException("The inner encrypted nonce did not match the initialization nonce.");
            }

            serverState.FirstSendHeaderKey = null;
            serverState.FirstReceiveHeaderKey = null;
            serverState.LocalEcdhRatchetStep0 = null;
            serverState.LocalEcdhRatchetStep1 = null;
            serverState.RootKey = null;
        }

        private byte[] SendFirstResponse(State state)
        {
            if (!(state is ServerState serverState)) throw new InvalidOperationException("Only the server can send the first response.");

            var payload = serverState.NextInitializationNonce;
            serverState.NextInitializationNonce = null;
            return ConstructMessage(serverState, payload, true, false, serverState.Ratchets.Last, MessageType.InitializationWithoutEcdh);
        }

        private void ReceiveFirstResponse(State state, byte[] data)
        {
            if (!(state is ClientState clientState)) throw new InvalidOperationException("Only the client can receive the first response.");

            var contents = DeconstructMessage(clientState, data, MessageType.InitializationWithoutEcdh, false);
            if (contents == null || contents.Length < 32)
            {
                throw new InvalidOperationException("The first response from the server was not valid");
            }

            var nonce = new byte[NonceSize];
            Array.Copy(contents, nonce, NonceSize);
            if (!nonce.Matches(clientState.InitializationNonce))
            {
                throw new InvalidOperationException("The first response from the server did not contain the correct nonce");
            }

            clientState.InitializationNonce = null;
        }

        private byte[] ConstructMessage(State state, byte[] message, bool pad, bool includeEcdh, EcdhRatchetStep step, MessageType? overrideMessageType = null)
        {
            // message format:
            // <nonce (4)>, <payload, padding>, mac(12)
            // <nonce (4), ecdh (32)>, <payload, padding>, mac(12)

            int mtu = Configuration.Mtu;

            // get the payload key and nonce
            var (payloadKey, messageNumber) = step.SendingChain.RatchetForSending(KeyDerivation);
            var nonce = BigEndianBitConverter.GetBytes(messageNumber);
            var messageType = overrideMessageType ?? (includeEcdh ? MessageType.NormalWithEcdh : MessageType.Normal);

            // calculate some sizes
            var headerSize = NonceSize + (includeEcdh ? EcdhSize : 0);
            var overhead = headerSize + MacSize;
            var messageSize = message.Length;
            var maxMessageSize = mtu - overhead;

            // build the payload: <payload, padding>
            byte[] payload;
            if (pad && messageSize < maxMessageSize)
            {
                payload = new byte[mtu - overhead];
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
            AesCtrMode icipher = new AesCtrMode(AesFactory.GetAes(true, new ArraySegment<byte>(payloadKey)), nonce);
            var encryptedPayload = icipher.Process(new ArraySegment<byte>(payload));

            // build the header: <nonce(4), ecdh(32)?>
            byte[] header = new byte[headerSize];
            Array.Copy(nonce, header, NonceSize);
            if (includeEcdh)
            {
                // this is the hottest line in the send process
                var ratchetPublicKey = step.GetPublicKey(KeyAgreementFactory);
                Array.Copy(ratchetPublicKey, 0, header, nonce.Length, ratchetPublicKey.Length);
            }

            // encrypt the header. Generate 32 kdf bytes. The first (keysize) is the header encryption key and the whole
            // 32 bytes is the MAC key.
            AesCtrMode hcipher = new AesCtrMode(GetHeaderKeyCipher(step.SendingChain.HeaderKey), encryptedPayload);
            var encryptedHeader = hcipher.Process(new ArraySegment<byte>(header));

            // set the message type (we can do this because we're using a stream cipher)
            encryptedHeader[0] = SetMessageType(encryptedHeader[0], messageType);

            // mac the message: <header>, <payload>, mac(12)
            // the mac uses the header encryption derived key (all 32 bytes)
            var Mac = new Poly(AesFactory);
            var encryptedNonce = new byte[4];
            Array.Copy(encryptedHeader, encryptedNonce, 4);
            Mac.Init(new ArraySegment<byte>(step.SendingChain.HeaderKey), new ArraySegment<byte>(encryptedNonce), MacSize * 8);
            Mac.Process(new ArraySegment<byte>(encryptedHeader));
            Mac.Process(new ArraySegment<byte>(encryptedPayload));
            var mac = Mac.Compute();

            // construct the resulting message
            byte[] result = new byte[encryptedHeader.Length + encryptedPayload.Length + mac.Length];
            Array.Copy(encryptedHeader, 0, result, 0, encryptedHeader.Length);
            Array.Copy(encryptedPayload, 0, result, encryptedHeader.Length, encryptedPayload.Length);
            Array.Copy(mac, 0, result, encryptedHeader.Length + encryptedPayload.Length, mac.Length);
            return result;
        }

        private byte[] DeconstructMessage(State state, byte[] payload, MessageType? expectedMessageType = null, bool? overrideHasEcdh = null)
        {
            var messageType = GetMessageType(payload[0]);
            if (expectedMessageType.HasValue)
            {
                if (expectedMessageType.Value != messageType)
                {
                    throw new InvalidOperationException("The message had an unexpected message type");
                }
            }
            else if (messageType != MessageType.Normal && messageType != MessageType.NormalWithEcdh)
            {
                throw new InvalidOperationException("The message had an unexpected message type");
            }

            bool hasEcdh = overrideHasEcdh ?? (messageType == MessageType.NormalWithEcdh);

            // extract the nonce
            byte[] nonce = new byte[NonceSize];
            Array.Copy(payload, nonce, nonce.Length);

            // extract other parts
            var messageSize = payload.Length;
            var headerSize = hasEcdh ? NonceSize + EcdhSize : NonceSize;
            var payloadSize = messageSize - MacSize - headerSize;
            byte[] encryptedPayload = new byte[payloadSize];
            byte[] encryptedHeader = new byte[headerSize];
            byte[] mac = new byte[MacSize];
            Array.Copy(payload, 0, encryptedHeader, 0, headerSize);
            Array.Copy(payload, headerSize, encryptedPayload, 0, payloadSize);
            Array.Copy(payload, headerSize + payloadSize, mac, 0, MacSize);

            // find the header key by checking the mac
            var Mac = new Poly(AesFactory);
            byte[] headerKey = null;
            EcdhRatchetStep ratchetUsed = null;
            bool usedNextHeaderKey = false;
            int cnt = 0;
            foreach (var ratchet in state.Ratchets.Enumerate())
            {
                cnt++;
                headerKey = ratchet.ReceivingChain.HeaderKey;
                Mac.Init(new ArraySegment<byte>(headerKey), new ArraySegment<byte>(nonce), MacSize * 8);
                Mac.Process(new ArraySegment<byte>(payload, 0, payload.Length - MacSize));
                byte[] compareMac = Mac.Compute();
                if (mac.Matches(compareMac))
                {
                    ratchetUsed = ratchet;
                    break;
                }
                else if (ratchet.ReceivingChain.NextHeaderKey != null)
                {
                    headerKey = ratchet.ReceivingChain.NextHeaderKey;
                    Mac.Init(new ArraySegment<byte>(headerKey), new ArraySegment<byte>(nonce), MacSize * 8);
                    Mac.Process(new ArraySegment<byte>(payload, 0, payload.Length - MacSize));
                    compareMac = Mac.Compute();
                    if (mac.Matches(compareMac))
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

            // decrypt the header
            AesCtrMode hcipher = new AesCtrMode(GetHeaderKeyCipher(headerKey), encryptedPayload);
            var decryptedHeader = hcipher.Process(new ArraySegment<byte>(payload, 0, headerSize));
            decryptedHeader[0] = ClearMessageType(decryptedHeader[0]);
            int step = BigEndianBitConverter.ToInt32(decryptedHeader);

            if (hasEcdh)
            {
                // the message contains ecdh parameters
                var clientEcdhPublic = new byte[EcdhSize];
                Array.Copy(decryptedHeader, NonceSize, clientEcdhPublic, 0, EcdhSize);

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
            var (key, nr) = ratchetUsed.ReceivingChain.RatchetForReceiving(KeyDerivation, step);

            // decrypt the inner payload
            var nonceBytes = new byte[NonceSize];
            Array.Copy(decryptedHeader, nonceBytes, NonceSize);
            AesCtrMode icipher = new AesCtrMode(AesFactory.GetAes(true, new ArraySegment<byte>(key)), nonceBytes);
            var decryptedInnerPayload = icipher.Process(new ArraySegment<byte>(encryptedPayload));
            return decryptedInnerPayload;
        }

        private byte[][] ConstructUnencryptedMultipartMessage(byte[] allData)
        {
            // unencrypted multipart message:
            // type (4 bits), num (2 bits), total (2 bits), data (until MTU)


            var chunkSize = Configuration.Mtu - 1;
            var numChunks = allData.Length / chunkSize;
            if (allData.Length % Configuration.Mtu != 0) numChunks++;

            if (numChunks > 4) throw new InvalidOperationException("Cannot create an unencrypted multipart message with more than 4 parts");

            int amt = 0;
            byte[][] chunks = new byte[numChunks][];
            for (int i = 0; i < numChunks; i++)
            {
                byte firstByte = (byte)(((int)MessageType.MultiPartMessageUnencrypted << 5) |
                    i << 2 | (numChunks - 1));

                var left = allData.Length - amt;
                int thisChunkSize = left > chunkSize ? chunkSize : left;
                chunks[i] = new byte[thisChunkSize + 1];
                chunks[i][0] = firstByte;
                Array.Copy(allData, amt, chunks[i], 1, thisChunkSize);
                amt += thisChunkSize;
            }

            return chunks;
        }

        private (byte[] payload, int num, int total) DeconstructUnencryptedMultipartMessagePart(byte[] data)
        {
            var messageType = GetMessageType(data[0]);
            if (messageType != MessageType.MultiPartMessageUnencrypted)
            {
                throw new InvalidOperationException("Cannot deconstrct non-multipart message");
            }

            int num = (data[0] & 0b0000_1100) >> 2;
            int tot = (data[0] & 0b0000_0011) + 1;
            byte[] payload = new byte[data.Length - 1];
            Array.Copy(data, 1, payload, 0, payload.Length);
            return (payload, num, tot);
        }

        private byte[] ProcessInitializationInternal(State state, byte[] dataReceived)
        {
            byte[] sendback;
            if (Configuration.IsClient)
            {
                if (dataReceived == null)
                {
                    // step 1: send first init request from client
                    sendback = SendInitializationRequest(state);
                }
                else
                {
                    var clientState = (ClientState)state;
                    var type = GetMessageType(dataReceived[0]);

                    if (clientState.Ratchets.Count == 0)
                    {
                        if (type == MessageType.InitializationResponse)
                        {
                            // step 2: init response from server
                            ReceiveInitializationResponse(clientState, dataReceived);
                            sendback = SendFirstClientMessage(clientState);
                        }
                        else
                        {
                            throw new InvalidOperationException("Expected an initialization response but got something else.");
                        }
                    }
                    else if (type == MessageType.InitializationWithoutEcdh)
                    {
                        // step 3: receive first message from server
                        ReceiveFirstResponse(clientState, dataReceived);
                        // initialization completed successfully.
                        sendback = null;
                    }
                    else
                    {
                        throw new InvalidOperationException("Unexpected message received during client initialization");
                    }
                }
            }
            else
            {
                Log.Verbose("\n\n###SERVER");
                var serverState = (ServerState)state;

                if (dataReceived == null) throw new InvalidOperationException("Only the client can send initialization without having received a response first");

                var type = GetMessageType(dataReceived[0]);

                if (type == MessageType.InitializationRequest)
                {
                    // step 1: client init request
                    var (initializationNonce, remoteEcdhForInit) = ReceiveInitializationRequest(serverState, dataReceived);
                    sendback = SendInitializationResponse(serverState, initializationNonce, remoteEcdhForInit);
                }
                else if (type == MessageType.InitializationWithEcdh)
                {
                    // step 2: first message from client
                    ReceiveFirstMessage(serverState, dataReceived);
                    sendback = SendFirstResponse(serverState);
                }
                else
                {
                    throw new InvalidOperationException("Unexpected message received during server initialization");
                }
            }

            return sendback;
        }

        private MessageInfo ProcessInitialization(State state, byte[] dataReceived)
        {
            byte[] sendback = ProcessInitializationInternal(state, dataReceived);

            if (sendback != null)
            {
                if (sendback.Length > Configuration.Mtu)
                {
                    return new MessageInfo { Messages = ConstructUnencryptedMultipartMessage(sendback) };
                }
                else
                {
                    return new MessageInfo { Messages = new[] { sendback } };
                }
            }
            else
            {
                return null;
            }
        }

        private MessageInfo SendSingle(State state, byte[] payload, bool pad)
        {
            bool canIncludeEcdh = payload.Length <= Configuration.Mtu - 48;
            EcdhRatchetStep step;
            if (canIncludeEcdh)
            {
                step = state.Ratchets.Last;
            }
            else
            {
                step = state.Ratchets.SecondToLast;
            }

            return new MessageInfo
            {
                Messages = new[] { ConstructMessage(state, payload, pad, canIncludeEcdh, step) }
            };
        }

        private MessageInfo SendInternal(byte[] payload, State state, bool pad)
        {
            if (payload.Length <= MaximumMessageSize)
            {
                return SendSingle(state, payload, pad);
            }
            else
            {
                throw new InvalidOperationException($"Payload is too big. Maximum payload is {MaximumMessageSize}");
            }
        }

        private State LoadState()
        {
            if (_state == null)
            {
                _state = Configuration.IsClient
                    ? (State)ClientState.Load(Storage, KeyAgreementFactory, 32)
                    : ServerState.Load(Storage, KeyAgreementFactory, 32);
            }
            return _state;
        }

        private State InitializeState()
        {
            _state = State.Initialize(Configuration.IsClient, 32);
            return _state;
        }

        private static MessageType GetMessageType(byte b) => (MessageType)((b & 0b1110_0000) >> 5);
        private static MessageType GetMessageType(int i) => (MessageType)((i & 0b11100000_00000000_00000000_00000000) >> 29);
        private static byte SetMessageType(byte b, MessageType type) => (byte)(b & 0b0001_1111 | ((int)type << 5));
        private static int SetMessageType(ref int i, MessageType type) => i & 0b00011111_11111111_11111111_11111111 | ((int)type << 29);
        private static byte ClearMessageType(byte b) => (byte)(b & 0b0001_1111);
        private static int ClearMessageType(int i) => i & 0b00011111_11111111_11111111_11111111;
        private static bool IsInitializationMessge(MessageType messageType) => messageType == MessageType.InitializationRequest || messageType == MessageType.InitializationResponse;
        private static bool IsNormalMessage(MessageType messageType) => messageType == MessageType.Normal || messageType == MessageType.NormalWithEcdh;
        private static bool IsMultipartMessage(MessageType messageType) => messageType == MessageType.MultiPartMessageUnencrypted;

        private int MaximumSingleMessageSize => Configuration.Mtu - MinimumOverhead;
        private int MaximumSingleMessageSizeWithEcdh => Configuration.Mtu - OverheadWithEcdh;
        private int MaximumMultipartMessageSize => (Configuration.Mtu - OverheadWithEcdh) * 65536;
        private int MaximumUnencryptedMultipartMessageSize => (Configuration.Mtu - 1) * 4;

        public MessageInfo InitiateInitialization(bool forceReinitialization = false)
        {
            var state = LoadState();

            if (state != null && state.IsInitialized && !forceReinitialization)
            {
                throw new InvalidOperationException("The client is already initialized");
            }

            if (!Configuration.IsClient)
            {
                throw new InvalidOperationException("only a client can initiate initialization");
            }

            state = InitializeState();

            return ProcessInitialization(state, null);
        }

        private ReceiveResult ReceiveInternal(byte[] data)
        {
            var state = LoadState();
            var messageType = GetMessageType(data[0]);
            var isClient = Configuration.IsClient;
            var isInitialized = state?.IsInitialized ?? false;

            if (IsInitializationMessge(messageType))
            {
                if (isClient && isInitialized)
                {
                    throw new InvalidOperationException("Received initialization message after initialization has been completed");
                }

                if (state == null)
                {
                    state = InitializeState();
                }
                var toSendBack = ProcessInitialization(state, data);

                return new ReceiveResult
                {
                    Payload = null,
                    ReceivedDataType = ReceivedDataType.InitializationWithResponse,
                    ToSendBack = toSendBack
                };
            }
            else if (messageType == MessageType.MultiPartMessageUnencrypted)
            {
                if (isClient && isInitialized)
                {
                    throw new InvalidOperationException("Received initialization message after initialization has been completed");
                }

                var (payload, num, total) = DeconstructUnencryptedMultipartMessagePart(data);
                var output = _multipart.Ingest(payload, 0, num, total); //seq = 0 is for initialization
                if (output != null)
                {
                    var innerMessageType = GetMessageType(output[0]);
                    if (!IsInitializationMessge(innerMessageType))
                    {
                        throw new InvalidOperationException("Only initialization can be used for unencrypted multipart messages");
                    }
                    var r2 = Receive(output);
                    return new ReceiveResult
                    {
                        MessageNumber = num,
                        MultipartSequence = 0,
                        TotalMessages = total,
                        Payload = r2.Payload,
                        ReceivedDataType = r2.ReceivedDataType,
                        ToSendBack = r2.ToSendBack
                    };
                }
                else
                {
                    return new ReceiveResult
                    {
                        MultipartSequence = 0,
                        MessageNumber = num,
                        TotalMessages = total,
                        Payload = payload,
                        ReceivedDataType = ReceivedDataType.Partial,
                        ToSendBack = null
                    };
                }
            }
            else
            {
                _multipart.Tick();
                if (IsNormalMessage(messageType))
                {
                    return new ReceiveResult
                    {
                        Payload = DeconstructMessage(state, data),
                        ToSendBack = null,
                        ReceivedDataType = ReceivedDataType.Normal
                    };
                }
                else if (IsMultipartMessage(messageType))
                {
                    if (messageType == MessageType.MultiPartMessageUnencrypted)
                    {
                        throw new NotImplementedException();
                    }
                }
            }

            throw new NotSupportedException("Unexpected message type received");
        }

        public ReceiveResult Receive(byte[] data)
        {
            Log.Verbose($"\n\n###{(Configuration.IsClient ? "CLIENT" : "SERVER")} RECEIVE");
            var result = ReceiveInternal(data);
            Log.Verbose($"/###{(Configuration.IsClient ? "CLIENT" : "SERVER")} RECEIVE");
            return result;
        }

        public MessageInfo Send(byte[] payload, bool pad = false)
        {
            Log.Verbose($"\n\n###{(Configuration.IsClient ? "CLIENT" : "SERVER")} SEND");
            var state = LoadState();
            if (!state.IsInitialized)
            {
                throw new InvalidOperationException("The client has not been initialized.");
            }

            if (pad == false && payload.Length < MinimumMessageSize)
            {
                throw new InvalidOperationException("The payload is too small for an unpadded message");
            }

            var response = SendInternal(payload, state, pad);
            Log.Verbose($"###/{(Configuration.IsClient ? "CLIENT" : "SERVER")} SEND");
            return response;
        }

        public void SaveState()
        {
            if (_state != null)
            {
                _state.Store(Storage, Configuration.NumberOfRatchetsToKeep, Configuration.MaxLostKeys);
            }
            else
            {
                var storage = Storage.LockCold();
                var bytes = new byte[storage.Length];
                storage.Write(bytes, 0, bytes.Length);
            }
        }
    }
}
