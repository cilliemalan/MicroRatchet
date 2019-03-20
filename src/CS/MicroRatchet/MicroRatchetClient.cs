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
        public const int MinimumOverhead = NonceSize + MacSize;
        public const int OverheadWithEcdh = MinimumOverhead + EcdhSize;
        public const int EncryptedMultipartHeaderOverhead = 6;

        IDigest Digest => Services.Digest;
        ISignature Signature => Services.Signature;
        IRandomNumberGenerator RandomNumberGenerator => Services.RandomNumberGenerator;
        IKeyAgreementFactory KeyAgreementFactory => Services.KeyAgreementFactory;
        ICipher Cipher => Services.Cipher;
        IKeyDerivation KeyDerivation;
        IVerifierFactory VerifierFactory => Services.VerifierFactory;
        IMac Mac => Services.Mac;
        IStorageProvider Storage => Services.Storage;

        private MultipartMessageReconstructor _multipart;

        private State _state;

        public IServices Services { get; }

        public MicroRatchetConfiguration Configuration { get; }
        public bool IsInitialized => LoadState().IsInitialized;

        public int MaximumMessageSize => Configuration.Mtu - MinimumOverhead;
        public int MaximumMessageSizeWithEcdh => Configuration.Mtu - OverheadWithEcdh;
        public int MultipartMessageSize => Configuration.Mtu - MinimumOverhead - EncryptedMultipartHeaderOverhead;

        public MicroRatchetClient(IServices services, MicroRatchetConfiguration config)
        {
            Services = services ?? throw new ArgumentNullException(nameof(services));
            Configuration = config ?? throw new ArgumentNullException(nameof(config));
            KeyDerivation = new KeyDerivation(Services.Digest);
            _multipart = new MultipartMessageReconstructor(MultipartMessageSize,
                config.MaximumBufferedPartialMessageSize,
                config.PartialMessageTimeout);
        }

        public MicroRatchetClient(IServices services, bool isClient, int? Mtu = null)
        {
            Services = services ?? throw new ArgumentNullException(nameof(services));
            Configuration = new MicroRatchetConfiguration();
            Configuration.IsClient = isClient;
            if (Mtu.HasValue) Configuration.Mtu = Mtu.Value;
            KeyDerivation = new KeyDerivation(Services.Digest);
            _multipart = new MultipartMessageReconstructor(MultipartMessageSize,
                Configuration.MaximumBufferedPartialMessageSize,
                Configuration.PartialMessageTimeout);
        }

        private byte[] SendInitializationRequest(State _state)
        {
            // message format:
            // nonce(4), pubkey(32), ecdh(32), signature(64) = 132 bytes

            if (!(_state is ClientState state)) throw new InvalidOperationException("Only the client can send init request.");

            // 4 bytes nonce
            state.InitializationNonce = RandomNumberGenerator.Generate(NonceSize);
            state.InitializationNonce[0] = SetMessageType(state.InitializationNonce[0], MessageType.InitializationRequest);

            // get the public key
            var pubkey = Signature.PublicKey;

            // generate new ECDH keypair for init message and root key
            var clientEcdh = KeyAgreementFactory.GenerateNew();
            state.LocalEcdhForInit = clientEcdh;

            // nonce(4), pubkey(32), ecdh(32), signature(64)
            using (MemoryStream ms = new MemoryStream())
            {
                using (BinaryWriter bw = new BinaryWriter(ms))
                {
                    bw.Write(state.InitializationNonce);
                    bw.Write(pubkey);
                    bw.Write(clientEcdh.GetPublicKey());
                    ms.TryGetBuffer(out var msbuffer);
                    byte[] digest = Digest.ComputeDigest(msbuffer);
                    bw.Write(Signature.Sign(digest));

                    if (ms.Length > Configuration.Mtu) throw new InvalidOperationException("The MTU was too small to create the message");
                    return ms.ToArray();
                }
            }
        }

        private (byte[] initializationNonce, byte[] remoteEcdhForInit, byte[] remotePublicKey) ReceiveInitializationRequest(State _state, byte[] data)
        {
            if (!(_state is ServerState state)) throw new InvalidOperationException("Only the server can receive an init request.");

            // nonce(4), pubkey(32), ecdh(32), signature(64)
            using (var ms = new MemoryStream(data))
            {
                using (var br = new BinaryReader(ms))
                {
                    // read stuff
                    var initializationNonce = br.ReadBytes(NonceSize);
                    var remotePublicKey = br.ReadBytes(EcdhSize);
                    var remoteEcdhForInit = br.ReadBytes(EcdhSize);

                    var verifier = VerifierFactory.Create(remotePublicKey);
                    if (!verifier.VerifySignedMessage(Digest, data))
                    {
                        throw new InvalidOperationException("The signature was invalid");
                    }

                    return (initializationNonce, remoteEcdhForInit, remotePublicKey);
                }
            }
        }

        private byte[] SendInitializationResponse(State _state, byte[] initializationNonce, byte[] remoteEcdhForInit)
        {
            // message format:
            // new nonce(4), ecdh pubkey(32),
            // <nonce from init request(4), server pubkey(32), 
            // new ecdh pubkey(32) x2, signature(64)>, mac(12) = 212 bytes

            if (!(_state is ServerState state)) throw new InvalidOperationException("Only the server can send init response.");
            var keySize = Configuration.UseAes256 ? 32 : 16;

            // generate a nonce and new ecdh parms
            var serverNonce = RandomNumberGenerator.Generate(NonceSize);
            serverNonce[0] = SetMessageType(serverNonce[0], MessageType.InitializationResponse);
            state.NextInitializationNonce = serverNonce;
            var rootPreEcdh = KeyAgreementFactory.GenerateNew();
            var rootPreEcdhPubkey = rootPreEcdh.GetPublicKey();
            var sharedSecret = rootPreEcdh.DeriveKey(remoteEcdhForInit);

            // generate server ECDH for root key and root key
            var rootPreKey = rootPreEcdh.DeriveKey(remoteEcdhForInit);
            var genKeys = KeyDerivation.GenerateKeys(rootPreKey, null, 3, keySize);
            state.RootKey = genKeys[0];
            state.FirstSendHeaderKey = genKeys[1];
            state.FirstReceiveHeaderKey = genKeys[2];

            // generate two server ECDH. One for ratchet 0 sending key and one for the next
            // this is enough for the server to generate a receiving chain key and sending
            // chain key as soon as the client sends a sending chain key
            var serverEcdhRatchet0 = KeyAgreementFactory.GenerateNew();
            state.LocalEcdhRatchetStep0 = serverEcdhRatchet0;
            var serverEcdhRatchet1 = KeyAgreementFactory.GenerateNew();
            state.LocalEcdhRatchetStep1 = serverEcdhRatchet1;

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
                    Cipher.Initialize(sharedSecret, serverNonce);
                    var encryptedPayload = Cipher.Encrypt(payload);

                    // calculate mac
                    Mac.Init(sharedSecret, serverNonce, MacSize * 8);
                    messageStream.TryGetBuffer(out var messageStreamBuffer);
                    Mac.Process(messageStreamBuffer);
                    Mac.Process(new ArraySegment<byte>(encryptedPayload));
                    var mac = Mac.Compute();

                    // write the encrypted payload
                    messageWriter.Write(encryptedPayload);

                    // write mac
                    messageWriter.Write(mac);

                    if (messageStream.Length > Configuration.Mtu) throw new InvalidOperationException("The MTU was too small to create the message");
                    return messageStream.ToArray();
                }
            }
        }

        private void ReceiveInitializationResponse(State _state, byte[] data)
        {
            if (!(_state is ClientState state)) throw new InvalidOperationException("Only the client can receive an init response.");
            var keySize = Configuration.UseAes256 ? 32 : 16;

            // new nonce(4), ecdh pubkey(32), <nonce(4), server pubkey(32), 
            // new ecdh pubkey(32) x2, signature(64)>, mac(12)
            using (var ms = new MemoryStream(data))
            {
                using (var br = new BinaryReader(ms))
                {
                    // decrypt
                    var nonce = br.ReadBytes(NonceSize);
                    var rootEcdhKey = br.ReadBytes(EcdhSize);
                    IKeyAgreement rootEcdh = state.LocalEcdhForInit;
                    var rootPreKey = rootEcdh.DeriveKey(rootEcdhKey);
                    Cipher.Initialize(rootPreKey, nonce);
                    var payload = Cipher.Decrypt(data, EcdhSize + NonceSize, data.Length - EcdhSize - NonceSize - MacSize);

                    // check mac
                    br.BaseStream.Seek(data.Length - MacSize, SeekOrigin.Begin);
                    var mac = br.ReadBytes(MacSize);
                    Mac.Init(rootPreKey, nonce, MacSize * 8);
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

                            if (!oldNonce.Matches(state.InitializationNonce))
                            {
                                throw new InvalidOperationException("Nonce did not match");
                            }

                            var verifier = VerifierFactory.Create(serverPubKey);
                            if (!verifier.VerifySignedMessage(Digest, payload))
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
                            var genKeys = KeyDerivation.GenerateKeys(rootPreKey, null, 3, keySize);
                            var rootKey = genKeys[0];
                            var receiveHeaderKey = genKeys[1];
                            var sendHeaderKey = genKeys[2];

                            state.Ratchets.Add(EcdhRatchetStep.InitializeClient(KeyDerivation, rootKey,
                                remoteRatchetEcdh0, remoteRatchetEcdh1, localStep0EcdhRatchet,
                                receiveHeaderKey, sendHeaderKey,
                                localStep1EcdhRatchet));

                            state.LocalEcdhForInit = null;
                        }
                    }
                }
            }
        }

        private byte[] SendFirstClientMessage(State _state)
        {
            if (!(_state is ClientState state)) throw new InvalidOperationException("Only the client can send the first client message.");

            return ConstructMessage(state, state.InitializationNonce, true, true, state.Ratchets.SecondToLast, MessageType.InitializationWithEcdh);
        }

        private void ReceiveFirstMessage(State _state, byte[] payload)
        {
            if (!(_state is ServerState state)) throw new InvalidOperationException("Only the server can receive the first client message.");

            int keySize = Configuration.UseAes256 ? 32 : 16;
            var messageType = GetMessageType(payload[0]);
            if (messageType != MessageType.InitializationWithEcdh)
            {
                throw new InvalidOperationException("The message had an unexpected message type");
            }

            // extract the nonce
            byte[] nonce = new byte[NonceSize];
            Array.Copy(payload, nonce, NonceSize);

            // use the header key we already agreed on
            byte[] headerKey = state.FirstReceiveHeaderKey;

            // double check the mac
            Mac.Init(headerKey, nonce, MacSize * 8);
            Mac.Process(new ArraySegment<byte>(payload, nonce.Length, payload.Length - NonceSize - MacSize));
            byte[] mac = Mac.Compute();
            if (!mac.Matches(new ArraySegment<byte>(payload, payload.Length - MacSize, MacSize)))
            {
                throw new InvalidOperationException("The first received message authentication code did not match");
            }

            // get the encrypted payload
            byte[] encryptedPayload;
            int headerSize = EcdhSize + NonceSize;
            encryptedPayload = new byte[payload.Length - headerSize - MacSize];
            Array.Copy(payload, headerSize, encryptedPayload, 0, encryptedPayload.Length);

            // derive the header
            var headerEncryptionKey = KeyDerivation.GenerateBytes(headerKey, encryptedPayload, keySize);
            Cipher.Initialize(headerEncryptionKey, null);
            var decryptedHeader = Cipher.Decrypt(payload, 0, headerSize);
            decryptedHeader[0] = ClearMessageType(decryptedHeader[0]);

            // the message contains ecdh parameters
            var clientEcdhPublic = new byte[EcdhSize];
            Array.Copy(decryptedHeader, NonceSize, clientEcdhPublic, 0, EcdhSize);

            // initialize the ecdh ratchet
            var ratchetUsed = EcdhRatchetStep.InitializeServer(KeyDerivation,
                state.LocalEcdhRatchetStep0,
                state.RootKey, clientEcdhPublic,
                state.LocalEcdhRatchetStep1,
                state.FirstReceiveHeaderKey,
                state.FirstSendHeaderKey);
            state.Ratchets.Add(ratchetUsed);

            // get the inner payload key from the server receive chain
            var (key, nr) = ratchetUsed.ReceivingChain.RatchetForReceiving(KeyDerivation, 1);

            // decrypt the inner payload
            var nonceBytes = new byte[NonceSize];
            Array.Copy(decryptedHeader, nonceBytes, NonceSize);
            Cipher.Initialize(key, nonceBytes);
            var decryptedInnerPayload = Cipher.Decrypt(encryptedPayload);

            // check the inner payload
            var innerNonce = new byte[NonceSize];
            Array.Copy(decryptedInnerPayload, innerNonce, NonceSize);
            if (!innerNonce.Matches(state.NextInitializationNonce))
            {
                throw new InvalidOperationException("The inner encrypted nonce did not match the initialization nonce.");
            }

            state.FirstSendHeaderKey = null;
            state.FirstReceiveHeaderKey = null;
            state.LocalEcdhRatchetStep0 = null;
            state.LocalEcdhRatchetStep1 = null;
            state.RootKey = null;
        }

        private byte[] SendFirstResponse(State _state)
        {
            if (!(_state is ServerState state)) throw new InvalidOperationException("Only the server can send the first response.");

            var payload = state.NextInitializationNonce;
            state.NextInitializationNonce = null;
            return ConstructMessage(state, payload, true, false, state.Ratchets.Last, MessageType.InitializationWithoutEcdh);
        }

        private void ReceiveFirstResponse(State _state, byte[] data)
        {
            if (!(_state is ClientState state)) throw new InvalidOperationException("Only the client can receive the first response.");

            var contents = DeconstructMessage(state, data, MessageType.InitializationWithoutEcdh, false);
            if (contents == null || contents.Length < 32)
            {
                throw new InvalidOperationException("The first response from the server was not valid");
            }

            var nonce = new byte[NonceSize];
            Array.Copy(contents, nonce, NonceSize);
            if (!nonce.Matches(state.InitializationNonce))
            {
                throw new InvalidOperationException("The first response from the server did not contain the correct nonce");
            }

            state.InitializationNonce = null;
        }

        private byte[] ConstructMessage(State _state, byte[] message, bool pad, bool includeEcdh, EcdhRatchetStep step, MessageType? overrideMessageType = null)
        {
            // message format:
            // <nonce (4)>, <payload, padding>, mac(12)
            // <nonce (4), ecdh (32)>, <payload, padding>, mac(12)

            var state = _state;
            int mtu = Configuration.Mtu;
            int keySize = Configuration.UseAes256 ? 32 : 16;

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
            Cipher.Initialize(payloadKey, nonce);
            var encryptedPayload = Cipher.Encrypt(payload);

            // build the header: <nonce(4), ecdh(32)?>
            byte[] header = new byte[headerSize];
            Array.Copy(nonce, header, NonceSize);
            if (includeEcdh)
            {
                // this is the hottest line in the send process
                var ratchetPublicKey = step.GetPublicKey(KeyAgreementFactory);
                Array.Copy(ratchetPublicKey, 0, header, nonce.Length, ratchetPublicKey.Length);
            }

            // encrypt the header
            var headerEncryptionKey = KeyDerivation.GenerateBytes(step.SendingChain.HeaderKey, encryptedPayload, keySize);
            Cipher.Initialize(headerEncryptionKey, null);
            var encryptedHeader = Cipher.Encrypt(header);

            // set the message type (we can do this because we're using a CTR stream cipher)
            encryptedHeader[0] = SetMessageType(encryptedHeader[0], messageType);

            // mac the message: <header>, <payload>, mac(12)
            // the mac uses the first 4 encrypted bytes as iv and the rest (incl ecdh if there) as ad.
            byte[] iv;
            if (includeEcdh)
            {
                iv = new byte[NonceSize];
                Array.Copy(encryptedHeader, iv, NonceSize);
                Mac.Init(step.SendingChain.HeaderKey, iv, MacSize * 8);
                Mac.Process(new ArraySegment<byte>(encryptedHeader, NonceSize, encryptedHeader.Length - NonceSize));
            }
            else
            {
                iv = encryptedHeader;
                Mac.Init(step.SendingChain.HeaderKey, iv, MacSize * 8);
            }
            Mac.Process(new ArraySegment<byte>(encryptedPayload));
            var mac = Mac.Compute();

            // construct the resulting message
            byte[] result = new byte[encryptedHeader.Length + encryptedPayload.Length + mac.Length];
            Array.Copy(encryptedHeader, 0, result, 0, encryptedHeader.Length);
            Array.Copy(encryptedPayload, 0, result, encryptedHeader.Length, encryptedPayload.Length);
            Array.Copy(mac, 0, result, encryptedHeader.Length + encryptedPayload.Length, mac.Length);
            if (result.Length > mtu) throw new InvalidOperationException("Could not create message within MTU");
            return result;
        }

        private byte[] DeconstructMessage(State _state, byte[] payload, MessageType? expectedMessageType = null, bool? overrideHasEcdh = null)
        {
            var state = _state;

            int keySize = Configuration.UseAes256 ? 32 : 16;
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

            // find the header key by checking the mac
            byte[] headerKey = null;
            EcdhRatchetStep ratchetUsed = null;
            bool usedNextHeaderKey = false;
            int cnt = 0;
            foreach (var ratchet in state.Ratchets.Enumerate())
            {
                cnt++;
                headerKey = ratchet.ReceivingChain.HeaderKey;
                Mac.Init(headerKey, nonce, MacSize * 8);
                Mac.Process(new ArraySegment<byte>(payload, nonce.Length, payload.Length - nonce.Length - MacSize));
                byte[] mac = Mac.Compute();
                if (mac.Matches(new ArraySegment<byte>(payload, payload.Length - mac.Length, mac.Length)))
                {
                    ratchetUsed = ratchet;
                    break;
                }
                else if (ratchet.ReceivingChain.NextHeaderKey != null)
                {
                    headerKey = ratchet.ReceivingChain.NextHeaderKey;
                    Mac.Init(headerKey, nonce, MacSize * 8);
                    Mac.Process(new ArraySegment<byte>(payload, nonce.Length, payload.Length - nonce.Length - MacSize));
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
            int headerSize = hasEcdh ? (EcdhSize + NonceSize) : NonceSize;
            encryptedPayload = new byte[payload.Length - headerSize - MacSize];
            Array.Copy(payload, headerSize, encryptedPayload, 0, encryptedPayload.Length);

            // decrypt the header
            var headerEncryptionKey = KeyDerivation.GenerateBytes(headerKey, encryptedPayload, keySize);
            Cipher.Initialize(headerEncryptionKey, null);
            var decryptedHeader = Cipher.Decrypt(payload, 0, headerSize);
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
                    state.Ratchets.Trim(Configuration.NumberOfRatchetsToKeep * 2, Configuration.NumberOfRatchetsToKeep);
                    ratchetUsed = newRatchet;
                }
            }

            // get the inner payload key from the server receive chain
            var (key, nr) = ratchetUsed.ReceivingChain.RatchetForReceiving(KeyDerivation, step);

            // decrypt the inner payload
            var nonceBytes = new byte[NonceSize];
            Array.Copy(decryptedHeader, nonceBytes, NonceSize);
            Cipher.Initialize(key, nonceBytes);
            var decryptedInnerPayload = Cipher.Decrypt(encryptedPayload);
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
                byte firstByte = (byte)(((int)MessageType.MultiPartMessageUnencrypted << 4) |
                    i << 2 | (numChunks - 1));

                var left = allData.Length - amt;
                int thisChunkSize = left > chunkSize ? chunkSize : left;
                chunks[i] = new byte[thisChunkSize + 1];
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

            int num = data[0] & 0b0000_1100 >> 2;
            int tot = (data[0] & 0b0000_0011) + 1;
            byte[] payload = new byte[data.Length - 1];
            return (payload, num, tot);
        }

        private byte[][] ConstructEncryptedMultipartMessage(byte[] allData)
        {
            // encrypted multipart message is a normal message without ECDH,
            // with a different type, and with a header inside the payload.
            // the header is: seq (2 bytes), num(2 bytes), total (2 bytes)
            var state = LoadState();
            var ratchet = state.Ratchets.SecondToLast;
            ushort seq = unchecked((ushort)ratchet.SendingChain.Generation);

            var chunkSize = MultipartMessageSize;
            var numChunks = allData.Length / chunkSize;
            if (allData.Length % chunkSize != 0) numChunks++;

            if (numChunks > 65536) throw new InvalidOperationException("Cannot create an encrypted multipart message with more than 65536 parts");

            byte[] numChunksBytes = BigEndianBitConverter.GetBytes((ushort)(numChunks - 1));
            byte[] seqBytes = BigEndianBitConverter.GetBytes(seq);
            int amt = 0;
            byte[][] chunks = new byte[numChunks][];
            byte[] payload = new byte[chunkSize + 6];
            for (int i = 0; i < numChunks; i++)
            {
                var left = allData.Length - amt;
                int thisChunkSize = left > chunkSize ? chunkSize : left;
                if ((thisChunkSize + 6) != payload.Length) payload = new byte[thisChunkSize + 6];
                Array.Copy(allData, amt, payload, 6, thisChunkSize);
                amt += thisChunkSize;

                // num and total
                payload[0] = seqBytes[0];
                payload[1] = seqBytes[1];
                payload[2] = (byte)((((ushort)i) >> 8) & 0xFF);
                payload[3] = (byte)(((ushort)i) & 0xFF);
                payload[4] = numChunksBytes[0];
                payload[5] = numChunksBytes[1];
                chunks[i] = ConstructMessage(state, payload, false, false, ratchet, MessageType.MultiPartMessageEncrypted);
            }

            return chunks;
        }

        private (byte[] payload, int seq, int num, int total) DeconstructEncryptedMultipartMessagePart(byte[] data)
        {
            var state = LoadState();
            var outerPayload = DeconstructMessage(state, data, MessageType.MultiPartMessageEncrypted, false);
            byte[] innerPayload = new byte[outerPayload.Length - 6];
            Array.Copy(outerPayload, 6, innerPayload, 0, innerPayload.Length);
            int seq = (int)BigEndianBitConverter.ToUInt16(outerPayload, 0);
            int num = (int)BigEndianBitConverter.ToUInt16(outerPayload, 2);
            int tot = (int)(BigEndianBitConverter.ToUInt16(outerPayload, 4) + 1);
            return (innerPayload, seq, num, tot);
        }

        private byte[] ConstructRetransmissionRequest(byte[] nonceToRetransmit)
        {
            // a retransmission request is a normal mesage, without ECDH parameters,
            // with a different type, that contains the nonce of the message to retransmit
            // as payload. Only encrypted messages may be retransmitted. If an incomplete unencrypted
            // message times out, it is considered dropped.
            var state = LoadState();
            var step = state.Ratchets.SecondToLast;

            return ConstructMessage(state, nonceToRetransmit, false, false, step, MessageType.MultiPartRetransmissionRequest);
        }

        private byte[] DeconstructRetransmissionRequest(byte[] data)
        {
            var state = LoadState();

            var nonceToRetransmit = DeconstructMessage(state, data, MessageType.MultiPartRetransmissionRequest, false);
            return nonceToRetransmit;
        }

        private SendResult ProcessInitialization(byte[] dataReceived = null)
        {
            _state = LoadState();
            if (_state == null)
            {
                int keySize = Configuration.UseAes256 ? 32 : 16;
                _state = State.Initialize(Configuration.IsClient, keySize);
            }

            byte[] sendback;
            if (Configuration.IsClient)
            {
                //Debug.WriteLine("\n\n###CLIENT");
                if (dataReceived == null)
                {
                    // step 1: send first init request from client
                    sendback = SendInitializationRequest(_state);
                }
                else
                {
                    var state = (ClientState)_state;
                    var type = GetMessageType(dataReceived[0]);

                    if (state.Ratchets.Count == 0)
                    {
                        if (type == MessageType.InitializationResponse)
                        {
                            // step 2: init response from server
                            ReceiveInitializationResponse(_state, dataReceived);
                            sendback = SendFirstClientMessage(_state);
                        }
                        else
                        {
                            throw new InvalidOperationException("Expected an initialization response but got something else.");
                        }
                    }
                    else if (type == MessageType.InitializationWithoutEcdh)
                    {
                        // step 3: receive first message from server
                        ReceiveFirstResponse(_state, dataReceived);
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
                //Debug.WriteLine("\n\n###SERVER");
                var state = (ServerState)_state;

                if (dataReceived == null) throw new InvalidOperationException("Only the client can send initialization without having received a response first");

                var type = GetMessageType(dataReceived[0]);

                if (type == MessageType.InitializationRequest)
                {
                    // step 1: client init request
                    var (initializationNonce, remoteEcdhForInit, remotePublicKey) = ReceiveInitializationRequest(_state, dataReceived);
                    sendback = SendInitializationResponse(_state, initializationNonce, remoteEcdhForInit);
                }
                else if (type == MessageType.InitializationWithEcdh)
                {
                    // step 2: first message from client
                    ReceiveFirstMessage(_state, dataReceived);
                    sendback = SendFirstResponse(_state);
                }
                else
                {
                    throw new InvalidOperationException("Unexpected message received during server initialization");
                }
            }

            if (sendback != null)
            {
                return new SendResult { Messages = new[] { sendback } };
            }
            else
            {
                return null;
            }
        }

        public SendResult InitiateInitialization()
        {
            var state = LoadState();

            if (state.IsInitialized)
            {
                throw new InvalidOperationException("The client is already initialized");
            }
            if (!Configuration.IsClient)
            {
                throw new InvalidOperationException("only a client can initiate initialization");
            }

            return ProcessInitialization();
        }

        public ReceiveResult Receive(byte[] data)
        {
            //Debug.WriteLine($"\n\n###{(IsClient ? "CLIENT" : "SERVER")} RECEIVE");
            var state = LoadState();

            var messageType = GetMessageType(data[0]);

            if (IsInitializationMessge(messageType))
            {
                if (state.IsInitialized)
                {
                    throw new InvalidOperationException("Received initialization message after initialization has been completed");
                }

                var toSendBack = ProcessInitialization(data);

                return new ReceiveResult
                {
                    Payload = null,
                    ReceivedDataType = ReceivedDataType.InitializationWithResponse,
                    ToSendBack = toSendBack
                };
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
                    else if (messageType == MessageType.MultiPartMessageEncrypted)
                    {
                        var (payload, seq, num, total) = DeconstructEncryptedMultipartMessagePart(data);
                        var entireMessage = _multipart.Ingest(payload, seq, num, total);
                        if (entireMessage != null)
                        {
                            return new ReceiveResult
                            {
                                MultipartSequence = seq,
                                MessageNumber = num,
                                TotalMessages = total,
                                Payload = entireMessage,
                                ReceivedDataType = ReceivedDataType.Normal,
                                ToSendBack = null
                            };
                        }
                        else
                        {
                            return new ReceiveResult
                            {
                                MultipartSequence = seq,
                                MessageNumber = num,
                                TotalMessages = total,
                                Payload = payload,
                                ReceivedDataType = ReceivedDataType.Partial,
                                ToSendBack = null
                            };
                        }
                    }
                }
            }

            throw new NotSupportedException("Unexpected message type received");
        }

        private SendResult SendSingle(byte[] payload)
        {
            //Debug.WriteLine($"\n\n###{(IsClient ? "CLIENT" : "SERVER")} SEND");
            var state = LoadState();

            if (!state.IsInitialized)
            {
                throw new InvalidOperationException("The MicroRatchetClient is not initialized");
            }

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

            return new SendResult
            {
                Messages = new[] { ConstructMessage(state, payload, false, canIncludeEcdh, step) }
            };
        }

        private SendResult SendMultipart(byte[] payload)
        {
            var state = LoadState();

            if (!state.IsInitialized)
            {
                throw new InvalidOperationException("The MicroRatchetClient is not initialized");
            }

            return new SendResult
            {
                Messages = ConstructEncryptedMultipartMessage(payload)
            };
        }

        public SendResult Send(byte[] payload, bool? allowMultipart = null)
        {
            if (payload.Length <= MaximumMessageSize)
            {
                return SendSingle(payload);
            }
            else
            {
                bool canSendMultipart = allowMultipart ?? Configuration.AllowImplicitMultipartMessages;
                if (!canSendMultipart)
                {
                    throw new InvalidOperationException("Cannot send multipart message as it has not been explicitly allowed.");
                }
                return SendMultipart(payload);
            }
        }

        private State LoadState()
        {
            if (_state == null)
            {
                int keySize = Configuration.UseAes256 ? 32 : 16;
                _state = Configuration.IsClient
                    ? (State)ClientState.Load(Storage, KeyAgreementFactory, keySize)
                    : ServerState.Load(Storage, KeyAgreementFactory, keySize);
            }

            return _state;
        }

        public void SaveState()
        {
            if (_state != null)
            {
                _state.Store(Storage, Configuration.NumberOfRatchetsToKeep, Configuration.MaxLostKeys);
            }
        }

        private static MessageType GetMessageType(byte b) => (MessageType)((b & 0b1110_0000) >> 5);
        private static MessageType GetMessageType(int i) => (MessageType)((i & 0b11100000_00000000_00000000_00000000) >> 29);
        private static byte SetMessageType(byte b, MessageType type) => (byte)(b & 0b0001_1111 | ((int)type << 5));
        private static int SetMessageType(ref int i, MessageType type) => i & 0b00011111_11111111_11111111_11111111 | ((int)type << 29);
        private static byte ClearMessageType(byte b) => (byte)(b & 0b0001_1111);
        private static int ClearMessageType(int i) => i & 0b00011111_11111111_11111111_11111111;
        private static bool IsInitializationMessge(MessageType messageType) => messageType == MessageType.InitializationRequest || messageType == MessageType.InitializationResponse;
        private static bool IsNormalMessage(MessageType messageType) => messageType == MessageType.Normal || messageType == MessageType.NormalWithEcdh;
        private static bool IsMultipartMessage(MessageType messageType) => messageType == MessageType.MultiPartMessageEncrypted || messageType == MessageType.MultiPartMessageUnencrypted;

        private int MaximumSingleMessageSize => Configuration.Mtu - MinimumOverhead;
        private int MaximumSingleMessageSizeWithEcdh => Configuration.Mtu - OverheadWithEcdh;
        private int MaximumMultipartMessageSize => (Configuration.Mtu - OverheadWithEcdh) * 65536;
        private int MaximumUnencryptedMultipartMessageSize => (Configuration.Mtu - 1) * 4;
    }
}
