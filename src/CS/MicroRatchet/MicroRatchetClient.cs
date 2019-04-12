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
        public const int EcPntSize = 32;
        public const int SignatureSize = 64;
        public const int MinimumMessageSize = 16;
        public const int MinimumOverhead = NonceSize + MacSize; // 16
        public const int OverheadWithEcdh = MinimumOverhead + EcPntSize; // 48
        public const int EncryptedMultipartHeaderOverhead = 6;

        private IDigest Digest => Services.Digest;
        private ISignature Signature => Services.Signature;
        private IRandomNumberGenerator RandomNumberGenerator => Services.RandomNumberGenerator;
        private IKeyAgreementFactory KeyAgreementFactory => Services.KeyAgreementFactory;
        private IAesFactory AesFactory => Services.AesFactory;
        private IKeyDerivation KeyDerivation { get; }
        private IVerifierFactory VerifierFactory => Services.VerifierFactory;
        private IStorageProvider Storage => Services.Storage;

        private readonly MultipartMessageReconstructor _multipart;
        private State _state;
        private readonly List<(byte[], IAes)> _headerKeyCiphers = new List<(byte[], IAes)>();

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

            KeyDerivation = new AesKdf(Services.AesFactory);
            _multipart = new MultipartMessageReconstructor(MaximumMessageSize,
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

            // minimum mtu is 64 bytes
            if (mtu < OverheadWithEcdh + MinimumMessageSize) throw new InvalidOperationException("The MTU is not big enough to facilitate key exchange");
        }

        private IAes GetHeaderKeyCipher(byte[] key)
        {
            foreach (var hkc in _headerKeyCiphers)
            {
                if (hkc.Item1.Matches(key)) return hkc.Item2;
            }

            var cipher = AesFactory.GetAes(true, key);
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

            // set the first bit and clear the second: initialization message
            clientState.InitializationNonce[0] &= 0b0011_1111;
            clientState.InitializationNonce[0] |= 0b1000_0000;

            // get the public key
            var pubkey = Signature.PublicKey;

            // generate new ECDH keypair for init message and root key
            var clientEcdh = KeyAgreementFactory.GenerateNew();
            clientState.LocalEcdhForInit = clientEcdh;

            // nonce(4), pubkey(32), ecdh(32), signature(64)
            byte[] message = new byte[132];
            Array.Copy(clientState.InitializationNonce, 0, message, 0, NonceSize);
            Array.Copy(pubkey, 0, message, NonceSize, EcPntSize);
            Array.Copy(clientEcdh.GetPublicKey(), 0, message, NonceSize + EcPntSize, 32);
            byte[] digest = Digest.ComputeDigest(message, 0, 68);
            Array.Copy(Signature.Sign(digest), 0, message, NonceSize + EcPntSize * 2, SignatureSize);
            return message;
        }

        private (ArraySegment<byte> initializationNonce, ArraySegment<byte> remoteEcdhForInit) ReceiveInitializationRequest(State state, byte[] data)
        {
            if (!(state is ServerState serverState)) throw new InvalidOperationException("Only the server can receive an init request.");

            // nonce(4), pubkey(32), ecdh(32), signature(64)
            var initializationNonce = new ArraySegment<byte>(data, 0, 4);
            var clientPublicKey = new ArraySegment<byte>(data, NonceSize, EcPntSize);
            var remoteEcdhForInit = new ArraySegment<byte>(data, NonceSize + EcPntSize, EcPntSize);

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

            serverState.ClientPublicKey = clientPublicKey.ToArray();
            var verifier = VerifierFactory.Create(clientPublicKey);

            if (!verifier.VerifySignedMessage(Digest, data))
            {
                throw new InvalidOperationException("The signature was invalid");
            }

            return (initializationNonce, remoteEcdhForInit);

        }

        private byte[] SendInitializationResponse(State state, ArraySegment<byte> initializationNonce, ArraySegment<byte> remoteEcdhForInit)
        {
            // message format:
            // new nonce(4), ecdh pubkey(32),
            // <nonce from init request(4), server pubkey(32), 
            // new ecdh pubkey(32) x2, signature(64)>, mac(12) = 212 bytes

            if (!(state is ServerState serverState)) throw new InvalidOperationException("Only the server can send init response.");

            // generate a nonce and new ecdh parms
            var serverNonce = RandomNumberGenerator.Generate(NonceSize);
            // set the first bit and clear the second: initialization message
            serverNonce[0] &= 0b0011_1111;
            serverNonce[0] |= 0b1000_0000;
            serverState.NextInitializationNonce = serverNonce;
            var rootPreEcdh = KeyAgreementFactory.GenerateNew();
            var rootPreEcdhPubkey = rootPreEcdh.GetPublicKey();

            // generate server ECDH for root key and root key
            var rootPreKey = rootPreEcdh.DeriveKey(remoteEcdhForInit);
            var genKeys = KeyDerivation.GenerateKeys(rootPreKey, serverNonce, 3, 32);
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

            var entireMessageSize = NonceSize * 2 + EcPntSize * 4 + SignatureSize + MacSize;
            var encryptedPayloadSize = NonceSize + EcPntSize * 3 + SignatureSize;
            var encryptedPayloadOffset = NonceSize + EcPntSize;
            var macOffset = entireMessageSize - MacSize;

            // construct the message
            byte[] message = new byte[entireMessageSize];
            Array.Copy(serverNonce, 0, message, 0, NonceSize);
            Array.Copy(rootPreEcdhPubkey, 0, message, NonceSize, EcPntSize);

            // construct the to-be-encrypted part
            Array.Copy(initializationNonce.Array, initializationNonce.Offset, message, encryptedPayloadOffset, NonceSize);
            Array.Copy(Signature.PublicKey, 0, message, encryptedPayloadOffset + NonceSize, EcPntSize);
            Array.Copy(serverEcdhRatchet0.GetPublicKey(), 0, message, encryptedPayloadOffset + NonceSize + EcPntSize, EcPntSize);
            Array.Copy(serverEcdhRatchet1.GetPublicKey(), 0, message, encryptedPayloadOffset + NonceSize + EcPntSize * 2, EcPntSize);

            // sign the message
            byte[] digest = Digest.ComputeDigest(message, encryptedPayloadOffset, encryptedPayloadSize - SignatureSize);
            Array.Copy(Signature.Sign(digest), 0, message, encryptedPayloadOffset + NonceSize + EcPntSize * 3, SignatureSize);

            // encrypte the message
            AesCtrMode cipher = new AesCtrMode(AesFactory.GetAes(true, rootPreKey), serverNonce);
            var encryptedPayload = cipher.Process(message, encryptedPayloadOffset, encryptedPayloadSize);
            Array.Copy(encryptedPayload, 0, message, encryptedPayloadOffset, encryptedPayloadSize);

            // calculate mac
            var Mac = new Poly(AesFactory);
            Mac.Init(rootPreKey, serverNonce, MacSize * 8);
            Mac.Process(message, 0, macOffset);
            var mac = Mac.Compute();
            Array.Copy(mac, 0, message, macOffset, MacSize);

            return message;
        }

        private void ReceiveInitializationResponse(State state, byte[] data)
        {
            if (!(state is ClientState clientState)) throw new InvalidOperationException("Only the client can receive an init response.");

            // new nonce(4), ecdh pubkey(32), <nonce(4), server pubkey(32), 
            // new ecdh pubkey(32) x2, signature(64)>, mac(12)
            var nonce = new ArraySegment<byte>(data, 0, NonceSize);
            var rootEcdhKey = new ArraySegment<byte>(data, NonceSize, EcPntSize);
            var encryptedPayload = new ArraySegment<byte>(data,
                        EcPntSize + NonceSize,
                        data.Length - EcPntSize - NonceSize - MacSize);
            var payloadToMac = new ArraySegment<byte>(data, 0, data.Length - MacSize);
            var mac = new ArraySegment<byte>(data, data.Length - MacSize, MacSize);

            // decrypt
            IKeyAgreement rootEcdh = clientState.LocalEcdhForInit;
            var rootPreKey = rootEcdh.DeriveKey(rootEcdhKey);
            AesCtrMode cipher = new AesCtrMode(AesFactory.GetAes(true, rootPreKey), nonce);
            var payload = cipher.Process(encryptedPayload);

            // check mac
            var Mac = new Poly(AesFactory);
            Mac.Init(rootPreKey, nonce, MacSize * 8);
            Mac.Process(payloadToMac);
            var checkMac = Mac.Compute();

            if (!mac.Matches(checkMac))
            {
                throw new InvalidOperationException("Could not decript payload");
            }

            var oldNonce = new ArraySegment<byte>(payload, 0, NonceSize);
            var serverPubKey = new ArraySegment<byte>(payload, NonceSize, EcPntSize);
            var remoteRatchetEcdh0 = new ArraySegment<byte>(payload, NonceSize + EcPntSize, EcPntSize);
            var remoteRatchetEcdh1 = new ArraySegment<byte>(payload, NonceSize + EcPntSize * 2, EcPntSize);

            if (!oldNonce.Matches(clientState.InitializationNonce))
            {
                throw new InvalidOperationException("Nonce did not match");
            }

            var verifier = VerifierFactory.Create(serverPubKey);
            if (!verifier.VerifySignedMessage(Digest, new ArraySegment<byte>(payload)))
            {
                throw new InvalidOperationException("The signature was invalid");
            }

            // store the new nonce we got from the server
            clientState.InitializationNonce = nonce.ToArray();
            Log.Verbose($"storing iniitlizaionta nonce: {Log.ShowBytes(nonce)}");

            // we now have enough information to construct our double ratchet
            var localStep0EcdhRatchet = KeyAgreementFactory.GenerateNew();
            var localStep1EcdhRatchet = KeyAgreementFactory.GenerateNew();

            // initialize client root key and ecdh ratchet
            var genKeys = KeyDerivation.GenerateKeys(rootPreKey, clientState.InitializationNonce, 3, 32);
            var rootKey = genKeys[0];
            var receiveHeaderKey = genKeys[1];
            var sendHeaderKey = genKeys[2];

            clientState.Ratchets.Add(EcdhRatchetStep.InitializeClient(KeyDerivation, rootKey,
                remoteRatchetEcdh0, remoteRatchetEcdh1, localStep0EcdhRatchet,
                receiveHeaderKey, sendHeaderKey,
                localStep1EcdhRatchet));

            clientState.LocalEcdhForInit = null;


        }

        private byte[] SendFirstClientMessage(State state)
        {
            if (!(state is ClientState clientState)) throw new InvalidOperationException("Only the client can send the first client message.");

            return ConstructMessage(new ArraySegment<byte>(clientState.InitializationNonce), true, true, clientState.Ratchets.SecondToLast);
        }

        private void ReceiveFirstMessage(State state, byte[] payload)
        {
            if (!(state is ServerState serverState)) throw new InvalidOperationException("Only the server can receive the first client message.");

            DeconstructMessage(state, payload, serverState.FirstReceiveHeaderKey);

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
            return ConstructMessage(new ArraySegment<byte>(payload), true, false, serverState.Ratchets.Last);
        }

        private void ReceiveFirstResponse(State state, byte[] data)
        {
            if (!(state is ClientState clientState)) throw new InvalidOperationException("Only the client can receive the first response.");

            var contents = DeconstructMessage(state, data);
            if (contents == null || contents.Length < 32)
            {
                throw new InvalidOperationException("The first response from the server was not valid");
            }

            var nonce = new ArraySegment<byte>(contents, 0, NonceSize);
            if (!nonce.Matches(clientState.InitializationNonce))
            {
                throw new InvalidOperationException("The first response from the server did not contain the correct nonce");
            }

            clientState.InitializationNonce = null;
        }

        private byte[] ConstructMessage(ArraySegment<byte> message, bool pad, bool includeEcdh, EcdhRatchetStep step)
        {
            // message format:
            // <nonce (4)>, <payload, padding>, mac(12)
            // <nonce (4), ecdh (32)>, <payload, padding>, mac(12)

            // get the payload key and nonce
            var (payloadKey, messageNumber) = step.SendingChain.RatchetForSending(KeyDerivation);
            var nonce = BigEndianBitConverter.GetBytes(messageNumber);

            // make sure the first two bits of the nonce are clear
            // this indicates an initialization message
            if ((nonce[0] & 0b1100_0000) != 0)
            {
                throw new InvalidOperationException($"The message number is too big. Cannot encrypt more than {(1 << 30) - 1} messages without exchanging keys");
            }

            // calculate some sizes
            int mtu = Configuration.Mtu;
            var headerSize = NonceSize + (includeEcdh ? EcPntSize : 0);
            var overhead = headerSize + MacSize;
            var messageSize = message.Count;
            var maxMessageSize = mtu - overhead;

            // build the payload: <payload, padding>
            ArraySegment<byte> payload;
            if (pad && messageSize < maxMessageSize)
            {
                payload = new ArraySegment<byte>(new byte[mtu - overhead]);
                Array.Copy(message.Array, message.Offset, payload.Array, 0, message.Count);
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
            AesCtrMode icipher = new AesCtrMode(AesFactory.GetAes(true, payloadKey), nonce);
            var encryptedPayload = icipher.Process(payload);

            // build the header: <nonce(4), ecdh(32)?>
            byte[] header = new byte[headerSize];
            Array.Copy(nonce, header, NonceSize);
            if (includeEcdh)
            {
                var ratchetPublicKey = step.GetPublicKey(KeyAgreementFactory);
                Array.Copy(ratchetPublicKey, 0, header, nonce.Length, ratchetPublicKey.Length);

                // set the has ecdh bit
                header[0] |= 0b0100_0000;
            }

            // encrypt the header using the header key and using the
            // last MinMessageSize bytes of the message as the nonce.
            var headerEncryptionNonce = new ArraySegment<byte>(encryptedPayload, encryptedPayload.Length - MinimumMessageSize, MinimumMessageSize);
            AesCtrMode hcipher = new AesCtrMode(GetHeaderKeyCipher(step.SendHeaderKey), headerEncryptionNonce);
            var encryptedHeader = hcipher.Process(header);

            // clear the first bit of the message indicating that it is a normal message
            encryptedHeader[0] = (byte)(encryptedHeader[0] & 0b0111_1111);

            // mac the message: <header>, <payload>, mac(12)
            // the mac uses the header encryption derived key (all 32 bytes)
            var Mac = new Poly(AesFactory);
            byte[] maciv = new byte[16];
            int epl = encryptedPayload.Length;
            int ehl = encryptedHeader.Length;
            if (ehl < maciv.Length)
            {
                Array.Copy(encryptedHeader, maciv, ehl);
                Array.Copy(encryptedPayload, 0, maciv, ehl, 16 - ehl);
            }
            else
            {
                Array.Copy(encryptedHeader, maciv, maciv.Length);
            }
            Mac.Init(step.SendHeaderKey, maciv, MacSize * 8);
            Mac.Process(encryptedHeader);
            Mac.Process(encryptedPayload);
            var mac = Mac.Compute();

            // construct the resulting message
            byte[] result = new byte[ehl + epl + mac.Length];
            Array.Copy(encryptedHeader, 0, result, 0, ehl);
            Array.Copy(encryptedPayload, 0, result, ehl, epl);
            Array.Copy(mac, 0, result, ehl + epl, mac.Length);
            return result;
        }

        private byte[] DeconstructMessage(State state, byte[] payload, byte[] overrideHeaderKey = null)
        {
            // get some basic parts
            var messageSize = payload.Length;
            var encryptedNonce = new ArraySegment<byte>(payload, 0, NonceSize);
            var payloadExceptMac = new ArraySegment<byte>(payload, 0, messageSize - MacSize);
            var mac = new ArraySegment<byte>(payload, messageSize - MacSize, MacSize);

            // find the header key by checking the mac
            var maciv = new byte[16];
            Array.Copy(payload, maciv, 16);
            var Mac = new Poly(AesFactory);
            bool usedNextHeaderKey = false;
            byte[] headerKey = null;
            EcdhRatchetStep ratchetUsed = null;
            if (overrideHeaderKey != null)
            {
                headerKey = overrideHeaderKey;
                Mac.Init(headerKey, maciv, MacSize * 8);
                Mac.Process(payloadExceptMac);
                byte[] compareMac = Mac.Compute();
                if (!mac.Matches(compareMac))
                {
                    throw new InvalidOperationException("Could not decrypt the incoming message with given header key");
                }
            }
            else
            {
                int cnt = 0;
                foreach (var ratchet in state.Ratchets.Enumerate())
                {
                    cnt++;
                    headerKey = ratchet.ReceiveHeaderKey;
                    Mac.Init(headerKey, maciv, MacSize * 8);
                    Mac.Process(payloadExceptMac);
                    byte[] compareMac = Mac.Compute();
                    if (mac.Matches(compareMac))
                    {
                        ratchetUsed = ratchet;
                        break;
                    }
                    else if (ratchet.NextReceiveHeaderKey != null)
                    {
                        headerKey = ratchet.NextReceiveHeaderKey;
                        Mac.Init(headerKey, maciv, MacSize * 8);
                        Mac.Process(payloadExceptMac);
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
            }


            // decrypt the nonce
            var headerEncryptionNonce = new ArraySegment<byte>(payload, payload.Length - MacSize - MinimumMessageSize, MinimumMessageSize);
            AesCtrMode hcipher = new AesCtrMode(GetHeaderKeyCipher(headerKey), headerEncryptionNonce);
            byte[] decryptedNonce = hcipher.Process(encryptedNonce);

            // clear the first bit again and get the ecdh bit
            decryptedNonce[0] = (byte)(decryptedNonce[0] & 0b0111_1111);
            var hasEcdh = HasEcdh(decryptedNonce[0]);
            decryptedNonce[0] &= 0b0011_1111;

            // extract ecdh if needed
            int step = BigEndianBitConverter.ToInt32(decryptedNonce);
            if (hasEcdh)
            {
                var clientEcdhPublic = new ArraySegment<byte>(hcipher.Process(new ArraySegment<byte>(payload, NonceSize, EcPntSize)));

                if (ratchetUsed == null)
                {
                    // an override header key was used.
                    // this means we have to initialize the ratchet
                    if (!(state is ServerState serverState)) throw new InvalidOperationException("Only the server can initialize a ratchet.");
                    ratchetUsed = EcdhRatchetStep.InitializeServer(KeyDerivation,
                        serverState.LocalEcdhRatchetStep0,
                        serverState.RootKey, clientEcdhPublic,
                        serverState.LocalEcdhRatchetStep1,
                        serverState.FirstReceiveHeaderKey,
                        serverState.FirstSendHeaderKey);
                    serverState.Ratchets.Add(ratchetUsed);
                }
                else
                {
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
            }


            // get the inner payload key from the server receive chain
            if (ratchetUsed == null)
            {
                throw new InvalidOperationException("An override header key was used but the message did not contain ECDH parameters");
            }
            var (key, _) = ratchetUsed.ReceivingChain.RatchetForReceiving(KeyDerivation, step);

            // get the encrypted payload
            int payloadOffset = hasEcdh ? NonceSize + EcPntSize : NonceSize;
            var encryptedPayload = new ArraySegment<byte>(payload, payloadOffset, messageSize - payloadOffset - MacSize);

            // decrypt the inner payload
            AesCtrMode icipher = new AesCtrMode(AesFactory.GetAes(true, key), decryptedNonce);
            var decryptedInnerPayload = icipher.Process(encryptedPayload);
            return decryptedInnerPayload;
        }

        private byte[][] ConstructUnencryptedMultipartMessage(byte[] allData)
        {
            // unencrypted multipart message:
            // 11 (2 bits), num (3 bits), total (3 bits), data (until MTU)

            var chunkSize = Configuration.Mtu - 1;
            var numChunks = allData.Length / chunkSize;
            if (allData.Length % Configuration.Mtu != 0) numChunks++;

            if (numChunks > 8) throw new InvalidOperationException("Cannot create an unencrypted multipart message with more than 4 parts");

            int amt = 0;
            byte[][] chunks = new byte[numChunks][];
            for (int i = 0; i < numChunks; i++)
            {
                byte firstByte = (byte)(0b1100_0000 | (i << 3) | (numChunks - 1));

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
            int num = (data[0] & 0b0011_1000) >> 3;
            int tot = (data[0] & 0b0000_0111) + 1;
            byte[] payload = new byte[data.Length - 1];
            Array.Copy(data, 1, payload, 0, payload.Length);
            return (payload, num, tot);
        }

        private byte[] ProcessInitializationInternal(State state, byte[] dataReceived)
        {
            byte[] sendback;
            if (Configuration.IsClient)
            {
                Log.Verbose("\n\n###CLIENT");
                var clientState = (ClientState)state;

                if (dataReceived == null)
                {
                    // step 1: send first init request from client
                    sendback = SendInitializationRequest(state);
                }
                else
                {
                    if (!IsEncryptedMessage(dataReceived[0]))
                    {
                        if (clientState.Ratchets.Count == 0)
                        {
                            if (IsInitializationMessage(dataReceived[0]))
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
                        else
                        {
                            throw new InvalidOperationException("Unexpected initialization message");
                        }
                    }
                    else
                    {
                        // step 3: receive first message from server
                        ReceiveFirstResponse(clientState, dataReceived);
                        // initialization completed successfully.
                        sendback = null;
                    }
                }
            }
            else
            {
                Log.Verbose("\n\n###SERVER");
                var serverState = (ServerState)state;

                if (dataReceived == null) throw new InvalidOperationException("Only the client can send initialization without having received a response first");

                if (!IsEncryptedMessage(dataReceived[0]))
                {
                    if (IsInitializationMessage(dataReceived[0]))
                    {
                        // step 1: client init request
                        var (initializationNonce, remoteEcdhForInit) = ReceiveInitializationRequest(serverState, dataReceived);
                        sendback = SendInitializationResponse(serverState, initializationNonce, remoteEcdhForInit);
                    }
                    else
                    {
                        throw new InvalidOperationException("Unexpected message received during server initialization");
                    }
                }
                else
                {
                    // step 2: first message from client
                    ReceiveFirstMessage(serverState, dataReceived);
                    sendback = SendFirstResponse(serverState);
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

        private MessageInfo SendSingle(State state, ArraySegment<byte> payload, bool pad)
        {
            bool canIncludeEcdh = payload.Count <= Configuration.Mtu - 48;
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
                Messages = new[] { ConstructMessage(payload, pad, canIncludeEcdh, step) }
            };
        }

        private MessageInfo SendInternal(ArraySegment<byte> payload, State state, bool pad)
        {
            if (payload.Count <= MaximumMessageSize)
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

        private static bool IsEncryptedMessage(byte b) => (b & 0b1000_0000) == 0;
        private static bool IsMultipartMessage(byte b) => (b & 0b1100_0000) == 0b1100_0000;
        private static bool IsInitializationMessage(byte b) => (b & 0b1100_0000) == 0b1000_0000;
        private static bool HasEcdh(byte b) => (b & 0b0100_0000) != 0;

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
            var isInitialized = state?.IsInitialized ?? false;
            var isEncrypted = IsEncryptedMessage(data[0]);
            var isMultipart = IsMultipartMessage(data[0]);

            if (!isInitialized || !isEncrypted)
            {
                if (isEncrypted || !isMultipart)
                {
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
                else if (!isEncrypted && isMultipart)
                {
                    var (payload, num, total) = DeconstructUnencryptedMultipartMessagePart(data);
                    var output = _multipart.Ingest(payload, 0, num, total); //seq = 0 is for initialization
                    if (output != null)
                    {
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
                    throw new InvalidOperationException("Unexpected message");
                }
            }
            else
            {
                _multipart.Tick();
                return new ReceiveResult
                {
                    Payload = DeconstructMessage(state, data),
                    ToSendBack = null,
                    ReceivedDataType = ReceivedDataType.Normal
                };
            }
        }

        public ReceiveResult Receive(byte[] data)
        {
            Log.Verbose($"\n\n###{(Configuration.IsClient ? "CLIENT" : "SERVER")} RECEIVE");
            var result = ReceiveInternal(data);
            Log.Verbose($"/###{(Configuration.IsClient ? "CLIENT" : "SERVER")} RECEIVE");
            return result;
        }

        public MessageInfo Send(ArraySegment<byte> payload, bool pad = false)
        {
            Log.Verbose($"\n\n###{(Configuration.IsClient ? "CLIENT" : "SERVER")} SEND");
            var state = LoadState();
            if (!state.IsInitialized)
            {
                throw new InvalidOperationException("The client has not been initialized.");
            }

            if (pad == false && payload.Count < MinimumMessageSize)
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
