using System;
using System.Collections.Generic;

namespace MicroRatchet
{
    public class MicroRatchetClient
    {
        public const int InitializationNonceSize = 16;
        public const int NonceSize = 4;
        public const int MacSize = 12;
        public const int EcPntSize = 32;
        public const int SignatureSize = EcPntSize * 2;
        public const int MinimumPayloadSize = InitializationNonceSize;
        public const int MinimumOverhead = NonceSize + MacSize; // 16
        public const int OverheadWithEcdh = MinimumOverhead + EcPntSize; // 48
        public const int MinimumMessageSize = MinimumPayloadSize + MinimumOverhead;
        public const int MinimumMaximumMessageSize = OverheadWithEcdh + MinimumPayloadSize;
        public const int HeaderIVSize = 16;

        private IDigest Digest => Services.Digest;
        private ISignature Signature => Services.Signature;
        private IRandomNumberGenerator RandomNumberGenerator => Services.RandomNumberGenerator;
        private IKeyAgreementFactory KeyAgreementFactory => Services.KeyAgreementFactory;
        private IAesFactory AesFactory => Services.AesFactory;
        private IKeyDerivation KeyDerivation { get; }
        private IVerifierFactory VerifierFactory => Services.VerifierFactory;
        private IStorageProvider Storage => Services.Storage;
        private State _state;
        private readonly List<(byte[], IAes)> _headerKeyCiphers = new List<(byte[], IAes)>();

        public IServices Services { get; }

        public MicroRatchetConfiguration Configuration { get; }

        public bool IsInitialized => LoadState().IsInitialized;
        public int MaximumMessageSize => Configuration.MaximumMessageSize - MinimumOverhead;

        public MicroRatchetClient(IServices services, MicroRatchetConfiguration config)
        {
            Services = services ?? throw new ArgumentNullException(nameof(services));
            Configuration = config ?? throw new ArgumentNullException(nameof(config));

            KeyDerivation = new AesKdf(Services.AesFactory);

            CheckMtu();
        }

        public MicroRatchetClient(IServices services, bool isClient, int? MaximumMessageSize = null, int? MinimumMessageSize = null)
        {
            Services = services ?? throw new ArgumentNullException(nameof(services));
            Configuration = new MicroRatchetConfiguration
            {
                IsClient = isClient
            };

            if (MaximumMessageSize.HasValue)
            {
                Configuration.MaximumMessageSize = MaximumMessageSize.Value;
            }

            if (MinimumMessageSize.HasValue)
            {
                Configuration.MinimumMessageSize = MinimumMessageSize.Value;
            }

            KeyDerivation = new AesKdf(Services.AesFactory);

            CheckMtu();
        }

        private void CheckMtu()
        {
            var maxtu = Configuration.MaximumMessageSize;
            var mintu = Configuration.MinimumMessageSize;

            // minimum mtu is 64 bytes
            if (maxtu < MinimumMaximumMessageSize) throw new InvalidOperationException("The Maxiumum Message Size is not big enough to facilitate key exchange");
            if (mintu < MinimumMessageSize) throw new InvalidOperationException("The Minimum Message Size is not big enough for header and authentication code.");
            if (mintu > maxtu) throw new InvalidOperationException("The Minimum Message Size cannot be greater than the Maxiumum Message Size.");
        }

        private IAes GetHeaderKeyCipher(byte[] key)
        {
            foreach ((byte[], IAes) hkc in _headerKeyCiphers)
            {
                if (hkc.Item1.Matches(key)) return hkc.Item2;
            }

            IAes cipher = AesFactory.GetAes(true, key);
            _headerKeyCiphers.Add((key, cipher));
            if (_headerKeyCiphers.Count > 3) _headerKeyCiphers.RemoveAt(0);
            return cipher;
        }

        private byte[] SendInitializationRequest(State state)
        {
            // message format:
            // nonce(16), pubkey(32), ecdh(32), padding(...), signature(64), mac(12)

            if (!(state is ClientState clientState)) throw new InvalidOperationException("Only the client can send init request.");

            // 16 bytes nonce
            clientState.InitializationNonce = RandomNumberGenerator.Generate(InitializationNonceSize);

            // get the public key
            var pubkey = Signature.PublicKey;

            // generate new ECDH keypair for init message and root key
            IKeyAgreement clientEcdh = KeyAgreementFactory.GenerateNew();
            clientState.LocalEcdhForInit = clientEcdh;

            // nonce(16), <pubkey(32), ecdh(32), signature(64)>, mac(12)
            var initializationMessageSize = InitializationNonceSize + EcPntSize * 4 + MacSize;
            var messageSize = Math.Max(Configuration.MinimumMessageSize, initializationMessageSize);
            var initializationMessageSizeWithSignature = messageSize - MacSize;
            var initializationMessageSizeWithoutSignature = messageSize - MacSize - SignatureSize;
            var signatureOffset = messageSize - MacSize - SignatureSize;
            var message = new byte[messageSize];
            Array.Copy(clientState.InitializationNonce, 0, message, 0, InitializationNonceSize);
            Array.Copy(pubkey, 0, message, InitializationNonceSize, EcPntSize);
            Array.Copy(clientEcdh.GetPublicKey(), 0, message, InitializationNonceSize + EcPntSize, EcPntSize);

            // sign the message
            var digest = Digest.ComputeDigest(message, 0, initializationMessageSizeWithoutSignature);
            Array.Copy(Signature.Sign(digest), 0, message, signatureOffset, SignatureSize);

            // encrypt the message with the application key
            var cipher = new AesCtrMode(AesFactory.GetAes(true, Configuration.ApplicationKey), clientState.InitializationNonce);
            var encryptedPayload = cipher.Process(message, InitializationNonceSize, initializationMessageSizeWithSignature - InitializationNonceSize);
            Array.Copy(encryptedPayload, 0, message, InitializationNonceSize, initializationMessageSizeWithSignature - InitializationNonceSize);

            // calculate mac
            var Mac = new Poly(AesFactory);
            Mac.Init(Configuration.ApplicationKey, clientState.InitializationNonce, MacSize * 8);
            Mac.Process(message, 0, initializationMessageSizeWithSignature);
            var mac = Mac.Compute();
            Array.Copy(mac, 0, message, initializationMessageSizeWithSignature, MacSize);
            return message;
        }

        private (ArraySegment<byte> initializationNonce, ArraySegment<byte> remoteEcdhForInit) ReceiveInitializationRequest(State state, byte[] data)
        {
            if (!(state is ServerState serverState)) throw new InvalidOperationException("Only the server can receive an init request.");

            // nonce(16), pubkey(32), ecdh(32), pading(...), signature(64), mac(12)
            var messageSize = data.Length;
            var macOffset = messageSize - MacSize;
            var initializationNonce = new ArraySegment<byte>(data, 0, InitializationNonceSize);

            // decrypt the message
            var cipher = new AesCtrMode(AesFactory.GetAes(true, Configuration.ApplicationKey), initializationNonce);
            var decryptedPayload = cipher.Process(data, InitializationNonceSize, macOffset - InitializationNonceSize);
            Array.Copy(decryptedPayload, 0, data, InitializationNonceSize, decryptedPayload.Length);

            var clientPublicKeyOffset = InitializationNonceSize;
            var remoteEcdhOffset = InitializationNonceSize + EcPntSize;
            var clientPublicKey = new ArraySegment<byte>(data, clientPublicKeyOffset, EcPntSize);
            var remoteEcdhForInit = new ArraySegment<byte>(data, remoteEcdhOffset, EcPntSize);
            var signedMessage = new ArraySegment<byte>(data, 0, macOffset);

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
            IVerifier verifier = VerifierFactory.Create(clientPublicKey);

            if (!verifier.VerifySignedMessage(Digest, signedMessage))
            {
                throw new InvalidOperationException("The signature was invalid");
            }

            return (initializationNonce, remoteEcdhForInit);
        }

        private byte[] SendInitializationResponse(State state, ArraySegment<byte> initializationNonce, ArraySegment<byte> remoteEcdhForInit)
        {
            // message format:
            // new nonce(16), ecdh pubkey(32),
            // <nonce from init request(4), server pubkey(32), 
            // new ecdh pubkey(32) x2, Padding(...), signature(64)>, mac(12) = 236 bytes

            if (!(state is ServerState serverState)) throw new InvalidOperationException("Only the server can send init response.");

            // generate a nonce and new ecdh parms
            var serverNonce = RandomNumberGenerator.Generate(InitializationNonceSize);
            serverState.NextInitializationNonce = serverNonce;
            IKeyAgreement rootPreEcdh = KeyAgreementFactory.GenerateNew();
            var rootPreEcdhPubkey = rootPreEcdh.GetPublicKey();

            // generate server ECDH for root key and root key
            var rootPreKey = rootPreEcdh.DeriveKey(remoteEcdhForInit);
            rootPreKey = Digest.ComputeDigest(rootPreKey);
            var genKeys = KeyDerivation.GenerateKeys(rootPreKey, serverNonce, 3, EcPntSize);
            serverState.RootKey = genKeys[0];
            serverState.FirstSendHeaderKey = genKeys[1];
            serverState.FirstReceiveHeaderKey = genKeys[2];

            // generate two server ECDH. One for ratchet 0 sending key and one for the next
            // this is enough for the server to generate a receiving chain key and sending
            // chain key as soon as the client sends a sending chain key
            IKeyAgreement serverEcdhRatchet0 = KeyAgreementFactory.GenerateNew();
            serverState.LocalEcdhRatchetStep0 = serverEcdhRatchet0;
            IKeyAgreement serverEcdhRatchet1 = KeyAgreementFactory.GenerateNew();
            serverState.LocalEcdhRatchetStep1 = serverEcdhRatchet1;

            var minimumMessageSize = InitializationNonceSize * 2 + EcPntSize * 6 + MacSize;
            var entireMessageSize = Math.Max(Configuration.MinimumMessageSize, minimumMessageSize);
            var entireMessageWithoutMacSize = entireMessageSize - MacSize;
            var entireMessageWithoutMacOrSignatureSize = entireMessageWithoutMacSize - SignatureSize;
            var encryptedPayloadOffset = InitializationNonceSize + EcPntSize;
            var encryptedPayloadSize = entireMessageWithoutMacSize - encryptedPayloadOffset;
            var macOffset = entireMessageSize - MacSize;

            // construct the message
            var message = new byte[entireMessageSize];
            Array.Copy(serverNonce, 0, message, 0, InitializationNonceSize);
            Array.Copy(rootPreEcdhPubkey, 0, message, InitializationNonceSize, EcPntSize);

            // construct the to-be-encrypted part
            var rre0 = serverEcdhRatchet0.GetPublicKey();
            var rre1 = serverEcdhRatchet1.GetPublicKey();
            Array.Copy(initializationNonce.Array, initializationNonce.Offset, message, encryptedPayloadOffset, InitializationNonceSize);
            Array.Copy(Signature.PublicKey, 0, message, encryptedPayloadOffset + InitializationNonceSize, EcPntSize);
            Array.Copy(rre0, 0, message, encryptedPayloadOffset + InitializationNonceSize + EcPntSize, EcPntSize);
            Array.Copy(rre1, 0, message, encryptedPayloadOffset + InitializationNonceSize + EcPntSize * 2, EcPntSize);

            // sign the message
            var digest = Digest.ComputeDigest(message, 0, entireMessageWithoutMacOrSignatureSize);
            Array.Copy(Signature.Sign(digest), 0, message, entireMessageWithoutMacOrSignatureSize, SignatureSize);

            // encrypt the message
            var cipher = new AesCtrMode(AesFactory.GetAes(true, rootPreKey), serverNonce);
            var encryptedPayload = cipher.Process(message, encryptedPayloadOffset, encryptedPayloadSize);
            Array.Copy(encryptedPayload, 0, message, encryptedPayloadOffset, encryptedPayloadSize);

            // encrypt the header
            cipher = new AesCtrMode(AesFactory.GetAes(true, Configuration.ApplicationKey), encryptedPayload, encryptedPayloadSize - HeaderIVSize, HeaderIVSize);
            var encryptedHeader = cipher.Process(message, 0, encryptedPayloadOffset);
            Array.Copy(encryptedHeader, 0, message, 0, encryptedPayloadOffset);

            // calculate mac
            var Mac = new Poly(AesFactory);
            Mac.Init(Configuration.ApplicationKey, encryptedHeader, 0, InitializationNonceSize, MacSize * 8);
            Mac.Process(message, 0, macOffset);
            var mac = Mac.Compute();
            Array.Copy(mac, 0, message, macOffset, MacSize);

            return message;
        }

        private void ReceiveInitializationResponse(State state, byte[] data)
        {
            if (!(state is ClientState clientState)) throw new InvalidOperationException("Only the client can receive an init response.");

            var messageSize = data.Length;
            var macOffset = messageSize - MacSize;
            var headerIvOffset = macOffset - HeaderIVSize;
            var headerSize = InitializationNonceSize + EcPntSize;
            var payloadSize = messageSize - headerSize - MacSize;

            // decrypt header
            var cipher = new AesCtrMode(AesFactory.GetAes(true, Configuration.ApplicationKey), data, headerIvOffset, HeaderIVSize);
            var decryptedHeader = cipher.Process(data, 0, headerSize);
            Array.Copy(decryptedHeader, 0, data, 0, headerSize);

            // new nonce(16), ecdh pubkey(32), <nonce(4), server pubkey(32), 
            // new ecdh pubkey(32) x2, signature(64)>, mac(12)
            var nonce = new ArraySegment<byte>(data, 0, InitializationNonceSize);
            var rootEcdhKey = new ArraySegment<byte>(data, InitializationNonceSize, EcPntSize);
            var encryptedPayload = new ArraySegment<byte>(data, headerSize, payloadSize);

            // decrypt payload
            IKeyAgreement rootEcdh = clientState.LocalEcdhForInit;
            var rootPreKey = rootEcdh.DeriveKey(rootEcdhKey);
            rootPreKey = Digest.ComputeDigest(rootPreKey);
            cipher = new AesCtrMode(AesFactory.GetAes(true, rootPreKey), nonce);
            var decryptedPayload = cipher.Process(encryptedPayload);
            Array.Copy(decryptedPayload, 0, data, headerSize, payloadSize);

            // extract some goodies
            var oldNonce = new ArraySegment<byte>(data, headerSize, InitializationNonceSize);
            var serverPubKey = new ArraySegment<byte>(data, headerSize + InitializationNonceSize, EcPntSize);
            var remoteRatchetEcdh0 = new ArraySegment<byte>(data, headerSize + InitializationNonceSize + EcPntSize, EcPntSize);
            var remoteRatchetEcdh1 = new ArraySegment<byte>(data, headerSize + InitializationNonceSize + EcPntSize * 2, EcPntSize);

            // make sure the nonce sent back by the server (which is encrypted and signed)
            // matches the nonce we sent previously
            if (!oldNonce.Matches(clientState.InitializationNonce))
            {
                throw new InvalidOperationException("Nonce did not match");
            }

            // verify that the signature matches
            IVerifier verifier = VerifierFactory.Create(serverPubKey);
            if (!verifier.VerifySignedMessage(Digest, new ArraySegment<byte>(data, 0, payloadSize + headerSize)))
            {
                throw new InvalidOperationException("The signature was invalid");
            }

            // store the new nonce we got from the server
            clientState.InitializationNonce = nonce.ToArray();
            Log.Verbose($"storing iniitlizaionta nonce: {Log.ShowBytes(nonce)}");

            // we now have enough information to construct our double ratchet
            IKeyAgreement localStep0EcdhRatchet = KeyAgreementFactory.GenerateNew();
            IKeyAgreement localStep1EcdhRatchet = KeyAgreementFactory.GenerateNew();

            // initialize client root key and ecdh ratchet
            var genKeys = KeyDerivation.GenerateKeys(rootPreKey, clientState.InitializationNonce, 3, 32);
            var rootKey = genKeys[0];
            var receiveHeaderKey = genKeys[1];
            var sendHeaderKey = genKeys[2];

            clientState.Ratchets.Add(EcdhRatchetStep.InitializeClient(KeyDerivation, Digest, rootKey,
                remoteRatchetEcdh0, remoteRatchetEcdh1, localStep0EcdhRatchet,
                receiveHeaderKey, sendHeaderKey,
                localStep1EcdhRatchet));

            clientState.LocalEcdhForInit = null;
        }

        private byte[] SendFirstClientMessage(State state)
        {
            if (!(state is ClientState clientState)) throw new InvalidOperationException("Only the client can send the first client message.");

            return ConstructMessage(new ArraySegment<byte>(clientState.InitializationNonce), true, clientState.Ratchets.SecondToLast);
        }

        private void ReceiveFirstMessage(State state, byte[] payload, EcdhRatchetStep ecdhRatchetStep)
        {
            if (!(state is ServerState serverState)) throw new InvalidOperationException("Only the server can receive the first client message.");

            var data = DeconstructMessage(state, payload, serverState.FirstReceiveHeaderKey, ecdhRatchetStep, false);
            if (data.Length < InitializationNonceSize || !serverState.NextInitializationNonce.Matches(data, 0, InitializationNonceSize))
            {
                throw new InvalidOperationException("The first received message did not contain the correct payload");
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
            return ConstructMessage(new ArraySegment<byte>(payload), false, serverState.Ratchets.Last);
        }

        private void ReceiveFirstResponse(State state, byte[] data, byte[] headerKey, EcdhRatchetStep ecdhRatchetStep)
        {
            if (!(state is ClientState clientState)) throw new InvalidOperationException("Only the client can receive the first response.");

            var contents = DeconstructMessage(state, data, headerKey, ecdhRatchetStep, false);
            if (contents == null || contents.Length < InitializationNonceSize)
            {
                throw new InvalidOperationException("The first response from the server was not valid");
            }

            var nonce = new ArraySegment<byte>(contents, 0, InitializationNonceSize);
            if (!nonce.Matches(clientState.InitializationNonce))
            {
                throw new InvalidOperationException("The first response from the server did not contain the correct nonce");
            }

            clientState.InitializationNonce = null;
        }

        private byte[] ConstructMessage(ArraySegment<byte> message, bool includeEcdh, EcdhRatchetStep step)
        {
            // message format:
            // <nonce (4)>, <payload, padding>, mac(12)
            // <nonce (4), ecdh (32)>, <payload, padding>, mac(12)

            // get the payload key and nonce
            (var payloadKey, var messageNumber) = step.SendingChain.RatchetForSending(KeyDerivation);
            var nonce = BigEndianBitConverter.GetBytes(messageNumber);

            // make sure the first bit is not set as we use that bit to indicate
            // the presence of new ECDH parameters
            if ((nonce[0] & 0b1000_0000) != 0)
            {
                throw new InvalidOperationException($"The message number is too big. Cannot encrypt more than {((uint)1 << 31) - 1} messages without exchanging keys");
            }

            // calculate some sizes
            var headerSize = NonceSize + (includeEcdh ? EcPntSize : 0);
            var overhead = headerSize + MacSize;
            var messageSize = message.Count;
            var maxMessageSize = Configuration.MaximumMessageSize - overhead;
            var minPayloadSize = Configuration.MinimumMessageSize - overhead;

            // build the payload: <payload, padding>
            ArraySegment<byte> payload;
            if (messageSize < minPayloadSize)
            {
                payload = new ArraySegment<byte>(new byte[minPayloadSize]);
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
            var icipher = new AesCtrMode(AesFactory.GetAes(true, payloadKey), nonce);
            var encryptedPayload = icipher.Process(payload);

            // build the header: <nonce(4), ecdh(32)?>
            var header = new byte[headerSize];
            Array.Copy(nonce, header, NonceSize);
            if (includeEcdh)
            {
                var ratchetPublicKey = step.GetPublicKey(KeyAgreementFactory);
                Array.Copy(ratchetPublicKey, 0, header, nonce.Length, ratchetPublicKey.Length);

                // set the has ecdh bit
                header[0] |= 0b1000_0000;
            }
            else
            {
                // clear the has ecdh bit
                header[0] &= 0b0111_1111;
            }

            // encrypt the header using the header key and using the
            // last MinMessageSize bytes of the message as the nonce.
            var headerEncryptionNonce = new ArraySegment<byte>(encryptedPayload, encryptedPayload.Length - HeaderIVSize, HeaderIVSize);
            var hcipher = new AesCtrMode(GetHeaderKeyCipher(step.SendHeaderKey), headerEncryptionNonce);
            var encryptedHeader = hcipher.Process(header);

            // mac the message: <header>, <payload>, mac(12)
            // the mac uses the header encryption derived key (all 32 bytes)
            var Mac = new Poly(AesFactory);
            var maciv = new byte[16];
            var epl = encryptedPayload.Length;
            var ehl = encryptedHeader.Length;
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
            var result = new byte[ehl + epl + mac.Length];
            Array.Copy(encryptedHeader, 0, result, 0, ehl);
            Array.Copy(encryptedPayload, 0, result, ehl, epl);
            Array.Copy(mac, 0, result, ehl + epl, mac.Length);
            return result;
        }

        private (byte[] headerKeyUsed, EcdhRatchetStep ratchetUsed, bool usedNextHeaderKey, bool usedApplicationKey) InterpretMessageMAC(State state, byte[] payload, byte[] overrideHeaderKey = null)
        {
            // get some basic parts
            var messageSize = payload.Length;
            var payloadExceptMac = new ArraySegment<byte>(payload, 0, messageSize - MacSize);
            var mac = new ArraySegment<byte>(payload, messageSize - MacSize, MacSize);

            // find the header key by checking the mac
            var maciv = new byte[16];
            Array.Copy(payload, maciv, 16);
            var Mac = new Poly(AesFactory);
            var usedNextHeaderKey = false;
            var usedApplicationHeaderKey = false;
            byte[] headerKey = null;
            EcdhRatchetStep ratchetUsed = null;
            if (overrideHeaderKey != null)
            {
                headerKey = overrideHeaderKey;
                Mac.Init(headerKey, maciv, MacSize * 8);
                Mac.Process(payloadExceptMac);
                var compareMac = Mac.Compute();
                if (!mac.Matches(compareMac))
                {
                    throw new InvalidOperationException("Could not decrypt the incoming message with given header key");
                }
            }
            else
            {
                // if we are initialized check the mac using ratchet receive header keys.
                if (state.Ratchets != null && !state.Ratchets.IsEmpty)
                {
                    foreach (EcdhRatchetStep ratchet in state.Ratchets.Enumerate())
                    {
                        headerKey = ratchet.ReceiveHeaderKey;
                        Mac.Init(headerKey, maciv, MacSize * 8);
                        Mac.Process(payloadExceptMac);
                        var compareMac = Mac.Compute();
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
                }

                if (ratchetUsed == null)
                {
                    // we're either not initialized or this is an initialization message.
                    // To determine that we mac using the application key
                    headerKey = Configuration.ApplicationKey;
                    Mac.Init(headerKey, maciv, MacSize * 8);
                    Mac.Process(payloadExceptMac);
                    var compareMac = Mac.Compute();
                    if (mac.Matches(compareMac))
                    {
                        usedApplicationHeaderKey = true;
                    }
                    else
                    {
                        headerKey = null;
                    }
                }
            }

            return (headerKey, ratchetUsed, usedNextHeaderKey, usedApplicationHeaderKey);
        }

        private byte[] DeconstructMessage(State state, byte[] payload, byte[] headerKey, EcdhRatchetStep ratchetUsed, bool usedNextHeaderKey)
        {
            var messageSize = payload.Length;
            var encryptedNonce = new ArraySegment<byte>(payload, 0, NonceSize);

            // decrypt the nonce
            var headerEncryptionNonce = new ArraySegment<byte>(payload, payload.Length - MacSize - HeaderIVSize, HeaderIVSize);
            var hcipher = new AesCtrMode(GetHeaderKeyCipher(headerKey), headerEncryptionNonce);
            var decryptedNonce = hcipher.Process(encryptedNonce);

            // get the ecdh bit
            var hasEcdh = (decryptedNonce[0] & 0b1000_0000) != 0;
            decryptedNonce[0] &= 0b0111_1111;

            // extract ecdh if needed
            var step = BigEndianBitConverter.ToInt32(decryptedNonce);
            if (hasEcdh)
            {
                var clientEcdhPublic = new ArraySegment<byte>(hcipher.Process(new ArraySegment<byte>(payload, NonceSize, EcPntSize)));

                if (ratchetUsed == null)
                {
                    // an override header key was used.
                    // this means we have to initialize the ratchet
                    if (!(state is ServerState serverState)) throw new InvalidOperationException("Only the server can initialize a ratchet.");
                    ratchetUsed = EcdhRatchetStep.InitializeServer(KeyDerivation, Digest,
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
                        IKeyAgreement newEcdh = KeyAgreementFactory.GenerateNew();

                        // this is the hottest line in the deconstruct process:
                        EcdhRatchetStep newRatchet = ratchetUsed.Ratchet(KeyAgreementFactory, KeyDerivation, Digest, clientEcdhPublic, newEcdh);
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
            (var key, var _) = ratchetUsed.ReceivingChain.RatchetForReceiving(KeyDerivation, step);

            // get the encrypted payload
            var payloadOffset = hasEcdh ? NonceSize + EcPntSize : NonceSize;
            var encryptedPayload = new ArraySegment<byte>(payload, payloadOffset, messageSize - payloadOffset - MacSize);

            // decrypt the inner payload
            var icipher = new AesCtrMode(AesFactory.GetAes(true, key), decryptedNonce);
            var decryptedInnerPayload = icipher.Process(encryptedPayload);
            return decryptedInnerPayload;
        }

        private byte[] ProcessInitializationInternal(State state, byte[] dataReceived, byte[] headerKeyUsed, EcdhRatchetStep ecdhRatchetStep, bool usedApplicationHeaderKey)
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
                    if (usedApplicationHeaderKey)
                    {
                        if (clientState.Ratchets.Count == 0)
                        {
                            // step 2: init response from server
                            ReceiveInitializationResponse(clientState, dataReceived);
                            sendback = SendFirstClientMessage(clientState);
                        }
                        else
                        {
                            throw new InvalidOperationException("Unexpected initialization message");
                        }
                    }
                    else
                    {
                        // step 3: receive first message from server
                        ReceiveFirstResponse(clientState, dataReceived, headerKeyUsed, ecdhRatchetStep);
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

                if (usedApplicationHeaderKey)
                {
                    // step 1: client init request
                    (ArraySegment<byte> initializationNonce, ArraySegment<byte> remoteEcdhForInit) = ReceiveInitializationRequest(serverState, dataReceived);
                    sendback = SendInitializationResponse(serverState, initializationNonce, remoteEcdhForInit);
                }
                else
                {
                    // step 2: first message from client
                    ReceiveFirstMessage(serverState, dataReceived, ecdhRatchetStep);
                    sendback = SendFirstResponse(serverState);
                }
            }

            return sendback;
        }

        private byte[] ProcessInitialization(State state, byte[] dataReceived, byte[] headerKeyUsed, EcdhRatchetStep ecdhRatchetStep, bool usedApplicationHeaderKey)
        {
            var sendback = ProcessInitializationInternal(state, dataReceived, headerKeyUsed, ecdhRatchetStep, usedApplicationHeaderKey);

            if (sendback != null)
            {
                if (sendback.Length > Configuration.MaximumMessageSize)
                {
                    throw new InvalidOperationException("The MTU is too small");
                }
                else
                {
                    return sendback;
                }
            }
            else
            {
                return null;
            }
        }

        private byte[] SendSingle(State state, ArraySegment<byte> payload)
        {
            var canIncludeEcdh = payload.Count <= Configuration.MaximumMessageSize - 48;
            EcdhRatchetStep step;
            if (canIncludeEcdh)
            {
                step = state.Ratchets.Last;
            }
            else
            {
                step = state.Ratchets.SecondToLast;
            }

            return ConstructMessage(payload, canIncludeEcdh, step);
        }

        private byte[] SendInternal(ArraySegment<byte> payload, State state)
        {
            if (payload.Count <= MaximumMessageSize)
            {
                return SendSingle(state, payload);
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

        public byte[] InitiateInitialization(bool forceReinitialization = false)
        {
            State state = LoadState();

            if (state != null && state.IsInitialized && !forceReinitialization)
            {
                throw new InvalidOperationException("The client is already initialized");
            }

            if (!Configuration.IsClient)
            {
                throw new InvalidOperationException("only a client can initiate initialization");
            }

            state = InitializeState();

            return ProcessInitialization(state, null, null, null, false);
        }

        private ReceiveResult ReceiveInternal(byte[] data)
        {
            State state = LoadState();

            // check the MAC and get info regarding the message header
            var (headerKeyUsed, ratchetUsed, usedNextHeaderKey, usedApplicationKey) = InterpretMessageMAC(state, data);

            // if the application key was used this is an initialization message
            if (usedApplicationKey || !IsInitialized)
            {
                if (state == null)
                {
                    state = InitializeState();
                }

                var toSendBack = ProcessInitialization(state, data, headerKeyUsed, ratchetUsed, usedApplicationKey);
                return new ReceiveResult
                {
                    ToSendBack = toSendBack
                };
            }
            else
            {
                if (ratchetUsed == null)
                {
                    throw new InvalidOperationException("Could not decrypt incoming message");
                }

                return new ReceiveResult
                {
                    Payload = DeconstructMessage(state, data, headerKeyUsed, ratchetUsed, usedNextHeaderKey)
                };
            }
        }

        public ReceiveResult Receive(byte[] data)
        {
            Log.Verbose($"\n\n###{(Configuration.IsClient ? "CLIENT" : "SERVER")} RECEIVE");
            ReceiveResult result = ReceiveInternal(data);
            Log.Verbose($"/###{(Configuration.IsClient ? "CLIENT" : "SERVER")} RECEIVE");
            return result;
        }

        public byte[] Send(ArraySegment<byte> payload)
        {
            Log.Verbose($"\n\n###{(Configuration.IsClient ? "CLIENT" : "SERVER")} SEND");
            State state = LoadState();
            if (!state.IsInitialized)
            {
                throw new InvalidOperationException("The client has not been initialized.");
            }

            var response = SendInternal(payload, state);
            Log.Verbose($"###/{(Configuration.IsClient ? "CLIENT" : "SERVER")} SEND");
            return response;
        }

        public void SaveState()
        {
            if (_state != null)
            {
                _state.Store(Storage, Configuration.NumberOfRatchetsToKeep);
            }
            else
            {
                System.IO.Stream storage = Storage.LockCold();
                var bytes = new byte[storage.Length];
                storage.Write(bytes, 0, bytes.Length);
            }
        }
    }
}
