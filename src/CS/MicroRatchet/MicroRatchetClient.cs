using System;
using System.Collections.Generic;
using System.IO;

namespace MicroRatchet
{
    public sealed class MicroRatchetClient : IDisposable
    {
        public const int InitializationNonceSize = 16;
        public const int NonceSize = 4;
        public const int MacSize = 12;
        public const int EcNumSize = 32;
        public const int SignatureSize = EcNumSize * 2;
        public const int MinimumPayloadSize = InitializationNonceSize;
        public const int MinimumOverhead = NonceSize + MacSize; // 16
        public const int OverheadWithEcdh = MinimumOverhead + EcNumSize; // 48
        public const int MinimumMessageSize = MinimumPayloadSize + MinimumOverhead;
        public const int MinimumMaximumMessageSize = OverheadWithEcdh + MinimumPayloadSize;
        public const int HeaderIVSize = 16;

        public static readonly int[] ExpectedBlockCipherKeySizes = new[] { 16, 32 };
        public const int ExpectedBlockSize = 16;
        public const int ExpectedDigestSize = 32;
        public const int ExpectedPublicKeySize = 32;
        public const int ExpectedPrivateKeySize = 32;
        public const int ExpectedSignatureSize = 64;

        private IDigest Digest => Services.Digest;
        private ISignature Signature => Services.Signature;
        private IRandomNumberGenerator RandomNumberGenerator => Services.RandomNumberGenerator;
        private IKeyAgreementFactory KeyAgreementFactory => Services.KeyAgreementFactory;
        private IAesFactory AesFactory => Services.AesFactory;
        private IKeyDerivation KeyDerivation { get; }
        private IVerifierFactory VerifierFactory => Services.VerifierFactory;

        private State state;

        private readonly List<(byte[], IAes)> _headerKeyCiphers = new List<(byte[], IAes)>();

        public IServices Services { get; }

        public MicroRatchetConfiguration Configuration { get; }

        public bool IsInitialized => state.IsInitialized;

        public int MaximumMessageSize => Configuration.MaximumMessageSize - MinimumOverhead;

        public MicroRatchetClient(IServices services, MicroRatchetConfiguration config, Stream stateData)
        {
            Services = services ?? throw new ArgumentNullException(nameof(services));
            Configuration = config ?? throw new ArgumentNullException(nameof(config));

            KeyDerivation = new AesKdf(Services.AesFactory);

            LoadState(stateData);

            VerifyServices();
            CheckMtu();
        }

        public MicroRatchetClient(IServices services, bool isClient, int? MaximumMessageSize = null, int? MinimumMessageSize = null, Stream stateData = null, byte[] stateBytes = null)
        {
            Services = services ?? throw new ArgumentNullException(nameof(services));

            if (stateData != null && stateBytes != null)
            {
                throw new InvalidOperationException("stateData and stateBytes cannot both be specified");
            }

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

            if (stateData != null)
            {
                LoadState(stateData);
            }
            else if (stateBytes != null)
            {
                using var ms = new MemoryStream(stateBytes);
                LoadState(ms);
            }
            else
            {
                InitializeState();
            }

            KeyDerivation = new AesKdf(Services.AesFactory);

            CheckMtu();
        }

        private void LoadState(Stream stateData)
        {
            if (stateData != null)
            {
                state = Configuration.IsClient
                    ? (State)ClientState.Load(stateData, KeyAgreementFactory, 32)
                    : ServerState.Load(stateData, KeyAgreementFactory, 32);
            }
            else
            {
                InitializeState();
            }
        }

        public void SaveState(Stream destination)
        {
            if (destination == null) throw new ArgumentNullException(nameof(destination));

            state.Store(destination, Configuration.NumberOfRatchetsToKeep);
        }

        private void InitializeState()
        {
            state?.Dispose();
            state = State.Initialize(Configuration.IsClient, 32);
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

        private void VerifyServices()
        {
            // check that the block cipher supports all the key sizes we need
            var keySizes = Services.AesFactory.GetAcceptedKeySizes();
            bool hasAcceptedKeySizes = keySizes.Length >= ExpectedBlockCipherKeySizes.Length;
            if (hasAcceptedKeySizes)
            {
                for (int i = 0; i < ExpectedBlockCipherKeySizes.Length; i++)
                {
                    var keysize = ExpectedBlockCipherKeySizes[i];
                    bool found = false;
                    for (int j = 0; j < keySizes.Length; j++)
                    {
                        if (keySizes[j] == keysize)
                        {
                            found = true;
                            break;
                        }
                    }

                    if (!found)
                    {
                        hasAcceptedKeySizes = false;
                        break;
                    }
                }
            }

            if (!hasAcceptedKeySizes) throw new InvalidOperationException($"The block cipher factory does not support the required key sizes of {string.Join(" and ", ExpectedBlockCipherKeySizes)} bytes");
            if (Services.AesFactory.BlockSize != ExpectedBlockSize) throw new InvalidOperationException($"The block cipher block size did not match the expected {ExpectedBlockSize} bytes");
            if (Services.Digest.DigestSize != ExpectedDigestSize) throw new InvalidOperationException($"The digest size differs from the expected size of {ExpectedDigestSize} bytes");
            if (Services.KeyAgreementFactory.PublicKeySize != ExpectedPublicKeySize) throw new InvalidOperationException($"The key agreement public key size differs from the expected size of {ExpectedPublicKeySize} bytes");
            if (Services.Signature.PublicKeySize != ExpectedPublicKeySize) throw new InvalidOperationException($"The signature public key size differs from the expected size of {ExpectedPublicKeySize} bytes");
            if (Services.Signature.SignatureSize != ExpectedSignatureSize) throw new InvalidOperationException($"The signature size differs from the expected size of {ExpectedSignatureSize} bytes");
            if (Services.VerifierFactory.SignatureSize != ExpectedSignatureSize) throw new InvalidOperationException($"The verifier signature size differs from the expected size of {ExpectedSignatureSize} bytes");
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
            var pubkey = Signature.GetPublicKey();

            // generate new ECDH keypair for init message and root key
            IKeyAgreement clientEcdh = KeyAgreementFactory.GenerateNew();
            clientState.LocalEcdhForInit = clientEcdh;

            // nonce(16), <pubkey(32), ecdh(32), signature(64)>, mac(12)
            var initializationMessageSize = InitializationNonceSize + EcNumSize * 4 + MacSize;
            var messageSize = Math.Max(Configuration.MinimumMessageSize, initializationMessageSize);
            var initializationMessageSizeWithSignature = messageSize - MacSize;
            var initializationMessageSizeWithoutSignature = messageSize - MacSize - SignatureSize;
            var signatureOffset = messageSize - MacSize - SignatureSize;
            var message = new byte[messageSize];
            Array.Copy(clientState.InitializationNonce, 0, message, 0, InitializationNonceSize);
            Array.Copy(pubkey, 0, message, InitializationNonceSize, EcNumSize);
            Array.Copy(clientEcdh.GetPublicKey(), 0, message, InitializationNonceSize + EcNumSize, EcNumSize);

            // sign the message
            var digest = Digest.ComputeDigest(message, 0, initializationMessageSizeWithoutSignature);
            Array.Copy(Signature.Sign(digest), 0, message, signatureOffset, SignatureSize);

            // encrypt the message with the application key
            var cipher = new AesCtrMode(AesFactory.GetAes(true, Configuration.ApplicationKey), clientState.InitializationNonce);
            var encryptedPayload = cipher.Process(message, InitializationNonceSize, initializationMessageSizeWithSignature - InitializationNonceSize);
            Array.Copy(encryptedPayload, 0, message, InitializationNonceSize, initializationMessageSizeWithSignature - InitializationNonceSize);

            // calculate mac
            var Mac = new Poly(AesFactory);
            Mac.Init(Configuration.ApplicationKey, clientState.InitializationNonce, MacSize);
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
            var remoteEcdhOffset = InitializationNonceSize + EcNumSize;
            var clientPublicKey = new ArraySegment<byte>(data, clientPublicKeyOffset, EcNumSize);
            var remoteEcdhForInit = new ArraySegment<byte>(data, remoteEcdhOffset, EcNumSize);
            var signedMessage = new ArraySegment<byte>(data, 0, macOffset);

            if (serverState.ClientPublicKey != null)
            {
                if (!serverState.ClientPublicKey.Matches(clientPublicKey))
                {
                    throw new InvalidOperationException("The server was initialized before with a different public key");
                }
                else if (serverState.ClientInitializationNonce != null && initializationNonce.Matches(serverState.ClientInitializationNonce))
                {
                    throw new InvalidOperationException("The server was initialized before with the same nonce");
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

            serverState.ClientInitializationNonce = initializationNonce.ToArray();

            IVerifier verifier = VerifierFactory.Create(clientPublicKey);

            if (!verifier.VerifySignedMessage(Digest, signedMessage))
            {
                throw new InvalidOperationException("The signature was invalid");
            }

            serverState.ClientPublicKey = clientPublicKey.ToArray();
            return (initializationNonce, remoteEcdhForInit);
        }

        private byte[] SendInitializationResponse(State state, ArraySegment<byte> initializationNonce, ArraySegment<byte> remoteEcdhForInit)
        {
            // message format:
            // new nonce(16), ecdh pubkey(32),
            // <nonce from init request(16), server pubkey(32), 
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
            var genKeys = KeyDerivation.GenerateKeys(rootPreKey, serverNonce, 3, EcNumSize);
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

            var minimumMessageSize = InitializationNonceSize * 2 + EcNumSize * 6 + MacSize;
            var entireMessageSize = Math.Max(Configuration.MinimumMessageSize, minimumMessageSize);
            var macOffset = entireMessageSize - MacSize;
            var entireMessageWithoutMacOrSignatureSize = macOffset - SignatureSize;
            var encryptedPayloadOffset = InitializationNonceSize + EcNumSize;
            var encryptedPayloadSize = macOffset - encryptedPayloadOffset;

            // construct the message
            var message = new byte[entireMessageSize];
            Array.Copy(serverNonce, 0, message, 0, InitializationNonceSize);
            Array.Copy(rootPreEcdhPubkey, 0, message, InitializationNonceSize, EcNumSize);

            // construct the to-be-encrypted part
            var rre0 = serverEcdhRatchet0.GetPublicKey();
            var rre1 = serverEcdhRatchet1.GetPublicKey();
            Array.Copy(initializationNonce.Array, initializationNonce.Offset, message, encryptedPayloadOffset, InitializationNonceSize);
            Array.Copy(Signature.GetPublicKey(), 0, message, encryptedPayloadOffset + InitializationNonceSize, EcNumSize);
            Array.Copy(rre0, 0, message, encryptedPayloadOffset + InitializationNonceSize + EcNumSize, EcNumSize);
            Array.Copy(rre1, 0, message, encryptedPayloadOffset + InitializationNonceSize + EcNumSize * 2, EcNumSize);

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
            Mac.Init(Configuration.ApplicationKey, encryptedHeader, 0, InitializationNonceSize, MacSize);
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
            var headerSize = InitializationNonceSize + EcNumSize;
            var payloadSize = messageSize - headerSize - MacSize;

            // decrypt header
            var cipher = new AesCtrMode(AesFactory.GetAes(true, Configuration.ApplicationKey), data, headerIvOffset, HeaderIVSize);
            var decryptedHeader = cipher.Process(data, 0, headerSize);
            Array.Copy(decryptedHeader, 0, data, 0, headerSize);

            // new nonce(16), ecdh pubkey(32), <nonce(16), server pubkey(32), 
            // new ecdh pubkey(32) x2, signature(64)>, mac(12)
            var nonce = new ArraySegment<byte>(data, 0, InitializationNonceSize);
            var rootEcdhKey = new ArraySegment<byte>(data, InitializationNonceSize, EcNumSize);
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
            var serverPubKey = new ArraySegment<byte>(data, headerSize + InitializationNonceSize, EcNumSize);
            var remoteRatchetEcdh0 = new ArraySegment<byte>(data, headerSize + InitializationNonceSize + EcNumSize, EcNumSize);
            var remoteRatchetEcdh1 = new ArraySegment<byte>(data, headerSize + InitializationNonceSize + EcNumSize * 2, EcNumSize);

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

            // keep the server public key around
            clientState.ServerPublicKey = serverPubKey.ToArray();

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
            if (serverState.FirstReceiveHeaderKey == null)
            {
                throw new InvalidOperationException("Invalid message received");
            }

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
            var headerSize = NonceSize + (includeEcdh ? EcNumSize : 0);
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
                var ratchetPublicKey = step.GetPublicKey();
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
            // last 16 bytes of the message as the nonce.
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
            Mac.Init(step.SendHeaderKey, maciv, MacSize);
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
                Mac.Init(headerKey, maciv, MacSize);
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
                        Mac.Init(headerKey, maciv, MacSize);
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
                            Mac.Init(headerKey, maciv, MacSize);
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
                    Mac.Init(headerKey, maciv, MacSize);
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
                var clientEcdhPublic = new ArraySegment<byte>(hcipher.Process(new ArraySegment<byte>(payload, NonceSize, EcNumSize)));

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
                        EcdhRatchetStep newRatchet = ratchetUsed.Ratchet(KeyDerivation, Digest, clientEcdhPublic, newEcdh);
                        state.Ratchets.Add(newRatchet);
                        ratchetUsed = newRatchet;
                    }
                }
            }


            // get the inner payload key from the receive chain
            if (ratchetUsed == null)
            {
                throw new InvalidOperationException("An override header key was used but the message did not contain ECDH parameters");
            }
            (var key, var _) = ratchetUsed.ReceivingChain.RatchetForReceiving(KeyDerivation, step);

            // get the encrypted payload
            var payloadOffset = hasEcdh ? NonceSize + EcNumSize : NonceSize;
            var encryptedPayload = new ArraySegment<byte>(payload, payloadOffset, messageSize - payloadOffset - MacSize);

            // decrypt the inner payload
            var icipher = new AesCtrMode(AesFactory.GetAes(true, key), decryptedNonce);
            var decryptedInnerPayload = icipher.Process(encryptedPayload);
            return decryptedInnerPayload;
        }

        private byte[] ProcessInitialization(State state, byte[] dataReceived, byte[] headerKeyUsed, EcdhRatchetStep ecdhRatchetStep, bool usedApplicationHeaderKey)
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

            if (sendback != null && sendback.Length > Configuration.MaximumMessageSize)
            {
                throw new InvalidOperationException("The MTU is too small");
            }

            return sendback;
        }

        public byte[] InitiateInitialization(bool forceReinitialization = false)
        {
            if (state != null && state.IsInitialized && !forceReinitialization)
            {
                throw new InvalidOperationException("The client is already initialized");
            }

            if (!Configuration.IsClient)
            {
                throw new InvalidOperationException("only a client can initiate initialization");
            }

            InitializeState();

            return ProcessInitialization(state, null, null, null, false);
        }

        public ReceiveResult Receive(byte[] data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (data.Length < MinimumMessageSize) throw new ArgumentException("The message is too small", nameof(data));

            Log.Verbose($"\n\n###{(Configuration.IsClient ? "CLIENT" : "SERVER")} RECEIVE");

            // check the MAC and get info regarding the message header
            var (headerKeyUsed, ratchetUsed, usedNextHeaderKey, usedApplicationKey) = InterpretMessageMAC(state, data);

            // if the application key was used this is an initialization message
            ReceiveResult result;
            if (usedApplicationKey || !IsInitialized)
            {
                result = new ReceiveResult
                {
                    ToSendBack = ProcessInitialization(state, data, headerKeyUsed, ratchetUsed, usedApplicationKey)
                };
            }
            else
            {
                if (ratchetUsed == null)
                {
                    throw new InvalidOperationException("Could not decrypt incoming message");
                }

                result = new ReceiveResult
                {
                    Payload = DeconstructMessage(state, data, headerKeyUsed, ratchetUsed, usedNextHeaderKey)
                };
            }

            Log.Verbose($"/###{(Configuration.IsClient ? "CLIENT" : "SERVER")} RECEIVE");
            return result;
        }

        public byte[] Send(ArraySegment<byte> payload)
        {
            Log.Verbose($"\n\n###{(Configuration.IsClient ? "CLIENT" : "SERVER")} SEND");

            if (!state.IsInitialized)
            {
                throw new InvalidOperationException("The client has not been initialized.");
            }

            if (payload.Count <= MaximumMessageSize)
            {
                if (payload.Count < HeaderIVSize)
                {
                    payload = Pad(payload, HeaderIVSize);
                }

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

                var response = ConstructMessage(payload, canIncludeEcdh, step);

                Log.Verbose($"###/{(Configuration.IsClient ? "CLIENT" : "SERVER")} SEND");
                return response;
            }
            else
            {
                throw new InvalidOperationException($"Payload is too big. Maximum payload is {MaximumMessageSize}");
            }
        }

        private ArraySegment<byte> Pad(ArraySegment<byte> payload, int minimumMessageSize)
        {
            var result = new byte[minimumMessageSize];
            Array.Copy(payload.Array, payload.Offset, result, 0, payload.Count);
            return new ArraySegment<byte>(result);
        }

        public byte[] GetRemotePublicKey()
        {
            if (state is ClientState cs) return cs.ServerPublicKey;
            if (state is ServerState ss) return ss.ClientPublicKey;
            return null;
        }

        private static int MatchMessageWithMac(ArraySegment<byte> message, IAesFactory aesFactory, params byte[][] keys)
        {
            var messageSize = message.Count;
            var mac = new ArraySegment<byte>(message.Array, message.Offset + messageSize - MacSize, MacSize);
            var maciv = new ArraySegment<byte>(message.Array, message.Offset, 16);
            var payloadExceptMac = new ArraySegment<byte>(message.Array, message.Offset, messageSize - MacSize);
            if (messageSize < MinimumMessageSize) return -1;

            for (int i = 0; i < keys.Length; i++)
            {
                var key = keys[i];
                if (key.Length != 32) throw new ArgumentException("Each key must be 32 bytes", nameof(keys));

                var Mac = new Poly(aesFactory);
                Mac.Init(key, maciv, MacSize);
                Mac.Process(payloadExceptMac);
                var compareMac = Mac.Compute();
                if (mac.Matches(compareMac))
                {
                    return i;
                }
            }

            return -1;
        }

        public static bool MatchMessageToApplicationKey(ArraySegment<byte> message, IAesFactory aesfac, byte[] applicationKey)
        {
            return MatchMessageWithMac(message, aesfac, applicationKey) >= 0;
        }

        public static bool MatchMessageToSession(ArraySegment<byte> message, IAesFactory aesfac, IKeyAgreementFactory kexfac, byte[] state)
        {
            if (message == null) throw new ArgumentNullException(nameof(message));
            if (aesfac == null) throw new ArgumentNullException(nameof(aesfac));
            if (kexfac == null) throw new ArgumentNullException(nameof(kexfac));
            if (state == null) throw new ArgumentNullException(nameof(state));
            if (message.Count < MinimumMessageSize) throw new ArgumentException("The message is too small to be a valid message", nameof(message));

            using var mem = new MemoryStream(state);
            var s = State.Load(mem, kexfac, 32);

            if (s == null)
            {
                return false;
            }

            if (s != null && s.Ratchets != null && !s.Ratchets.IsEmpty)
            {
                byte[][] keys = new byte[s.Ratchets.Count + 1][];
                for (int i = 0; i < s.Ratchets.Count; i++)
                {
                    keys[i] = s.Ratchets[i].ReceiveHeaderKey;
                    if (i == s.Ratchets.Count - 1)
                    {
                        keys[i + 1] = s.Ratchets[i].NextReceiveHeaderKey;
                    }
                }

                return MatchMessageWithMac(message, aesfac, keys) >= 0;
            }

            if (s is ServerState ss && ss.FirstReceiveHeaderKey != null)
            {
                return MatchMessageWithMac(message, aesfac, ss.FirstReceiveHeaderKey) >= 0;
            }

            return false;
        }

        public void Dispose()
        {
            state?.Dispose();
            state = null;
        }
    }
}
