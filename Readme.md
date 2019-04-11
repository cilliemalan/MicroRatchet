# Micro Ratchet
Micro Ratchet is a secure messaging protocol for embedded environments based
on [Double Ratchet](https://signal.org/docs/specifications/doubleratchet/).
Micro Ratchet doesn't require retransmission of dropped packets, doesn't wait
for out-of-order packets, and can operate with an overhead as low as 16 bytes
per message. Micro Ratchet provides strong message confidentiality, authentication,
and forward secrecy.

### Forward Secrecy Note
Forward secrecy is facilitated by periodically exchanging new ECDH keys. These
keys are automatically included if one can fit in the message. This means
that applications that always have big payloads should periodically send a
smaller (or empty) message to allow for ECDH key exchange. Servers that don't
typically communicate with devices should periodically send a message, if solely
to facilitate a key exchange.


# Process
## Initialization
The main goal of initialization is to initialize shared state between devices and initialize the ECDH and symmetric ratchets.
Initialization is initiated by the "client", usually a device and responded to by the "server", usually a server that manages
multiple devices. The client must trust the server public key.

The initialization process consists of two phases: key agreement and initial ratchet. Key agreement consists of a unique
client message and a unique server response containing shared information. The initial ratchet consists of the client sending
a normal message including ECDH paramters and the server responding with a normal message excluding ECDH parameters.

After these four messages, both sides are initialized and barring the loss of state would never need to be reinitialized.

**Client**
1. The client generates an ecdsa key pair (C), ecdh key pair (X), and nonce (Nc)
2. The client sends the public key (Cp), the ECDH public key (Xp), the Nonce (Nc), all signed with Sp


**Server**
3. The server receives the message from the client and generates a nonce (Ns) along with three ECDH pairs (M, S0, S1).
4. The server generates a root pre-key as the key agreement between X and M.
5. The root pre-key is used to derive the root key (RK), the first receive header key (RHK), and the first send header key (SHK).
6. The server sends these back along with a new nonce, the client nonce, the server public key (Sp), signed. All except
   the server nonce (Ns) and first ECDH public key (Mp) are encrypted and macced with the shared secret.

**Client**
7. The client receives the message and initializes its root pre-key as the shared secret between X and M.
8. The root pre-key is used to derive the root key (RK), the first receive header key (RHK), and the first send header key (SHK)
9. The client generates two ECDH key pairs (C0 and C1).
10. The client ratchet is initialized with RK, S0p, S1p, S1p, RHK, and SHK. The client generates two generations of the ECDH ratchet.
   The first has only a sending chain, and the second has both sending and receiving chain.
11. The client sends a normal message including the first generation ECDH public key C0p. The payload is the server nonce Ns.
   The message is encrypted with the first generation send header key.

**Server**
12. The server receives the normal message and uses the receive header key to decrypt and check the MAC.
13. The server uses the ECDH public C0p along with RK, S0p and S1p, RHK, and SHK to initialize the server ratchet.

## Normal messaging
During normal message sending, if the message size is small enough, the latest ECDH paramters are included. When
ECDH paramters won't fit, the second-last ECDH ratchet step is used for sending because the very fact that it is
second-last means that the other end already has the ECDH step associated with it.

When receiving a message with new ECDH parameters, an ECDH ratchet step is performed.

### Sending
When sending a message, if the message size - nonce overhead - MAC overhead >= 32 bytes, then ECDH may be included. In 
  this case
	a. The latest ratchet ECDH public key is included in the message
	b. The latest ratchet SHK is used to encrypt the header and MAC the message.
	c. The latest ratchet sending chain is used to encrypt the message.
When sending a message where there is not enough room for ECDH paramters (message size - nonce overhead - MAC overhead < 32)
	a. The second-last ratchet is used. ECDH public key is not included
	b. The second-last SHK is used to encrypt the header and MAC the message.
	c. The second-last ratchet sending chain is used to encrypt the message.
The second-last ratchet is used so that, in the even that a previous message including ECDH parameters was dropped, the
other side can still decrypt the message.

For each send, the symmetric ratchet for the ECDH ratchet used is ratcheted forward one step and its generation increased by 1.
The generation is the nonce used in the message sent. Note that it is therefore very important that a device never "forget"
that it performed a symmetric ratchet to avoid multiple messages being encrypted with the same key.

The only state that changes on send is the symmetric ratchet generation and chain key.

### Receiving
When receiving a message, one of two things happens depending on whether new ECDH paramters were included. The process is like so:
1. Use the newest local ECDH ratchet step RHK to verify the message MAC. If it succeeds, decrypt the message using the latest
   receive chain.
2. Use the newest local ECDH ratchet step NRHK (next receive header key) to verify the MAC. If it succeeds, the message contains
   new ECDH paramters and an ECDH ratchet step needs to be performed. Receiving a message like this verifies that the latest
   ECDH paramters sent from this end was received by the other and was used to ECDH ratchet forward.
3. If neither can sucessfully MAC the message, go through ECDH ratchet steps starting from newest, moving backward, and verify the message MAC using each header key. If one
   is found to work, decrypt the message using the receive chain associated with that ratchet step.
4. If no MAC succeeds, the message cannot be decrypted.

To perform the symmetric ratchet on receipt, the nonce contains the generation to ratchet to. If the generation skips previous
generations, the "lost keys" may be stored, or the symmetric ratchet state held back, waiting for the missing messages to come
in.

## Security
During operation, backward secrecy is provided by the symmetric ratchet and forward secrecy by the ECDH ratchet. Each
payload is encrypted with a 128-bit key generated by the symmetric ratchet process. A unique, monotonically increasing
nonce is used for encryption. The header containing a nonce and optionally ECDH public key paramters is encrypted with
a header key that changes with each ECDH ratchet. To provide additional security, the header cipher uses the encrypted
payload as a nonce. Finally, each message is authenticated with a 96-bit MAC using the header key as the key and
the first four bytes of the encrypted header as the nonce (TODO: change to the first sixteen bytes of the entire message).
This means that each payload is encrypted with a unique key, each header is encrypted with a unique nonce, and each
message is MACed with a unique nonce.

# License
See [LICENSE](LICENSE)
