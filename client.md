## Abstract

This document specifies the protocol-level obligations of a
Sealed Envelope Messaging Protocol (SEMP) client: the
cryptographic operations the client MUST perform locally, the
constraints on what it MUST and MUST NOT transmit to its home
server, the wire-level behaviors required for correct
interoperability with SEMP servers and other clients, the
client side of the handshake, envelope composition and
decryption, key management, the submission protocol with its
legacy fallback path, the device sync pattern by which
multiple devices belonging to one user coordinate, the user
policy and abuse reporting surfaces, and the security
constraints on notifications and remote content. SEMP clients
are the sole encryptors and decryptors of envelope content.
Home servers can read the brief layer of every envelope they
deliver but MUST NOT be able to read the enclosure under any
circumstances.

# Introduction

A SEMP client is any software that authenticates a user to
their home server, composes and encrypts outbound envelopes,
and receives and decrypts inbound envelopes. This document
specifies the obligations a client MUST satisfy at the
protocol layer.

The architectural role of the client is defined in
[Architecture](architecture.md). The handshake the client
performs with its home server is in
[Handshake](handshake.md). The envelope format the client
composes and parses is in [Envelope](envelope.md). The
discovery, key publication, and device directory mechanisms
the client consumes are in [Discovery](discovery.md). The
delivery semantics, user policy synchronization, abuse
reporting, and reason-code registry the client surfaces to
the user are in [Delivery](delivery.md). The extension
mechanism the client recognizes is in
[Extensions](extensions.md).

The client is a normative role. Implementations claiming SEMP
client conformance MUST satisfy the obligations in this
document.

# Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown here.

This document additionally uses terminology from [RFC 4949](https://www.rfc-editor.org/rfc/rfc4949)
for general security-protocol terms.

# Connection and Trust Model

## Connection Topology

A SEMP client communicates only with its home server. All
cross-domain delivery is server-to-server per
[Handshake](handshake.md). A client that attempts a SEMP
handshake with a server outside its own domain violates this
specification. A server that receives such a handshake SHOULD
treat it as suspicious and MAY reject it.

## Trust Boundary

The home server is a trusted but bounded party. It can read
the `brief` of every envelope it delivers. It MUST NOT be
able to read the `enclosure` under any circumstances. The
client is the only party that encrypts and decrypts
`enclosure` content. This boundary is enforced by the key
wrapping model defined in [Envelope](envelope.md) and
MUST NOT be circumvented by any client behavior.

<a id="local-crypto"></a>

## Local Cryptographic Obligations
The following operations MUST be performed by the client and
MUST NOT be delegated to the home server:

* generation of the user's identity and encryption key pairs;
* encryption of outbound `brief` and `enclosure` content;
* decryption of inbound `brief` and `enclosure` content;
* generation of per-envelope symmetric keys (`K_brief` and
  `K_enclosure`);
* wrapping of symmetric keys under recipient public keys;
* signing of identity proofs during the handshake.

Seal computation (`seal.signature` and `seal.session_mac`) is
not a client responsibility. These require the domain private
key and session key material, which clients do not hold. The
client transmits the assembled envelope to its home server,
which computes the seal before forwarding.

# Authentication

## Handshake Obligations

Clients authenticate to their home server using the handshake
defined in [Handshake](handshake.md). Client-specific
obligations:

* The init message MUST be anonymous. Clients MUST NOT
  include any identifying information in this message.
* The identity proof in the confirm message MUST be encrypted
  under the session secret before transmission. It MUST NOT
  appear in plaintext on the wire at any point.
* The `identity_signature` in the identity proof MUST be
  computed over `session_id || confirmation_hash` using the
  client's long-term identity key.
* The client MUST verify the server's `server_signature` on
  the response message before transmitting the identity
  proof. If verification fails, the client MUST abort.
* The client MUST verify the `server_signature` on the
  accepted or rejected message before treating the session as
  established.
* On receipt of the accepted message, the client MUST record
  the session state defined in [Handshake](handshake.md),
  including `session_ttl` and the locally computed
  `expires_at`, and MUST manage that state in accordance with
  the storage constraints, backgrounding rules, and expiry
  detection requirements in [Handshake](handshake.md).

## Key Registration

<a id="first-device-registration"></a>

### First-Device Registration
For the account's very first device (no existing device
directory entry for the account):

1. The client generates an identity key pair (Ed25519).
2. The client generates an encryption key pair
   (suite-specific KEM).
3. The client generates its device key pair per the
   device-key requirements in [Discovery](discovery.md).
4. The client registers with the home server via `POST` to
   the URL advertised as `endpoints.register` in the server's
   configuration document
   ([Discovery](discovery.md)), submitting its public
   keys and account credentials.
5. The server stores the public keys, creates the initial
   device directory record with this device as the sole
   full-access entry, and returns its domain signing and
   encryption keys. The client caches the server keys locally
   for handshake verification.

Account-credential semantics (password, invite token,
administratively provisioned identity) are operator policy
and are out of scope for this specification.

### Subsequent-Device Enrollment

For every device after the first, the client MUST follow the
device enrollment flow defined in [Discovery](discovery.md)
rather than the first-device flow above. The new device does
not generate a fresh identity key; it receives the existing
identity private key from an authorizing full-access device.
The home server MUST reject a fresh `endpoints.register`
submission that names an account already present in the
device directory. Subsequent devices enroll via the device
enrollment flow, and a re-registration submission MUST NOT be
accepted.

The identity private key MUST NOT transit the network in
plaintext. In first-device registration the server receives
only public key material. In subsequent-device enrollment the
identity private key travels between devices only in
KEM-wrapped form per the enrollment flow in
[Discovery](discovery.md), carried over a local pairing
channel.

### Registration Endpoint

Servers MUST advertise a client registration endpoint as
`endpoints.register` in their configuration document
([Discovery](discovery.md)) and MUST accept `POST`
requests at that URL for client key registration.

Request:

~~~ json
{
    "address": "alice@example.com",
    "password": "account-password",
    "identity_key": {
        "algorithm": "ed25519",
        "public_key": "base64-encoded-ed25519-public-key"
    },
    "encryption_key": {
        "algorithm": "x25519-chacha20-poly1305",
        "public_key": "base64-encoded-kem-public-key"
    }
}
~~~

Response (200 OK):

~~~ json
{
    "status": "registered",
    "domain_signing_key": {
        "algorithm": "ed25519",
        "public_key": "base64-encoded-key",
        "key_id": "sha256-fingerprint"
    },
    "domain_encryption_key": {
        "algorithm": "x25519-chacha20-poly1305",
        "public_key": "base64-encoded-key",
        "key_id": "sha256-fingerprint"
    }
}
~~~

The server MUST verify the account credentials before storing
the keys. The server MUST return its domain signing and
encryption public keys so the client can cache them for
handshake verification. The client needs the domain signing
key to verify the server's signature on handshake response
messages.

After successful registration, the user's public keys are
available at `<endpoints.keys><address>` (where
`endpoints.keys` is read from the home server's configuration
document per [Discovery](discovery.md)) and through the
in-session `SEMP_KEYS` protocol ([Recipient Key Request Protocol](#recipient-key-request)).

For subsequent device additions, the client MUST provide an
authorization proof from an existing trusted device per
[Discovery](discovery.md). A device registration without
a valid authorization proof MUST be rejected by the home
server.

<a id="delegated-client-registration"></a>

## Delegated Client Registration
A primary client MAY authorize a delegated client with
restricted permissions by issuing a scoped device certificate
per [Discovery](discovery.md). The delegation flow:

1. The delegated service generates a device key pair.
2. The primary client obtains the delegated device's public
   key through an out-of-band channel (QR code, secure paste,
   API integration).
3. The primary client composes a `SEMP_DEVICE_CERTIFICATE`
   with the desired permission scope and signs it with its
   own device key.
4. The primary client submits the certificate to the home
   server via the standard device registration flow.
5. The home server verifies the signature chain (certificate
   signed by primary device, primary device authorized for
   the account) and stores the certificate.
6. The delegated client connects and authenticates through
   the standard handshake. The server identifies the device
   by its key and retrieves the associated certificate.

The delegated client is a full SEMP client. It composes
envelopes, encrypts content, and signs handshake identity
proofs. The scope restricts what the server will accept from
the delegated client; it does not restrict what the delegated
client can compute locally.

<a id="scope-enforcement"></a>

## Scope Enforcement at Submission
When a delegated client submits an envelope, the home server
enforces the scope from the device's current certificate:

1. Authenticate the session (standard handshake
   verification).
2. Retrieve the current `SEMP_DEVICE_CERTIFICATE` for the
   submitting device key.
3. If no certificate exists (full-access device), proceed
   without scope checks.
4. If a certificate exists, extract the `scope` fields per
   the scoped device certificate definition in
   [Discovery](discovery.md).
5. For each recipient in the envelope, evaluate the
   `scope.send` matcher per the matcher rules in
   [Discovery](discovery.md). Reject with
   `reason_code: "scope_exceeded"` when any recipient fails
   the matcher. The rejection MUST identify which
   recipient(s) failed.
6. Evaluate every tier in `scope.send.rate_limits` per the
   rate-limit rules in [Discovery](discovery.md). Reject
   with `reason_code: "rate_limited"` if any tier's
   rolling-window cap would be exceeded, and do not record
   the operation against the counters.
7. On every inbound envelope addressed to the account,
   evaluate the delegated device's `scope.receive` matcher
   against `brief.from`. The server MUST NOT deliver to the
   device's session if the matcher rejects. Other account
   devices with permissive matchers are unaffected. If the
   matcher accepts, evaluate `scope.receive.rate_limits` in
   the same manner as step 6.
8. For operations addressing the account's block list, keys,
   or devices, dispatch on read versus write, check the
   corresponding `read` or `write` flag on
   `scope.blocklist`, `scope.keys`, or `scope.devices`, then
   evaluate that scope field's `rate_limits` tiers.

Scope enforcement uses the current certificate at the time of
each submission, and not the certificate that was active when
the session was established. A certificate update by the
primary client takes effect immediately on the next
submission within an existing session.

## Delegated Client Obligations

A delegated client has the same cryptographic obligations as
any other client ([Local Cryptographic Obligations](#local-crypto)) and MUST additionally:

* Accept `scope_exceeded` rejections gracefully. The
  delegated client MUST NOT retry a submission that was
  rejected for scope reasons without user or operator
  intervention.
* Refrain from attempting to register additional devices,
  modify block lists, or manage keys when the certificate
  scope does not permit these operations.
* Surface its own permission scope to its operator so that
  scope-related rejections can be diagnosed.

# Envelope Composition

<a id="composition-sequence"></a>

## Composition Sequence
When sending a message, the client MUST execute this
sequence:

1. Compose the plaintext `brief` and `enclosure` JSON objects
   from user input. For a forward, populate
   `enclosure.forwarded_from` per the forwarded-envelope
   definition in [Envelope](envelope.md) and produce
   `forwarded_from.forwarder_attestation` over its canonical
   bytes using the sending user's identity key.

2. Compute `enclosure.sender_signature` over the canonical
   enclosure bytes per the sender-signature definition in
   [Envelope](envelope.md), using the sending user's
   identity key. The signature MUST be computed before any
   enclosure encryption.

3. Generate two fresh independent random symmetric keys:
   `K_brief` and `K_enclosure`. These MUST be freshly
   generated for each envelope and MUST NOT be reused.

4. Encrypt the `brief` JSON under `K_brief`. Encrypt the (now
   signed) `enclosure` JSON under `K_enclosure`.

5. Request recipient public keys from the home server using
   the key request protocol defined in
   [Recipient Key Request Protocol](#recipient-key-request). The response classifies each
   recipient as `found`, `not_found`, `legacy_required`,
   `recipient_not_found`, or `error` per
   [Key Response Status Values](#key-response-status-values). The client MUST process
   each per-recipient status before encrypting under any
   recipient key:

   * For `found` recipients, the response includes both the
     recipient server's domain key and the recipient
     client's encryption key, along with the remote domain's
     original signature. The client MUST check the
     revocation status of every key received. A revoked key
     MUST NOT be used for encryption. If a
     `replacement_key_id` is present, the client MUST fetch
     and validate the replacement before proceeding.
   * For `legacy_required` recipients, the client MUST hand
     the recipient off to the legacy fallback handling in
     [Legacy Required Fallback](#legacy-required-fallback).
   * For `recipient_not_found` recipients, the client MUST
     surface the address as undeliverable and remove the
     recipient from the SEMP send.
   * For `not_found` recipients, the client MUST treat the
     address as undeliverable for the current send and
     surface the outcome to the user. The client MAY retry
     after the recipient's key publication TTL has elapsed.
   * If any recipient list mixes `found` and
     `legacy_required` recipients, the client MUST follow
     the mixed-recipient handling in
     [Mixed-Recipient Composes](#mixed-recipient-composes) before any envelope is
     submitted or any SMTP message is sent.

6. For each recipient, produce:
   * `K_brief` encrypted under the recipient server's domain
     key, recorded as an entry in `seal.brief_recipients`
     keyed by the server domain key fingerprint;
   * `K_brief` encrypted under the recipient client's
     encryption key, recorded as an entry in
     `seal.brief_recipients` keyed by the client key
     fingerprint;
   * `K_enclosure` encrypted under the recipient client's
     encryption key, recorded as an entry in
     `seal.enclosure_recipients` keyed by the client key
     fingerprint.

7. For BCC recipients, generate a distinct envelope copy per
   recipient per the BCC handling rules in
   [Envelope](envelope.md).

8. Compose the `postmark`, including the active
   `session_id`.

9. Transmit the assembled envelope to the home server. The
   server computes `seal.signature` and `seal.session_mac`.
   Clients do not compute these, since they require the
   domain private key and session key material that clients
   do not hold.

## Sent Message Availability

To make sent messages available on the sender's other
registered devices, the client MUST include entries in
`seal.brief_recipients` and `seal.enclosure_recipients` for
each of the sender's own active device encryption keys, in
addition to the recipient entries. This is the only mechanism
for sent message availability across devices. There is no
server-side plaintext copy.

## Recipient Key Validation

Before encrypting to a recipient, the client MUST:

1. Verify the domain signature on the key response per the
   domain-signature rules in [Discovery](discovery.md).
2. Where present, verify the self-signature per the
   self-signature rules in [Discovery](discovery.md).
3. Verify revocation status. A revoked key MUST NOT be used.

If a recipient's key has changed since the last message to
that correspondent, the client MUST surface the key change to
the user and MUST require explicit confirmation before
encrypting to the new key.

## Algorithm Selection

Clients MUST prefer `pq-kyber768-x25519` where supported.
Clients MUST support `x25519-chacha20-poly1305` as the
baseline fallback per the algorithm-suite definitions in
[Envelope](envelope.md). Clients MUST NOT select a
weaker algorithm when a stronger one is available for both
parties.

## BCC Handling

Clients MUST implement BCC via per-recipient envelope copies
per the BCC rules in [Envelope](envelope.md). The `bcc`
field of each envelope copy MUST contain only the address of
that specific BCC recipient. The `bcc` field MUST be absent
from envelope copies delivered to `to` and `cc` recipients.
Clients MUST NOT rely on server-side BCC stripping.

## Threading

When composing a reply, the client MUST:

* Set `in_reply_to` to the `message_id` of the message being
  replied to.
* Set `thread_id` to the `thread_id` of the parent message,
  or to the parent's `message_id` if no `thread_id` exists.

The `thread_id` MUST remain stable for the life of the thread
and MUST NOT change when recipients are added.

## Forward Composition

To forward a previously received envelope, the client MUST:

1. Take the original received envelope's decrypted enclosure
   plaintext verbatim, including its `sender_signature`. This
   becomes
   `enclosure.forwarded_from.original_enclosure_plaintext`
   in the new envelope. The forwarder MUST NOT modify any
   field of the original enclosure plaintext.

2. Populate the remaining `forwarded_from` fields per the
   forwarded-envelope fields in
   [Envelope](envelope.md):
   * `original_sender_address`: the full sender address from
     the original envelope's `brief.from` as the forwarder
     observed it on receipt;
   * `received_at`: the timestamp at which the forwarding
     client received the original envelope from its home
     server;
   * `original_seal` and `original_postmark` MAY be included
     verbatim from the original envelope as advisory
     context.

3. Compute `forwarded_from.forwarder_attestation` over the
   canonical bytes of `forwarded_from` (with
   `forwarder_attestation.value` set to `""`) using the
   forwarding user's identity key, per the
   forwarder-attestation rules in
   [Envelope](envelope.md). The
   `forwarder_attestation.key_id` MUST equal the `key_id`
   that will appear in the new enclosure's
   `sender_signature`.

4. Compose the rest of the new enclosure normally. The
   forwarder's own commentary, if any, belongs in the new
   enclosure's `subject`, `body`, and `attachments` fields.
   The original content MUST NOT be duplicated into these
   fields.

5. Sign and encrypt the new enclosure per
   [Composition Sequence](#composition-sequence) (steps 2 and 4).

A forward of a forward MAY be composed by repeating this
process. The inner `original_enclosure_plaintext` MAY itself
contain a non-null `forwarded_from`, preserving the full
chain. Clients MUST NOT collapse, truncate, or reorder a
forwarding chain.

<a id="send-time-obfuscation"></a>

## Send-Time Obfuscation
An envelope's submission time is observable to any passive
network observer of the sending client's home-server session.
When the same observer can also see the recipient server's
session, the two timestamps correlate and expose
correspondent pairs even though envelope sizes are padded per
[Envelope](envelope.md) and postmark metadata is
domain-level only. Timing is a side channel that size padding
does not address.

Clients MAY mitigate this side channel by delaying
submission. Once the user triggers a send and the client has
produced a fully composed envelope per
[Composition Sequence](#composition-sequence), the client MAY hold the envelope in
a local outbound queue for a bounded random interval before
submitting it to the home server. The interval SHOULD be
drawn uniformly at random from `[0, D]`, where `D` is an
operator-configurable ceiling.

### Bounds

* `D` SHOULD NOT exceed 60 seconds by default. Longer delays
  degrade user-perceived responsiveness without
  proportionally improving unlinkability.
* The chosen delay MUST NOT push the submission past
  `postmark.expires`. The client MUST reduce `D` for any
  envelope whose expiry window is shorter than `D`, or MUST
  recompose the envelope with a longer expiry before
  queuing.
* Delay applies only to the first submission. Retry
  scheduling per [Delivery](delivery.md) governs
  subsequent attempts and is unaffected.
* Clients SHOULD NOT apply delay to envelopes the user has
  explicitly flagged as time-sensitive. A verification code
  the user is actively reading, a just-in-time reply to a
  live conversation, or similar interactions are poor
  candidates for obfuscation.
* Device-sync envelopes (`semp.dev/device-sync` marker, see
  [Device Sync](#device-sync)) MAY be batched and delayed more
  aggressively than user-visible sends, since their timing
  is not directly observable to correspondents.

### Scope of Protection

Send-time obfuscation reduces the temporal resolution at
which a passive observer can link a submission to a later
delivery. It does not:

* hide correspondent pairs from the sender's home server,
  which sees every outbound envelope regardless of
  submission timing;
* hide correspondent pairs from the recipient's home server,
  which sees every inbound envelope after routing;
* defeat active adversaries who can correlate cross-session
  traffic at resolutions finer than the delay bound;
* provide mixnet-class unlinkability. Users requiring
  mixnet-class protection SHOULD use a mixnet rather than
  SEMP; systems such as Nym and Katzenpost are designed for
  that threat model.

The mechanism is a modest defense against casual traffic
analysis. It is not a substitute for architectural
anonymity.

# Envelope Receipt and Decryption

## Decryption Sequence

On receiving an envelope from the home server, the client:

1. Iterates over entries in `seal.brief_recipients`,
   attempting decryption with each active private encryption
   key until one succeeds, yielding `K_brief`.

2. Decrypts `envelope.brief` using `K_brief` and parses the
   result.

3. Iterates over entries in `seal.enclosure_recipients`,
   attempting decryption with each active private key until
   one succeeds, yielding `K_enclosure`.

4. Decrypts `envelope.enclosure` using `K_enclosure` and
   parses the result.

5. Verifies `enclosure.sender_signature` per the
   sender-signature verification rules in
   [Envelope](envelope.md) against the sender's
   published identity key. The client MUST NOT render
   enclosure content if verification fails. A failure MUST
   be surfaced as a security warning per the rendering rules
   in [Envelope](envelope.md).

6. If `enclosure.forwarded_from` is non-null, performs the
   forwarded-envelope verification chain per
   [Envelope](envelope.md).

7. Verifies each attachment hash against its decrypted
   content per the attachment integrity rules in
   [Envelope](envelope.md).

If any step fails, the client MUST surface an explicit error
and MUST NOT silently discard the envelope, and MUST NOT
present partial content as complete.

## Symmetric Key Lifetime

`K_brief` and `K_enclosure` MUST NOT be written to persistent
storage. They exist in memory only for the duration of the
decryption operation.

<a id="legacy-origin"></a>

## Legacy-Origin Messages
Messages retrieved from a legacy mail account are not SEMP
envelopes. They arrive through whatever retrieval protocol
the user's legacy provider supports (typically IMAP or POP3,
occasionally JMAP or a proprietary provider API), and they
do not arrive through the SEMP server. SEMP does not
constrain the retrieval protocol; any mechanism that lets
the client fetch legacy messages is compatible. The client
MUST clearly distinguish legacy messages from SEMP-delivered
messages in the user interface. Legacy messages carry none
of SEMP's guarantees. They have no sealed metadata, no
end-to-end encryption, no integrity proof, and no explicit
rejection semantics.

Clients MUST NOT present legacy messages and SEMP messages
in a unified inbox without a persistent, unambiguous
indicator identifying the origin of each message. The
indicator MUST be visible without additional user
interaction.

<a id="upgrade-signal-detection"></a>

### Upgrade-Signal Detection
A SEMP-capable client processing an inbound legacy message
SHOULD inspect the `SEMP-Capability`, `SEMP-Identity`,
`SEMP-Domain`, and `SEMP-Address` headers
([SEMP Upgrade-Signaling Headers](#semp-upgrade-headers)) if present. When all four are
present and `SEMP-Capability` is `1`, the client MAY record
the sender as potentially SEMP-reachable at `SEMP-Address`.

The client MUST NOT treat the upgrade signal as
authoritative without verification. Before routing a reply
via SEMP on the basis of these headers, the client MUST:

1. Perform SEMP discovery against `SEMP-Domain` per
   [Discovery](discovery.md).
2. Fetch the identity key record for `SEMP-Address` from the
   resulting SEMP server.
3. Verify that the fetched identity key's fingerprint
   matches the `SEMP-Identity` header value.
4. Confirm that the fetched record's `address` matches
   `SEMP-Address` after canonicalization per
   [Envelope](envelope.md).

A mismatch at any step MUST cause the client to discard the
upgrade hint. The client MUST NOT surface a false upgrade to
the user. A discarded hint means the reply path remains SMTP
until a subsequent signal verifies.

Successful verification results in the client caching
`(From-address, SEMP-Address, SEMP-Identity-fingerprint,
verified-at)` in its local correspondent table. Cache TTL is
implementation-defined; clients SHOULD re-verify at least
every 30 days, on any key-record rotation notification, and
whenever an upgrade signal from the same correspondent
arrives with a different fingerprint.

### Reply Routing From Legacy

When the user replies to a legacy message:

* If the sender is in the verified SEMP correspondent table
  per [Upgrade-Signal Detection](#upgrade-signal-detection), the client SHOULD
  default to SEMP for the reply and MUST surface the routing
  choice to the user alongside any user-editable recipient
  list.
* If the sender is not verified as SEMP-reachable, the
  client defaults to SMTP and behaves per
  [Legacy Required Fallback](#legacy-required-fallback).

The user MAY override the default route on any specific
reply. An override downgrading a SEMP-reachable reply to
SMTP triggers the degradation warning required by
[User Consent](#user-consent).

### Origin Indicator Requirements

Every legacy message displayed alongside SEMP messages MUST
carry a visible origin indicator. The indicator MUST:

* Be rendered without additional user interaction (no hover,
  no click, no menu expansion required).
* Distinguish at least three states: `SEMP`, `legacy`, and
  `legacy with verified SEMP-capable sender` (see
  [Upgrade-Signal Detection](#upgrade-signal-detection)).
* Remain visible when the message is displayed in compact,
  expanded, threaded, and notification views.

A client MAY add further origin categorizations (for
example, `SEMP with key-transparency verification`),
provided the three baseline states remain distinguishable.

<a id="history-sync"></a>

## Message History Sync Across Devices
When a new device is registered, it cannot decrypt envelopes
that were delivered before its encryption key existed. Those
envelopes' seal maps contain entries only for the device
keys that were active at send time. Syncing message history
to a new device requires re-wrapping the symmetric keys
under the new device's key, an operation that only an
existing device that holds the original private keys can
perform.

### Sync Methods

Three approaches are available, in increasing order of user
experience quality:

**Offline transfer.** The existing device exports stored
`.semp` files and transfers them to the new device via USB,
local network, or external storage. The new device imports
the files. If the new device also holds the old private keys
(from an encrypted key backup per
[Recovery](recovery.md)), it can decrypt directly. If
not, the existing device MUST re-wrap the symmetric keys in
each envelope under the new device's public key before
export. This approach is fully offline and requires zero
server trust.

**Direct device-to-device transfer.** The existing device
establishes a secure channel to the new device, using the
device keys already registered and authenticated through the
handshake. The existing device decrypts the symmetric keys
from each stored envelope and re-wraps them under the new
device's public key, transmitting updated seal entries over
the secure channel. The new device applies the updated
entries to the envelopes it retrieves from the server. The
server is not involved in the re-wrapping.

**Server-assisted sync.** The home server retains encrypted
envelopes as part of its normal retention policy. When a new
device is registered, the server notifies the existing
device that a sync is requested. The existing device
performs the re-wrapping operation in the background. For
each stored envelope, it decrypts `K_brief` and
`K_enclosure` using its own private key, re-wraps both under
the new device's public key, and sends the new seal entries
to the server. The server patches its stored copies of the
envelopes with the additional seal entries and delivers them
to the new device. The new device decrypts normally using
its own private key.

### Server-Assisted Sync Constraints

When the server facilitates message history sync:

* The server MUST NOT learn the symmetric keys (`K_brief`,
  `K_enclosure`) at any point during the sync. The server
  receives and stores opaque wrapped key blobs (the same
  type of data it already handles during normal delivery).
* The existing device MUST be online to perform the
  re-wrapping. If no existing device is available (all prior
  devices are lost), server-assisted sync is not possible
  and the user MUST restore from an encrypted key backup per
  [Recovery](recovery.md).
* The sync MUST be authenticated. The server MUST verify
  that the re-wrapping request originated from a registered
  device for the same account. The new device MUST be
  registered through the standard device registration flow
  ([First-Device Registration](#first-device-registration) or the enrollment flow in
  [Discovery](discovery.md)) before sync begins.
* The server MUST NOT initiate sync without explicit
  authorization from the existing device. A malicious actor
  who registers a new device (bypassing the authorization
  proof) MUST NOT be able to trigger re-wrapping of
  historical envelopes.
* The server MAY limit the sync to recent envelopes (for
  example, the last 30 days) as a matter of retention
  policy. Older envelopes beyond the server's retention
  window require offline transfer from the existing device.
* Sync progress SHOULD be surfaced to the user on both
  devices. The existing device SHOULD indicate that it is
  re-wrapping keys for the new device and display progress.
  The new device SHOULD indicate that it is waiting for
  history to become available.

### Sync and Key Rotation

If the user has rotated encryption keys since some envelopes
were received, the existing device may hold retired private
keys needed to decrypt older envelopes. The re-wrapping
operation uses whichever private key successfully decrypts
each envelope's seal entry; the device iterates its retired
keys just as it does during normal decryption. After
re-wrapping under the new device's key, the retired keys are
not transferred. Only the re-wrapped symmetric keys are
sent. The new device receives access to the content without
ever holding the retired keys.

### Alternative: Encrypted Key Backup

A user MAY transfer their retired private keys directly to
the new device via an encrypted key backup per
[Recovery](recovery.md) rather than re-wrapping
individual envelopes. The new device imports the backup,
gains access to all historical private keys, and can decrypt
any envelope whose seal contains an entry for any of those
keys. This approach is simpler than per-envelope re-wrapping
and requires the user to maintain and safeguard a key
backup.

The choice between re-wrapping and key backup is a client
implementation decision. Both approaches preserve the
security model: the server never holds plaintext keys or
content, and the user controls which devices have access to
historical envelopes.

<a id="device-sync"></a>

## Device Sync
A SEMP user frequently operates across multiple registered
devices (see the device directory in
[Discovery](discovery.md)) and MAY also authorize
delegated clients with scoped certificates
([Delegated Client Registration](#delegated-client-registration)). Coordination between
these devices is a protocol concern, because without a
defined mechanism clients from different vendors cannot
interoperate when the same user switches clients or
servers.

This section defines the wire-level pattern for a device
belonging to a user to send an opaque, end-to-end encrypted
message to one or more other devices belonging to the same
user, routed through the home server. The pattern covers new
device onboarding, historical mail sync, read-state
propagation, draft propagation, classification results
produced by delegated filter devices, and any other
coordination signal that remains within the scope of a
single user's account.

<a id="sync-envelope-pattern"></a>

### Sync Envelope Pattern
Device sync reuses the existing envelope delivery pipeline.
A sync envelope is an ordinary SEMP envelope with the
following properties:

1. The brief MUST include the device sync marker defined in
   [Device Sync Marker](#device-sync-marker). The marker is the discriminator
   that distinguishes a sync envelope from any other
   envelope.
2. The envelope `from` and `to` fields in the brief MUST
   resolve to the same user address.
3. `seal.enclosure_recipients` MUST contain entries for the
   target device encryption keys only. It MUST NOT contain
   entries for device keys that are not intended recipients
   of the sync message.
4. `seal.brief_recipients` MUST contain entries for the
   recipient device encryption keys and MAY additionally
   contain entries for other registered devices that require
   awareness of the sync message at the brief layer.

Address equality alone (`from` and `to` resolving to the
same user) does not mark an envelope as a sync envelope. A
user MAY compose an ordinary correspondence envelope
addressed to themselves (a "note to self") that does not
carry the device sync marker. Such an envelope is treated as
ordinary correspondence by both the server and the recipient
client: it counts toward reputation accounting normally, it
follows the ordinary delivery pipeline, and the recipient
client renders it in the mailbox view alongside other
correspondence.

Self-addressed envelopes (with or without the device sync
marker) are a valid envelope shape. Servers MUST NOT reject
an envelope solely because `from` and `to` resolve to the
same address.

<a id="device-sync-marker"></a>

### Device Sync Marker
The device sync marker is a core extension entry in
`brief.extensions` with the identifier
`semp.dev/device-sync`. It MUST be present on every sync
envelope and MUST carry `required: true`.

~~~ json
"brief": {
    "extensions": {
        "semp.dev/device-sync": {
            "required": true,
            "data": {
                "kind": "classification"
            }
        }
    }
}
~~~

| Field | Type | Required | Description |
|---|---|---|---|
| `kind` | string | Yes | Identifies the sync category. Each sync extension declares the `kind` value it produces. |

The marker lives in the brief rather than the enclosure so
that the home server can apply correct policy
([Home Server Obligations](#device-sync-server-obligations)) without decrypting the
enclosure. The marker is encrypted against routing servers
because the brief is encrypted, and it is visible only to
the recipient server and the recipient client.

Clients MUST recognize the marker. A client that decrypts a
brief carrying `semp.dev/device-sync` MUST NOT surface the
envelope as correspondence in a mailbox view or any
equivalent user interface element. The client MAY surface
the sync message in a diagnostic or developer view.

<a id="device-sync-field-placement"></a>

### Field Placement
Each sync kind specifies the placement of its fields
according to the layered privacy model in
[Envelope](envelope.md). A sync kind's definition MUST
declare the placement for every field it carries.

* **Content fields** (body-equivalent semantic data
  exchanged between the user's devices, hidden from the home
  server) MUST be placed in `enclosure.extensions` under a
  namespaced identifier specific to the kind. Examples
  include the body of a draft sync, the plaintext of a
  rewrapped historical envelope, and classification labels
  attached to a correspondence envelope.
* **Server-actionable fields** (kinds that require the home
  server to read and act on the sync) MUST be placed in
  `brief.extensions`, either inside the
  `semp.dev/device-sync` marker's `data` object or in a
  sibling brief-layer extension namespaced to the kind. The
  home server MUST NOT act on sync fields unless the sync
  kind's specification explicitly requires it.
* **Public metadata** MUST NOT appear in
  `postmark.extensions` or `seal.extensions` unless the
  kind's specification explicitly requires routing-server
  visibility, which is unusual for sync.

This placement rule makes the home server's role in each
sync kind explicit. A kind that is purely client-to-client
places nothing the server can read beyond the marker itself.
A kind that asks for server action places that ask in a
layer the server can read.

When a sync envelope carries no human-readable content, the
enclosure body MAY be empty. When a sync kind carries no
content fields, the `seal.enclosure_recipients` map MAY also
be empty, since no client key wrapping is required.

Example of a client-to-client sync kind (classification)
with its content field in the enclosure:

~~~ json
"brief": {
    "extensions": {
        "semp.dev/device-sync": {
            "required": true,
            "data": { "kind": "classification" }
        }
    }
}

"enclosure": {
    "extensions": {
        "semp.dev/classification-result": {
            "required": true,
            "data": {
                "source_envelope_id":
                    "01HF3X7M8N9P0Q1R2S3T4U5V6W",
                "labels": ["newsletter", "low-priority"],
                "confidence": 0.92
            }
        }
    }
}
~~~

Example of a server-actionable sync kind
(delivery-disposition) with its fields in the marker's
`data` object:

~~~ json
"brief": {
    "extensions": {
        "semp.dev/device-sync": {
            "required": true,
            "data": {
                "kind": "delivery-disposition",
                "source_envelope_id":
                    "01HF3X7M8N9P0Q1R2S3T4U5V6W",
                "disposition": "suppress",
                "reason": "spam",
                "device_id": "filter-device-ulid"
            }
        }
    }
}
~~~

Specific sync extensions (new device onboarding, historical
mail rewrap, read-state, draft state, classification
results, delivery-disposition, and similar) are registered
independently per [Extensions](extensions.md). Each such
extension MUST declare the `kind` value it uses and the
placement of each of its fields so that receiving parties
(server for server-actionable kinds, devices for
client-to-client kinds) can route and handle the sync
without speculative decryption.

<a id="device-sync-server-obligations"></a>

### Home Server Obligations
When a home server processes an envelope whose brief carries
`semp.dev/device-sync`, the server MUST:

1. Apply the ordinary delivery pipeline per
   [Delivery](delivery.md) for authentication, seal
   verification, and fan-out to the device keys present in
   `seal.brief_recipients` and `seal.enclosure_recipients`.
2. Exclude the envelope from reputation signals and abuse
   accounting per [Delivery](delivery.md). A sync
   envelope is not correspondence and MUST NOT contribute to
   sender abuse rates, recipient complaint rates, or trust
   gossip records.
3. Omit sync envelopes from delivery event notifications
   sent to external correspondents. Sync envelopes have no
   external sender.

The server MAY apply distinct retention policy to sync
envelopes. The server MAY apply distinct rate limits to sync
envelopes, since legitimate sync traffic (for example,
per-envelope classification results produced by a delegated
filter device, or historical mail rewrap during new device
onboarding) can exceed ordinary correspondence rates by a
significant margin.

The server MUST NOT act on any field under
`enclosure.extensions`, since it cannot read that layer. The
server MUST act on brief-layer fields of a sync kind only
when the kind's specification explicitly defines that action
(see [Field Placement](#device-sync-field-placement) and the staged-delivery
handling in [Staged Delivery and the delivery-disposition Kind](#delivery-disposition-kind)). Unknown
brief-layer sync fields MUST be ignored per the `required`
criticality rules in [Extensions](extensions.md).

The server MUST NOT log, cache, or transmit the enclosure
plaintext.

### Delegated Client Authorization

A delegated client that produces sync envelopes MUST hold a
`SEMP_DEVICE_CERTIFICATE` per [Discovery](discovery.md)
whose `scope.send.allow` permits sending to the user's own
address. The home server enforces scope at submission
([Scope Enforcement at Submission](#scope-enforcement)) without special-casing sync
envelopes.

A delegated client that consumes sync envelopes MUST hold a
certificate whose `scope.receive` matcher permits the user's
own address (the source of sync envelopes). The home server
delivers sync envelopes to delegated devices on the same
terms as correspondence envelopes, subject to the device
keys present in `seal.enclosure_recipients`.

### Relationship to Message History Sync

The server-assisted message history sync flow defined in
[Message History Sync Across Devices](#history-sync) MAY use the device sync pattern as its wire
format. When a history sync extension is defined, it carries
the rewrapped `K_brief` and `K_enclosure` entries as a sync
payload addressed from the rewrapping device to the new
device. The home server applies the resulting seal entries
to stored envelopes as described in [Message History Sync Across Devices](#history-sync), and
the server does not learn the plaintext keys.

<a id="delivery-disposition-kind"></a>

### Staged Delivery and the delivery-disposition Kind
A user MAY place a delegated device at a lower receive stage
than their full-access devices, so that the delegate (for
example a spam filter or virus scanner) processes inbound
envelopes before full-access devices see them. Stage is
declared per device in `scope.receive.delivery_stage` per
[Discovery](discovery.md). Server handling of staged
delivery is defined in [Delivery](delivery.md).

The `delivery-disposition` sync kind is the control signal
by which a staged device tells the home server whether the
held envelope should advance to the next stage or be
suppressed. It is a server-actionable kind with all fields
in the marker's `data` object:

~~~ json
"brief": {
    "from": "alice@example.com",
    "to":   "alice@example.com",
    "extensions": {
        "semp.dev/device-sync": {
            "required": true,
            "data": {
                "kind": "delivery-disposition",
                "source_envelope_id":
                    "01HF3X7M8N9P0Q1R2S3T4U5V6W",
                "disposition": "advance",
                "reason": "accepted",
                "device_id": "filter-device-ulid"
            }
        }
    }
}
~~~

| Field | Type | Required | Description |
|---|---|---|---|
| `kind` | string | Yes | MUST be `"delivery-disposition"`. |
| `source_envelope_id` | string | Yes | `postmark.id` of the held envelope this disposition addresses. |
| `disposition` | string | Yes | One of `"advance"` or `"suppress"`. |
| `reason` | string | No | Operator-defined reason tag. RECOMMENDED values: `spam`, `accepted`, `policy`, `other`. |
| `device_id` | string | Yes | Identifier of the device issuing the disposition. MUST match the authenticated device's id. |

A delivery-disposition envelope is composed as a normal
self-addressed envelope under the device's current session.
The enclosure MAY be empty.
`seal.enclosure_recipients` MAY be empty.
`seal.brief_recipients` MUST contain the home server's
domain key entry so that the server can decrypt the brief
and read the disposition.

On receipt, the home server MUST:

1. Verify the envelope's seal per the ordinary delivery
   pipeline.
2. Verify that `from` and `to` resolve to the same user, and
   that the authenticated session belongs to the device
   identified by `device_id`.
3. Look up the held envelope by `source_envelope_id` in the
   staged-delivery queue per [Delivery](delivery.md).
   If no such held envelope exists for this account at this
   device's stage or an earlier stage, the disposition MUST
   be discarded.
4. Record the disposition against the held envelope and
   apply the aggregation rules in
   [Delivery](delivery.md).

A delivery-disposition envelope's brief MUST NOT carry any
sync fields other than the `semp.dev/device-sync` marker. A
server that receives a disposition envelope with additional
sync fields MUST reject the envelope with
`reason_code: "extension_unsupported"`. This keeps the
dispatch path unambiguous.

A delivery-disposition envelope MUST NOT itself trigger
staged delivery. The home server delivers the disposition
envelope directly (the envelope is server-acted and is not
shown to a user), without placing it into the staged queue.

### Device Sync Conformance

The device sync marker is a core extension. A conformant
SEMP client MUST recognize `semp.dev/device-sync` and MUST
implement the user-interface obligations in
[Device Sync Marker](#device-sync-marker) regardless of which specific sync
extensions it supports. A conformant SEMP server MUST
implement the home server obligations in
[Home Server Obligations](#device-sync-server-obligations) and, when it supports
staged delivery, the `delivery-disposition` handling in
[Staged Delivery and the delivery-disposition Kind](#delivery-disposition-kind).

Support for individual sync extensions (new device
onboarding, historical mail rewrap, read-state
synchronization, draft synchronization, classification
results, and similar) is optional and is negotiated through
capability advertisement per [Discovery](discovery.md)
and [Handshake](handshake.md). Lack of support for a
specific sync extension MUST NOT cause the device sync
marker itself to be rejected; the unrecognized inner
extension is handled per the criticality rules in
[Extensions](extensions.md).

# Key Management

## Private Key Storage

Private keys MUST be stored encrypted at rest, gated behind
user authentication, per the private-key storage rules in
[Discovery](discovery.md). Private keys MUST NOT be
stored in any form accessible to the home server.

## Key Rotation

On encryption key rotation:

1. The client generates the new key pair on the device.
2. The client publishes the new public key to the home
   server.
3. The client issues a revocation record for the old key
   with reason `superseded` per
   [Discovery](discovery.md).
4. The client retains the old private key for a transition
   period sufficient to decrypt messages encrypted before
   rotation was propagated. The transition period SHOULD be
   at least 14 days.
5. After the transition period, the old private key MAY be
   erased.

## Key Transparency

Clients SHOULD maintain a local log of key operations
(generation, publication, rotation, revocation, and signing
events) per the key-transparency mechanism in
[Recovery](recovery.md). If key usage is detected from
an unrecognized device, the client MUST surface this to the
user as an alert.

<a id="recipient-key-request"></a>

## Recipient Key Request Protocol
Clients cannot connect to remote domain servers. To obtain
recipient public keys (both the recipient server's domain
key and the recipient client's encryption key), the client
sends a `SEMP_KEYS` message with `step: request` to its home
server over the authenticated session. The home server
fulfills the request from its cache or by fetching from the
remote domain's well-known URI per
[Discovery](discovery.md). This is the same `SEMP_KEYS`
message type used for server-to-server key exchanges,
extended to the client-to-server channel with additional
fields for domain key inclusion.

When the HTTP/2 transport binding is in use, the client MAY
also issue a `GET` request to `/v1/keys/{address}` on its
home server (the address-in-path form defined in
[Handshake](handshake.md)) for ad-hoc lookups outside an
established session. Servers MUST accept both `GET` and
`POST` on `/v1/keys/{address}` so that callers requiring a
signed request body can use the lookup path.

### Key Request Schema

~~~ json
{
    "type": "SEMP_KEYS",
    "step": "request",
    "version": "1.0.0",
    "id": "request-ulid",
    "timestamp": "2025-06-10T20:30:00Z",
    "addresses": [
        "recipient1@example.com",
        "recipient2@otherdomain.com"
    ],
    "include_domain_keys": true
}
~~~

### Key Request Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | Yes | MUST be `"SEMP_KEYS"`. |
| `step` | string | Yes | MUST be `"request"`. |
| `version` | string | Yes | SEMP protocol version (semver). |
| `id` | string | Yes | Unique request identifier. ULID RECOMMENDED. |
| `timestamp` | string | Yes | ISO 8601 UTC timestamp. |
| `addresses` | array | Yes | Recipient addresses whose keys are needed. |
| `include_domain_keys` | boolean | No | If `true`, include the domain key for each recipient's server in addition to user keys. Default: `true`. |

The request is sent over the encrypted session channel
established by the handshake. It does not require a separate
signature because session authentication is sufficient. The
client's identity is not revealed to any remote domain by
this request. The home server fetches on the client's behalf
using the key fetching mechanisms its operator has
configured per [Discovery](discovery.md).

### Key Response Schema

~~~ json
{
    "type": "SEMP_KEYS",
    "step": "response",
    "version": "1.0.0",
    "id": "echoed-request-ulid",
    "timestamp": "2025-06-10T20:30:01Z",
    "results": [
        {
            "address": "recipient1@example.com",
            "status": "found",
            "domain": "example.com",
            "domain_key": {
                "algorithm": "ed25519",
                "public_key":
                    "base64-encoded-domain-public-key",
                "key_id": "domain-key-fingerprint",
                "created": "2025-01-15T08:30:00Z",
                "expires": "2026-01-15T08:30:00Z"
            },
            "user_keys": [
                {
                    "address": "recipient1@example.com",
                    "key_type": "encryption",
                    "algorithm": "pq-kyber768-x25519",
                    "public_key": "base64-encoded-public-key",
                    "key_id": "key-fingerprint",
                    "created": "2025-01-15T08:30:00Z",
                    "expires": "2026-01-15T08:30:00Z",
                    "signatures": [
                        {
                            "signer": "example.com",
                            "key_id": "domain-key-fingerprint",
                            "value": "base64-domain-signature",
                            "timestamp":
                                "2025-01-15T08:30:05Z"
                        },
                        {
                            "signer": "recipient1@example.com",
                            "key_id":
                                "identity-key-fingerprint",
                            "value": "base64-self-signature",
                            "timestamp":
                                "2025-01-15T08:30:10Z"
                        }
                    ],
                    "revocation": null
                }
            ],
            "origin_signature": {
                "algorithm": "ed25519",
                "key_id": "domain-key-fingerprint",
                "value":
                    "base64-signature-from-origin-domain"
            }
        },
        {
            "address": "alice@oldmail.example",
            "status": "legacy_required",
            "domain": "oldmail.example",
            "domain_key": null,
            "user_keys": [],
            "origin_signature": null
        },
        {
            "address": "unknown@nowhere.example",
            "status": "recipient_not_found",
            "domain": "nowhere.example",
            "domain_key": null,
            "user_keys": [],
            "origin_signature": null
        },
        {
            "address": "private@semp.example",
            "status": "not_found",
            "domain": "semp.example",
            "domain_key": null,
            "user_keys": [],
            "origin_signature": null
        }
    ]
}
~~~

### Key Response Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | Yes | MUST be `"SEMP_KEYS"`. |
| `step` | string | Yes | MUST be `"response"`. |
| `version` | string | Yes | SEMP protocol version (semver). |
| `id` | string | Yes | Echo of request `id`. |
| `timestamp` | string | Yes | ISO 8601 UTC timestamp. |
| `results` | array | Yes | One result per requested address. |

### Result Entry Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `address` | string | Yes | The requested address. |
| `status` | string | Yes | One of the status values defined in [Key Response Status Values](#key-response-status-values). |
| `domain` | string | Yes | The recipient's domain. |
| `domain_key` | object or null | No | The recipient server's domain key. Present when `include_domain_keys` was `true` and `status` is `found`. |
| `user_keys` | array | Yes | User key records, following the format in [Discovery](discovery.md). Empty when `status` is not `found`. |
| `origin_signature` | object or null | No | The original domain signature from the remote server's key response. The client MUST verify this per [Recipient Key Request Protocol](#recipient-key-request). |

<a id="key-response-status-values"></a>

### Key Response Status Values
In SEMP every outbound send starts with a key fetch. The
key-response status surfaces the recipient's reachability
classification early, so the client can choose the right
delivery path (SEMP, legacy fallback, or no delivery)
before composing and submitting an envelope. The status
values mirror the submission-time status values defined in
[Submission Status Values](#submission-status-values) so a client implementation can
share the dispatching logic between key fetch and
submission.

| Status | Meaning |
|---|---|
| `found` | The recipient's SEMP keys were obtained. The client MAY proceed with SEMP composition. |
| `not_found` | The recipient's domain supports SEMP, but no key record was returned for the requested address. The address may be unpublished, withheld by recipient policy, or non-existent on the domain; the protocol does not distinguish these cases at the discovery layer. |
| `legacy_required` | The recipient's domain does not support SEMP, and MX records confirm legacy mail is available. The client MAY fall back to SMTP per [Legacy Required Fallback](#legacy-required-fallback), subject to the user-consent and integrity rules. |
| `recipient_not_found` | The recipient's domain supports neither SEMP nor legacy mail (no SEMP discovery, no MX records). No delivery path is available, and the client MUST surface the address as undeliverable. |
| `error` | The home server could not complete the discovery or key fetch operation. The `reason` field describes the failure. Transient failures MAY be retried. |

The `origin_signature` field carries the remote domain's
signature over the key material as received from the remote
server's well-known URI. This allows the client to verify
that the keys were signed by the remote domain rather than
only by the home server. The home server MUST NOT strip or
replace this signature. If the home server cannot obtain a
signed response (for example, the remote server does not
sign key responses), `origin_signature` is `null` and the
client MUST treat the keys with reduced trust per the
domain-signature rules in [Discovery](discovery.md).

### Server Obligations

The home server MUST:

* Fulfill key requests using whatever fetching mechanism its
  operator has configured per
  [Discovery](discovery.md) (speculative batch cache,
  third-party relay, or direct well-known fetch).
* Return cached keys when available and within their TTL.
* Forward the remote domain's original signature intact in
  `origin_signature`.
* Return `status: "found"` when the recipient's domain
  supports SEMP and a key record for the requested address
  was obtained.
* Return `status: "not_found"` when the recipient's domain
  supports SEMP but no key record was obtained for the
  requested address.
* Return `status: "legacy_required"` when discovery
  classifies the recipient's domain as `legacy` per
  [Discovery](discovery.md) (no SEMP support, MX
  records present). The result entry's `user_keys` MUST be
  empty in this case.
* Return `status: "recipient_not_found"` when discovery
  classifies the recipient's domain as `not_found` per
  [Discovery](discovery.md) (no SEMP support, no MX
  records).
* Return `status: "error"` with a `reason` field if the
  fetch failed transiently (network error, timeout,
  rate-limited by remote domain).

The home server MUST NOT:

* Modify, re-sign, or substitute key material received from
  a remote domain.
* Cache keys beyond the TTL declared in the remote server's
  response.
* Reveal to the remote domain which specific user on the
  home server requested the keys.

# Envelope Submission Protocol

When the client transmits an assembled envelope to its home
server, the server MUST respond with a structured submission
response. This section defines that response format and the
client obligations that follow from each response type. When
the HTTP/2 transport binding is in use, envelope submission
is a `POST` to `/v1/envelope` per
[Handshake](handshake.md).

## Submission Response Schema

~~~ json
{
    "type": "SEMP_SUBMISSION",
    "step": "response",
    "version": "1.0.0",
    "envelope_id": "postmark-ulid-of-submitted-envelope",
    "timestamp": "2025-06-10T20:35:18Z",
    "results": [
        {
            "recipient": "user@example.com",
            "status": "delivered",
            "reason_code": null,
            "reason": null
        }
    ]
}
~~~

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | Yes | MUST be `"SEMP_SUBMISSION"`. |
| `step` | string | Yes | MUST be `"response"`. |
| `version` | string | Yes | SEMP protocol version (semver). |
| `envelope_id` | string | Yes | The `postmark.id` of the submitted envelope. |
| `timestamp` | string | Yes | ISO 8601 UTC timestamp of the server's response. |
| `results` | array | Yes | One result entry per recipient. See [Result Entry Schema](#submission-result-entry). |

<a id="submission-result-entry"></a>

## Result Entry Schema
Each entry in `results` describes the delivery outcome for
one recipient address.

| Field | Type | Required | Description |
|---|---|---|---|
| `recipient` | string | Yes | The recipient address this result applies to. |
| `status` | string | Yes | One of the status values defined in [Submission Status Values](#submission-status-values). |
| `reason_code` | string | No | Machine-readable reason. Present for `rejected`, `legacy_required`, and migration redirects (see [Migration Notice Handling](#migration-notice-handling)). |
| `reason` | string | No | Human-readable description. Present when `reason_code` is present. |

<a id="submission-status-values"></a>

## Submission Status Values
| Status | Meaning |
|---|---|
| `delivered` | Server accepted and delivered the envelope to the recipient server. |
| `rejected` | Recipient server explicitly refused. `reason_code` is present. |
| `silent` | No response from recipient server within the timeout window. |
| `legacy_required` | Recipient domain does not support SEMP. MX records confirm SMTP is available. See [Legacy Required Fallback](#legacy-required-fallback). |
| `recipient_not_found` | No SEMP support and no MX records found. The recipient domain cannot receive mail by any known method. Per-address existence is not checked. |
| `queued` | Server accepted the envelope and will attempt delivery. Outcome pending. |

`queued` applies when the server cannot complete delivery
synchronously (for example, the recipient server is
temporarily unreachable). The server MUST follow up with a
delivery event notification when the queued envelope is
eventually delivered, rejected, or times out.

<a id="migration-notice-handling"></a>

## Migration Notice Handling
When a recipient's home provider has published a migration
record for the recipient's address, the recipient server
MUST return `rejected` with `reason_code: "policy_forbidden"`
and a body carrying the migration notice per
[Recovery](recovery.md) and
[Delivery](delivery.md). The body shape:

~~~ json
{
    "migration_notice": {
        "address": "alice@oldprovider.example",
        "new_address": "alice@newprovider.example",
        "record_id": "migration-record-ulid",
        "notice_window_until": "2026-08-19T00:00:00Z"
    }
}
~~~

On receipt, the client MUST:

1. Surface the migration notice to the user with the new
   address and the migration record reference.
2. Offer the user an action to update the local address book
   entry for the recipient to the new address. The client
   MUST NOT silently rewrite address book entries.
3. Resend to the new address only after explicit user
   confirmation. The client MUST NOT auto-forward to the new
   address without user input.

After the notice window has ended, the old provider stops
returning the migration notice and the recipient's address
is handled as a non-existent address per
[Recovery](recovery.md). The client's behavior in this
case is the same as for any other `recipient_not_found` or
`rejected` outcome.

A user MAY manually forward a previously received envelope
addressed to the old provider through a still-active client
session at the old provider, using the ordinary forwarding
primitive in [Envelope](envelope.md). This is ordinary
user-initiated forwarding by the still-authenticated user;
the old provider does not perform forwarding on the user's
behalf.

<a id="legacy-required-fallback"></a>

## Legacy Required Fallback
When the server returns `legacy_required` for a recipient,
it has determined via discovery that the recipient domain
does not support SEMP. The envelope cannot be delivered via
SEMP for that recipient. The client's fallback path is its
own legacy mail credentials for a separate, classically
provisioned mail account. The SEMP home server is not a
participant in legacy delivery.

SEMP does not constrain the legacy send protocol. SMTP
Submission [RFC 6409](https://www.rfc-editor.org/rfc/rfc6409), typically port 587, is the dominant
and RECOMMENDED mechanism for legacy outbound. Where this
specification refers to "SMTP fallback" or "SMTP
credentials", it means whatever protocol the client uses to
hand a MIME message off to the user's legacy outbound
provider. A client using a provider API (for example a
proprietary HTTP send endpoint) in place of SMTP Submission
is conformant as long as the resulting message on the
legacy network satisfies the composition rules in
[MIME Composition](#mime-composition) and the upgrade-signal rules in
[SEMP Upgrade-Signaling Headers](#semp-upgrade-headers).

The inbound counterpart is symmetric. The client retrieves
legacy mail via IMAP, POP3, or any other mechanism the
legacy provider supports per [Legacy-Origin Messages](#legacy-origin). The choice
is operational, and this specification does not constrain
it.

<a id="user-consent"></a>

### User Consent
The client MUST:

1. Surface the degradation to the user before proceeding.
   The user MUST be informed that the message to this
   recipient will be sent without end-to-end encryption,
   sealed metadata, or explicit rejection guarantees.
2. Require explicit user confirmation to proceed with SMTP
   fallback. The client MUST NOT automatically send via
   SMTP without user awareness.
3. If the user confirms: compose a MIME message per
   [MIME Composition](#mime-composition) and deliver it via SMTP per
   [SEMP Upgrade-Signaling Headers](#semp-upgrade-headers).
4. If the user declines: surface the message as undelivered
   for that recipient and retain it for the user to act on.

The client MUST NOT include decrypted `enclosure` content in
SMTP delivery without first surfacing the encryption
degradation to the user.

<a id="mime-composition"></a>

### MIME Composition
The MIME message submitted to SMTP MUST be a
standards-compliant [RFC 5322](https://www.rfc-editor.org/rfc/rfc5322) and [RFC 2045](https://www.rfc-editor.org/rfc/rfc2045) message
derived from the plaintext content of the intended SEMP
envelope. The client MUST produce the following header set
at minimum:

| Header | Value |
|---|---|
| `From` | The user's legacy SMTP address as configured in the client's SMTP credentials. This is not the user's SEMP address unless the two coincide. |
| `To` | The legacy recipients for this send, one per address. Multiple addresses are comma-separated per [RFC 5322](https://www.rfc-editor.org/rfc/rfc5322). |
| `Cc` | As set by the user at compose time. MAY be absent. |
| `Bcc` | The client MUST NOT emit `Bcc` headers. Blind copies are delivered by omitting the recipient from `To` and `Cc` while still including them in SMTP `RCPT TO`. |
| `Subject` | The `subject` the user entered at compose time. Identical to what would have gone into `brief.subject` for a SEMP send. |
| `Date` | Current UTC time in [RFC 5322](https://www.rfc-editor.org/rfc/rfc5322) date-time form. |
| `Message-ID` | A fresh [RFC 5322](https://www.rfc-editor.org/rfc/rfc5322) Message-ID. The client MUST record this value in its local legacy-threading map ([Thread Continuity Across SEMP and Legacy](#thread-continuity)). |
| `In-Reply-To` | If the send is a reply, the Message-ID the client resolved per [Thread Continuity Across SEMP and Legacy](#thread-continuity). |
| `References` | The ancestor chain resolved per [Thread Continuity Across SEMP and Legacy](#thread-continuity). |
| `MIME-Version` | `1.0`. |
| `Content-Type` | Set per the message's structure: `text/plain; charset="utf-8"` for plain bodies, `multipart/alternative` when both HTML and text are present, `multipart/mixed` when attachments accompany the body. Encoding MUST be a valid MIME transfer encoding (7bit, quoted-printable, or base64). |

The body is the plaintext content the user composed.
Attachments MUST be carried as additional MIME parts with
`Content-Type`, `Content-Disposition`, and
`Content-Transfer-Encoding` per [RFC 2183](https://www.rfc-editor.org/rfc/rfc2183) and
[RFC 2045](https://www.rfc-editor.org/rfc/rfc2045). The client MUST NOT attach any SEMP-layer
artifact (postmark, seal, encrypted brief, encrypted
enclosure, domain signature) to the MIME message. Those
fields have no meaning to an SMTP recipient, and including
them risks exposing metadata in plaintext.

SMTP envelope addresses (`MAIL FROM` and `RCPT TO`) MUST use
the ASCII A-label form of any IDN domain per
[Envelope](envelope.md).

<a id="semp-upgrade-headers"></a>

### SEMP Upgrade-Signaling Headers
When a SEMP-capable recipient client processes a received
legacy message, an advertised SEMP identity on the sender
allows the recipient to offer a thread upgrade without an
additional DNS lookup. A sending client SHOULD include the
following headers on every SMTP message it sends:

| Header | Value |
|---|---|
| `SEMP-Capability` | `1`. Present whenever the sender's client can receive via SEMP at a published SEMP address. |
| `SEMP-Identity` | Fingerprint of the sender's current SEMP identity public key, in the form `<algorithm>:<hex>` (for example `ed25519:abc123...`). |
| `SEMP-Domain` | The sender's SEMP domain (the domain part of the sender's SEMP address). MAY differ from the domain of `From`. |
| `SEMP-Address` | Full SEMP address of the sender. Included so the recipient does not have to infer it from the `From` local-part when the SMTP and SEMP local-parts differ. |

The sending client MAY omit these headers on messages the
user has flagged as "do not advertise SEMP-capability", for
example when sending from a throwaway SMTP identity the
user does not wish to link to their SEMP identity. Omission
is a user-privacy setting, and a server MUST NOT treat
omission as a protocol fault.

A receiving SEMP-capable client that observes these headers
on an inbound legacy message MAY cache `(From-address,
SEMP-Address, SEMP-Identity, SEMP-Domain)` as an upgrade
hint per [Upgrade-Signal Detection](#upgrade-signal-detection). A recipient client
that does not recognize the headers MUST ignore them per
[RFC 5322](https://www.rfc-editor.org/rfc/rfc5322)'s tolerance for unknown headers.

The upgrade signal is unauthenticated at the SMTP layer. An
attacker who can inject SMTP mail can also inject false
SEMP headers. A recipient client that acts on the signal
MUST verify the advertised identity by completing SEMP
discovery against `SEMP-Domain` and fetching the identity
key from that domain before treating the upgrade as
trusted per [Upgrade-Signal Detection](#upgrade-signal-detection).

<a id="thread-continuity"></a>

### Thread Continuity Across SEMP and Legacy
A conversation may mix SEMP and legacy messages: a
SEMP-capable user replies via SMTP to a legacy contact; a
SEMP-capable user receives SMTP mail and later upgrades the
correspondent to SEMP. The client MUST maintain a local
mapping so that thread state is continuous regardless of the
origin of each message.

**Local threading map.** For every message the client sends
or receives (SEMP or legacy), the client stores a tuple
`(thread_key, message_origin, message_id_legacy,
message_id_semp, parent_message_id, sent_at)`, where:

* `thread_key` is a stable identifier the client chooses at
  thread creation. All messages in the thread share this
  key.
* `message_origin` is `semp` or `legacy`.
* `message_id_legacy` is the [RFC 5322](https://www.rfc-editor.org/rfc/rfc5322) `Message-ID`
  header if the message traversed SMTP, otherwise empty.
* `message_id_semp` is the `brief.message_id` value if the
  message is a SEMP envelope, otherwise empty.
* `parent_message_id` is the identifier (of either form) of
  the message this one replies to, if any.

**Reply routing.** On reply:

* If the parent message was SEMP and the reply is being
  sent via SEMP, the client sets `brief.in_reply_to` to the
  parent's `message_id_semp`.
* If the parent message was SEMP and the reply is being
  sent via SMTP (because the recipient is legacy-only at
  reply time), the client sets SMTP `In-Reply-To` to a
  synthetic Message-ID derived from the parent's
  `message_id_semp`, encoded as
  `<message_id_semp>@semp.example`, where `semp.example` is
  a placeholder hostname the client uses consistently for
  synthetic SEMP-derived Message-IDs.
* If the parent message was legacy and the reply is being
  sent via SMTP, the client sets SMTP `In-Reply-To` to the
  parent's `message_id_legacy` directly.
* If the parent message was legacy and the reply is being
  sent via SEMP (because the correspondent was upgraded in
  the meantime), the client sets `brief.in_reply_to` to a
  synthetic value derived from the parent's
  `message_id_legacy`, prefixed with `legacy:`, for
  example `legacy:01234567@example.com`. This form is
  never emitted as an [RFC 5322](https://www.rfc-editor.org/rfc/rfc5322) Message-ID, and it is
  used solely as a SEMP internal reference.

The client MUST build the full `References` header and
`brief.thread_ancestors` (if the brief defines one) from its
local thread map so that receiving clients, SEMP or legacy,
can reconstruct the thread in full. The mapping is
client-local, and the home server does not participate.

The client MUST NOT attempt to reuse a legacy Message-ID as
a SEMP `brief.message_id` value or vice versa. The
identifier spaces are distinct. The synthetic-prefix rules
above are the only cross-references a client MAY emit.

<a id="mixed-recipient-composes"></a>

### Mixed-Recipient Composes
When a single compose action names both SEMP-reachable
recipients and recipients classified as `legacy_required`
(either at key fetch per [Key Response Status Values](#key-response-status-values) or
at envelope submission per [Submission Status Values](#submission-status-values)),
the client MUST split the delivery rather than downgrade
the entire send.

The user-consent check on the legacy group gates the
entire send. The gate covers every recipient in the
compose action, including the SEMP-reachable group. Until
the user resolves the prompt the client MUST NOT submit
the SEMP envelope, MUST NOT send the SMTP message, and
MUST NOT release the composed content to any recipient.
This preserves the integrity of the conversation: the user
is the only party that decides whether a thread the user
intended to keep end-to-end encrypted should split into a
plaintext copy for some recipients.

Required behavior:

1. Classify each recipient as SEMP-reachable (`found`) or
   legacy (`legacy_required`). Other statuses (see
   [Key Response Status Values](#key-response-status-values) and
   [Submission Status Values](#submission-status-values)) are handled per their own
   semantics; this subsection concerns the SEMP/legacy
   split only.

2. Surface the split to the user, listing which recipients
   would receive via SEMP and which via SMTP, with the
   SMTP group flagged with the degradation warning required
   by [User Consent](#user-consent).

3. Require an explicit user decision before any artifact is
   transmitted. The client MUST offer at least the
   following options:

   * **Send to all.** Compose and submit the SEMP envelope
     to the SEMP group and compose and send the SMTP
     message to the legacy group. Both are recorded in the
     local threading map under the same `thread_key`.
   * **Send only to SEMP recipients.** Compose and submit
     the SEMP envelope to the SEMP group, omit the legacy
     group entirely, and mark the legacy recipients as
     undelivered in the local delivery state. The client
     MUST surface the undelivered legacy recipients to the
     user in the same display surface used for partial
     failures per [Multi-Recipient Partial Failure](#multi-recipient-partial-failure), and
     the client MUST NOT auto-send to the legacy
     recipients later without a fresh user decision.
   * **Cancel.** Neither artifact is transmitted. The
     composed content remains in the user's drafts.

   The client MAY offer additional refinements (for
   example, demoting a SEMP-reachable recipient to the SMTP
   group for this specific send, or removing a single
   recipient from the list).

4. On a "Send to all" decision, produce two outbound
   artifacts:

   * A SEMP envelope addressed to the SEMP group, composed
     and submitted per the normal composition sequence
     ([Composition Sequence](#composition-sequence)).
   * A single SMTP message addressed to the legacy group,
     composed per [MIME Composition](#mime-composition) and sent via the
     client's SMTP credentials.

   Both artifacts MUST be recorded in the local threading
   map under the same `thread_key`.

5. On a "Send only to SEMP recipients" decision, produce
   only the SEMP envelope and record the legacy group as
   undelivered. The undelivered state MUST persist across
   client restarts so the user can act on it later.

A conformant client MUST NOT:

* Silently downgrade SEMP-reachable recipients to SMTP
  without explicit user confirmation.
* Submit the SEMP envelope before the user has resolved the
  legacy-consent prompt.
* Omit legacy recipients from the send without informing
  the user that the delivery was partial and recording the
  legacy recipients as undelivered.
* Combine the SEMP and SMTP artifacts into a single MIME
  message that includes both encrypted and plaintext
  renditions of the same content.
* Persist the legacy plaintext on the home server, or any
  remote system controlled by the home server, while the
  user-consent prompt is open.

### Legacy Credentials

The client MUST use its locally held legacy mail credentials
only (SMTP Submission for send, or a provider equivalent).
Credentials MUST NOT be transmitted to the home server or
any other SEMP protocol participant. See
[Legacy Credential Isolation](#legacy-credential-isolation), which applies symmetrically
to outbound send credentials and inbound retrieval
credentials (IMAP, POP3, JMAP, or provider API).

<a id="delivery-events"></a>

## Delivery Event Notifications
For envelopes with status `queued`, the server MUST send a
delivery event notification to the client when the outcome
is known:

~~~ json
{
    "type": "SEMP_SUBMISSION",
    "step": "event",
    "version": "1.0.0",
    "envelope_id": "postmark-ulid",
    "recipient": "user@example.com",
    "status": "delivered",
    "reason_code": null,
    "reason": null,
    "timestamp": "2025-06-10T20:36:45Z",
    "receipt": {
        "type": "SEMP_DELIVERY_RECEIPT",
        "version": "1.0.0",
        "envelope_hash": {
            "algorithm": "sha-256",
            "value": "base64-digest"
        },
        "recipient_domain": "recipient.example",
        "accepted_at": "2025-06-10T20:36:44Z",
        "signature": {
            "algorithm": "ed25519",
            "key_id":
                "recipient-domain-key-fingerprint",
            "value": "base64-signature"
        }
    }
}
~~~

The client MUST update its local delivery state on receipt
of a delivery event. A delivery event with
`status: delivered` is the only valid basis for displaying a
confirmed delivery indicator for a previously queued
envelope.

The `status` field in a delivery event MAY take any terminal
state defined in [Delivery](delivery.md), including
`delivered`, `rejected`, `expired`, and `canceled`. The
`reason_code` field is present for `rejected` terminal
states and absent for the others.

### Receipt Handling

When `status` is `delivered`, the server MUST include the
signed delivery receipt returned by the recipient server in
the `receipt` field. The receipt schema and semantics are
defined in [Delivery](delivery.md).

The client MUST verify the receipt's signature against the
recipient domain's published signing key before treating
the event as confirmed delivery. A delivery event with
`status: delivered` that lacks a `receipt` field, or whose
receipt does not verify, MUST NOT be displayed to the user
as confirmed delivery. The client SHOULD surface the
anomaly and treat the envelope's delivery state as
indeterminate.

The client SHOULD retain the receipt in local storage keyed
by `envelope_id` and SHOULD offer an export action that
writes the receipt as a `.semp-receipt` file per the
`application/semp-receipt` media type in
[Envelope](envelope.md). The client MUST NOT discard
the receipt before the user has had an opportunity to
export it.

For `status` values other than `delivered`, the `receipt`
field MUST be absent.

## Cancellation Request

A client MAY request cancellation of a queued envelope
before it reaches a terminal state, per
[Delivery](delivery.md). The client sends a
cancellation request to its home server over its
authenticated client session.

### Cancellation Request Schema

~~~ json
{
    "type": "SEMP_SUBMISSION",
    "step": "cancel",
    "version": "1.0.0",
    "envelope_id": "postmark-ulid",
    "recipient": "user@example.com",
    "timestamp": "2025-06-10T20:36:00Z"
}
~~~

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | Yes | MUST be `"SEMP_SUBMISSION"`. |
| `step` | string | Yes | MUST be `"cancel"`. |
| `version` | string | Yes | SEMP protocol version (semver). |
| `envelope_id` | string | Yes | The `postmark.id` of the envelope to cancel. |
| `recipient` | string or null | No | Target recipient address. If absent, cancel applies to all non-terminal recipients of the envelope. |
| `timestamp` | string | Yes | ISO 8601 UTC timestamp of the cancellation request. |

### Cancellation Response Schema

The home server MUST respond with a per-record summary:

~~~ json
{
    "type": "SEMP_SUBMISSION",
    "step": "cancel_response",
    "version": "1.0.0",
    "envelope_id": "postmark-ulid",
    "timestamp": "2025-06-10T20:36:01Z",
    "results": [
        {
            "recipient": "user@example.com",
            "state": "canceled",
            "reason_code": null,
            "reason": null
        }
    ]
}
~~~

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | Yes | MUST be `"SEMP_SUBMISSION"`. |
| `step` | string | Yes | MUST be `"cancel_response"`. |
| `version` | string | Yes | SEMP protocol version (semver). |
| `envelope_id` | string | Yes | The `postmark.id` of the envelope addressed by the cancellation request. |
| `timestamp` | string | Yes | ISO 8601 UTC timestamp of the response. |
| `results` | array | Yes | One entry per affected queue state record. |

Each `results` entry has the following fields:

| Field | Type | Required | Description |
|---|---|---|---|
| `recipient` | string | Yes | The recipient address this result applies to. |
| `state` | string | Yes | The queue state record's state after processing: `canceled`, `delivered`, `rejected`, `expired`, or `queued` (if cancellation was not accepted). |
| `reason_code` | string or null | No | Machine-readable reason when `state` is `rejected` or when the cancellation was refused. |
| `reason` | string or null | No | Human-readable description. Present when `reason_code` is present. |

### Cancellation Client Obligations

The client MUST NOT display a `canceled` indicator for a
recipient until a `cancel_response` entry or a delivery
event ([Delivery Event Notifications](#delivery-events)) reports `state: canceled` for
that recipient. The client MUST NOT assume cancellation
succeeded based on having sent the request.

If the cancellation response reports a terminal state other
than `canceled` for a given recipient (for example,
`delivered` because an in-flight attempt completed before
the cancellation could be applied), the client MUST display
that terminal state in place of `canceled`. The client MUST
NOT misrepresent a delivered envelope as canceled.

A delegated client MUST NOT send cancellation requests for
envelopes it did not itself submit. Attempting to cancel
another client's envelope MUST result in a refused
cancellation ([Refused Cancellation](#refused-cancellation)).

<a id="refused-cancellation"></a>

### Refused Cancellation
If the home server refuses a cancellation request in whole
or in part, it MUST return `state: queued` (or the current
non-canceled state) with a `reason_code`. The following
reason codes apply:

| Reason code | Meaning |
|---|---|
| `not_found` | No queue state record exists for the given `envelope_id` and `recipient`. |
| `scope_exceeded` | The requesting delegated client did not submit the target envelope. |
| `unauthorized` | The requesting session does not belong to the sending user account. |

# Delivery State

## Acknowledgment Reporting

Clients MUST accurately reflect the submission status
received from the home server:

| Status | Required client behavior |
|---|---|
| `delivered` | Display a confirmed delivery indicator. |
| `rejected` | Display an explicit failure indicator with the reason accessible to the user. |
| `silent` | Display an unacknowledged state, distinct from both `delivered` and `rejected`. |
| `legacy_required` | Surface degradation warning and await user confirmation before SMTP fallback. |
| `recipient_not_found` | Display an undeliverable indicator. No fallback is available. |
| `queued` | Display a pending state. Update when delivery event is received. |
| `expired` | Display a delivery-failed indicator. Received only via delivery event after the effective deadline elapses (see [Delivery](delivery.md)). |
| `canceled` | Display a canceled indicator. Received only via delivery event or cancellation response. |

Clients MUST NOT display a delivery-confirmed indicator
until a `delivered` status has been received, either in the
submission response or in a subsequent delivery event.
Clients MUST distinguish all states above in the UI
presented to the user.

## Persistent Silent Recipient Visibility

When the sending server has shortened the effective delivery
deadline for a recipient on the basis of the persistent
silent counter defined in [Delivery](delivery.md), the
server MAY surface the shortened-deadline state to the
client through the queue state record's `deadline` field.
The client MAY surface this to the user as additional
context (for example, "delivery to this recipient is
attempted on a shortened window because of repeated silent
outcomes"). The counter is sender-side state and MUST NOT
be exposed on the wire to other parties. A client MUST NOT
publish or share the counter outside the local user's
display.

<a id="first-contact-inbox"></a>

## First-Contact Inbox
When the recipient client receives an envelope from a sender
that is not yet a known correspondent per
[Delivery](delivery.md), the client SHOULD present the
envelope in a separate first-contact area of the user
interface, distinct from the primary inbox. The user MAY
then approve, ignore, or block the sender.

The criteria the client uses to determine "known
correspondent" SHOULD match the home server's criteria per
[Delivery](delivery.md). Where the client's local view
differs from the server's, the client SHOULD treat the union
of the two as the known set, so that no envelope from an
already trusted sender is gated on either side.

### Approval Action

When the user approves a first-contact sender, the client
MUST:

1. Add the sender to its local known correspondents store.
2. Transmit a signed user policy update to the home server
   carrying an `add` operation with
   `kind: "accepted_sender"` per
   [Delivery](delivery.md). The `kind` is a core
   user-policy kind and is used without a namespace prefix.
3. Move the envelope into the primary inbox.

### Reply Implies Approval

When the user replies to an envelope still in the
first-contact area, the client MUST treat the reply as an
implicit approval of the sender and MUST perform the
actions in the approval flow above before transmitting the
reply.

### No Auto-Approval

The client MUST NOT auto-approve first-contact senders on
heuristics (sender reputation, message content scoring,
attachment absence, prior contact within the user's address
book). Approval MUST be the result of an explicit user
action: tap, click, keyboard shortcut, or reply.

<a id="multi-recipient-partial-failure"></a>

## Multi-Recipient Partial Failure
When delivery fails for a subset of recipients in a
multi-recipient message, the client MUST surface which
recipients received the message and which did not. Partial
failure information MUST NOT be suppressed. `legacy_required`
for a subset of recipients is a partial degradation and MUST
be surfaced per-recipient, and it MUST NOT be suppressed or
aggregated.

# User Policy

## User Policy Synchronization

User policy changes initiated by the client (block list
entries, accepted-senders entries, first-contact policy
mode, and any other rule kinds defined in
[Delivery](delivery.md)) MUST be transmitted to the
home server as signed `SEMP_USER_POLICY` messages per
[Delivery](delivery.md). The client MUST sign sync
messages with the originating device's key before
transmission.

## Recipient Status Configuration

The recipient status mechanism defined in
[Delivery](delivery.md) is produced by the client. The
client composes a signed `SEMP_STATUS` record carrying the
user's `state`, optional `message` and `until` fields, and a
`visibility` rule that determines which senders may receive
the status in acknowledgments. The client transmits the
record to the home server as a signed message under the
originating device's key, using the same authentication
model as user policy sync messages.

The client MUST present the user with a configuration
interface for `state`, `message`, `until`, and `visibility`.
The default visibility mode is `nobody`. The client MUST NOT
publish or transmit a status update without an explicit user
action.

When the user removes a previously configured status, the
client MUST transmit an updated `SEMP_STATUS` record with
the cleared fields and a fresh `updated_at` so that the home
server retires the prior record.

## Attachment Storage Configuration

When the user has elected to attach files larger than the
inline embedding limit, the client uses an out-of-band
storage URL identified per the attachment mechanism in
[Envelope](envelope.md). The storage URL is a
client-side configuration value held by the user, and it is
not advertised in the home server's discovery configuration.
The client MUST allow the user to configure one or more
storage URLs (operator-hosted, third-party, or self-hosted)
and to select among them at compose time. The code path is
the same regardless of where storage is located.

## Abuse Reporting

When a user files an abuse report, the client collects the
postmark and seal from the reported envelope and submits the
report to the home server per the abuse reporting protocol
in [Delivery](delivery.md).

If the report includes decrypted `brief` or `enclosure`
content as evidence, the client MUST obtain the user's
explicit signed authorization before including it per
[Delivery](delivery.md). The client MUST NOT
automatically include decrypted content in any abuse
report.

<a id="abuse-evidence-integrity"></a>

### Evidence Integrity
The evidence package the client assembles is self-proving
under the existing SEMP cryptographic primitives, and the
client does not need to compute any additional signature
over the evidence beyond what those primitives already
produce.

A reviewer who holds the disclosed evidence verifies it as
follows:

* The envelope's `seal.signature` binds the postmark, brief,
  and enclosure ciphertext to the sender's domain key per
  [Envelope](envelope.md). A reviewer that fetches the
  sender domain's signing key from [Discovery](discovery.md)
  and verifies `seal.signature` over the canonical sealed
  bytes confirms that the sender's home server posted this
  exact envelope.
* The decrypted `enclosure.sender_signature` binds the
  enclosure plaintext (including its `subject`, `body`,
  `attachments`, and any `forwarded_from` chain) to the
  sender's long-term identity key per
  [Envelope](envelope.md). A reviewer that fetches the
  sender's identity key from
  [Discovery](discovery.md) and verifies the signature
  over the canonical enclosure bytes confirms that the
  sender authored that exact plaintext. Any tampering with
  any enclosure field invalidates the signature.
* The signed delivery receipt (if retained, see
  [Delivery Event Notifications](#delivery-events)) binds the envelope's content hash to
  the recipient domain's acceptance per
  [Delivery](delivery.md). A reviewer that fetches the
  recipient domain's signing key and verifies the receipt
  confirms that the recipient's home server accepted this
  exact envelope.
* The user's signed authorization that accompanies the
  disclosure binds the consent to disclose to the
  recipient's identity key, so a reviewer can confirm the
  disclosure is not unauthorized.

The client's obligation is therefore to preserve and
forward these existing signed artifacts verbatim. The
client MUST NOT modify any signed bytes (canonical
enclosure, postmark, seal, or receipt) when including them
as evidence. The client MUST NOT generate a new signature
"over the report" as a substitute for the existing
signatures; that would introduce a parallel attestation
path the protocol does not need.

When the report concerns adversarial trust gossip rather
than an envelope, evidence integrity rests on the
observation record's own signature and the `evidence_hash`
field per [Delivery](delivery.md). The same principle
applies: the existing signed bytes are forwarded verbatim,
without an additional client-applied signature.

### Abuse-Category Enumeration

The user-facing abuse-category enumeration MUST include the
categories registered in [Delivery](delivery.md),
including `spam`, `phishing`, `harassment`, `malware`,
`policy_violation`, and `observation_record_abuse` (the
last applies when the user is reporting adversarial trust
gossip behavior rather than a correspondence envelope, and
SHOULD be presented under a distinct surface from
correspondence-envelope reports). When the user selects
`observation_record_abuse`, the client MUST collect the
offending observation record (or its identifier) as
evidence, in place of an envelope's postmark and seal.

# Notification Content Constraints

Push notifications generated for incoming messages MUST NOT
include content derived from the `enclosure`. Subject, body
preview, and attachment names MUST NOT appear in
notification payloads transmitted to platform notification
services (APNs, FCM, or equivalent).

When platform notification services are used, the
notification payload serves only as a wakeup signal. The
client retrieves and decrypts the envelope after connecting
to the home server. Envelope content MUST NOT be included
in the push payload.

# Security Considerations

## Private Key Confidentiality

Private key material MUST NOT be transmitted over any
network interface, including to the home server. Clients
MUST NOT log private key material.

## Enclosure Content Boundary

Clients MUST NOT transmit plaintext `enclosure` content to
the home server for any purpose, including search indexing,
notification previews, or draft storage. If draft
synchronization across devices is implemented, draft content
MUST be encrypted before transmission to the home server
using key material the server does not hold.

## Remote Content in Message Bodies

Remote resource loading from `enclosure` HTML content
(images, stylesheets, scripts) MUST be blocked by default.
Loading remote resources reveals the recipient's IP address
and read timing to external infrastructure. Clients MUST
require explicit user permission before loading remote
content.

## Active Content

Clients MUST prevent execution of scripts or active content
embedded in `enclosure` message bodies.

<a id="legacy-credential-isolation"></a>

## Legacy Credential Isolation
When a client holds credentials for legacy mail access (SMTP
Submission, IMAP, POP3, JMAP, or a proprietary provider API)
per [Legacy-Origin Messages](#legacy-origin) and [Legacy Required Fallback](#legacy-required-fallback),
those credentials MUST be stored locally on the client only.
Clients MUST NOT transmit legacy credentials to the SEMP
home server for any purpose. If a client implementation
stores credentials in a shared credential store, it MUST use
the most restrictive access controls available on the
platform.

This rule applies symmetrically to outbound credentials
(used by the SMTP fallback path in
[Legacy Required Fallback](#legacy-required-fallback)) and inbound credentials (used
to retrieve legacy messages per [Legacy-Origin Messages](#legacy-origin)). The SEMP
server never needs these credentials and MUST never be
given them.

## Upgrade Signal Trust

The SEMP upgrade-signaling headers carried on SMTP messages
([SEMP Upgrade-Signaling Headers](#semp-upgrade-headers)) are unauthenticated at the SMTP
layer. A recipient client that observes these headers MUST
verify the advertised SEMP identity through discovery and
key fetch before treating the upgrade hint as actionable.
The verification flow is defined in
[Upgrade-Signal Detection](#upgrade-signal-detection).

## Mixed-Source Inbox Confusion

Combining SEMP and legacy messages in a single inbox is a
common usability requirement and a known source of user
confusion about the trust properties of each message. The
origin indicator requirements ([Legacy-Origin Messages](#legacy-origin)) reduce
this risk. A client that fails to render a persistent
origin indicator on every legacy message in a unified inbox
view is non-conformant. Implementations SHOULD also
distinguish key-transparency-verified SEMP messages from
unverified SEMP messages in user-visible ways.

# IANA Considerations

This document does not request new IANA registrations. The
extension namespace and the registries this document
references (reason codes, abuse categories, observation
kinds, delivery acknowledgment values) are governed by
registries defined in [Delivery](delivery.md) and
[Extensions](extensions.md).

The media types `application/semp-envelope`,
`application/semp-receipt`, `application/semp-recovery`, and
`application/semp-migration` referenced in this document
are registered in [Envelope](envelope.md).

# Acknowledgments

The author thanks the contributors to the SEMP specification
for review, design discussion, and prior-art analysis.

