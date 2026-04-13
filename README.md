# SEMP: Sealed Envelope Messaging Protocol (DRAFT, SUBJECT TO CHANGES)

SEMP is a federated messaging protocol designed to replace SMTP. It addresses
five structural failures of email that decades of patches have failed to fix:

1. **Metadata is exposed.** Sender, recipient, and subject are visible in
   plaintext to every server that handles a message. SEMP seals them inside
   an encrypted envelope. Routing servers see only the destination domain.

2. **Trust is anchored to IP addresses.** New mail servers are treated as
   suspicious regardless of their operator's legitimacy. SEMP anchors trust
   to cryptographic domain identity. New domains start at zero reputation.

3. **Rejection is dishonest.** SMTP servers silently accept messages they
   intend to discard. SEMP requires explicit rejection with a reason code.

4. **Messages have no integrity proof.** Content can be altered in transit
   with no reliable way to detect it. SEMP envelopes carry two independent
   integrity proofs: a domain signature verifiable by any routing server and
   a session MAC verifiable by the receiving server.

5. **The protocol cannot evolve.** Adding capabilities to SMTP requires
   fragile extensions that implementations are free to ignore. SEMP is built
   for extensibility, since capability negotiation is part of every connection.

## The Envelope Model

SEMP's message unit is the **envelope**, modeled on physical correspondence:

```
envelope
  ├── postmark     outer public header, visible to routing servers
  ├── seal         cryptographic integrity proof, tamper evident
  ├── brief        inner private header, encrypted, recipient only
  └── enclosure    message body and attachments, encrypted, recipient only
```

The postmark carries only what routing servers need: source and destination
domains. The brief contains correspondence metadata (full addresses,
timestamps, threading), encrypted so only the recipient server and client
can read it. The enclosure holds the message body and attachments, encrypted
under the recipient's key alone.

## Key Properties

**Transport-agnostic.** SEMP runs over WebSocket, HTTP/2, or QUIC on port
443. No dedicated port, no special firewall rules. A SEMP server can run on
shared PHP hosting behind a standard web server.

**Forward secret.** Every session uses ephemeral key exchange. Compromise of
any long-term key cannot retroactively decrypt past sessions. Session keys are
derived per-connection and erased after use.

**Post-quantum ready.** The recommended cipher suite uses a hybrid Kyber768 +
X25519 key agreement. Sessions are protected against harvest-now-decrypt-later
attacks from future quantum computers.

**Incrementally adoptable.** SEMP coexists with SMTP. When a recipient domain
doesn't support SEMP, the client is notified and can fall back to SMTP with
explicit user consent. No flag day required.

**Tor-compatible.** SEMP operates over Tor without protocol modification. A
`.onion` address triggers direct well-known URI discovery over Tor via HTTP/2.

## Specification Documents

| Document | Description |
|---|---|
| [DESIGN.md](DESIGN.md) | Philosophy, principles, and non-goals. |
| [ENVELOPE.md](ENVELOPE.md) | The envelope model and field specifications. |
| [HANDSHAKE.md](HANDSHAKE.md) | Session establishment protocol. |
| [DISCOVERY.md](DISCOVERY.md) | Server and protocol discovery mechanisms. |
| [KEY.md](KEY.md) | Key management, publication, rotation, and revocation. |
| [SESSION.md](SESSION.md) | Forward secrecy, session key lifecycle, and rekeying. |
| [DELIVERY.md](DELIVERY.md) | Blocking, rejection, and delivery acknowledgment. |
| [CLIENT.md](CLIENT.md) | Client obligations, envelope submission, and legacy interop. |
| [REPUTATION.md](REPUTATION.md) | Trust signals, gossip protocol, and domain transfer. |
| [TRANSPORT.md](TRANSPORT.md) | Transport requirements, bindings, and negotiation. |
| [ERRORS.md](ERRORS.md) | Error codes registry and status values. |
| [CONFORMANCE.md](CONFORMANCE.md) | Conformance requirements for implementations. |
| [VECTORS.md](VECTORS.md) | Test vectors for implementers. |

## How It Works

**Discovery.** The sender's server queries DNS for the recipient domain's SEMP
records, then fetches capability information from the domain's well-known URI.
If the domain doesn't support SEMP, the client is informed and can fall back to
SMTP.

**Handshake.** The sender's server establishes a session with the recipient's
server through a four-message handshake. Ephemeral keys are exchanged, a shared
secret is derived, and both sides authenticate. Client identity never appears
in plaintext on the wire.

**Envelope delivery.** The client composes the message, encrypts the brief and
enclosure under fresh symmetric keys, wraps those keys under the recipient's
public keys, and submits the envelope to its home server. The server computes
the seal and delivers to the recipient's server over the established session.

**Explicit outcome.** The recipient's server returns one of three responses:
delivered, rejected with a reason code, or silent (permitted only for deliberate
privacy policy).

## SMTP vs SEMP

| | SMTP | SEMP |
|---|---|---|
| Metadata | Plaintext to every hop | Sealed; only domains visible in postmark |
| Trust anchor | IP address reputation | Cryptographic domain identity |
| Rejection | Silent discard common | Explicit with reason code |
| Integrity | Partial (DKIM on select headers) | Full envelope, two independent proofs |
| Forward secrecy | None | Per-session ephemeral key exchange |
| Post-quantum | None | Hybrid Kyber768 + X25519 |
| Transport | Dedicated port 25 | HTTPS on port 443 |
| Extensibility | Fragile optional headers | Built-in capability negotiation |

## Running a SEMP Server

A minimal SEMP deployment requires:

1. A domain with two DNS records (SRV + TXT under `_semp._tcp`).
2. A well-known URI endpoint at `/.well-known/semp/configuration`.
3. An HTTP/2 endpoint handling SEMP message types.
4. A domain key pair for signing.

Because SEMP is an application-layer protocol running over standard HTTPS,
it works on any infrastructure that can serve a web application, including
shared hosting.

## Project Status

SEMP is in the **draft specification** phase. The protocol design is complete
and internally consistent. Reference implementations and client/server
libraries are in development.

## Contributing

SEMP is an open protocol. Contributions to the specification and
implementations are welcome. If you're interested in contributing:

- Read the specification documents starting with [DESIGN.md](DESIGN.md).
- Review the [CONFORMANCE.md](CONFORMANCE.md) requirements.
- Use the [VECTORS.md](VECTORS.md) test vectors to validate your implementation.
- Open an issue or pull request.

## License

Code is licensed under the [MIT License](LICENSE). Protocol specification and its
documents are licensed under [Creative Commons Attribution 4.0](https://creativecommons.org/licenses/by/4.0/). See [LICENSE](LICENSE) for
details.
