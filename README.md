# SEMP: Sealed Envelope Messaging Protocol

Status: Internet-Draft. Subject to change.

SEMP is a federated messaging protocol designed to replace SMTP. Two independent implementations exist and interoperate end to end under both algorithm suites: [semp-go](https://github.com/semp-dev/semp-go) and [semp-ts](https://github.com/semp-dev/semp-ts), each passing the same 42 cross-language test vectors byte-for-byte.

The specification is split across eight Internet-Drafts. This repository holds the GitHub-rendered form of each draft together with the cross-language test vector corpus under [`vectors/`](vectors/). Project page: <https://semp.dev>.

## Drafts

### [Architecture](architecture.md)

Sealed Envelope Messaging Protocol: Architecture and Threat Model

- [Introduction](architecture.md#introduction)
- [Conventions and Definitions](architecture.md#conventions-and-definitions)
- [Terminology](architecture.md#terminology)
- [Design Principles](architecture.md#design-principles)
- [Non-Goals](architecture.md#non-goals)
- [The Envelope Model](architecture.md#the-envelope-model)
- [Trust and Reputation Model](architecture.md#trust-and-reputation-model)
- [Key Management Philosophy](architecture.md#key-management-philosophy)
- [Blocking and Rejection](architecture.md#blocking-and-rejection)
- [Legacy Interoperability](architecture.md#legacy-interoperability)
- [Relationship to Existing Standards](architecture.md#relationship-to-existing-standards)
- [Comparison with Related Systems](architecture.md#comparison-with-related-systems)
- [Document Series](architecture.md#document-series)
- [Threat Model](architecture.md#threat-model)
- [Security Considerations](architecture.md#security-considerations)
- [Protocol Constants](architecture.md#protocol-constants)
- [IANA Considerations](architecture.md#iana-considerations)
- [Acknowledgments](architecture.md#acknowledgments)

### [Envelope](envelope.md)

Sealed Envelope Messaging Protocol: Envelope Format

- [Introduction](envelope.md#introduction)
- [Conventions and Definitions](envelope.md#conventions-and-definitions)
- [Envelope Structure](envelope.md#envelope-structure)
- [Postmark](envelope.md#postmark)
- [Seal](envelope.md#seal)
- [Brief](envelope.md#brief)
- [Enclosure](envelope.md#enclosure)
- [Encryption Model](envelope.md#encryption-model)
- [Extensibility](envelope.md#extensibility)
- [Server Responsibilities](envelope.md#server-responsibilities)
- [Media Types](envelope.md#media-types)
- [Security Considerations](envelope.md#security-considerations)
- [Privacy Considerations](envelope.md#privacy-considerations)
- [Test Vectors](envelope.md#test-vectors)
- [IANA Considerations](envelope.md#iana-considerations)
- [Acknowledgments](envelope.md#acknowledgments)

### [Handshake](handshake.md)

Sealed Envelope Messaging Protocol: Handshake, Session, and Transport

- [Introduction](handshake.md#introduction)
- [Conventions and Definitions](handshake.md#conventions-and-definitions)
- [Connection Model and Privacy Constraint](handshake.md#connection-model-and-privacy-constraint)
- [Packet Discrimination](handshake.md#packet-discrimination)
- [Client Handshake](handshake.md#client-handshake)
- [Federation Handshake](handshake.md#federation-handshake)
- [Resumption](handshake.md#resumption)
- [Session Lifecycle](handshake.md#session-lifecycle)
- [Session Rekeying](handshake.md#rekeying)
- [Post-Quantum Forward Secrecy](handshake.md#post-quantum-forward-secrecy)
- [Session Invalidation and Blocking](handshake.md#session-invalidation-and-blocking)
- [Reason Codes](handshake.md#reason-codes)
- [Sending Server Retry Responsibility](handshake.md#sending-server-retry-responsibility)
- [Transport Bindings](handshake.md#transport-bindings)
- [Security Considerations](handshake.md#security-considerations)
- [Privacy Considerations](handshake.md#privacy-considerations)
- [Test Vectors](handshake.md#test-vectors)
- [IANA Considerations](handshake.md#iana-considerations)
- [Acknowledgments](handshake.md#acknowledgments)

### [Discovery](discovery.md)

Sealed Envelope Messaging Protocol: Discovery and Key Publication

- [Introduction](discovery.md#introduction)
- [Conventions and Definitions](discovery.md#conventions-and-definitions)
- [Discovery Responsibility and Privacy](discovery.md#discovery-responsibility-and-privacy)
- [DNS-Based Discovery](discovery.md#dns-based-discovery)
- [Tor-Reachable Deployments](discovery.md#tor-reachable-deployments)
- [Well-Known URI Discovery](discovery.md#well-known-uri-discovery)
- [Domain Key Publication](discovery.md#domain-key-publication)
- [User Key Publication](discovery.md#user-key-publication)
- [Key Request and Response](discovery.md#key-request-and-response)
- [Key Verification](discovery.md#key-verification)
- [Key Fetching Mechanisms](discovery.md#key-fetching-mechanisms)
- [Key Rotation](discovery.md#key-rotation)
- [Key Revocation](discovery.md#key-revocation)
- [Multi-Device Support](discovery.md#multi-device-support)
- [Protocol Lookup](discovery.md#protocol-lookup)
- [Discovery Flow](discovery.md#discovery-flow)
- [Caching](discovery.md#caching)
- [Legacy Integration](discovery.md#legacy-integration)
- [Security Considerations](discovery.md#security-considerations)
- [Privacy Considerations](discovery.md#privacy-considerations)
- [Test Vectors](discovery.md#test-vectors)
- [IANA Considerations](discovery.md#iana-considerations)
- [Acknowledgments](discovery.md#acknowledgments)

### [Delivery](delivery.md)

Sealed Envelope Messaging Protocol: Delivery, Reputation, and Errors

- [Introduction](delivery.md#introduction)
- [Conventions and Definitions](delivery.md#conventions-and-definitions)
- [Delivery Outcomes](delivery.md#delivery-outcomes)
- [Queueing, Retry, and Expiry](delivery.md#queueing-retry-expiry)
- [Delivery Pipeline](delivery.md#delivery-pipeline)
- [Block List](delivery.md#block-list)
- [Enforcement Points](delivery.md#enforcement-points)
- [User Policy Synchronization](delivery.md#user-policy-synchronization)
- [Reputation Signals](delivery.md#reputation-signals)
- [Abuse Reporting](delivery.md#abuse-reporting)
- [Trust Gossip](delivery.md#trust-gossip)
- [Trust Gossip Publication and Fetching](delivery.md#trust-gossip-publication-and-fetching)
- [Trust Transfer](delivery.md#trust-transfer)
- [Reason Code Registry](delivery.md#reason-codes)
- [Security Considerations](delivery.md#security-considerations)
- [Privacy Considerations](delivery.md#privacy-considerations)
- [Test Vectors](delivery.md#test-vectors)
- [IANA Considerations](delivery.md#iana-considerations)
- [Acknowledgments](delivery.md#acknowledgments)

### [Recovery](recovery.md)

Sealed Envelope Messaging Protocol: Recovery, Migration, Closure, and Transparency

- [Introduction](recovery.md#introduction)
- [Conventions and Definitions](recovery.md#conventions-and-definitions)
- [Account Recovery](recovery.md#recovery)
- [Provider Migration](recovery.md#migration)
- [Account Closure](recovery.md#closure)
- [Key Transparency](recovery.md#transparency)
- [Security Considerations](recovery.md#security-considerations)
- [Privacy Considerations](recovery.md#privacy-considerations)
- [Test Vectors](recovery.md#test-vectors)
- [IANA Considerations](recovery.md#iana-considerations)
- [Acknowledgments](recovery.md#acknowledgments)

### [Extensions](extensions.md)

Sealed Envelope Messaging Protocol: Extensions and Conformance

- [Introduction](extensions.md#introduction)
- [Conventions and Definitions](extensions.md#conventions-and-definitions)
- [Extension Framework](extensions.md#extension-framework)
- [Library Extension Enforcement](extensions.md#library-extension-enforcement)
- [Trust Model](extensions.md#trust-model)
- [Large-Attachment Extension](extensions.md#large-attachment)
- [Conformance](extensions.md#conformance)
- [Security Considerations](extensions.md#security-considerations)
- [Privacy Considerations](extensions.md#privacy-considerations)
- [Test Vectors](extensions.md#test-vectors)
- [IANA Considerations](extensions.md#iana-considerations)
- [Acknowledgments](extensions.md#acknowledgments)

### [Client](client.md)

Sealed Envelope Messaging Protocol: Client Specification

- [Introduction](client.md#introduction)
- [Conventions and Definitions](client.md#conventions-and-definitions)
- [Connection and Trust Model](client.md#connection-and-trust-model)
- [Authentication](client.md#authentication)
- [Envelope Composition](client.md#envelope-composition)
- [Envelope Receipt and Decryption](client.md#envelope-receipt-and-decryption)
- [Key Management](client.md#key-management)
- [Envelope Submission Protocol](client.md#envelope-submission-protocol)
- [Delivery State](client.md#delivery-state)
- [User Policy](client.md#user-policy)
- [Notification Content Constraints](client.md#notification-content-constraints)
- [Security Considerations](client.md#security-considerations)
- [Test Vectors](client.md#test-vectors)
- [IANA Considerations](client.md#iana-considerations)
- [Acknowledgments](client.md#acknowledgments)

## Test Vectors

Machine-readable test vectors live under [`vectors/`](vectors/README.md). Implementations load these JSON files and assert their outputs match. The Python generator under `vectors/generators/` is the source of byte values; the spec drafts above are the normative source for what is being computed.
