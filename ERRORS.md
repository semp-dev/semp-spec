# SEMP Error Codes Registry

**Sealed Envelope Messaging Protocol**  
Status: Internet-Draft  
Version: 0.1.0  
Related: `HANDSHAKE.md`, `ENVELOPE.md`, `DELIVERY.md`, `CLIENT.md`,
`DISCOVERY.md`, `KEY.md`, `SESSION.md`, `REPUTATION.md`, `TRANSPORT.md`

---

## Abstract

This document defines the authoritative registry of all machine-readable
error codes, reason codes, and status values used across the SEMP protocol.
Each code is assigned to a layer, classified by recoverability, and
cross-referenced to the specification that governs its semantics.

Implementations MUST use codes exactly as registered. Unknown codes received
from a peer MUST be treated as non-recoverable unless the implementation has
explicit knowledge of the code's semantics through an extension.

---

## 1. Registry Structure

Each registered code has the following properties:

| Property        | Description                                                              |
|-----------------|--------------------------------------------------------------------------|
| Code            | The machine-readable string used on the wire.                            |
| Layer           | The protocol layer where this code is defined and used.                  |
| Recoverable     | Whether an automated retry is appropriate without user intervention.     |
| Source spec     | The specification and section that defines the code's semantics.         |
| Sender behavior | The action the sending implementation MUST or SHOULD take on receipt.    |

Recoverability governs automated retry only. A non-recoverable code means
the sender server MUST NOT retry automatically; the condition requires either
user action or indicates a bug. A recoverable code means the sender server
SHOULD retry after taking the corrective action described in the sender
behavior column.

---

## 2. Handshake Reason Codes

These codes appear in `SEMP_HANDSHAKE` messages with `step: "rejected"`. They
govern session establishment failures. Defined in `HANDSHAKE.md` section 4.1.

| Code                | Recoverable | Sender behavior                                                   |
|---------------------|-------------|-------------------------------------------------------------------|
| `blocked`           | No          | Surface to user. Do not retry.                                    |
| `auth_failed`       | No          | Surface to user. Do not retry.                                    |
| `policy_violation`  | No          | Surface to user. Do not retry.                                    |
| `handshake_expired` | Yes         | Re-handshake and retry.                                           |
| `handshake_invalid` | Yes         | Re-handshake and retry.                                           |
| `no_session`        | Yes         | Establish new session and retry.                                  |
| `rate_limited`      | Yes         | Back off and retry.                                               |
| `challenge`         | Yes         | Solve the issued challenge and continue handshake.                |
| `challenge_failed`  | Yes         | Request new challenge by restarting the handshake.                |
| `challenge_invalid` | No          | The challenge exceeds protocol bounds (for example, `proof_of_work` difficulty greater than 28, or `expires` below the minimum floor for its difficulty). Surface to user or operator as a misbehaving or compromised server. Do not retry. Implementations SHOULD retain the signed `challenge` message for potential inclusion in an abuse report under category `protocol_abuse` (`REPUTATION.md` section 8.3.6). See `HANDSHAKE.md` section 2.2a.2. |
| `server_at_capacity`| Yes         | Back off and retry later.                                         |

`challenge` is unique: it is not a terminal rejection but a conditional gate.
The handshake is suspended, not failed, until the challenge is resolved. See
`HANDSHAKE.md` section 2.2a.

---

## 3. Envelope Reason Codes

These codes appear in structured rejection responses to envelope delivery
attempts. They are a subset of the handshake codes plus envelope-specific
additions. Defined in `ENVELOPE.md` section 9.3.

| Code                  | Recoverable | Sender behavior                                                 |
|-----------------------|-------------|-----------------------------------------------------------------|
| `blocked`             | No          | Surface to user. Do not retry.                                  |
| `seal_invalid`        | No          | Indicates a bug. Do not retry the same envelope.                |
| `session_mac_invalid` | No          | Indicates a bug or session mismatch. Re-handshake before retry. |
| `envelope_expired`    | No          | Recompose with new expiry if content is still relevant.         |
| `handshake_invalid`   | Yes         | Establish new session and resend.                               |
| `handshake_expired`   | Yes         | Establish new session and resend.                               |
| `no_session`          | Yes         | Establish new session and resend.                               |
| `extension_unsupported` | No        | A required extension is not supported by the recipient, or runtime validation against the extension's definition document failed (`EXTENSIONS.md` §8.3). Surface the unsupported extension key and any `validation_failure` diagnostic to the sender. Do not retry without removing or renegotiating the extension. |
| `extension_size_exceeded` | No      | An `extensions` object exceeds the size limit for its layer. Reduce extension payload size. Do not retry the same envelope. |
| `scope_exceeded`    | No          | The submitting device's scoped certificate does not authorize sending to one or more recipients. Surface the rejected recipient(s) to the operator. Do not retry without updating the device certificate scope. See `KEY.md` section 10.3. |
| `scope_invalid`     | No          | A scoped device certificate submitted for registration is malformed: missing required scope fields, `allow` list exceeds 10,000 entries, or `expires_at` exceeds the 365-day cap. See `KEY.md` section 10.3. |
| `certificate_expired` | No        | The submitting delegated device's certificate has passed its `expires_at`. The primary device MUST issue a renewed certificate before the delegated device resumes operation. See `KEY.md` section 10.3.8. |

`seal_invalid` and `session_mac_invalid` are cryptographic verification
failures. In production, these almost always indicate an implementation bug
rather than a transient condition. Implementations SHOULD log these at error
severity.

---

## 4. Rekeying Reason Codes

These codes appear in `SEMP_REKEY` messages with `step: "rejected"`. They
govern in-session rekeying failures. Defined in `SESSION.md` section 3.2.

| Code                 | Recoverable | Sender behavior                                                  |
|----------------------|-------------|------------------------------------------------------------------|
| `session_expired`    | No          | Session has ended. Begin a fresh handshake.                      |
| `rekey_unsupported`  | No          | Remote party does not support in-session rekeying. Let session expire and re-handshake. |
| `rate_limited`       | Yes         | Too many rekey attempts. Back off within the session lifetime.   |

---

## 5. Submission Status Values

These values appear in `SEMP_SUBMISSION` response messages from the home
server to the client. They describe per-recipient delivery outcomes. Defined
in `CLIENT.md` section 6.3.

| Status                | Terminal | Meaning                                                                     |
|-----------------------|----------|-----------------------------------------------------------------------------|
| `delivered`           | Yes      | Envelope accepted and delivered to the recipient server.                    |
| `rejected`            | Yes      | Recipient server explicitly refused. `reason_code` is present.              |
| `silent`              | Yes      | No response from recipient server within the timeout window.                |
| `legacy_required`     | Yes      | Recipient domain does not support SEMP. SMTP fallback is possible.          |
| `recipient_not_found` | Yes      | No SEMP support and no MX records. Domain cannot receive mail.              |
| `queued`              | No       | Server accepted the envelope and will attempt delivery asynchronously.      |

`queued` is the only non-terminal status. The server MUST follow up with a
delivery event notification when the outcome is resolved to `delivered`,
`rejected`, or `silent`.

`legacy_required` triggers the client's SMTP fallback flow per `CLIENT.md`
section 6.4.

---

## 6. Discovery Status Values

These values appear in `SEMP_DISCOVERY` response result objects. They describe
per-address capability. Defined in `DISCOVERY.md` section 4.6.

| Status      | Meaning                                                                         |
|-------------|---------------------------------------------------------------------------------|
| `semp`      | Address supports SEMP. Handshake and envelope delivery may proceed.             |
| `legacy`    | No SEMP support found. MX records confirm SMTP is available.                    |
| `not_found` | No SEMP support and no MX records. Domain cannot receive mail.                  |

These map directly to submission status values: `semp` → proceed with SEMP
delivery; `legacy` → return `legacy_required` to client; `not_found` → return
`recipient_not_found` to client. See `DISCOVERY.md` section 7.1.

---

## 7. Key Request Status Values

These values appear in `SEMP_KEYS` response result objects returned to the
client via the home server. Defined in `CLIENT.md` section 5.4.5.

| Status      | Meaning                                                                         |
|-------------|---------------------------------------------------------------------------------|
| `found`     | Keys located and returned. `user_keys` array is populated.                      |
| `not_found` | Domain has no SEMP support or user keys are not published.                      |
| `error`     | Transient fetch failure (network error, timeout, rate-limited by remote domain). |

`error` is the only recoverable status. The client or home server MAY retry
the key fetch. `not_found` is definitive for the duration of the result's TTL.

---

## 8. Key Revocation Reasons

These values appear in `SEMP_KEY_REVOCATION` records. They describe why a key
was revoked. Defined in `KEY.md` section 8.2.

| Reason                   | Meaning                                                     |
|--------------------------|-------------------------------------------------------------|
| `key_compromise`         | Key has been or is suspected of being compromised.          |
| `superseded`             | Key has been replaced by a newer key.                       |
| `cessation_of_operation` | The user or domain no longer uses this key.                 |
| `temporary_hold`         | Temporary suspension pending investigation.                 |

`temporary_hold` is the only potentially reversible reason. All others
represent permanent revocation. When a revoked key includes a
`replacement_key_id`, the sender SHOULD fetch and use the replacement.

---

## 9. Abuse Report Categories

These values appear in `SEMP_ABUSE_REPORT` messages. They classify the nature
of the reported abuse. Defined in `REPUTATION.md` section 3.4.

| Category           | Description                                                          |
|--------------------|----------------------------------------------------------------------|
| `spam`             | Unsolicited bulk messaging.                                          |
| `harassment`       | Targeted abusive or threatening content.                             |
| `phishing`         | Impersonation or credential harvesting attempts.                     |
| `malware`          | Messages containing or linking to malicious software.                |
| `protocol_abuse`   | Malformed envelopes, enumeration, handshake flooding, or similar.    |
| `impersonation`    | Sender falsely represents their identity or affiliation.             |
| `other`            | Abuse not covered by defined categories.                             |

---

## 10. Delivery Acknowledgment Types

These are protocol-level wire outcomes for envelope delivery between servers.
They are not error codes but form the foundation on which submission statuses
are built. Defined in `DELIVERY.md` section 1.

| Acknowledgment | Description                                                                 |
|----------------|-----------------------------------------------------------------------------|
| `delivered`    | Recipient server accepted the envelope and will deliver it to the client.   |
| `rejected`     | Recipient server explicitly refused the envelope with a reason code.        |
| `silent`       | Recipient server did not respond within the sender's timeout window.        |

`rejected` is the RECOMMENDED default for any envelope the server will not
deliver. `silent` is permitted for deliberate privacy or anti-harassment
policy. A server MUST NOT return `delivered` for an envelope it does not intend
to deliver.

---

## 11. Transport-Layer Status Codes

These codes are returned at the transport layer, below the SEMP application
layer. They appear as HTTP status codes in the HTTP/2 and QUIC bindings and
as equivalent transport-level error signals in other bindings. Defined in
`TRANSPORT.md` section 4.2.2.

Transport-layer codes are distinct from SEMP reason codes. A 200 HTTP response
with a SEMP rejection in the body is normal operation: the transport succeeded
but the application rejected the message. Transport codes and SEMP codes are
independent layers.

| HTTP Status | Transport meaning                                                     | Recoverable | Sender behavior                                      |
|-------------|-----------------------------------------------------------------------|-------------|------------------------------------------------------|
| 200         | SEMP message processed. Application outcome is in the response body.  | N/A         | Parse the SEMP response and act on its reason codes.  |
| 400         | Malformed SEMP message. Could not parse.                              | No          | Fix the message. Do not retry the same payload.       |
| 413         | Payload exceeds the server's `max_envelope_size`.                      | No          | Reduce payload size or split content.                 |
| 429         | Transport-level rate limit.                                           | Yes         | Back off and retry. Distinct from SEMP `rate_limited`.|
| 503         | Server temporarily unavailable.                                       | Yes         | Back off and retry.                                   |

### 11.1 Transport Connection Failures

The following conditions are not wire codes but transport-level failure states
that implementations MUST handle. They arise during the transport fallback
procedure defined in `TRANSPORT.md` section 5.4.

| Condition               | Meaning                                                                 | Recoverable | Sender behavior                                                  |
|-------------------------|-------------------------------------------------------------------------|-------------|------------------------------------------------------------------|
| `connection_refused`    | The remote server rejected the transport connection.                    | Yes         | Attempt the next transport in the fallback order.                |
| `connection_timeout`    | No response within the transport timeout (recommended: 10 seconds).     | Yes         | Attempt the next transport in the fallback order.                |
| `tls_handshake_failed`  | TLS negotiation failed (certificate mismatch, expired, or untrusted).   | No          | Do not retry on this transport. Log and surface to operator.     |
| `tls_version_rejected`  | Remote server does not support TLS 1.2 or higher.                       | No          | Do not connect. The server does not meet minimum requirements.   |
| `subprotocol_rejected`  | WebSocket server did not confirm the `semp.v1` subprotocol.             | No          | Attempt the next transport in the fallback order.                |
| `transport_exhausted`   | All mutually supported transports have been attempted and failed.        | No          | Surface as a delivery failure. Do not silently discard.          |

These conditions are internal to the connecting implementation. They are not
transmitted on the wire and do not appear in SEMP rejection messages. They
govern the transport fallback logic and determine when to escalate a failure
to the SEMP layer.

---

## 12. Extension Codes

Additional codes MAY be defined in extensions using the standard SEMP
namespacing convention: `"vendor.example.com/code-name"`. This applies to
reason codes, abuse categories, and any other registered code space.

Extension codes MUST NOT collide with core codes. Implementations that
encounter an unrecognized code MUST treat it as non-recoverable unless the
extension is explicitly supported.

Extension authors SHOULD publish their code definitions at the namespace URI
to allow discovery by other implementations.

---

## 13. Code Reuse Across Layers

Several codes appear at multiple protocol layers with consistent semantics:

| Code                | Appears in                  | Consistent meaning                           |
|---------------------|-----------------------------|----------------------------------------------|
| `blocked`           | Handshake, Envelope         | Sender or domain is blocked.                 |
| `handshake_invalid` | Handshake, Envelope         | Session has been invalidated.                |
| `handshake_expired` | Handshake, Envelope         | Session TTL has elapsed.                     |
| `no_session`        | Handshake, Envelope         | No valid session referenced.                 |
| `rate_limited`      | Handshake, Rekeying         | Rate limit exceeded.                         |
| `extension_unsupported` | Envelope, Handshake    | A required extension is not understood by the recipient. |
| `extension_size_exceeded` | Envelope              | An extensions object exceeds the layer size limit. |
| `scope_exceeded`    | Envelope (submission)       | Delegated device attempted an action outside its certificate scope. |
| `scope_invalid`     | Device registration         | Scoped device certificate is malformed, over-capped, or has an excessive lifetime. |
| `certificate_expired` | Envelope (submission), Handshake | Delegated device's scoped certificate has passed `expires_at`. |

When the same code appears at multiple layers, the meaning is identical. The
sender behavior differs only in the context of the operation being performed
(session establishment vs. envelope delivery vs. rekeying).

---

## 14. Implementation Notes

### 14.1 Human-Readable Descriptions

All rejections carry both a machine-readable `reason_code` and a human-readable
`reason` string. The `reason` string is for operator diagnostics and user
display. Implementations MUST NOT parse the `reason` string programmatically;
only `reason_code` governs behavior.

### 14.2 Unknown Code Handling

An implementation that receives a `reason_code` it does not recognize MUST:

1. Treat it as non-recoverable (do not retry automatically).
2. Surface the code and the human-readable `reason` to the user or operator.
3. Log the unknown code for diagnostic purposes.

This ensures forward compatibility: a newer server can introduce codes
(via extensions) without causing older clients to enter infinite retry loops.

### 14.3 Case Sensitivity

All codes are lowercase with underscores. Implementations MUST perform
case-sensitive matching. `Blocked` is not `blocked`.

---

## 15. Relationship to Other Specifications

| Specification  | Relationship                                                                          |
|----------------|---------------------------------------------------------------------------------------|
| `HANDSHAKE.md` | Defines handshake reason codes (section 4.1) and blocking behavior (section 4.2).     |
| `ENVELOPE.md`  | Defines envelope reason codes (section 9.3) and server rejection obligations (section 9.2). |
| `DELIVERY.md`  | Defines the three acknowledgment types (section 1) and blocking enforcement.          |
| `CLIENT.md`    | Defines submission status values (section 6.3) and client UI obligations (section 7.1). |
| `DISCOVERY.md` | Defines discovery status values (section 4.6) and legacy fallback mapping (section 7.1). |
| `KEY.md`       | Defines key revocation reasons (section 8.2) and scoped device certificates (section 10.3). `scope_exceeded` originates from certificate enforcement. |
| `SESSION.md`   | Defines rekeying reason codes (section 3.2).                                          |
| `REPUTATION.md`| Defines abuse report categories (section 3.4).                                        |
| `TRANSPORT.md` | Defines transport-layer status codes (section 4.2.2) and transport failure conditions (section 5.4). |
| `EXTENSIONS.md`| Defines extension framework, criticality signaling, and size constraints. `extension_unsupported` and `extension_size_exceeded` originate there (sections 3.1 and 4.2). The `validation_failure` diagnostic vocabulary attached to `extension_unsupported` is defined in section 8.3. |

---

*This document is an Internet-Draft. It is subject to revision prior to
finalization as a stable specification.*