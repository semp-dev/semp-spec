# SEMP Reputation Specification

**Sealed Envelope Messaging Protocol**  
Status: Internet-Draft  
Version: 0.2.0-draft  
Related: `DESIGN.md`, `KEY.md`, `HANDSHAKE.md`, `ENVELOPE.md`, `DELIVERY.md`

---

## Abstract

The SEMP reputation specification defines the observable signals that inform
delivery policy, the mechanism by which servers share trust observations about
other domains, the cryptographically verifiable abuse evidence model, and the
trust transfer process for domain ownership changes. Reputation in SEMP is
peer-to-peer and observation-based: a domain's reputation is not what it claims
about itself, but what other servers have observed about it.

---

## 1. Overview

SEMP defines three reputation signals, established in `DESIGN.md` section 5.2:

- **Domain registration age**:  publicly verifiable via WHOIS, resistant to
  retroactive manipulation.
- **Abuse rate**:  the ratio of reported abuse events to message volume over
  a domain's observed history.
- **Trust gossip**:  signed observations that one server publishes about another
  domain's behavior, fetchable by any interested party.

These signals are inputs to operator-defined policy, per `DESIGN.md`
section 2.4.

### 1.1 Core Principle: Reputation Is Observed, Not Self-Reported

A domain does not control its own reputation. Its reputation is the aggregate
of observations held by every server it has interacted with. The evidence is
distributed across the network and cryptographically bound to the domain's
own signatures.

This is possible because every SEMP envelope carries a `seal.signature` produced
by the sender's domain key. That signature is non-repudiable. A server that
receives abusive traffic holds cryptographic proof of the sender's behavior --
proof that any third party can independently verify against the sender's
published domain key.

### 1.2 No Central Authority

SEMP does not define or endorse any central reputation authority, aggregation
service, or blocklist provider. Reputation is a peer-to-peer concern. Servers
observe, record, and optionally share their observations. Third-party
aggregation services may emerge as a convenience layer.

### 1.3 Reputation Is Domain-Keyed

Every reputation signal, observation record, gossip fetch, and abuse
report defined in this document is keyed by **domain identity** rather
than by IP address. IP addresses are transport-layer artifacts and MUST
NOT appear as keys in any protocol-layer reputation artifact. This
applies specifically to:

- The local observation ledger a server maintains per section 4.1.
- Observation records published via trust gossip per section 5.1.
- Abuse reports per section 3.
- Block list entries per `DELIVERY.md` section 5 (which uses user,
  domain, or server identity, never IP).
- Rate limits that feed into reputation assessment per
  `DISCOVERY.md` section 6.2.4.

The separation between transport-layer operational defenses and
protocol-layer trust is defined in `DESIGN.md` section 2.2.1. A server
that observes abusive traffic from a specific IP MAY apply transport-
layer operational defenses to that IP (DoS protection, connection caps)
but MUST NOT translate that observation into a protocol-layer
reputation signal keyed by IP.

A conformant server MUST:

- Key every reputation ledger entry and published observation by
  domain. An entry keyed by IP or by any transport-layer artifact MUST
  be rejected as malformed.
- Preserve a domain's accumulated reputation across changes of source
  IP. A domain that migrates hosting, adopts a CDN, or becomes
  Tor-only does not lose its reputation history as a consequence.
- Start unrelated SEMP domains that share a single hosting IP at
  independent zero reputation. One domain's behavior MUST NOT taint
  another domain on the same IP.
- Accept federation from domains reached via Tor exit nodes or other
  anonymizing transports on the same terms as domains reached over
  conventional IP transport, subject only to domain-level policy.

---

## 2. Reputation Signals

### 2.1 Domain Registration Age

Domain registration age is the simplest reputation signal. It is publicly
available via WHOIS, requires no SEMP-specific infrastructure, and is resistant
to manipulation, since a domain cannot retroactively make itself older.

Servers SHOULD query WHOIS data as part of their policy evaluation for any
domain they have not previously observed. This signal is the primary structural
defense against burn-and-rotate abuse, a pattern where an actor registers a
fresh domain, sends high-volume abusive traffic before any trust gossip has
accumulated, then abandons it and repeats. Because domain registration is cheap
and IP reputation is not a factor in SEMP, this attack is otherwise low-cost.
Domain age does not eliminate it, but it makes each campaign observable and
raises the time cost of sustained abuse.

Servers SHOULD apply automatic rate limiting to domains with insufficient
registration age, regardless of other signals. The RECOMMENDED minimum threshold
is 30 days; operators MAY configure a longer window based on their own risk
model. The 30-day figure is a floor, not a mandate: an operator running a
high-sensitivity deployment is not required to accept that threshold. Rate
limiting under this rule SHOULD be combined with the proof-of-work mechanism
defined in section 8.3 when available.

A new domain starts at zero reputation. Servers MUST
NOT reject messages from zero-reputation domains on the basis of age alone
without explicit operator configuration, per `DESIGN.md` section 5.4. Rate
limiting is not rejection. A message that is rate-limited has not been refused --
it is being delivered at a reduced throughput until the domain accumulates
behavioral history.

### 2.2 Abuse Rate

The abuse rate is the ratio of abuse events to total message volume observed
for a domain over a time window. Each server computes this independently from
its own observations. There is no global abuse rate, only per-observer rates.

What constitutes an "abuse event" is defined locally by each server's policy.
Common categories include: spam (unsolicited bulk messaging), harassment,
phishing, malware distribution, and protocol abuse (malformed envelopes,
enumeration attempts, handshake flooding).

### 2.3 Trust Gossip

Trust gossip is the mechanism by which servers share their observations about
other domains. It is the most technically substantive reputation signal and is
defined in detail in sections 4 through 6 of this specification.

---

## 3. Abuse Reporting

### 3.1 Reporting Model

Abuse reports flow from users to their home server. The home server aggregates
reports internally and uses them as input to its own policy decisions and,
optionally, as the basis for trust gossip observations shared with other
servers.

```
User observes abuse
  │
  ├─ Reports to home server
  │
  Home server
  ├─ Validates report
  ├─ Records abuse event internally
  ├─ Updates local abuse rate for sender domain
  └─ Optionally publishes observation via trust gossip (section 4)
```

Users report to their own home server only. They do not report directly to the
sender's server. This protects the reporter's identity from the abuser and
keeps the reporting relationship within the existing trust boundary.

### 3.2 Abuse Report Schema

```json
{
    "type": "SEMP_ABUSE_REPORT",
    "version": "1.0.0",
    "id": "report-ulid",
    "reporter": "user@example.com",
    "reported_domain": "offender.com",
    "reported_address": "spammer@offender.com",
    "category": "spam",
    "timestamp": "2025-06-10T20:30:00Z",
    "evidence": {
        "type": "envelope_metadata",
        "postmark_ids": ["01J4K7P2XVEM3Q8YNZHBRC5T06"],
        "count": 47,
        "window": "2025-06-10T19:00:00Z/2025-06-10T20:00:00Z"
    },
    "description": "Unsolicited bulk messages, 47 received in one hour.",
    "extensions": {}
}
```

### 3.3 Abuse Report Fields

| Field              | Type     | Required | Description                                                         |
|--------------------|----------|----------|---------------------------------------------------------------------|
| `type`             | `string` | Yes      | MUST be `"SEMP_ABUSE_REPORT"`                                       |
| `version`          | `string` | Yes      | SEMP protocol version (semver)                                      |
| `id`               | `string` | Yes      | Unique report identifier. ULID RECOMMENDED.                         |
| `reporter`         | `string` | Yes      | Address of the reporting user.                                      |
| `reported_domain`  | `string` | Yes      | Domain of the reported sender.                                      |
| `reported_address` | `string` | No       | Specific address, if known. Requires `brief` decryption.            |
| `category`         | `string` | Yes      | Abuse category. See section 3.4.                                    |
| `timestamp`        | `string` | Yes      | ISO 8601 UTC timestamp of the report.                               |
| `evidence`         | `object` | Yes      | Evidence supporting the report. See section 3.5.                    |
| `description`      | `string` | No       | Human-readable description of the abuse.                            |
| `extensions`       | `object` | No       | Application-defined metadata.                                       |

### 3.4 Abuse Categories

| Category            | Description                                                          |
|---------------------|----------------------------------------------------------------------|
| `spam`              | Unsolicited bulk messaging.                                          |
| `harassment`        | Targeted abusive or threatening content.                             |
| `phishing`          | Impersonation or credential harvesting attempts.                     |
| `malware`           | Messages containing or linking to malicious software.                |
| `protocol_abuse`    | Malformed envelopes, enumeration, handshake flooding, unreasonable challenge issuance (section 8.3.6), or similar. |
| `impersonation`     | Sender falsely represents their identity or affiliation.             |
| `other`             | Abuse not covered by defined categories.                             |

Additional categories MAY be defined in extensions using the standard
namespacing convention.

### 3.5 Evidence Types

Abuse reports carry evidence. The type of evidence determines what can be
independently verified by third parties.

#### Envelope Metadata Evidence

Evidence derived from the postmark and seal (the public layer of the envelope).
This is independently verifiable by any party that can fetch the sender's
published domain key. No decryption is required.

```json
{
    "type": "envelope_metadata",
    "postmark_ids": ["01J4K7P2XVEM3Q8YNZHBRC5T06"],
    "count": 47,
    "window": "2025-06-10T19:00:00Z/2025-06-10T20:00:00Z"
}
```

#### Sealed Evidence

Full or partial envelope data (postmark, seal, and optionally fragments of the
decrypted `brief` or `enclosure`) packaged as verifiable evidence. The seals
are intact, so the sender's domain signature can be verified. Decrypted content
is included only when the affected user has explicitly authorized disclosure.

```json
{
    "type": "sealed_evidence",
    "envelopes": [
        {
            "postmark": { },
            "seal": { },
            "disclosed_brief": { },
            "disclosed_enclosure": null,
            "disclosure_authorization": {
                "user": "victim@example.com",
                "authorized_at": "2025-06-10T20:25:00Z",
                "scope": "brief_only",
                "signature": "base64-user-signature-over-authorization"
            }
        }
    ]
}
```

### 3.6 Evidence Verification

The cryptographic verification chain for abuse evidence:

1. **Sender attribution**: verify `seal.signature` against the reported
   domain's published domain key. This proves the domain produced the envelope.
   The domain cannot deny it.
2. **Report authenticity**: the reporting server signs the observation record
   that contains the evidence (section 4). This proves which server made the
   report.
3. **Disclosure authorization**: if decrypted content is included, verify the
   user's signature over the disclosure authorization. This proves the affected
   user consented to the disclosure.

Any party receiving abuse evidence can independently perform all three
verification steps using published public keys.

### 3.7 Pattern Abuse vs Content Abuse

Abuse evidence falls into two categories with different privacy properties:

**Pattern abuse**:  spam, volume attacks, enumeration, protocol abuse. Provable
entirely from postmarks and seals. No decryption required. The cryptographic
proof is complete and carries no privacy cost.

**Content abuse**:  harassment, phishing, impersonation. Proving the abusive
nature of the content requires revealing decrypted `brief` or `enclosure`
material. This requires explicit authorization from the affected user. The user
decides whether the privacy cost of disclosure is worth the benefit of a
verifiable report.

A server MUST NOT disclose decrypted envelope content in abuse evidence without
the explicit, signed authorization of the affected user. Unauthorized disclosure
is itself a violation of the protocol's privacy guarantees.

---

## 4. Trust Gossip

Trust gossip is the mechanism by which servers share observations about other
domains. It is pull-based, consistent with SEMP's approach to revocation,
discovery, and key fetching.

### 4.1 Observation Model

Each server maintains an internal ledger of its interactions with other domains.
From this ledger, it may produce **observation records**: signed, timestamped
assessments of a domain's behavior as observed by that server. Observation
records are the unit of trust gossip.

An observation record is not a subjective opinion. It is a summary of
measurable signals: message volume, abuse rate, rejection rate, evidence count.
The receiving server interprets these signals according to its own policy.

### 4.2 Observation Record Schema

```json
{
    "type": "SEMP_TRUST_OBSERVATION",
    "version": "1.0.0",
    "id": "observation-ulid",
    "observer": "reporting-server.com",
    "subject": "observed-domain.com",
    "window": {
        "start": "2025-05-01T00:00:00Z",
        "end": "2025-06-01T00:00:00Z"
    },
    "metrics": {
        "envelopes_received": 12400,
        "envelopes_rejected": 23,
        "abuse_reports": 5,
        "abuse_categories": ["spam", "spam", "phishing", "spam", "spam"],
        "unique_senders_observed": 340,
        "handshakes_completed": 890,
        "handshakes_rejected": 12
    },
    "assessment": "neutral",
    "evidence_available": true,
    "evidence_uri": "https://reporting-server.com/v1/reputation/evidence/observed-domain.com",
    "timestamp": "2025-06-01T12:00:00Z",
    "expires": "2025-07-01T12:00:00Z",
    "signature": {
        "algorithm": "ed25519",
        "key_id": "observer-domain-key-fingerprint",
        "value": "base64-signature-over-observation"
    },
    "extensions": {}
}
```

### 4.3 Observation Record Fields

| Field                | Type     | Required | Description                                                         |
|----------------------|----------|----------|---------------------------------------------------------------------|
| `type`               | `string` | Yes      | MUST be `"SEMP_TRUST_OBSERVATION"`                                  |
| `version`            | `string` | Yes      | SEMP protocol version (semver)                                      |
| `id`                 | `string` | Yes      | Unique observation identifier. ULID RECOMMENDED.                    |
| `observer`           | `string` | Yes      | Domain of the server making the observation.                        |
| `subject`            | `string` | Yes      | Domain being observed.                                              |
| `window`             | `object` | Yes      | Time window the observation covers. See section 4.4.                |
| `metrics`            | `object` | Yes      | Quantitative observations. See section 4.5.                         |
| `assessment`         | `string` | Yes      | Summary assessment. One of: `trusted`, `neutral`, `suspicious`, `hostile`. |
| `evidence_available` | `boolean`| Yes      | Whether verifiable evidence is available for this observation.      |
| `evidence_uri`       | `string` | No       | URI where evidence can be fetched. Present when `evidence_available` is `true`. |
| `timestamp`          | `string` | Yes      | ISO 8601 UTC timestamp of observation publication.                  |
| `expires`            | `string` | Yes      | ISO 8601 UTC expiry. Observations are time-bounded.                 |
| `signature`          | `object` | Yes      | Signature over the observation using the observer's domain key.     |
| `extensions`         | `object` | No       | Observer-defined extensions.                                        |

### 4.4 Observation Windows

Observations cover a defined time window. This prevents stale assessments from
persisting indefinitely and ensures that a domain's current behavior, not its
historical behavior, drives its reputation.

Observation windows SHOULD be 30 days or less. Servers SHOULD publish fresh
observations on a regular cadence. An expired observation MUST be treated as
absent, not as evidence of continued behavior.

### 4.5 Metrics Fields

| Field                     | Type      | Required | Description                                              |
|---------------------------|-----------|----------|----------------------------------------------------------|
| `envelopes_received`      | `integer` | Yes      | Total envelopes received from the subject domain.        |
| `envelopes_rejected`      | `integer` | Yes      | Envelopes rejected for any reason.                       |
| `abuse_reports`           | `integer` | Yes      | Abuse reports filed by users against the subject domain. |
| `abuse_categories`        | `array`   | No       | List of abuse categories reported. May contain duplicates.|
| `unique_senders_observed` | `integer` | No       | Distinct sender addresses observed from the domain.      |
| `handshakes_completed`    | `integer` | No       | Successful handshakes with the subject domain.           |
| `handshakes_rejected`     | `integer` | No       | Handshakes rejected from the subject domain.             |

Servers MUST NOT fabricate or inflate metrics. An observation record is a
factual report of measurable events. Its value depends on the observer's
credibility, which is itself subject to the same peer observation mechanism.

### 4.6 Assessment Values

| Assessment   | Meaning                                                                  |
|--------------|--------------------------------------------------------------------------|
| `trusted`    | Consistent good behavior observed over the window. Low or zero abuse.    |
| `neutral`    | Insufficient data or mixed signals. No strong conclusion.                |
| `suspicious` | Elevated abuse rate or anomalous patterns. Warrants caution.             |
| `hostile`    | Sustained, verified abusive behavior. Evidence available.                |

Assessment values are the observer's summary. Receiving servers MAY apply their
own policy interpretation; a `suspicious` assessment from a server with a
history of aggressive classification may carry different weight than one from
a conservative observer.

### 4.7 Observation Kinds

Observations carry a `kind` field distinguishing what the observation
is about. The following kinds are defined:

| Kind                | Subject                                                                       | Defined in                 |
|---------------------|-------------------------------------------------------------------------------|----------------------------|
| `abuse_rate`        | Volume and severity of abuse reports attributed to the subject domain.        | Section 4 of this document.|
| `delivery_outcomes` | Delivery success and rejection ratios observed by the publishing server.      | Section 4 of this document.|
| `key_transparency`  | Observations of the subject domain's key transparency log (STH snapshots, consistency verifications, equivocation reports). | `TRANSPARENCY.md` section 5. |

Additional kinds MAY be defined by future revisions or extensions.
Observation record consumers MUST ignore unknown kinds rather than
rejecting the containing record.

---

## 5. Trust Gossip Publication and Fetching

### 5.1 Publication

A server that publishes trust gossip MUST advertise a `reputation` endpoint
in its configuration document (`DISCOVERY.md` section 3.1.1). The advertised
URL is the base URL for published observations. Observation records for a
given subject domain are retrieved by appending the subject domain to the
base URL:

```
<endpoints.reputation><subject-domain>
```

A server that does not advertise a `reputation` endpoint does not publish
trust gossip. Peers MUST NOT probe for observations at any other path and
MUST treat the absence of the endpoint as a definitive signal that the
server does not participate in gossip publication.

Response format:

```json
{
    "type": "SEMP_TRUST_OBSERVATIONS",
    "version": "1.0.0",
    "subject": "observed-domain.com",
    "observations": [
        { }
    ],
    "signature": {
        "algorithm": "ed25519",
        "key_id": "observer-domain-key-fingerprint",
        "value": "base64-signature-over-response"
    }
}
```

A server MAY publish multiple non-overlapping observation records for the same
subject, covering different time windows.

### 5.2 Fetching

Trust gossip is pull-based. When a server encounters a domain it has no prior
experience with, it MAY fetch observations from servers it already trusts.
The fetch flow is:

1. Resolve the trusted server's configuration document per `DISCOVERY.md`
   section 3.
2. Read `endpoints.reputation` from the configuration. If the field is
   absent, the trusted server does not publish gossip and MUST NOT be
   probed further.
3. Append the subject domain to the advertised base URL and perform a
   `GET` on the resulting URL.
4. Verify the signature on every fetched observation before using it. An
   unsigned or unverifiable observation MUST be discarded.

```
Sender's server delivers envelope from unknown-domain.com
  │
  ├─ Check local observation ledger → no data
  ├─ Fetch configuration from trusted-server-1.com
  │     GET /.well-known/semp/configuration
  │     Read endpoints.reputation (if present)
  ├─ Fetch observations from trusted-server-1.com's reputation endpoint
  │     GET <endpoints.reputation>unknown-domain.com
  ├─ Repeat for other trusted servers
  ├─ Verify signatures on all fetched observations
  ├─ Apply local policy using fetched observations as input
  └─ Proceed with delivery decision
```

### 5.3 Observation Fetching Is Optional

Servers are not required to fetch or publish trust gossip. A server that makes
all reputation decisions based solely on its own direct observations is fully
compliant, and a server that omits the `reputation` endpoint from its
configuration is fully compliant. Trust gossip is a tool for informed
decision-making, not a protocol obligation.

### 5.4 Speculative Caching

Consistent with the key fetching and discovery specifications, servers MAY
speculatively fetch and cache observations for domains they interact with
frequently, independent of any pending delivery decision. This decouples the
fetch timing from communication intent and improves privacy.

### 5.5 Evidence Fetching

When an observation record has `evidence_available: true` and provides an
`evidence_uri`, the fetching server MAY retrieve the underlying evidence.
The `evidence_uri` is an absolute URL chosen by the publishing server and
is not required to share a path prefix with the reputation endpoint:

```
GET <evidence_uri>
```

Response:

```json
{
    "type": "SEMP_ABUSE_EVIDENCE",
    "version": "1.0.0",
    "subject": "observed-domain.com",
    "observation_id": "observation-ulid",
    "evidence_records": [
        {
            "id": "evidence-ulid",
            "category": "spam",
            "evidence": {
                "type": "envelope_metadata",
                "postmarks": [
                    {
                        "id": "01J4K7P2XVEM3Q8YNZHBRC5T06",
                        "from_domain": "observed-domain.com",
                        "to_domain": "reporting-server.com",
                        "expires": "2025-06-08T13:05:00Z",
                        "session_id": "session-ulid"
                    }
                ],
                "seals": [
                    {
                        "algorithm": "pq-kyber768-x25519",
                        "key_id": "observed-domain-key-fingerprint",
                        "signature": "base64-original-seal-signature"
                    }
                ]
            },
            "timestamp": "2025-06-08T14:00:00Z"
        }
    ],
    "signature": {
        "algorithm": "ed25519",
        "key_id": "reporting-server-key-fingerprint",
        "value": "base64-signature-over-evidence"
    }
}
```

The fetching server can independently verify each `seal.signature` against the
subject domain's published key, confirming that the subject domain did in fact
produce the envelopes cited as evidence.

### 5.6 Reputation Self-Referencing

A domain MAY publish a reputation references document containing links to
observation records that other servers have published about it. The
publishing URL is advertised as `endpoints.reputation_references` in the
domain's configuration document (`DISCOVERY.md` section 3.1.1). A domain
that does not advertise `reputation_references` does not self-publish
references. The response format is:

Response:

```json
{
    "type": "SEMP_REPUTATION_REFERENCES",
    "version": "1.0.0",
    "domain": "example.com",
    "references": [
        {
            "observer": "trusted-server-1.com",
            "uri": "https://trusted-server-1.com/v1/reputation/example.com",
            "fetched_at": "2025-06-10T12:00:00Z",
            "assessment": "trusted"
        },
        {
            "observer": "large-provider.net",
            "uri": "https://large-provider.net/reputation/example.com",
            "fetched_at": "2025-06-10T11:30:00Z",
            "assessment": "trusted"
        }
    ],
    "timestamp": "2025-06-10T20:00:00Z",
    "signature": {
        "algorithm": "ed25519",
        "key_id": "example-domain-key-fingerprint",
        "value": "base64-signature-over-references"
    }
}
```

#### 5.6.1 Reputation References Fields

| Field        | Type     | Required | Description                                                       |
|--------------|----------|----------|-------------------------------------------------------------------|
| `type`       | `string` | Yes      | MUST be `"SEMP_REPUTATION_REFERENCES"`                            |
| `version`    | `string` | Yes      | SEMP protocol version (semver)                                    |
| `domain`     | `string` | Yes      | The domain publishing the references.                             |
| `references` | `array`  | Yes      | Links to third-party observation records. See section 5.6.2.      |
| `timestamp`  | `string` | Yes      | ISO 8601 UTC timestamp of publication.                            |
| `signature`  | `object` | Yes      | Signature over the document using the domain's key.               |

#### 5.6.2 Reference Entry Fields

| Field        | Type     | Required | Description                                                       |
|--------------|----------|----------|-------------------------------------------------------------------|
| `observer`   | `string` | Yes      | Domain of the server whose observation is referenced.             |
| `uri`        | `string` | Yes      | Full URI of the observation record.                               |
| `fetched_at` | `string` | Yes      | ISO 8601 UTC timestamp of when the domain last verified this URI. |
| `assessment` | `string` | No       | The assessment value from the referenced observation at fetch time.|

#### 5.6.3 Self-Referencing Is Not Self-Reporting

The reputation references document is a convenience index: it tells a querying
server where to look, not what to conclude. The domain is curating links, not
making claims about itself. Every referenced observation record is independently
signed by the observer that produced it, and the fetching server MUST verify
that signature directly. The referencing domain cannot forge, modify, or
misrepresent the contents of the linked observation.

A domain will naturally reference its most favorable observations. This is
expected and not a problem. The receiving server knows the references are
curated, since they are published by the subject domain, not by a neutral party.
Operators MAY use self-references as a starting point for reputation discovery
while giving them appropriate weight: useful for finding observers to query,
not authoritative as a reputation signal in themselves.

#### 5.6.4 Cold Start Utility

Self-referencing is most valuable during the cold start period. When a server
encounters a new domain for the first time and has no observations from its
own trust set, the new domain's references document provides a set of leads --
third-party servers that have published observations. The receiving server can
fetch those observations, verify the signatures, and decide whether to trust
the observers. This does not shortcut the trust process; it accelerates
the discovery of relevant observers.

---

## 6. Trust Topology

### 6.1 Trust Relationships Are Asymmetric

Server A trusting observations from server B does not imply server B trusts
observations from server A. Trust relationships are configured per operator
policy. The protocol does not define a default trust set.

### 6.2 No Transitive Trust

If server A trusts server B, and server B trusts server C, server A does not
automatically trust server C's observations. Transitive trust is a policy
decision. Operators MAY implement transitive trust if they choose, but the
protocol does not assume or encourage it.

### 6.3 Observer Credibility

A server's observations are only as valuable as its credibility. A server that
publishes inflated or fabricated observations will be observed doing so by the
domains it misrepresents, and by servers that cross-reference multiple
observers. Over time, an unreliable observer's assessments carry less weight --
not because the protocol enforces this, but because operators learn which
sources to trust.

This is the same social trust mechanism that governs any reputation system. The
protocol provides the evidence format and verification mechanism. The human
judgment of which observers to rely on remains with the operators.

### 6.4 Cold Start

A new server with no federation partners has no one to ask for trust gossip.
The cold start path is:

1. The new server begins accumulating its own direct observations.
2. It establishes federation relationships with other servers.
3. Federation partners begin publishing observations about the new server's
   domain based on their direct interactions.
4. The new server begins fetching observations from its federation partners
   about domains it encounters.

A new server earns access to the trust network by participating in it. Per
`DESIGN.md` section 5.4, a new domain starts at zero reputation.

---

## 7. Trust Transfer

When a domain changes ownership or rotates its domain key, the trust
history associated with the prior domain key MAY be transferred to the
new key through a cryptographic handshake requiring both parties'
private keys. This implements `DESIGN.md` section 5.3.

Trust transfer is the mechanism by which SEMP handles legitimate
domain transitions (sales, mergers, key rotations) without leaking
trust to the wrong operator and without forcing legitimate new
operators to start from zero. Both directions matter: a buyer of a
reputable domain cannot fully inherit its trust, and a buyer of a
disreputable domain cannot launder away its history.

### 7.1 Transfer Record Schema

```json
{
    "type": "SEMP_TRUST_TRANSFER",
    "version": "1.0.0",
    "id": "transfer-ulid",
    "domain": "transferred-domain.com",
    "reason": "sold",
    "from": {
        "domain_key_id": "seller-domain-key-fingerprint",
        "signature": "base64-seller-signature-over-transfer",
        "signed_at": "2025-06-10T18:00:00Z"
    },
    "to": {
        "domain_key_id": "buyer-domain-key-fingerprint",
        "signature": "base64-buyer-signature-over-transfer",
        "signed_at": "2025-06-10T18:05:00Z"
    },
    "effective_at": "2025-06-10T18:05:00Z",
    "extensions": {}
}
```

### 7.2 Transfer Record Fields

| Field          | Type     | Required | Description                                                       |
|----------------|----------|----------|-------------------------------------------------------------------|
| `type`         | `string` | Yes      | MUST be `"SEMP_TRUST_TRANSFER"`.                                  |
| `version`      | `string` | Yes      | SEMP protocol version (semver).                                   |
| `id`           | `string` | Yes      | Unique transfer identifier. ULID RECOMMENDED.                     |
| `domain`       | `string` | Yes      | The domain being transferred.                                     |
| `reason`       | `string` | Yes      | One of the enum values in section 7.3.                            |
| `from`         | `object` | Yes      | Prior key holder's signed attestation.                            |
| `to`           | `object` | Yes      | New key holder's signed acceptance.                               |
| `effective_at` | `string` | Yes      | ISO 8601 UTC timestamp when the transfer takes effect.            |
| `extensions`   | `object` | No       | Transfer-related metadata.                                        |

### 7.3 Transfer Reasons

| `reason`                    | Meaning                                                                                          | Default carry-over class |
|-----------------------------|--------------------------------------------------------------------------------------------------|--------------------------|
| `key_rotation`              | Same operator, new domain key. No change in control. Operator is rotating per `KEY.md` §7.       | Full                     |
| `sold`                      | Ownership transferred to a new operator via commercial sale.                                     | Asymmetric (section 7.6) |
| `merged`                    | Organizational merger: the new operator subsumes the prior operator's infrastructure.            | Asymmetric (section 7.6) |
| `corporate_reorganization`  | Same corporate entity, legal restructure (spin-off, reincorporation, name change).               | Full                     |
| `inherited`                 | Ownership transferred due to dissolution, bankruptcy, or death of the prior operator.            | Asymmetric (section 7.6) |
| `other`                     | Reason outside the enum. Observers MAY treat as `sold` for policy purposes.                      | Asymmetric (section 7.6) |

`key_rotation` is the routine case: the operator is rotating their
domain key per the schedule in `KEY.md` section 7.1. The transfer
record binds the prior key's trust history to the new key. This is
distinct from key revocation: a rotation with transfer preserves
continuity; a revocation without transfer severs it.

Operators whose transfer does not fit the enum SHOULD use `other`
with an optional `extensions["semp.dev/transfer-reason-note"]`
human-readable note. Observer policy defaults to treating `other`
conservatively.

### 7.4 Transfer Publication

The transfer record MUST be published through the `reputation_transfer`
endpoint advertised in the publishing domain's configuration document
(`DISCOVERY.md` section 3.1.1). The endpoint is a base URL; the
outgoing and incoming records are retrieved by appending `out` and
`in` respectively:

**Prior-key publisher:**

```
GET <endpoints.reputation_transfer>out
```

**New-key publisher:**

```
GET <endpoints.reputation_transfer>in
```

For `sold`, `merged`, and `inherited`, the transfer is cross-domain
(or cross-operator on the same domain). Both the prior and new
publishers MUST advertise and serve their respective record for at
least **2 years** after `effective_at`. This retention window is the
minimum period during which an observer newly encountering the
domain is expected to discover the transition.

For `key_rotation` and `corporate_reorganization`, both records are
published on the same domain under the respective keys. The same
2-year retention applies.

A domain that does not advertise `reputation_transfer` does not
publish transfer records. Absence of a transfer record at the
advertised endpoint MUST NOT be interpreted as evidence that a
transfer did not occur; it is evidence that no transfer record is
available for observers at that endpoint.

### 7.5 Transfer Verification

Any server that encounters a transfer record MUST verify the chain:

1. Verify `from.signature` against the prior domain key, fetched from
   the domain's published key history or DNS.
2. Verify `to.signature` against the new domain key.
3. Confirm both signatures cover the same transfer `id`, `domain`,
   and `reason`.
4. Confirm `from.signed_at <= to.signed_at <= effective_at`.
5. Confirm `effective_at` is not in the future per the clock tolerance
   in `CONFORMANCE.md` section 9.3.1.

If any check fails, the transfer is invalid. Servers MUST NOT honor
an unverifiable transfer and MUST record no continuity between the
two keys.

### 7.6 Asymmetric Carry-Over

Transfer records have different default carry-over behavior depending
on `reason` (section 7.3). The following rules are normative defaults;
operators MAY adjust them via policy, subject to the constraints in
section 7.7.

**Negative observations always carry at full weight.** Any abuse
reports, gossip observations, or policy signals produced about the
prior key during its active period MUST continue to apply to the
domain's reputation after transfer, at full weight, regardless of
`reason`. Negative history does not decay under transfer.

**Positive observations carry with discount for asymmetric reasons.**
For `sold`, `merged`, `inherited`, and `other`, observers SHOULD
discount transferred positive reputation by at least 50% for the
90-day cooldown period following `effective_at`. After the cooldown,
observers MAY restore full weight based on post-transfer observed
behavior.

**Full carry-over for continuity reasons.** For `key_rotation` and
`corporate_reorganization`, both positive and negative observations
carry at full weight with no cooldown discount. These reasons assert
no change of operator; the transfer is an administrative act.

The 90-day cooldown is the RECOMMENDED default. Operators that prefer
faster onboarding MAY apply shorter cooldowns but MUST NOT treat
newly-transferred positive reputation as if no transfer had occurred.
Operators that prefer more conservative onboarding MAY extend the
cooldown or refuse to honor the transfer entirely.

### 7.7 Immutability of Pre-Transfer Observations

Observations published before `effective_at` about the prior key's
activity MUST NOT be retracted, hidden, modified, or otherwise
altered as a consequence of a transfer. A transfer is a continuity
claim; it is not a redaction mechanism.

Publishers of observations MUST continue to serve their prior
observation records after a transfer of the subject domain through
the window defined in section 4.4. Observers fetching observations
about a domain whose key has been transferred MUST retain
pre-transfer observations at their original timestamps.

A publisher who retracts or amends a prior observation in response
to a transfer MUST treat the retraction as a new observation with
the retraction timestamp. The original observation is preserved in
the publisher's ledger.

### 7.8 Observer Fetch Policy

A conformant server that federates with a domain for the first time,
or that encounters a domain key it does not recognize on an already
federated domain, MUST fetch the `reputation_transfer` records at
that domain proactively and cache them. The cache SHOULD be
refreshed on expiry of the cached entry, and MUST be re-fetched if
the server receives a `SEMP_TRUST_TRANSFER` reference it does not
yet have.

Proactive fetch ensures that observers are aware of a continuity
claim before they make delivery decisions, rather than discovering
it only when they encounter stale cached reputation.

### 7.9 Fail-Open on Fetch Failure

If a server cannot fetch a transfer record (network failure, 404,
timeout, signature verification failure), it MUST treat the domain
as if no transfer occurred. An inability to fetch MUST NOT be
interpreted as evidence that a transfer happened.

This rule prevents network partitions, denial-of-service attacks on
the publishing endpoint, or deliberate endpoint suppression from
creating phantom transfers that would otherwise let a new operator
inherit reputation they did not sign for.

### 7.10 Security Considerations

**Inherited abuse immunity.** An operator cannot clean up a
disreputable domain by purchasing and transferring it. Negative
observations from the prior key carry at full weight. The new
operator starts with the prior domain's negative history intact and
must earn clean status through observed behavior post-transfer.

**Reputation laundering across owned domains.** An operator that
controls multiple domains can issue transfers between their own
keys. The protocol cannot distinguish this from a genuine
third-party sale. Observers MAY weigh transfers with suspicion when
the prior and new keys share infrastructure, registrant, or other
correlatable signals. This weighting is policy.

**Fraudulent transfer claims.** A transfer record MUST be signed by
both the prior and new keys. A unilateral transfer is
cryptographically impossible. If the prior key is compromised, an
attacker holding it can co-sign a transfer to a key they control,
but the transfer is still publicly visible and subject to observer
policy. Prompt revocation of a compromised prior key (per `KEY.md`
section 8) supersedes any transfer the attacker might have
published.

**Observer disagreement.** Observers are not required to honor any
transfer. A domain that depends on its trust being honored across
the network SHOULD prepare for divergent observer policies and
SHOULD NOT assume universal continuity.

### 7.11 Loss of Private Key

Loss of the domain private key without a transfer record means
permanent loss of the associated trust history. There is no recovery
path. Per `DESIGN.md` section 5.3 and `KEY.md` section 11, trust
cannot be forged, reassigned unilaterally, or reconstructed from
backup by an unauthorized party.

---

## 8. New Domain Behavior

Per `DESIGN.md` section 5.4, a domain with no history starts at zero
reputation.

### 8.1 Zero Reputation Is Not Negative Reputation

Servers MUST NOT reject messages from zero-reputation domains solely because
they are unknown. Servers SHOULD apply the following baseline scrutiny to
zero-reputation domains, in increasing order of friction:

1. **Rate limiting**: cap inbound envelope volume per unit time. The specific
   threshold is operator policy; the practice is RECOMMENDED for all
   zero-reputation senders.
2. **Domain age gate**: apply additional rate limiting when the sender domain
   is less than 30 days old, per section 2.1. This is independent of and
   additive to general zero-reputation rate limiting.
3. **Proof of work**: require a valid PoW token before completing handshake,
   per section 8.3. Servers MAY require this for any zero-reputation sender.
   Servers SHOULD require it for zero-reputation senders that are also within
   the domain age gate window.
4. **Hold for review**: queue messages for operator or automated review before
   delivery. Operators MAY apply this as a last resort for senders that
   repeatedly hit rate limits or fail PoW.

These measures impose a cost on high-volume abuse from new domains without
blocking legitimate new senders.

### 8.2 Reputation Accumulation

A new domain builds reputation through normal operation:

1. It sends messages. Receiving servers observe its behavior.
2. Receiving servers record metrics: volume, rejection rate, abuse reports.
3. Over time, receiving servers may publish trust gossip observations about
   the domain.
4. Other servers fetch these observations and incorporate them into their
   own policy decisions.

Reputation accrues from sustained, observed behavior.

### 8.3 Proof of Work

SEMP defines a standard proof-of-work challenge-response mechanism for use
during the handshake. PoW imposes a per-envelope computational cost on the
sender that is negligible for low-volume senders and prohibitive for bulk
senders.

PoW is not scoped to zero-reputation or new domains. Any receiving server MAY
require PoW from any sender as a matter of operator policy, including
established domains that are exhibiting suspicious patterns, domains that have
recently crossed an abuse threshold, or any domain the operator chooses to
subject to additional friction. The domain age gate (section 2.1) is the most
common trigger, but it is not the only one. PoW is a general-purpose cost
imposition tool available across the full reputation spectrum.

#### 8.3.1 Challenge

A receiving server that requires PoW MUST issue a challenge in its handshake
response before accepting envelopes. The challenge format:

```json
{
    "type": "SEMP_POW_CHALLENGE",
    "version": "1.0.0",
    "id": "challenge-ulid",
    "algorithm": "sha256",
    "prefix": "base64-random-bytes",
    "difficulty": 20,
    "expires": "2025-06-10T20:35:00Z"
}
```

| Field        | Type     | Required | Description                                                         |
|--------------|----------|----------|---------------------------------------------------------------------|
| `type`       | `string` | Yes      | MUST be `"SEMP_POW_CHALLENGE"`                                      |
| `version`    | `string` | Yes      | SEMP protocol version (semver)                                      |
| `id`         | `string` | Yes      | Unique challenge identifier. ULID RECOMMENDED.                      |
| `algorithm`  | `string` | Yes      | Hash algorithm. MUST be `sha256`. Future versions MAY add others.   |
| `prefix`     | `string` | Yes      | Base64-encoded random bytes. Minimum 16 bytes of entropy.           |
| `difficulty` | `integer`| Yes      | Number of leading zero bits required in the solution hash.          |
| `expires`    | `string` | Yes      | ISO 8601 UTC timestamp. Solution MUST be submitted before expiry.   |

#### 8.3.2 Difficulty Calibration

Difficulty is expressed as a number of leading zero bits required in the
SHA-256 hash of the solution. Each additional bit doubles the expected
computation required.

| Difficulty | Expected hashes | Approximate CPU time (2024 hardware) |
|------------|-----------------|---------------------------------------|
| 16         | 65,536          | < 1ms                                 |
| 20         | 1,048,576       | ~10ms                                 |
| 24         | 16,777,216      | ~150ms                                |
| 28         | 268,435,456     | ~2.5s                                 |

Servers SHOULD use difficulty 20 as the default for zero-reputation senders.
Servers MAY increase difficulty for senders that have previously submitted
invalid solutions, are within the domain age gate window, or are exhibiting
suspicious patterns regardless of reputation age. Difficulty above 24 SHOULD
be reserved for confirmed suspicious behavior, as it imposes meaningful latency
on legitimate senders.

Servers MUST NOT issue a `proof_of_work` challenge with difficulty greater
than 28. This cap is defined normatively in `HANDSHAKE.md` section 2.2a.2
and prevents a malicious or compromised server from exhausting the
resources of either clients or federation peers through prohibitively
expensive challenges. Any handshake initiator, whether a client or a
federation peer, MUST abort the handshake with reason code
`challenge_invalid` when it receives a challenge above the cap. Servers
that require stronger gating than difficulty 28 provides MUST use blocking
(`DELIVERY.md` section 5) or another non-challenge mechanism rather than
raising the difficulty further.

Suggested difficulty by condition:

| Condition                                        | Suggested Difficulty |
|--------------------------------------------------|----------------------|
| Zero reputation, domain age < threshold          | 20                   |
| Zero reputation, domain age > threshold          | 16                   |
| Established domain, `suspicious` assessment      | 20 to 24             |
| Established domain, `hostile` assessment         | 24 to 28             |
| Operator policy (any domain)                     | Operator-configured, capped at 28 |

#### 8.3.3 Solution

The sender computes a solution by finding a nonce such that:

```
SHA-256(prefix || ":" || challenge_id || ":" || nonce)
```

produces a hash with at least `difficulty` leading zero bits. The nonce is an
arbitrary byte string chosen by the sender. The solution is submitted as:

```json
{
    "type": "SEMP_POW_SOLUTION",
    "version": "1.0.0",
    "challenge_id": "challenge-ulid",
    "nonce": "base64-encoded-nonce",
    "hash": "hex-encoded-sha256-hash"
}
```

| Field          | Type     | Required | Description                                              |
|----------------|----------|----------|----------------------------------------------------------|
| `type`         | `string` | Yes      | MUST be `"SEMP_POW_SOLUTION"`                            |
| `version`      | `string` | Yes      | SEMP protocol version (semver)                           |
| `challenge_id` | `string` | Yes      | The `id` from the corresponding challenge.               |
| `nonce`        | `string` | Yes      | Base64-encoded nonce that produces the valid hash.       |
| `hash`         | `string` | Yes      | Hex-encoded SHA-256 hash of the full preimage.           |

#### 8.3.4 Verification

The receiving server verifies the solution by:

1. Confirming the `challenge_id` matches an issued, unexpired challenge.
2. Recomputing `SHA-256(prefix || ":" || challenge_id || ":" || nonce)`.
3. Confirming the result matches the submitted `hash`.
4. Confirming the hash has at least `difficulty` leading zero bits.

A solution that fails any of these checks MUST be rejected. A challenge that
has expired MUST NOT be accepted even with a valid solution; the sender must
request a new challenge.

Each challenge MUST be single-use. The receiving server MUST record used
challenge IDs and reject duplicate submissions. Challenge IDs MAY be pruned
after their expiry time plus the clock skew tolerance defined in
`CONFORMANCE.md` section 9.3.1.

#### 8.3.5 PoW and Reputation

A valid PoW solution does not grant trust. It grants permission to proceed with
the handshake. The sender's envelope is still subject to normal delivery policy,
rate limiting, and reputation evaluation.

Servers MUST NOT treat PoW completion as evidence of legitimacy. A bulk spammer
with sufficient compute can satisfy PoW, but doing so at scale is expensive.

#### 8.3.6 Challenge Issuance Observations

A server that issues challenges MUST itself behave reasonably. The difficulty
cap (`HANDSHAKE.md` section 2.2a.2) and the minimum expiry table bound each
individual challenge, but the pattern of challenges a server issues over time
is itself a reputation signal. A server that routinely issues challenges at
or near the cap to peers or clients without corresponding risk indicators is
degrading the performance of the ecosystem and MAY be the subject of
observation records published by affected parties.

An initiator that aborts a handshake with `reason_code: "challenge_invalid"`
SHOULD record the event, including the signed `challenge` message, for
potential inclusion in an abuse report. The signed challenge message is
self-authenticating evidence because it carries the issuing server's
domain signature.

A conformant server MAY publish an observation record against a remote
domain when it has observed, across multiple unrelated handshakes within a
single observation window (section 4.4), both of the following:

1. A sustained share of that domain's issued challenges at `difficulty`
   greater than 24, measured against handshakes where the observing server
   or its users had no reputation condition that would justify elevated
   difficulty.
2. Either a challenge above the difficulty cap of 28, or a challenge whose
   `expires` value was below the minimum expiry floor for its difficulty.

The observation record MUST use the `protocol_abuse` category (section
3.4) and SHOULD include one or more signed `challenge` messages as
evidence under a `signed_handshake_challenge` evidence type. The evidence
MUST NOT include any material derived from a session that the observing
server did not itself initiate or receive.

A server that issues challenges MUST be prepared for its challenge
pattern to be observed and reported. Operators that wish to use aggressive
challenge policy for defensible reasons (a recent abuse surge from a
specific network, for example) SHOULD document the policy publicly so that
peer observations can be interpreted in context.

Servers MUST NOT publish observations based on a single challenge in
isolation, except in the case of a challenge that violates the cap or the
minimum expiry floor, which is a conformance violation rather than a
policy choice.

---

## 9. Security Considerations

### 9.1 Observation Forgery

Observation records are signed by the observer's domain key. Forging an
observation requires compromising the observer's private key. Servers MUST
verify observation signatures before using them. An observation signed by an
unknown or untrusted key SHOULD be discarded.

### 9.2 Evidence Integrity

Abuse evidence includes original `seal.signature` values from the reported
domain. These can be verified against the domain's published key independently
of the reporting server. A reporting server cannot fabricate evidence of
messages it never received because it would need to forge the sender domain's
signature, which requires the sender's private key.

### 9.3 Reputation Manipulation

A malicious domain could attempt to manipulate its reputation by:

- **Collusion**:  operating multiple servers that publish favorable observations
  about each other. Mitigated by the asymmetric trust model: operators choose
  which observers they trust based on the observer's track record, not the
  observations alone.
- **Evidence flooding**:  generating legitimate-looking traffic to dilute its
  abuse rate. Mitigated by per-observer metrics: each server tracks its own
  experience. Flooding one server does not improve the domain's reputation at
  another.
- **Selective behavior**:  behaving well toward well-connected servers while
  abusing smaller ones. Mitigated by trust gossip: the smaller server's
  observations are available to anyone who fetches them.

No reputation system eliminates manipulation entirely. These mitigations make
it expensive, requiring sustained good behavior toward many independent
observers.

### 9.4 Observer Manipulation

A malicious observer could publish false observations to damage a domain's
reputation. Mitigations:

- Observations are signed, so the malicious observer is accountable for its claims.
- Evidence is independently verifiable, so false claims that cite fabricated
  evidence will fail `seal.signature` verification.
- Cross-referencing: a domain defamed by one observer will have different
  assessments from other observers, exposing the discrepancy.
- Operator judgment: operators who discover an unreliable observer can remove
  it from their trust set.

### 9.5 Burn-and-Rotate Abuse

Because SEMP anchors trust to domains rather than IP addresses, and domain
registration is cheap, a bad actor could attempt to register fresh domains
continuously, sending abusive traffic from each before any reputation
accumulates, then discarding it.

This attack is mitigated by the layered response defined in section 8.1:

- **Domain age gate** (section 2.1): domains below the operator's age
  threshold face automatic rate limiting. The recommended minimum threshold is
  30 days. Each new domain registration restarts the clock. The attacker's
  throughput is bounded by how many domains they are willing to register and
  operate simultaneously.
- **Proof of work** (section 8.3): per-envelope computational cost limits
  volume from any sender an operator chooses to challenge, regardless of how
  many domains they rotate through or how established those domains are.
- **Non-repudiable evidence** (section 3.6): every envelope carries a
  `seal.signature` from the sender's domain key. A domain that sends abusive
  traffic before abandonment still leaves a verifiable trail. If the same
  operator reuses infrastructure, behavioral patterns across domains may be
  correlated by operators as a matter of local policy.

No mechanism eliminates this attack entirely at zero cost to legitimate new
senders. Legitimate senders tolerate rate limiting and PoW during their early
period; abusive senders face a volume cap that makes burn-and-rotate
uneconomical at scale.

### 9.6 Privacy of Abuse Reporters

Abuse reports are internal to the reporter's home server. The `reporter` field
in the abuse report schema (section 3.2) is stored locally and MUST NOT be
included in published observation records or evidence. A reporting user's
identity is never disclosed to the reported domain or to third parties.

When evidence includes disclosed `brief` or `enclosure` content, the
disclosure authorization identifies the consenting user. This is an explicit,
informed decision by the user, not an automatic exposure.

---

## 10. Privacy Considerations

### 10.1 Observation Fetching Reveals Interest

Fetching observations about a domain from a trusted server reveals that the
fetching server has encountered that domain and is seeking reputation data.
This is a privacy leak consistent with the pattern documented across all SEMP
specifications. Mitigations include speculative batch caching (section 5.4)
and proxied fetching through intermediaries.

### 10.2 Metrics as Metadata

Published observation metrics reveal traffic patterns between domains --
message volume, sender counts, rejection rates. Operators SHOULD consider
whether publishing detailed metrics is appropriate for their threat model.
Servers MAY publish observations with reduced-precision metrics (bucketed
ranges instead of exact counts) to limit metadata exposure while still
providing useful signals.

### 10.3 Evidence and Recipient Privacy

Sealed evidence that includes decrypted `brief` content reveals the full
sender and recipient addresses of the reported messages. This is the privacy
cost of verifiable content abuse reporting. The protocol requires explicit user
authorization (section 3.5) before any decrypted content is disclosed and
limits disclosure to the minimum necessary.

---

## 11. Relationship to Other Specifications

| Specification | Relationship |
|---|---|
| `DESIGN.md` | Governing principles. This specification implements section 5. Zero-reputation behavior implements section 5.4. Trust transfer implements section 5.3. |
| `KEY.md` | Domain keys are used to sign observation records, evidence, and transfer records. Key rotation interacts with trust transfer (section 7.3). |
| `HANDSHAKE.md` | Handshake metrics (completed, rejected) feed into observation records. PoW challenge-response (section 8.3) occurs during the handshake sequence for zero-reputation senders. |
| `ENVELOPE.md` | `seal.signature` on envelopes is the cryptographic basis for non-repudiable abuse evidence. |
| `DELIVERY.md` | Delivery policy decisions consume reputation signals as inputs. |
| `DISCOVERY.md` | Reputation fetching uses the same well-known URI infrastructure. |

---

*This document is an Internet-Draft. It is subject to revision prior to
finalization as a stable specification.*