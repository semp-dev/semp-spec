---
name: Spec change proposal
about: Propose a new feature, change in normative behavior, or new section. Substantial proposals MUST include rationale and a security analysis.
title: "[proposal] "
labels: proposal
assignees: ''
---

## Summary

<!-- One paragraph: what changes, and at the highest level, why. -->

## Motivation

<!-- The problem this solves. Concrete examples beat abstract reasoning. Cite an existing implementation pain point, an attack the current spec permits, or a use case the current spec cannot accommodate. -->

## Proposed change

<!-- The concrete change. New field, new section, modified normative-keyword, new optional module -- be specific. JSON example if applicable. -->

## Rationale

<!-- Why this shape and not an alternative? At least one alternative considered, with reasoning for why it was rejected. -->

## Security analysis

<!-- How does this affect the threat model in THREAT.md? Does it widen or narrow the attack surface? Does it interact with any existing normative requirement? -->

- [ ] No change to the threat model.
- [ ] Threat model narrows (the spec now defends against an attack class it previously did not).
- [ ] Threat model widens (a new attack surface; mitigations described below).
- [ ] Interaction with existing requirements (described below).

<!-- If checked any of the bottom three, expand here. -->

## Implementation impact

- Existing implementations: <!-- "no change required", "MUST update X by date Y", or "wire-incompatible; bump major version" -->
- Reference library (`semp-go`): <!-- "library follow-up will land at semp-dev/semp-go#NNN" -->
- Conformance test vectors: <!-- "VECTORS.md §X needs new entry", "no new vectors needed" -->

## Backwards compatibility

<!-- Pre-1.0 the spec tolerates breaking changes between minor versions. Still, be explicit: do existing v0.2.0-draft implementations need to update? -->

## Open questions

<!-- Anything you want maintainer feedback on before drafting the spec text. -->
