<!--
Thanks for contributing to semp-spec.

Editorial fixes (typos, broken cross-references, formatting) can land
directly. Substantial spec changes (new normative behavior, schema
changes, threat-model impact) typically need a "[proposal]" issue
discussion first.
-->

## Summary

<!-- 1-3 bullets describing what changes. -->

-

## Type of change

- [ ] Editorial / typo / cross-reference / formatting
- [ ] Clarifying rewrite (no normative meaning change)
- [ ] New normative requirement (MUST / SHOULD / MAY added or strengthened)
- [ ] Relaxed normative requirement (MUST → SHOULD, etc.)
- [ ] New record schema or new optional module
- [ ] Wire-incompatible change

## Linked issue

<!-- For substantial changes, link the [proposal] issue where this was discussed. Editorial fixes need not. -->

Closes #

## Rationale

<!-- For non-editorial changes: why this shape, what alternatives were considered. Editorial PRs can write "typo fix" and skip. -->

## Security analysis

<!-- Required for any normative change. Editorial PRs can write "no change" and skip. -->

- [ ] No change to the threat model.
- [ ] Threat model narrows (a defended attack added).
- [ ] Threat model widens (new attack surface; mitigations described below).
- [ ] Threat-model section in THREAT.md updated if applicable.

## Implementation impact

- [ ] No reference library change required.
- [ ] Reference library (`semp-go`) follow-up linked: <!-- semp-dev/semp-go#NNN -->
- [ ] Conformance test vectors updated in VECTORS.md.
- [ ] Existing implementations need to update (described below).

## Cross-references

<!-- If you added a section or constant: -->

- [ ] Document table of contents updated.
- [ ] All sibling sections that should reference the new content link to it.
- [ ] No dangling cross-references introduced.

## Style

- [ ] Normative keywords (MUST / SHOULD / MAY / RECOMMENDED) used per RFC 2119 / RFC 8174.
- [ ] No em-dashes, en-dashes, or inline `--`.
- [ ] Citations are precise (e.g., "DELIVERY.md §3.2.5", not "the delivery doc").
- [ ] New record schemas include a JSON example.

## Internet-Draft sync

- [ ] Corresponding `drafts/draft-semp-*.md` updated.
- [ ] N/A: editorial-only change with no normative impact on the I-D series.

## Checklist

- [ ] PR title is short and descriptive.
- [ ] Commit messages explain the why, not just the what.
- [ ] If AI-assisted, commits carry a `Co-Authored-By:` trailer naming the model.
