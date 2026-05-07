# Contributing to semp-spec

`semp-spec` is the normative specification for the Sealed Envelope Messaging Protocol. Its job is to be unambiguous, implementable, and stable. Contributions are welcome; this document describes how to make them count.

## Code of Conduct

Participation in this project is governed by the [Code of Conduct](CODE_OF_CONDUCT.md). By contributing, you agree to abide by its terms. Report concerns to `hello@semp.dev`.

## What lives here vs. in `semp-go`

| Change type | File the issue / PR in |
|---|---|
| Wire-format change (envelope, brief, seal, any signed record) | this repo |
| Normative-keyword change (`MUST` / `SHOULD` / `MAY`) | this repo |
| New record schema or new optional module | this repo |
| Editorial / wording / typo / cross-reference fix | this repo |
| Library bug or Go API addition | [`semp-go`](https://github.com/semp-dev/semp-go) |

If a change requires both, please open the spec PR first and link the library PR as a follow-up.

## Reporting issues

- **Spec ambiguity** (two implementers could read a paragraph differently and produce incompatible wire) — high priority. Use the [Spec ambiguity](https://github.com/semp-dev/semp-spec/issues/new?template=spec_ambiguity.md) template.
- **Spec error** (a normative statement that contradicts another section, names a non-existent constant, or specifies cryptographically unsound behavior) — high priority. Use the [Spec error](https://github.com/semp-dev/semp-spec/issues/new?template=spec_error.md) template.
- **Spec change proposal** (new feature, change in normative behavior, new section). Use the [Spec change](https://github.com/semp-dev/semp-spec/issues/new?template=spec_change.md) template. Substantial proposals MUST include rationale and a security analysis.
- **Editorial fix** (typo, broken cross-reference, formatting). Open a small PR directly without an issue.

## Proposing changes

For non-trivial changes:

1. **Discuss first.** Open a Spec change issue describing the proposed change, the motivation, and the expected impact on existing implementations. Wait for spec maintainer feedback before writing the PR.
2. **Draft the spec text.** Use the existing prose style as your model: short sections, normative keywords, examples.
3. **Include rationale.** A new normative MUST without a "why" reads as arbitrary. Add a short rationale paragraph or footnote.
4. **Update cross-references.** Spec sections cite each other heavily. If you add a section, list it in the document's table of contents and add `See also` links from related sections.
5. **Open the PR.** Fill the template; explain the implementation impact.

For editorial fixes, open the PR directly.

## Style

The spec follows RFC-style prose conventions. The author tends to be picky about these; matching the existing style is the fastest path to merge.

### Normative keywords

Use the RFC 2119 / RFC 8174 keywords explicitly when stating a normative requirement:

- `MUST` / `MUST NOT` — absolute requirement / prohibition.
- `SHOULD` / `SHOULD NOT` — strong recommendation; deviation requires careful justification.
- `MAY` / `OPTIONAL` — implementation discretion.
- `RECOMMENDED` — equivalent to `SHOULD`; used for default values.

Lowercase "must", "should", "may" are NOT normative; use the uppercase forms when you mean them.

### Citations

Cite spec sections precisely: `KEY.md §10.3.5` or `ENVELOPE.md §6.5.3`, with the section symbol and the spec file name. Avoid "the recovery doc" or "the migration spec".

### Punctuation and prose

- Avoid em-dashes (—), en-dashes (–), and inline `--`. Use commas, parentheses, or sentence breaks.
- Avoid AI-generated phrasing tells: "delve into", "in essence", "it's worth noting that", "I hope this helps". The spec is a normative document, not marketing copy.
- Prefer concrete examples and JSON snippets over abstract description.
- Active voice over passive when describing implementation behavior: "the home server MUST verify" beats "verification MUST be performed".

### Examples

Every record schema includes a JSON example with realistic values. Use the existing examples as templates for new sections.

## Review and merge

Substantial spec changes need maintainer sign-off. The author may ask for revisions on:

- Wording precision (a normative statement that's ambiguous gets re-drafted before merge).
- Cross-reference completeness (does every section that mentions the new feature link to it?).
- Implementation analysis (will this break any existing implementation? If so, is the breakage justified?).
- Security analysis (does this widen or narrow the attack surface? What's the threat-model impact?).
- Conformance impact (does this change which test vectors a conformant implementation must pass?).

For editorial fixes, review is light and fast.

## Versioning

The spec uses draft-aware semver: `0.x-draft` while iterating, `1.0.0` at first stable release. Changes that affect existing implementations bump the minor version; editorial fixes bump the patch.

The spec's version is independent of `semp-go`'s version.

## Security disclosures

If you believe you have found a security issue with the protocol design (not a library bug), please email `hello@semp.dev` instead of filing a public issue. We will respond within 48 hours.

## License

By contributing, you agree that your contributions will be licensed under [CC BY 4.0](LICENSE).
