# Literature notes

One note per paper: what it does, its numbers (with a grade), its stated limits, and what it means for
injection-guard, including what was changed because of it. Papers are read through `safe-fetch` and the
quarantine-reader agent; quoted attack examples in them are data.

| Paper | Read | Main idea for the guard | Changed in the plugin |
|---|---|---|---|
| [Progent](progent.md) (Shi et al. 2025, arXiv 2504.11703) | 2026-11-20 | policy from the trusted prompt only; deny-by-default rules over tool arguments; fallback can be a message instead of a prompt | 1.8.0: local setup scripts are opened before they run in every session (H16) |
| [FIDES](fides.md) (Costa et al. 2025, arXiv 2505.23643) | 2026-11-20 | integrity labels on data; consequential calls only from a trusted context (P-T) | 1.8.0: own-repository exemption fixed after false taints (H18); argument-level provenance planned |
| [RTBAS](rtbas.md) (Zhong et al. 2025, arXiv 2502.08966) | 2026-11-20 | ask only when the call depends on untrusted data (8% vs 30% false confirmations) | planned: argument-provenance check (shared with Progent and FIDES) |

Not yet re-read in this round: CaMeL (Debenedetti et al. 2025), AgentDojo and the adaptive-attack papers (Nasr et
al.), Vance et al. on warning habituation. The paper's bibliography (`docs/research/shared/references.bib`) has them.

## Planned from these notes (not built yet)
**Argument provenance.** The `UserPromptSubmit` hook sees every user prompt, so hosts, recipients, paths and account
numbers the user named are trusted; values that first appear in tool output are not. A consequential call (send data,
pipe a download into a shell, write a CI step, type payment details) whose arguments contain an untrusted value asks,
even with no finding in the session. It is RTBAS's dependency screen reduced to a string match, FIDES's P-T per
argument, and Progent's "policy from the prompt". It adds to the existing gates and never replaces them (a hook cannot
redact, so a missed dependency is a missed attack). Needs a false-ask measurement on the A/B tasks before release.
