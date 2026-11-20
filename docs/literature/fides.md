# FIDES: information-flow control for agents (Costa et al. 2025, arXiv 2505.23643)

Read 2026-11-20 through safe-fetch and the quarantine reader (scanner HIGH came from PDF metadata; the paper quotes an
example injection email in Sec. 1 and reprints its planner prompt in App. D.1, both as data).

## What it does
- Every piece of data carries a label from a product lattice: confidentiality (who may read) x integrity (trusted /
  untrusted). Tool results are JSON trees with a label per node; trusted wrappers assign labels (web results untrusted)
  (Sec. 4.1).
- The planner's context label is the join of everything it has seen; a tool call inherits the context label (Sec. 4.2).
- Policies before each call: **P-T**, a consequential call may only be made from a trusted context; **P-F**, data may
  only flow to recipients allowed to read it; combined "P-F or P-T" (Sec. 4.3-4.4).
- To keep the context trusted, results more restrictive than the context are **hidden** behind variables; the planner
  passes variables into tool arguments, and a tool-less quarantined LLM with constrained decoding extracts typed values
  (bool, enum, string) from hidden data (Sec. 5-6).

## Numbers
AgentDojo with gpt-4o: successful attacks 163 (basic) vs 1 (FIDES with policy checks); task completion with policies
FIDES 50-62% vs basic 41-45% across five models; 2-3x token cost (Sec. 7-8, Tables 1, 7). Grade B.

## Limits the paper states
Text-only attacks on the final answer pass (policies apply only to tool calls); implicit flows allowed; propagation
through the LLM is conservative, so data-dependent tasks fail strict P-T; the quarantined LLM's output can itself be
manipulated (Sec. 9).

## What it means for injection-guard
1. **Our session taint is FIDES's context label with one bit and a timeout.** P-T is what the tainted gate does:
   consequential actions ask once the context holds untrusted, flagged content. Difference: FIDES labels *all*
   external data untrusted, we label only data with a HIGH finding. Their design catches attacks our scanner misses;
   ours asks far less. Our A/B already measured the cost side (one wrong deny, +47% median time).
2. **Variable hiding needs the agent loop.** A hook cannot remove text from the context, so FIDES's main utility
   mechanism is out of reach for a plugin. The `quarantine-reader` agent is the closest thing we have: the main agent
   sees a fixed-format digest instead of the raw text. Its output can be manipulated like FIDES's query_llm.
3. **Argument-level labels are reachable.** A hook can remember values (hosts, recipients, IBANs) that appeared in tool
   results but in no user prompt, and check the arguments of the next consequential call against them. That is P-T
   applied per argument instead of per session, and it does not depend on detecting the injected text at all. Planned
   with Progent's point 2 (same mechanism).
4. **False taint is a real cost.** During this reading session the taint fired on the guard's own report of the paper
   metadata and on a grep of the guard's own source. Each refreshes the 30-minute window. Fixed: the own-repository
   exemption now looks at the command word, not at any occurrence of "curl" in a grep pattern.
