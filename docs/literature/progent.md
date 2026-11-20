# Progent: privilege control for agents (Shi et al. 2025, arXiv 2504.11703)

Read 2026-11-20 through safe-fetch and the quarantine reader (scanner HIGH came from PDF metadata and font remaps, no
instruction aimed at the reader; the paper quotes its own adaptive attacks in App. E as data).

## What it does
- A policy is a list of rules `allow|forbid tool when {argument conditions}, fallback f`. Conditions are boolean
  expressions over arguments (constants, indexing, length, `in`, regex match). Implemented as JSON Schema (Sec. 4.1, 7).
- Deny by default; forbid rules are checked before allow rules (Sec. 4.2).
- Fallback on a violation: stop, ask the user, or **return a message to the agent** ("not allowed because ...; try
  other tools") so it carries on. The paper's default is the message, not the prompt (Sec. 4.1).
- Task policies come from an LLM that sees **only the user's request and the tool list**, which are trusted (Sec. 5).
  Updates during the task: a first LLM decides whether an update is needed without seeing tool results; a second writes
  the update and does see them. Z3 checks whether the new policy only narrows; widening needs an approver (auto-deny,
  rules, or the human). Only 6% of updates needed approval (Sec. 8.2).
- Hand-written generic policies sit above the task policies and cannot be overridden (Sec. 7).

## Numbers (their benchmarks, their models)
AgentDojo attack success 39.9% -> 1.0% with utility kept; ASB 70.3% -> 3.9% (hand-written policies 0%). With an
already robust model (claude-sonnet-4) 6.8% -> 0.5% (Sec. 8). Grade B (one paper, author-run benchmarks).

## Limits the paper states
Attacks that stay inside least privilege (steering an answer, choosing among allowed actions) pass; a wrong user
approval or a vague task widens the policy; proxy mode cannot see built-in tools; no shell or coding-agent rules
(Sec. 3.2, 9). For a coding agent the tool is `Bash`, so a policy over "tool + arguments" is a policy over command
strings, which Progent does not address.

## What it means for injection-guard
1. **Our generic layer is Progent's hand-written layer.** The effect gate (download-and-run, config edits, foreign
   build code) is a fixed forbid-unless-approved list. That matches their top layer; we have no task layer.
2. **Policy from the trusted prompt only.** The idea we can use in hooks: the `UserPromptSubmit` hook sees every user
   prompt, so hosts, paths and recipients the *user* named are trusted; values that first appear in tool results are
   not. Gate consequential calls whose arguments contain values the user never named (see FIDES note: same idea as
   integrity labels on arguments). Planned as a separate change with its own tests (false-ask rate on the A/B tasks).
3. **Fallback = message, not prompt, where the verdict is certain.** Fewer prompts keep the remaining ones meaningful
   (Vance et al. on habituation). Candidate: when a command pipes a download from a host seen only in tool output into
   a shell, deny with a message instead of asking. Not done yet: a deny the user cannot override in the moment is a
   bigger change; it needs Stefan's decision.
4. **Monotonic narrowing.** Our taint only ever adds asks for 30 minutes, which is the same direction. Good.

## Done in the plugin because of this paper
- Local scripts are now opened before they run, in every session (not only tainted ones): a setup script that pipes a
  download into a shell gets the same ask as typing that line (C38). Twin: a script that only makes a venv and a
  self-signed certificate passes.
