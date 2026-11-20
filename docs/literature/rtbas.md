# RTBAS: selective confirmation by dependency screening (Zhong et al. 2025, arXiv 2502.08966)

Read 2026-11-20 through safe-fetch and the quarantine reader (scanner HIGH came from reference titles and file names;
the paper's Fig. 1 example injection is an illustration, not aimed at the reader).

## What it does
- Tool results carry integrity and confidentiality labels. Before each step a **screener** picks the earlier regions
  the next output depends on; their labels are joined; regions more restrictive than that join are **redacted** from
  the history; a tool call asks the user only if the joined label does not flow to what the policy allows for that
  tool (Sec. 6.2, 7.3, Alg. 3-4).
- Screeners: an LM judge that returns relevant region ids (prompt "sandwich"), or an attention-statistics classifier on
  a small local model (81% test accuracy on 40 cases) (Sec. 7.1-7.2).
- The safety argument that screener errors only cost utility rests on redaction (Sec. 7.3).

## Numbers
AgentDojo: all policy-violating attacks blocked, utility loss under attack under 1-3%, without attack 7-10% (Sec. 8.1).
Privacy set (37 hand-made cases): false confirmations 8.1% (LM judge) vs 29.7% for "confirm every call"; missed leaks
10.8% vs 51.4% for "never confirm"; about 2x cost and time (Sec. 8.2-8.3, Table 2, 4). Grade B; small privacy set; the
reader noted swapped FPR/FNR definitions in Sec. 8.2, so check the page images before quoting.

## What it means for injection-guard
1. **Ask only when the call depends on untrusted data.** Our tainted gate asks for every risky call in the 30-minute
   window, whether or not the call has anything to do with the flagged text. RTBAS's dependency idea, cut down to what
   a hook can see: does the call's argument contain a value (host, recipient, path, IBAN) that occurs in a flagged or
   untrusted tool result and in no user prompt? That is the argument-provenance check planned from Progent and FIDES,
   and it is the cheap screener (string match, no LM).
2. **No redaction in a hook,** so a missed dependency is a missed attack for us, not just lost utility. The provenance
   check must therefore be added to the existing gates, never replace them.
3. **Habituation is the cost being saved.** RTBAS reports 8% vs 30% false confirmations; that is the gap that matters
   for prompt fatigue (Vance et al., not re-read this session).
