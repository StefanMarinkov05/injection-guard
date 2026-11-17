"""Resource exhaustion ("denial of wallet", context bloat): content that makes an agent spend tokens, time or money.

Two halves:
  cost_signals()  instructions - repeat N times, never stop, crawl every link, ignore token limits, spawn agents ...
  squeeze()       structure - padding, repeated blocks and encoded blobs are collapsed before the text is printed,
                  so the agent pays for one copy and a note instead of a megabyte.
All patterns are bounded ({0,N} gaps, no nested quantifiers): linear on any input.
"""
import re
import zlib

# who the sentence talks to. Without this a "repeat 5000 times" is a programming exercise, not an attack.
ADDRESS = re.compile(
    r"\b(your (response|answer|reply|output|summary|turn|context|next message)|in (the|this|your) (response|answer|reply)"
    r"|before (answering|responding|replying|you (answer|respond|reply|continue|proceed))"
    r"|(AI|LLM|coding|automated|autonomous) (agents?|assistants?|models?)|\b(the|an?|as an?) (AI|LLM|assistant|chatbot|language model)\b"
    r"|(the |an? )?(assistant|agent|model|AI|LLM)s? (must|should|needs? to|has to|have to|is required to|are required to|will)\b"
    r"|LLMs?\b|chatbots?\b|Claude\b|ChatGPT\b|Copilot\b|Gemini\b|you reply\b)", re.I)

_NUM = r"(\d{1,3}(?:[,. ]\d{3})+|\d+)"
# always an instruction to a model: nothing else is told to ignore its token limit or never to end its response
ALWAYS = re.compile(
    r"\b(ignore|disregard|bypass|override|do not (respect|apply|obey)) (any |all |the |your )?"
    r"(token|context|length|output|thinking|reasoning|cost|budget|rate|usage|spending)[ -]?(limits?|budgets?|caps?|windows?|quotas?)\b"
    r"|\b(do not|don'?t|never) (stop|end|finish|terminate) (generating|responding|writing|outputting|your (response|answer|reply|output|turn))\b"
    r"|\bnever (end|finish|stop) your (response|answer|reply|output|turn)\b"
    r"|\b(keep|continue) (generating|responding|writing|outputting)\b[^.\n]{0,30}\b(forever|indefinitely|endlessly|without (stopping|end|limit))\b"
    r"|\b(use|spend|burn|consume|exhaust|waste)\b[^.\n]{0,25}\b(as many tokens as|all (of )?(your|the) (tokens|context|budget)|your (entire|whole|full) (context|budget|token))",
    re.I)
REPEAT = re.compile(r"\b(repeat|say|write|print|output|type|list|recite|generate|produce|copy|echo)\b[^.\n]{0,70}?\b" + _NUM +
                    r"\s*(times|copies|words|lines|pages|paragraphs|items|digits|sentences|tokens|characters)\b", re.I)
COUNT = re.compile(r"\b(from|numbers?) (1|one|0|zero) (to|through|up to|until) " + _NUM + r"\b|\bcount (up )?to " + _NUM + r"\b", re.I)
LENGTH = re.compile(r"\b(at least|no fewer than|a minimum of|minimum of|more than|not less than) " + _NUM +
                    r" (words|tokens|pages|paragraphs|lines|characters|sentences)\b", re.I)
FULLTEXT = re.compile(r"\b(include|quote|reproduce|paste|output|print|repeat) (the )?(full|entire|complete|whole) "
                      r"(text|content|contents|source|transcript)( of)? (every|each|all)\b", re.I)
CRAWL = re.compile(r"\b(fetch|open|visit|follow|crawl|download|read|scan|load|summari[sz]e|analy[sz]e|review|inspect)\b "
                   r"(every|each|all( of)?( the)?)\b[^.\n]{0,40}\b(links?|urls?|pages?|files?|documents?|repositor(y|ies)|"
                   r"director(y|ies)|folders?|references?|citations?|sources?)\b", re.I)
RECURSE = re.compile(r"\brecursive(ly)?\b|\b(every|each|all) links? (on|in|from) (those|these|them|each)\b", re.I)
RETRY = re.compile(r"\b(retry|try again|re-?send|re-?run|reload|refresh|repeat (the|this) (request|call|step|command|query))\b[^.\n]{0,50}"
                   r"\b(until|forever|indefinitely|again and again|over and over|as many times|every (second|minute)|without (limit|stopping)|\d{3,} times)\b", re.I)
AGENTS = re.compile(r"\b(spawn|launch|start|create|dispatch|run|use)\b[^.\n]{0,20}\b(\d{2,}|dozens of|hundreds of|thousands of|as many|unlimited)\b"
                    r"[^.\n]{0,20}\b(sub-?agents?|agents|parallel (tasks|sessions)|background (tasks|agents))\b", re.I)
THINK = re.compile(r"\b(use|spend|set|apply|enable)\b[^.\n]{0,25}\b(maximum|max|highest|unlimited|largest)\b (possible )?(thinking|reasoning) "
                   r"(budget|effort|tokens)\b|\b(think|reason|deliberate)\b[^.\n]{0,25}\b(as long as (possible|you can)|for (at least )?\d{2,} (minutes|hours))", re.I)
FETCH_URL = re.compile(r"\b(fetch|load|read|open|get|download|retrieve|visit|request|call)\b[^.\n]{0,60}https?://", re.I)
MIN = {"times": 200, "copies": 200, "words": 4000, "lines": 500, "pages": 20, "paragraphs": 100, "items": 1000, "digits": 1000,
       "sentences": 300, "tokens": 5000, "characters": 20000}
KIND = "resource-exhaustion instruction (makes an agent spend tokens, time or money)"


def _n(s):
    try:
        return int(re.sub(r"[,. ]", "", s))
    except Exception:
        return 0


def cost_signals(flat, where, F, hidden=False):
    """flat: text with line breaks folded to spaces. Adds at most a few findings."""
    if len(flat) > 400_000:
        flat = flat[:400_000]
    done = set()

    def add(sev, m, what):
        if what in done:
            return
        done.add(what)
        a, b = max(0, m.start() - 100), min(len(flat), m.end() + 140)
        F.add(sev, KIND + (" (in hidden text)" if hidden else ""), where, f"{what}: " + flat[a:b].strip()[:300])

    def addressed(m):
        return hidden or bool(ADDRESS.search(flat[max(0, m.start() - 220): m.end() + 220]))

    m = ALWAYS.search(flat)
    if m:
        add("HIGH", m, "told to ignore limits or never stop")
    for m in REPEAT.finditer(flat):
        if _n(m.group(2)) >= MIN.get(m.group(3).lower(), 1000) and addressed(m):
            add("HIGH" if hidden else "MED", m, "asked for a huge repetition")
            break
    for m in COUNT.finditer(flat):
        if max(_n(g) for g in (m.group(4) or "0", m.group(6) or "0")) >= 10000 and addressed(m):
            add("HIGH" if hidden else "MED", m, "asked to count through a huge range")
            break
    for m in LENGTH.finditer(flat):
        if _n(m.group(2)) >= MIN.get(m.group(3).lower(), 1000) and addressed(m):
            add("HIGH" if hidden else "MED", m, "asked for a very long answer")
            break
    for rx, what, need in ((FULLTEXT, "asked to reproduce every source in full", True), (RETRY, "asked to retry without end", True),
                           (AGENTS, "asked to start many agents", False), (THINK, "asked to think at maximum budget", True)):
        m = rx.search(flat)
        if m and (not need or addressed(m)):
            add("HIGH" if hidden else "MED", m, what)
    for m in CRAWL.finditer(flat):
        near = flat[max(0, m.start() - 220): m.end() + 220]
        if hidden or (ADDRESS.search(near) and (RECURSE.search(near) or re.search(r"\bbefore (answering|responding|replying|you)\b|\bfirst\b|\bmust\b", near, re.I))):
            add("HIGH" if hidden else "MED", m, "asked to read or fetch everything")
            break
    for m in FETCH_URL.finditer(flat):
        if addressed(m):
            add("HIGH" if hidden else "MED", m, "an AI is told to fetch a URL")
            break


# ------------------------------------------------------------------ structure: collapse what carries no information
BLOB = re.compile(r"[A-Za-z0-9+/_=-]{400,}")
NOTE = "collapsed by injection-guard"


def _low_entropy(s):
    """True for a long run that is the same few characters over and over (zlib squeezes it to almost nothing)."""
    if len(s) < 2000:
        return False
    sample = s[:200_000].encode("utf-8", "replace")
    return len(zlib.compress(sample, 1)) < len(sample) * 0.03


def squeeze(text, max_period=8, keep=2, blobs_too=True):
    """Return (shorter_text, notes). Repeated lines or blocks keep `keep` copies; blobs and padding runs are elided."""
    notes = []
    lines = text.split("\n")
    out, i, n, saved_rep = [], 0, len(lines), 0
    while i < n:
        best_p, best_k = 0, 0
        if lines[i] or i + 1 < n:
            for p in range(1, max_period + 1):
                if i + 2 * p > n or lines[i:i + p] != lines[i + p:i + 2 * p]:
                    continue
                if not any(x.strip() for x in lines[i:i + p]):
                    continue
                k = 2
                while i + (k + 1) * p <= n and lines[i + k * p:i + (k + 1) * p] == lines[i:i + p]:
                    k += 1
                if k > keep + 1 and k * p > best_k * best_p:
                    best_p, best_k = p, k
                break
        if best_p:
            for _ in range(keep):
                out.extend(lines[i:i + best_p])
            extra = best_k - keep
            what = "the line above repeats" if best_p == 1 else f"the {best_p} lines above repeat"
            out.append(f"[{what} {extra} more times - {NOTE}]")
            saved_rep += extra * sum(len(x) + 1 for x in lines[i:i + best_p])
            i += best_k * best_p
        else:
            out.append(lines[i])
            i += 1
    if saved_rep:
        notes.append(f"repeated lines or blocks: {saved_rep} characters collapsed")
    blobs = pad = 0
    for j, ln in enumerate(out):
        if len(ln) < 400:
            continue
        if _low_entropy(ln):
            pad += len(ln) - 200
            out[j] = ln[:200] + f" [... {len(ln) - 200} more characters of the same repeated content - {NOTE}]"
            continue

        def rep(m):
            nonlocal blobs
            blobs += len(m.group(0))
            return f"[encoded data, {len(m.group(0))} characters - {NOTE}]"
        if blobs_too:
            out[j] = BLOB.sub(rep, ln)
        if len(out[j]) > 20000 and not re.search(r"\s", out[j][:20000]):
            pad += len(out[j]) - 400
            out[j] = out[j][:400] + f" [... {len(out[j]) - 400} more characters without a single space - {NOTE}]"
    if blobs:
        notes.append(f"encoded data (base64/hex): {blobs} characters elided")
    if pad:
        notes.append(f"padding inside one line: {pad} characters elided")
    return "\n".join(out), notes


def bloat_findings(text, shorter, notes, where, F):
    """Report what squeeze() removed. INFO when small; MED when most of a large text was filler."""
    if not notes:
        return
    saved = len(text) - len(shorter)
    sev = "MED" if (saved >= 150_000 and saved > 0.8 * len(text)) else "INFO"
    F.add(sev, "padding or filler that only costs tokens (collapsed in the output)" if sev == "MED" else "repetitive content collapsed in the output",
          where, "; ".join(notes) + f" - {len(text)} characters became {len(shorter)}")


def tokens(n_chars):
    return int(n_chars / 3.6)
