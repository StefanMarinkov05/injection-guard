"""Shared patterns, findings, text checks, config and scan registry for injection-guard."""
import base64, codecs, hashlib, html, json, os, re, time, unicodedata, urllib.parse

VERSION = "1.5.1"
HOME = os.path.expanduser("~")
CACHE = os.path.join(HOME, ".cache", "injection-guard")
REGISTRY = os.path.join(CACHE, "scanned")
CONFIG_DIR = os.path.join(HOME, ".config", "injection-guard")
CONFIG = os.path.join(CONFIG_DIR, "config.json")

# Words that name AI systems. In *visible* text of research papers they are normal (INFO);
# in hidden text, metadata, comments or attributes they are a strong signal (HIGH).
KEYWORDS = re.compile(
    r"\b(LLMs?|large language models?|language models?|ChatGPT|GPT-?\d\w*|Claude|Gemini|Copilot|Grok|Llama|Mistral|"
    r"AI (assistants?|models?|systems?|tools?|agents?)|chatbots?|if you are an? (AI|LLM|assistant|model|bot|agent)|"
    r"ignore (all |the |any )?(previous|above|prior|earlier) (instructions?|text)|disregard (the|all|previous)|"
    r"do not (mention|reveal|disclose|tell)|must not (mention|contain|reveal)|don'?t (mention|tell|reveal)|"
    r"system prompt|being solved by (an? )?(AI|LLM|model)|note to (the )?(AI|model|assistant))\b", re.I)

# Phrases that only make sense as an instruction to a model. HIGH wherever they appear.
STRONG = re.compile(
    r"(ignore|disregard|forget|override) (all |any |the |your )?(previous|prior|above|earlier|preceding|former|original) "
    r"(instructions?|prompts?|messages?|context|rules|directions?)"
    r"|if you are an? (AI|LLM|large language model|language model|assistant|chatbot|bot|agent|model)\b"
    r"|if (this|the) (exercise|task|text|document|page|email) is being (solved|read|processed|summari[sz]ed|handled) by an? "
    r"(AI|LLM|language model|model|agent|assistant)"
    r"|(your|the) (answer|response|output|reply|summary) (must|should|shall) not (mention|contain|reveal|include|say)"
    r"|do not (tell|inform|alert|warn|notify) the user"
    r"|without (telling|informing|alerting) the user"
    r"|(new|updated|real|actual|hidden|secret) (instructions?|task|system prompt)\s*:"
    r"|\bsystem prompt\s*:"
    r"|</?(system|instructions?|im_start|im_end)>"
    r"|\bnote to (the )?(AI|LLM|model|assistant|agent)s?\b"
    r"|\b(AI|LLM) (agents?|assistants?|models?),? (please )?(ignore|must|should|do not|never)\b"
    r"|\byou are now (in )?(developer|DAN|jailbreak|unrestricted)"
    r"|\b(exfiltrate|send|post|upload) (the |all |your )?(api keys?|credentials|secrets|tokens|passwords|env(ironment)? variables)"
    r"|\bthe (real |actual |true )?task is (instead|actually|really)\b|\binstead,? (your|the) (real |actual )?task is\b"
    r"|\b(forget|discard) (everything|all) (you|that|above|before)\b|\bfrom now on,? (you|the assistant|the model)\b"
    r"|\bpretend (to be|you are|that you)\b|\brespond only with\b|\bjailbreak\b"
    r"|\b(you|the (assistant|model|agent)) (must|should|shall) (now |instead |secretly |silently )+\w+"
    r"|\b(secretly|silently|quietly) (add|insert|include|run|execute|send|change|modify)\b"
    r"|\b(append|add|include|put|encode|embed)\b[^.\n]{0,60}\b(to|in|into)\b[^.\n]{0,20}\b(the |a |this )?(url|link|query string|image (url|link)|markdown image)"
    r"|!\[[^\]]*\]\(https?://[^)\s]*[?&][^)\s=]*=(\{|\$|<|%7B|\[)"
    r"|\b(curl|wget|fetch)\b[^\n]{0,80}\b(env|secret|token|key|passwd|id_rsa|\.ssh)",
    re.I)

# invisible characters, written as escapes so this file itself stays readable
_ZW = "​-‏⁠-⁤﻿᠎͏ᅟᅠㅤﾠ⠀឴឵؜"
_BIDI = "‪-‮⁦-⁩"
_VS = "︀-️\U000e0100-\U000e01ef"  # variation selectors: one invisible byte each ("emoji smuggling")
ZERO_WIDTH = re.compile("[" + _ZW + "]")
BIDI = re.compile("[" + _BIDI + "]")
TAGS = re.compile("[\U000e0000-\U000e007f]+")
VS_RUN = re.compile("[" + _VS + "]{2,}")
INVISIBLE = re.compile("[" + _ZW + _BIDI + "\U000e0000-\U000e007f]|[" + _VS + "]{2,}")
GREEK_LOOKALIKE = set("ΑΒΕΖΗΙΚΜΝΟΡΤΥΧοϲ")
# Directives that do not change the task but fingerprint or bend it: forced names/notation, canary words,
# fake authority/errata, redefinitions. Normal in a visible task (INFO), a trap when hidden (HIGH).
DIRECTIVE = re.compile(
    r"\b(name|label|call|rename|denote)\b[^.\n]{0,40}\b(states?|nodes?|symbols?|variables?|letters?|notation|"
    r"alphabets?|transitions?|start state|accepting states?|final states?|automat(on|a)|the language|non-?terminals?|lemma|cases?)\b"
    r"|\b(use|write|represent)\b[^.\n]{0,25}\b(symbol|letter|notation|name|subscript|superscript|unicode|greek)\b"
    r"|\b(start|begin|end|finish|sign|conclude|close)\b (your|the|each|every) (answer|solution|response|proof|submission|reply)s? with\b"
    r"|\binclude the (word|phrase|string|sentence|token|marker|emoji|number)\b|\bmention the (word|phrase|name)\b"
    r"|\buse the (word|phrase|term|name) [\"'“‘]"
    r"|\b(always|must|should) (use|write|name|call|label|denote|refer to|spell)\b"
    r"|\binstead of (the )?(symbol|letter|notation|name|word|term|q_?\d)\b"
    r"|\b(erratum|errata|correction|clarification|announcement|notice|note from (the )?(instructor|professor|tutor|ta|lecturer|teacher))\s*[:\-]"
    r"|\b(the )?(official|correct|real|updated|new) (solution|answer|task|deadline|version|exercise|formula|regex) (is|reads|should be)\b"
    r"|\b(deadline|due date|submission) (has been|was|is now) (moved|extended|changed|postponed|cancelled)\b"
    r"|\bin this (course|lecture|sheet|exercise|document),? [^.\n]{0,40}\b(denotes?|means|stands for|is defined as|is written)\b"
    r"|\b(do not|don't|never) (use|mention|write|cite|name) (the )?(symbol|word|lemma|theorem|notation|term|name)\b",
    re.I)
# --- red-team extensions (30 Oct 2026): synonyms, chat templates, reading-mode probes, other languages
_STRONG_EXTRA = (
    r"\b(pay no attention to|do not pay attention to|set aside|overlook|supersede|supersedes|replace|discard|drop)"
    r" (all |any |the |your )?(earlier|previous|prior|above|preceding|original|former|initial) "
    r"(directions?|guidance|instructions?|rules|prompts?|tasks?|text|context|messages?)\b"
    r"|\bthe (task|instructions?|text|prompt|exercise)s? (above|before|so far) (is|are|was|were) (outdated|fake|wrong|a test|obsolete|void|cancelled|a decoy)"
    r"|\bthe (actual|real|true) (task|instructions?|exercise) (follows?|is below|comes next|is the following)"
    r"|<\|(im_start|im_end|system|user|assistant|endoftext|eot_id|start_header_id)\|>|\[/?INST\]|<</?SYS>>"
    r"|(^|\n)[ \t]*#{2,}\s*(instruction|system|response|system prompt)\s*:|\n\n(Human|Assistant)\s*:"
    r"|\bif you (can|are able to) (read|see) this\b|\bif you are reading this (as|in|via) (plain |raw )?text"
    r"|\b(text-only|plain-text|machine|automated) readers?\s*[:,]|\bif this (text|sentence|line) is visible to you\b"
    r"|\bwenn du (eine |ein )?(KI|AI|Sprachmodell|Chatbot|LLM|Assistent)\b|\bwenn Sie (eine |ein )?(KI|Sprachmodell)\b"
    r"|\bignorier(e|en Sie)? (alle |die |sämtliche )?(vorherigen|bisherigen|obigen|vorangegangenen|früheren) (Anweisungen|Instruktionen|Befehle|Regeln)"
    r"|\bals (KI|Sprachmodell|Chatbot)\b[^.\n]{0,40}\b(musst|sollst|darfst|bitte)\b"
    r"|\bsi (tu es|vous êtes) (une? )?(IA|intelligence artificielle|modèle de langage|assistant)"
    r"|\bignore[zr]? (toutes )?les (instructions|consignes) (précédentes|ci-dessus|antérieures)"
    r"|\bsi eres (una? )?(IA|inteligencia artificial|modelo de lenguaje|asistente)"
    r"|\bignora (todas )?las instrucciones (anteriores|previas)|\bignora (tutte )?le istruzioni precedenti|\bse sei un'?(IA|intelligenza artificiale)")
# --- Nov 2026: wordings seen in agent-targeted pages and repositories; Bulgarian and Russian
_STRONG_EXTRA2 = (
    r"\b(attention|important|notice|warning|hey|dear|hello),? (all )?(AI|LLM|coding|autonomous) ?"
    r"(agents?|assistants?|models?|systems?|crawlers?|bots?|language models?)\s*[:,!]"
    r"|\b(AI|LLM|coding|autonomous) (agents?|assistants?|models?|tools?) (reading|processing|parsing|summari[sz]ing|visiting|analy[sz]ing|"
    r"reviewing|indexing|crawling|working (on|in|with)) (this|the) [^.\n]{0,40}\b(must|should|shall|need to|have to|are required to|please)\b"
    r"|\bwhen (you )?(summari[sz]e|summari[sz]ing|review|reviewing|analy[sz]e|analy[sz]ing|process|processing|read|reading|describe|describing) "
    r"this (page|document|file|repo|repository|code|email|message|text|article|paper|website|site|content|pull request|PR|issue),? "
    r"(you )?(must|should|always|also|make sure|be sure|remember|never|do not)\b"
    r"|\bbefore (you )?(answer|answering|respond|responding|reply|replying|summari[sz]e|summari[sz]ing),? "
    r"(you must |you should |please |first |always ){1,3}(run|execute|fetch|open|visit|download|call|send|load|install|curl)\b"
    r"|\bdo not (follow|obey|trust|listen to) (the |your )?(user|system|developer|operator|original|previous)\b"
    r"|\b(stop|cease|abandon|halt) (what you are doing|your current task|the current task) and\b"
    r"|\b(ignore|disregard|forget) (everything|all|anything) (above|before this|prior|written above|you were told)\b"
    r"|\bигнорирай(те)? (всички |всякакви )?(предишни|предходни|горни|досегашни)(те)? (инструкции|указания|команди|правила)"
    r"|\bако (си|сте) (изкуствен интелект|ИИ|езиков модел|AI|чатбот|асистент)\b"
    r"|\bигнорируй(те)? (все )?(предыдущие|прежние|вышеуказанные|прошлые) (инструкции|указания|команды|правила)"
    r"|\bесли (ты|вы) (ИИ|искусственный интеллект|языковая модель|нейросеть|AI|чат-?бот|ассистент)\b")
STRONG = re.compile(STRONG.pattern + "|" + _STRONG_EXTRA + "|" + _STRONG_EXTRA2, re.I)
CHAT_RX = re.compile(r"(^|\n)[ \t]*#{2,}\s*(instruction|system|response|system prompt)\s*:|\n\n(Human|Assistant)\s*:", re.I)
KEYWORDS = re.compile(KEYWORDS.pattern + r"|\b(?-i:KI)\b|\b(Sprachmodells?|künstliche Intelligenz|modèle de langage|modelo de lenguaje)\b", re.I)
DIRECTIVE = re.compile(DIRECTIVE.pattern +
                       r"|\b(nenne|benenne|bezeichne|beschrifte)\b[^.\n]{0,40}\b(Zustände|Zustand|Symbole?|Variablen?|Startzustand|Endzustände)\b"
                       r"|\b(verwende|benutze|schreibe)\b[^.\n]{0,25}\b(Symbol|Buchstaben|Notation|Namen)\b"
                       r"|\b(beende|beginne)\b (deine|die|jede) (Antwort|Lösung|Abgabe)\b", re.I)
# letters that pass for Latin but are not (flagged in a Latin/formula context); Greek math letters like alpha are excluded
LOOKALIKE = set("аеорсухіјһԁԛԝѕАВЕКМ"
                "НОРСТХІЈЅοΑΒΕΖΗΙΚΜΝ"
                "ΟΡΤΥΧϲıɡⅼⅰ")
LOOKALIKE_RX = re.compile("[" + "".join(sorted(LOOKALIKE)) + "]")
COMPAT_RX = re.compile("[！-～Ⅰ-ↈ①-⓿\U0001d7ce-\U0001d7ff\U0001f100-\U0001f1ff]")
MATH_WORD_RX = re.compile("[\U0001d400-\U0001d6a5]{4,}")
SENTENCE = re.compile(r"\b[A-Za-z]{2,}+(?:[ ,'][A-Za-z]++){6,}[.!?:]")  # anchored + possessive: linear on long words

# Text that poses as the user, the harness, a tool, the guard itself, or invents consent / errors with a "fix".
IMPERSONATION = re.compile(
    r"<\s*/?\s*system[-_ ]?reminder\s*>|\[\s*SYSTEM NOTIFICATION|the user sent a new message while you were working"
    r"|<\s*/?\s*(function_results?|function_calls|tool_result|tool_use|antml:\w+|invoke|parameter name)\b"
    r"|\bhookSpecificOutput\b|\bpermissionDecision(Reason)?\b|\"systemMessage\"\s*:|\badditionalContext\"\s*:"
    r"|<\s*/?\s*(user|assistant|human|system|developer|operator)(_message)?\s*>"
    r"|(^|\n)[ \t]*(System|Developer|Operator) (message|prompt|note|instruction)s?\s*:"
    r"|\b(message|note|instructions?|update|notice) from (anthropic|openai|the claude( code)? team|your (operator|developer|administrator|admin|owner))\b"
    r"|===\s*injection-guard|\bVERDICT:\s*(clean|HIGH|MED)\b|<<<\s*(END\s+)?UNTRUSTED CONTENT|\binjection-guard\s*(\d|:|\(|says|reports|verdict)"
    r"|\b(the )?user (has|had) (already )?(explicitly )?(approved|confirmed|authori[sz]ed|agreed|consented)\b"
    r"|\bas (you|we) (agreed|discussed|confirmed|decided) (earlier|before|previously|above)"
    r"|\byou (have )?(already )?(agreed|promised|confirmed) (to|that)\b"
    r"|\b(permission|approval|consent|authori[sz]ation) (has been|was|is|had been) (already )?(granted|given|obtained|confirmed)\b|\bpre-?approved\b"
    r"|\b(error|failed|failure|exception|warning|denied)\b[^\n]{0,120}\b(run|execute|paste|type|enter)\b[^\n]{0,60}"
    r"(curl|wget|\| ?sh\b|bash -c|python3? -c|pip install|npm install|chmod \+x|sudo|rm -rf|INJECTION_GUARD_MODE|--no-verify|trusted_paths)"
    r"|\bINJECTION_GUARD_MODE\s*=|\btrusted_paths\b\s*[\":=]"
    r"|\b(disable|turn off|deactivate|uninstall|bypass|skip|remove) (the )?(injection[- ]guard|guard|scanner|hooks?|safety checks?|security checks?)\b"
    r"|\bclaude plugins? (disable|uninstall|remove)\b"
    r"|(^|\n)[ \t]*(Assistant|AI|Claude|ChatGPT|Model)\s*:\s*(Sure|Of course|Okay|OK|I will|I'll|Understood|Certainly|Done)\b",
    re.I)

# Hidden text that changes the task without addressing anyone ("without the prefix", "c*", "over {a,b,c,d}").
TASK_VOCAB = re.compile(  # domain terms: enough on their own
    r"\b(regex|regular expressions?|automat(on|a)|DFA|NFA|PDA|Turing|states?|transitions?|alphabet|prefix(es)?|suffix(es)?|substrings?|"
    r"languages?|grammars?|minimal|deterministic|complement|reversal|intersection|concatenation|Kleene|lemma|theorem|exercise|formula|"
    r"algorithm|equations?|vertex|vertices|divisible|modulo|epsilon|nonterminals?|derivation|reduction|decidable|NP-hard)\b", re.I)
TASK_MODIFIER = re.compile(  # generic words: only together (three or more) do they look like a task change
    r"\b(without|except|excluding|instead|only|revers(e|ed)|plus|minus|at least|at most|exactly|even|odd|length|words?|empty|"
    r"accept(s|ed|ing)?|reject(s|ed)?|union|star|proofs?|prove|answers?|solutions?|points?)\b", re.I)
FORMULA_FRAG = re.compile(r"[A-Za-z0-9)\]][*+^]|[(\[{][a-z0-9]|\|[a-z0-9]|[∗⋆∈∪∩Σε∅]|=\s*\{")


def hidden_task_signal(t):
    """True if hidden text looks like part of a task (vocabulary or formula symbols) - wording-independent trap."""
    return bool(TASK_VOCAB.search(t) or FORMULA_FRAG.search(t) or len({m.group(0).lower() for m in TASK_MODIFIER.finditer(t)}) >= 3)


def whitespace_stego(text, where, F):
    """Trailing spaces/tabs carrying bits (SNOW-style): invisible in every viewer."""
    tails = re.findall(r"[^\S\n]+(?=\n)", text)
    mixed = [t for t in tails if (" " in t and "\t" in t) or len(t) >= 8]
    if len(mixed) >= 3:
        bits = "".join("1" if c == "\t" else "0" for t in tails for c in t)
        dec = ""
        for order in (bits, bits[::-1]):
            b = bytes(int(order[i:i + 8], 2) for i in range(0, len(order) - 7, 8))
            cand = b.decode("latin1")
            if sum(c.isprintable() for c in cand) > 0.9 * max(1, len(cand)):
                dec = cand
                break
        sev = "HIGH" if dec and (STRONG.search(dec) or KEYWORDS.search(dec) or DIRECTIVE.search(dec)) else "MED"
        F.add(sev, "trailing whitespace pattern (whitespace steganography?)", where,
              f"{len(mixed)} lines with long/mixed trailing whitespace" + (f"; decodes to {short(dec, 120)!r}" if dec else ""))
IMPERATIVE = re.compile(r"\b(must|should|shall|instead|your (task|answer|response|output)|respond|reply|do not|don'?t|never|always|please|ignore)\b", re.I)
ORDER = {"HIGH": 0, "MED": 1, "INFO": 2}


def short(s, n=200):
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[:n] + "..."


class Findings:
    def __init__(self):
        self.items = []
        self._seen = set()

    def add(self, sev, kind, where, detail=""):
        key = (sev, kind, where, detail)
        if key not in self._seen:
            self._seen.add(key)
            self.items.append({"sev": sev, "kind": kind, "where": where, "detail": detail})

    def sorted(self):
        return sorted(self.items, key=lambda f: ORDER[f["sev"]])

    def verdict(self):
        sevs = {f["sev"] for f in self.items}
        return "HIGH" if "HIGH" in sevs else "MED" if "MED" in sevs else "clean"

    def counts(self):
        c = {"HIGH": 0, "MED": 0, "INFO": 0}
        for f in self.items:
            c[f["sev"]] += 1
        return c


def decode_tags(run):
    """Unicode tag characters U+E0020..E007E mirror ASCII ('ASCII smuggling')."""
    return "".join(chr(ord(c) - 0xE0000) for c in run if 0x20 <= ord(c) - 0xE0000 < 0x7F)


def mixed_script(word):
    scripts = set()
    for ch in word:
        if ch.isalpha():
            n = unicodedata.name(ch, "")
            sc = n.split()[0] if n else "?"
            if sc == "GREEK" and ch not in GREEK_LOOKALIKE:
                continue  # ordinary math such as x_sigma
            scripts.add(sc)
    return len(scripts & {"LATIN", "CYRILLIC", "GREEK"}) > 1


def _native(tok):
    """A token written in real Cyrillic or Greek: it has a letter of that script that does not pass for Latin, and no Latin."""
    nat = False
    for c in tok:
        if c.isascii():
            if c.isalpha():
                return False
        elif c.isalpha() and c not in LOOKALIKE and unicodedata.name(c, "").split(" ")[0] in ("CYRILLIC", "GREEK"):
            nat = True
    return nat


def natural_script(clean, i):
    """True if the look-alike letter at i belongs to ordinary Cyrillic/Greek writing rather than to a Latin word, an
    identifier or a formula: its own word is native, or it is a one-word particle next to a native word (bg "а не")."""
    n = len(clean)
    a = i
    while a > 0 and i - a < 48 and not clean[a - 1].isspace():   # bounded: a megabyte-long "word" must stay linear
        a -= 1
    b = i
    while b < n and b - i < 48 and not clean[b].isspace():
        b += 1
    tok = clean[a:b]
    if _native(tok):
        return True
    if any(c.isascii() and (c.isalnum() or c in "()*+{}[]|_^=") for c in tok):
        return False
    prev = clean[max(0, a - 40):a].split()
    nxt = clean[b:b + 40].split()
    return bool((prev and _native(prev[-1])) or (nxt and _native(nxt[0])))


def check_text(text, where, F, hidden=False, keywords=True, _depth=0):
    """Unicode and phrase checks. hidden=True: the text is not visible to a human reader."""
    if not text:
        return
    for run in TAGS.findall(text):
        dec = decode_tags(run)
        F.add("HIGH" if len(dec) >= 3 else "MED", "Unicode tag characters (invisible 'ASCII smuggling')", where,
              f"decoded: {short(dec)!r}" if dec else f"{len(run)} tag chars")
        if dec:
            check_text(dec, where + " (decoded tag characters)", F, hidden=True, _depth=_depth + 1)
    zw = ZERO_WIDTH.findall(text)
    if zw:
        collapsed = ZERO_WIDTH.sub("", text)
        sev = "HIGH" if (STRONG.search(collapsed) and not STRONG.search(text)) else "MED"
        F.add(sev, "zero-width / invisible characters", where,
              f"{len(zw)} chars: " + " ".join(f"U+{ord(c):04X}" for c in sorted(set(zw))))
    bd = BIDI.findall(text)
    if bd:
        F.add("MED", "bidirectional control characters (text may display in a different order)", where, f"{len(bd)} chars")
    clean = INVISIBLE.sub("", text)
    # phrase matching runs on a flattened copy: soft hyphens out, "previ-\nous" joined, line breaks as spaces
    flat = re.sub(r"[^\S\n]+", " ", clean.replace("\u00ad", ""))  # tabs, NBSP, em/thin/ideographic spaces -> " "
    flat = re.sub(r" ?\n ?", " ", re.sub(r"(\w)- ?\n ?(\w)", r"\1\2", flat))
    last = -10**9
    for m in STRONG.finditer(flat):
        if m.start() - last < 400:
            continue  # one finding per passage
        last = m.start()
        a, b = max(0, m.start() - 120), min(len(flat), m.end() + 160)
        F.add("HIGH", "instruction aimed at an AI" + (" (in hidden text)" if hidden else ""), where, short(flat[a:b], 320))
    if last < 0 and "\n" in clean:  # patterns that need the original line structure (chat templates: "\n\nHuman:")
        m = CHAT_RX.search(clean)
        if m:
            F.add("HIGH", "instruction aimed at an AI" + (" (in hidden text)" if hidden else ""), where,
                  short(clean[max(0, m.start() - 120): m.end() + 160], 320))
    look = []
    for m in LOOKALIKE_RX.finditer(clean):  # a Cyrillic/Greek look-alike next to Latin letters, digits or formula symbols
        win = clean[max(0, m.start() - 2): m.start()] + clean[m.end(): m.end() + 2]
        if re.search(r"[A-Za-z0-9()*+{}\[\],|_^]", win) and not natural_script(clean, m.start()):
            look.append(clean[max(0, m.start() - 6): m.end() + 6].replace("\n", " "))
    if look:
        F.add("MED", "look-alike letters in Latin text or a formula (Cyrillic/Greek characters that pass for Latin)", where,
              "; ".join(f"{x!r}" for x in look[:8]) + " - a copied answer would use a different alphabet")
    compat = COMPAT_RX.findall(clean)
    if compat:
        F.add("MED", "compatibility characters posing as ASCII letters/digits (full-width, Roman numerals, math digits, enclosed)", where,
              " ".join(f"{c}=U+{ord(c):04X}" for c in sorted(set(compat))[:10]))
    from .ocr import dictionary
    mw = [w for w in MATH_WORD_RX.findall(clean) if unicodedata.normalize("NFKC", w).lower() in dictionary()]
    if mw:
        F.add("MED", "words spelled with mathematical alphanumeric letters (evade text filters)", where,
              ", ".join(unicodedata.normalize("NFKC", w) for w in mw[:8]))
    if keywords:
        hits = [ln.strip() for ln in clean.splitlines() if KEYWORDS.search(ln)]
        if hits:
            if hidden:
                F.add("HIGH", "AI-directed words in hidden text", where, short(" / ".join(hits[:4]), 320))
            elif any(IMPERATIVE.search(h) for h in hits):
                F.add("MED", "visible text addresses AI with imperative wording", where,
                      short(" / ".join(h for h in hits if IMPERATIVE.search(h))[:600], 320))
            else:
                F.add("INFO", "text mentions AI systems", where, f"{len(hits)} line(s), e.g. {short(hits[0], 120)!r}")
    collapsed = re.sub(r" {2,}", " ", re.sub(r"\b(\w) (?=\w\b)", r"\1", clean))  # "i g n o r e  a l l" -> "ignore all"
    dotted = re.sub(r"\b(\w)[.\-_\u00b7*/](?=\w\b)", r"\1", clean)                # "i.g.n.o.r.e" / "i-g-n-o-r-e"
    if dotted != clean and STRONG.search(dotted) and not STRONG.search(clean):
        F.add("HIGH", "instruction hidden by letters separated with dots/dashes", where, short(STRONG.search(dotted).group(0)))
    if collapsed != clean:
        m = STRONG.search(collapsed) or (KEYWORDS.search(collapsed) if hidden else None)
        if m and not (STRONG.search(clean) if m.re is STRONG else KEYWORDS.search(clean)):
            F.add("HIGH", "instruction hidden by spaced-out letters", where, short(m.group(0)))
    mixed = sorted(w for w in set(re.findall(r"\w+", clean)) if not w.isascii() and mixed_script(w))
    if mixed:
        F.add("MED", "mixed-script words (homoglyphs: Cyrillic/Greek letters posing as Latin)", where, ", ".join(mixed[:10]))
    # identifiers such as state names: one look-alike letter plus digits/underscores ("q0" with Cyrillic q)
    # tokenise, then filter (a regex alternative here backtracks quadratically on very long words)
    ids = sorted(w for w in set(re.findall(r"\w+", clean)) if not w.isascii() and any(c in LOOKALIKE for c in w)
                 and any(ch.isdigit() or ch == "_" for ch in w) and any(ch.isalpha() for ch in w) and w.translate(CONFUSABLE).isascii())
    if ids:
        F.add("MED", "identifier with look-alike letters (e.g. a state name q0 written with a Cyrillic letter)", where, ", ".join(ids[:10]))
    for m in list(IMPERSONATION.finditer(flat))[:5]:
        F.add("HIGH", "impersonation: text poses as the user, the system, a tool or the guard (or invents consent)", where,
              short(flat[max(0, m.start() - 80): m.end() + 120], 280))
    if hidden and _depth == 0 and hidden_task_signal(flat) and not (STRONG.search(flat) or DIRECTIVE.search(flat)):
        F.add("HIGH", "hidden task modifier (hidden text with exercise vocabulary or formula symbols)", where, short(flat, 280))
    dflat = flat if hidden else flat[:300_000]  # visible directives are only INFO: a bounded scan is enough
    src = dflat
    d = DIRECTIVE.search(dflat)
    if not d and not dflat.isascii():
        src = unicodedata.normalize("NFKC", dflat).translate(CONFUSABLE)
        d = DIRECTIVE.search(src)
    if d:
        a, b = max(0, d.start() - 80), min(len(src), d.end() + 120)
        if hidden:
            F.add("HIGH", "hidden directive (forced naming/notation, canary word, fake erratum or redefinition)", where, short(src[a:b], 300))
        else:
            F.add("INFO", "visible directive about naming/notation/answers (check it belongs to the task)", where, short(src[a:b], 200))
    for run in VS_RUN.findall(text):
        dec = decode_vs(run)
        F.add("HIGH" if len(dec) >= 3 else "MED", "variation-selector smuggling (bytes hidden after a visible character)", where,
              f"{len(run)} selectors, decoded: {short(dec)!r}")
        if dec:
            check_text(dec, where + " (decoded variation selectors)", F, hidden=True, _depth=_depth + 1)
    if _depth < 2:
        decoded_variants(clean, where, F, _depth, plain=last >= 0)


def decode_vs(run):
    out = bytearray()
    for c in run:
        o = ord(c)
        out.append(o - 0xFE00 if o <= 0xFE0F else o - 0xE0100 + 16)
    return out.decode("utf-8", "replace")


# ---------------------------------------------------------------- encodings a model can read but a regex cannot
CONFUSABLE = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
    "ј": "j", "һ": "h", "ԁ": "d", "ԛ": "q", "ԝ": "w", "ѕ": "s", "А": "A", "В": "B",
    "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
    "Х": "X", "І": "I", "Ј": "J", "Ѕ": "S", "ο": "o", "α": "a", "ι": "i", "ν": "v",
    "ρ": "p", "τ": "t", "κ": "k", "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H",
    "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y",
    "Χ": "X", "ı": "i", "ɡ": "g", "ⅼ": "l", "ⅰ": "i"})
BRAILLE = str.maketrans({chr(0x2800 + v): c for c, v in zip("abcdefghijklmnopqrstuvwxyz",
                         [1, 3, 9, 25, 17, 11, 27, 19, 10, 26, 5, 7, 13, 29, 21, 15, 31, 23, 14, 30, 37, 39, 58, 45, 61, 53])} | {"\u2800": " "})
BRAILLE_RX = re.compile("[\u2801-\u28ff]{3,}")
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "|": "l", "!": "i"})


def _caesar(t, k):
    lo = "abcdefghijklmnopqrstuvwxyz"
    tab = str.maketrans(lo + lo.upper(), lo[k:] + lo[:k] + lo.upper()[k:] + lo.upper()[:k])
    return t.translate(tab)


def _blobs(text):
    """Encoded runs: yield (encoding, decoded text)."""
    for m in re.findall(r"[A-Za-z0-9+/_-]{40,}={0,2}", text)[:50]:
        for dec in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                yield "base64", dec(m + "=" * (-len(m) % 4)).decode("utf-8")
                break
            except Exception:
                pass
    for m in re.findall(r"(?:[0-9a-fA-F]{2}[\s:]?){24,}", text)[:50]:
        h = re.sub(r"[^0-9a-fA-F]", "", m)
        try:
            yield "hex", bytes.fromhex(h[: len(h) // 2 * 2]).decode("utf-8")
        except Exception:
            pass
    for m in re.findall(r"[A-Z2-7]{40,}={0,6}", text)[:50]:
        try:
            yield "base32", base64.b32decode(m + "=" * (-len(m) % 8)).decode("utf-8")
        except Exception:
            pass
    for m in re.findall(r"(?:[^\s%]{0,40}%[0-9A-Fa-f]{2}){5,}[^\s%]*", text)[:50]:
        yield "URL encoding", urllib.parse.unquote(m)
    for m in re.findall(r"(?:\\u[0-9A-Fa-f]{4}|\\x[0-9A-Fa-f]{2}){6,}", text)[:50]:
        try:
            yield "escape sequences", m.encode().decode("unicode_escape")
        except Exception:
            pass
    for m in re.findall(r"(?:[01]{8}[\s,]?){6,}", text)[:50]:
        bits = re.sub(r"[^01]", "", m)
        yield "binary", bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - 7, 8)).decode("latin1")
    for m in re.findall(r"(?:&#x?[0-9A-Fa-f]+;){6,}", text)[:50]:
        yield "HTML entities", html.unescape(m)


ANCHORS = ("ignore", "instructions", "previous", "disregard", "assistant", "system", "prompt", "pretend", "secretly", "answer")


def _shift_words(k):
    return [_caesar(w, (26 - k) % 26) for w in ANCHORS]  # what each anchor looks like after encoding with shift k


_ANCHOR_K = {}
for _k in range(1, 26):
    for _w in _shift_words(_k):
        _ANCHOR_K.setdefault(_w, set()).add(_k)
for _w in ANCHORS:
    _ANCHOR_K.setdefault(_w[::-1], set()).add("rev")
_ANCHOR_RX = re.compile(r"\b(" + "|".join(sorted(_ANCHOR_K, key=len, reverse=True)) + r")\b")
_LEETY = re.compile(r"\b(?=\w*[a-z])(?=\w*[013457@$])[\w@$]{4,}\b", re.I)


def decoded_variants(clean, where, F, depth=0, plain=None):
    """Run the phrase check on transformed copies of the text. Each finding names the transformation.
    Cheap literal pre-checks decide which transformations can possibly match, so large documents stay fast."""
    if len(clean) > 3_000_000:
        clean = clean[:3_000_000]
    if plain is None:
        plain = bool(STRONG.search(clean))
    trans = []
    if not clean.isascii():
        trans.append(("full-width / compatibility forms (NFKC)", lambda: unicodedata.normalize("NFKC", clean)))
        trans.append(("combining marks / diacritics", lambda: "".join(c for c in unicodedata.normalize("NFKD", clean)
                                                                    if not unicodedata.combining(c) and c not in "\u0335\u0336\u0337\u0338")))
        trans.append(("look-alike letters (Cyrillic/Greek skeleton)", lambda: clean.translate(CONFUSABLE)))
    if BRAILLE_RX.search(clean):
        trans.append(("Braille letters", lambda: clean.translate(BRAILLE)))
    if _LEETY.search(clean):
        trans.append(("leetspeak", lambda: clean.translate(LEET)))
    ks = set()
    for m in _ANCHOR_RX.finditer(clean.lower()):  # one pass finds every shift (and reversal) that could hide an anchor word
        ks |= _ANCHOR_K[m.group(1)]
    if "rev" in ks:
        trans.append(("reversed text", lambda: clean[::-1]))
    for k in sorted(x for x in ks if x != "rev"):
        label = "ROT13" if k == 13 else f"Caesar cipher (shift {26 - k})"
        trans.append((label, lambda k=k: _caesar(clean, k)))
    if not plain:
        for label, make in trans:
            t = make()
            if t != clean:
                m = STRONG.search(t)
                if m:
                    F.add("HIGH", f"instruction hidden by {label}", where, short(t[max(0, m.start() - 80): m.end() + 120], 300))
    for enc, dec in _blobs(clean):
        if not dec or sum(c.isprintable() or c in "\n\t" for c in dec) < 0.9 * len(dec):
            continue
        if STRONG.search(dec) or KEYWORDS.search(dec):
            F.add("HIGH", f"{enc} blob that decodes to AI-directed text", where, short(dec, 300))
        elif len(dec) >= 24 and re.search(r"\b[A-Za-z]{3,}+ [A-Za-z]{3,}+ [A-Za-z]{3,}+", dec):
            F.add("MED", f"{enc} blob that decodes to readable text", where, short(dec, 200))
        if depth < 1:
            check_text(dec, where + f" (decoded {enc})", F, hidden=True, _depth=depth + 1)


def invisible_report(text):
    """Invisible-character findings only, for text where any wording is legitimate (the user's own prompt, instruction
    files). Returns (notes, decoded hidden text). ZWJ/ZWNJ (emoji, Persian, Indic) and single variation selectors are normal."""
    notes, hidden = [], []
    for run in TAGS.findall(text):
        dec = decode_tags(run)
        notes.append(f"{len(run)} Unicode tag characters" + (f" decoding to {short(dec, 200)!r}" if dec else ""))
        hidden.append(dec)
    for run in VS_RUN.findall(text):
        if len(run) >= 4:
            dec = decode_vs(run)
            notes.append(f"{len(run)} variation selectors after one character, decoding to {short(dec, 200)!r}")
            hidden.append(dec)
    if BIDI.search(text):
        notes.append("bidirectional control characters (the text displays in a different order than it is stored)")
    zw = [c for c in ZERO_WIDTH.findall(text) if c not in "\u200c\u200d"]
    if len(zw) >= 3:
        notes.append(f"{len(zw)} zero-width characters (" + " ".join(f"U+{ord(c):04X}" for c in sorted(set(zw))) + ")")
        collapsed = ZERO_WIDTH.sub("", text)
        m = STRONG.search(collapsed)
        if m and not STRONG.search(text):
            hidden.append(m.group(0))
    return notes, " ".join(h for h in hidden if h)


def strip_invisible(text):
    return INVISIBLE.sub("", text)


# ---------------------------------------------------------------- config and registry
DEFAULT_CONFIG = {
    "mode": "strict",            # strict: block unscanned/HIGH documents and WebFetch; warn: only add warnings; off
    "trusted_paths": [],         # files below these directories skip the read gate (post-scan warnings still apply)
    "html_in_git_is_source": True,  # .html/.svg inside a git work tree count as source code, not documents
    "block_on": "MED",           # raw reads are blocked for files with findings at or above this level (HIGH or MED)
    "taint_minutes": 30,         # after a HIGH finding, risky actions (send data, read secrets, install, persist) ask for this long; 0 = off
}


def load_config():
    cfg = dict(DEFAULT_CONFIG)
    try:
        with open(CONFIG) as f:
            cfg.update(json.load(f))
    except Exception:
        pass
    env = os.environ.get("INJECTION_GUARD_MODE")
    if env in ("strict", "warn", "off"):
        cfg["mode"] = env
    cfg["trusted_paths"] = [os.path.realpath(os.path.expanduser(p)) for p in cfg.get("trusted_paths", [])]
    return cfg


def sha256_file(path, limit=None):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(1 << 20)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def registry_put(sha, record):
    os.makedirs(REGISTRY, exist_ok=True)
    tmp = os.path.join(REGISTRY, sha + ".tmp")
    with open(tmp, "w") as f:
        json.dump(record, f, indent=1)
    os.replace(tmp, os.path.join(REGISTRY, sha + ".json"))


def registry_get(sha):
    try:
        with open(os.path.join(REGISTRY, sha + ".json")) as f:
            return json.load(f)
    except Exception:
        return None


def make_record(path, sha, ftype, F, source_url=None):
    return {"path": os.path.realpath(path), "sha256": sha, "type": ftype, "verdict": F.verdict(), "counts": F.counts(),
            "findings": F.sorted()[:12], "scanned_at": time.strftime("%Y-%m-%d %H:%M:%S"), "guard_version": VERSION,
            "source_url": source_url}
