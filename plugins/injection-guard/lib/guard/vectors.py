"""Text signals from browsing, shopping and downloading (round 7, Nov 2026).

ClickFix pages, exfiltration through a rendered image whose URL is to be filled with private data, spreadsheet
formulas that fetch a URL or start a program, and file names with a disguised extension. Each check is a bounded,
linear pattern plus a window test; none of them needs AI vocabulary.
"""
import re

from .common import short

# ---------------------------------------------------------------- ClickFix: a fake human check that ends in a pasted command
VERIFY = re.compile(r"\b(verif(y|ication)|prove|confirm|complete|pass)\b[^.\n]{0,40}\b(human|not a (ro)?bot|captcha|real person|you are real|turnstile)\b"
                    r"|\b(captcha|human|bot|robot|cloudflare|turnstile) (check|verification|test|challenge)\b|\bverification (failed|required|step)\b", re.I)
RUN_IT = re.compile(r"\bwin(dows)?( key)?\s*\+\s*r\b|\brun dialog\b|\bpowershell\b|\bcommand prompt\b|\bcmd(\.exe)?\b|\bterminal\b"
                    r"|\bctrl\s*\+\s*v\b|⌘\s*\+?\s*v\b|\bcommand\s*\+\s*v\b|\bpaste\b|\bmshta\b", re.I)

# ---------------------------------------------------------------- a rendered image or link that is to carry private data
IMG_URL = re.compile(r"!\[[^\]\n]{0,120}\]\(\s*<?(https?://[^)\s>]{4,600})|<img\b[^>]{0,200}?\bsrc\s*=\s*[\"']?(https?://[^\"'\s>]{4,600})", re.I)
PLACEHOLDER = re.compile(r"[?&#=/](\{[\w ]{2,30}\}|<[\w ]{2,30}>|\[[\w ]{2,30}\]|[A-Z][A-Z_]{2,30})(?=$|[&#/.])")
PRIVATE = re.compile(r"\b(replace|substitute|fill( it)?( in)?|insert|put|where|with)\b[^.\n]{0,80}?(\b(api ?keys?|tokens?|passwords?|secrets?|credentials?|"
                     r"environment( variables)?|conversation|chat( history)?|history|previous messages|system prompt|cookies?|private|personal|"
                     r"e-?mail address|ssh key|session)\b|\.env\b)", re.I)

# ---------------------------------------------------------------- spreadsheet formulas (CSV/TSV opened in Excel, LibreOffice, Sheets)
FORMULA_RUN = re.compile(r"(?:^|[,;\t\"])[ \t]*[=+\-@][^\n,;\t]{0,60}?\b(cmd|powershell|mshta|msexcel|DDEAUTO|DDE)\s*\|", re.I | re.M)
FORMULA_FETCH = re.compile(r"(?:^|[,;\t\"])[ \t]*[=+@][ \t]*(HYPERLINK|WEBSERVICE|IMPORTXML|IMPORTDATA|IMPORTHTML|IMPORTFEED|IMPORTRANGE|IMAGE|FILTERXML)\s*\(",
                           re.I | re.M)

# ---------------------------------------------------------------- file names that show one type and are another
DISGUISED = re.compile(r"(?<![\w.-])[\w ()-]{1,80}\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|mp4|mp3|mov|zip|csv|odt|rtf)"
                       r"\.(exe|scr|bat|cmd|com|pif|jse?|vbe|vbs|wsf|hta|lnk|desktop|app|msi|ps1|jar|apk|command)\b", re.I)


# ---------------------------------------------------------------- pastejacking: a page script puts a command on the clipboard
CLIP = re.compile(r"clipboard\s*\.\s*write(Text)?\s*\(|execCommand\s*\(\s*[\"']copy|clipboardData\s*\.\s*setData\s*\(", re.I)
SHELLY = re.compile(r"\b(powershell|pwsh|iex|invoke-expression|iwr|invoke-webrequest|mshta|certutil|bitsadmin|rundll32|regsvr32|osascript|"
                    r"cmd(\.exe)?\s+/[ck]|bash\s+-c|sh\s+-c|base64\s+-d)\b|\b(curl|wget)\b[^\"'`\n]{0,200}\|\s*(sudo\s+)?(ba|z)?sh\b", re.I)
JS_LIT = re.compile(r"\"((?:[^\"\\\n]|\\.){4,2000})\"|'((?:[^'\\\n]|\\.){4,2000})'|`((?:[^`\\]|\\.){4,2000})`")


def clipboard_check(js, visible, F, where):
    """A script that writes a shell command to the clipboard. HIGH when the command is not the one shown on the page."""
    if not CLIP.search(js[:5_000_000]):
        return
    shown = re.sub(r"\s+", " ", visible[:2_000_000])
    for n, m in enumerate(JS_LIT.finditer(js[:5_000_000])):
        if n >= 5000:
            break
        lit = next(g for g in m.groups() if g)
        if SHELLY.search(lit):
            same = re.sub(r"\s+", " ", lit).strip() in shown
            F.add("MED" if same else "HIGH", "page script puts a shell command on the clipboard (pastejacking / ClickFix)", where,
                  short(lit, 200) + (" - the same command is shown on the page" if same else
                                     " - this command is not shown on the page; pasting it into a terminal runs it"))
            return


# ---------------------------------------------------------------- breadcrumbs: steering a reader's choice or skipping content
AI_WORDS = re.compile(r"\b(AI|A\.I\.|LLMs?|language models?|chat ?bots?|Claude|GPT|ChatGPT|Gemini|Copilot|agents?|assistants?|crawlers?|"
                      r"scrapers?|summari[sz]ers?|models?)\b", re.I)
STEER = re.compile(r"\b(recommend|suggest|promote|rank|push|favou?r|prefer|choose|pick|upsell|add|present|describe|call|list)\b[^.\n]{0,60}?"
                   r"\b(most expensive|priciest|premium|highest[- ]priced|extended warranty|pro plan|the upgrade|the \w+ (?:plan|tier|model|package|edition|subscription)|this (one|product|item|seller|vendor|plan|shop|store)|"
                   r"our (product|brand|service|plan|offer|shop|store))\b[^.\n]{0,80}?"
                   r"\b(to the (user|customer|shopper|buyer|reader)|regardless|above (all )?others|as the (best|top|only|right)|no matter|"
                   r"over (any|all|the) (others?|competitors?|alternatives?)|to the (cart|basket|order)|by default)\b", re.I)
ADDRESS = re.compile(r"(?:(?:^|\n)[^\w\n]{0,8}|[\"'`=(\[{][ \t]?|/|\t| {2}|:\d\d |:[ \t]+|[.!?][ \t]+|>[ \t]*|\b(note|message|reminder|instruction)s? (for|to) )"
                     r"((?:the |all |any )?(?:AI|LLMs?|language models?|chat ?bots?|(?:(?:AI|coding|shopping|research|browsing|web) ){0,2}(?:agents?|assistants?)|"
                     r"Claude|GPT|crawlers?|scrapers?)(?: (?:reading|summari[sz]ing|parsing|crawling|visiting|processing) (?:this|the)[^:,\n]{0,30})?)"
                     r"(?:[ \t]*[:,]|[ \t]+-[ \t])[ \t]*(\w+(?:'\w+)?)", re.I)  # "AI agents: skip", "Claude - do"; not "anthropic.claude-code", "claude -p"
IMPERATIVE_START = re.compile(r"^(skip|ignore|recommend|do|don't|dont|never|always|tell|say|mention|include|add|run|open|send|rank|prefer|treat|"
                              r"consider|use|avoid|omit|stop|delete|summari[sz]e|report|answer|respond|reply|write|forget|please|make|buy|choose|"
                              r"pick|click|visit|install|download|leave|exclude|disregard|state|claim|describe|call|praise|warn|trust|distrust)$", re.I)


MODAL_ORDER = re.compile(r"(?:you|we need you to|you'?ll|you will)[ \t]+(?:must|should|need to|have to|are to|shall|are required to|will)?[ \t]*(?:always |never |not |now )?"
                         r"(?:recommend|skip|ignore|tell|say|mention|rank|prefer|add|omit|avoid|run|install|send|treat|describe|choose|pick|buy)\b"
                         r"|(?:you|we need you to)[ \t]+(?:must|should|need to|have to|are to|shall|are required to)\b", re.I)
AGENT_ORDER = re.compile(r"\b(?:the |an? |your |all |any )?(?:AI |coding |LLM )?(?:assistant|agent|model|LLM|Claude|Copilot|GPT|bot)s? "
                         r"(?:must|should|shall|needs? to|has to|have to|is to|are to) (?:now |first |always |immediately |silently |secretly )?"
                         r"(?:run|execute|install|download|curl|wget|send|upload|post|email|delete|remove|disable|turn off|ignore|disregard|skip|"
                         r"recommend|approve|grant|pay|buy|purchase|transfer)\b", re.I)
YOU_MUST = re.compile(r"\b(you|your|please|must|should|need to|have to|do not|don'?t|never|always)\b", re.I)
CONCEAL = re.compile(r"\b(don'?t|do not|never|avoid) (tell(ing)?|inform(ing)?|mention(ing)?|reveal(ing)?|disclos(e|ing)|bring(ing)? up)\b[^.\n]{0,15}?"
                     r"\b(the |your )?(user|human|customer|owner|operator|shopper|buyer)\b[^.\n]{0,60}", re.I)
HIDDEN_STEER = re.compile(r"\b(recommend|skip|rank|prefer|promote|suggest|ignore|omit|leave out|praise|favou?r)\b", re.I)


def steering(t, where, F, label="", hidden=False):
    found = False
    m = CONCEAL.search(t)
    if m:
        win = t[max(0, m.start() - 200): m.end() + 60]
        ai = AI_WORDS.search(win)
        F.add("HIGH" if ai or hidden else "MED", f"text that tells a reader to keep something from the user{label}", where, short(win.strip(), 240))
        found = True
    if hidden:
        m = HIDDEN_STEER.search(t)
        if m:
            F.add("HIGH", f"hidden text that steers what a reader skips or recommends{label}", where,
                  short(t[max(0, m.start() - 80): m.end() + 160].strip(), 240) + " - a human visitor never sees it")
            found = True
    for n, m in enumerate(ADDRESS.finditer(t)):
        if n >= 300:
            break
        imp = bool(IMPERATIVE_START.match(m.group(4))) or bool(MODAL_ORDER.match(t, m.start(4), m.start(4) + 40))
        explicit = m.group(1) or re.search(r" (reading|summari|parsing|crawling|visiting|processing)", m.group(3), re.I)
        clause = re.split(r"[.!?\n`\u2014]", t[m.start(4): m.start(4) + 100], maxsplit=1)[0]  # "`claude: command not found` - ... your PATH"
        if not (imp or explicit or YOU_MUST.search(clause)):  # "AI: changes work rather than ending it" is a heading
            continue
        F.add("HIGH" if imp else "MED", f"text addressed to AI readers{label}" + (" with an order" if imp else ""), where,
              short(t[m.start(): m.end() + 200].strip(), 260) + " - a page writes to AI readers only to change what they do or say")
        found = True
        break
    if not found:
        m = AGENT_ORDER.search(t)
        if m:  # MED: agent design docs say "the agent must run the tests"; in a file name or a page it is an order to the reader
            F.add("MED", f"sentence that orders an AI agent to act{label}", where, short(t[max(0, m.start() - 80): m.end() + 120].strip(), 240))
            found = True
    m = STEER.search(t)
    if m:
        win = t[max(0, m.start() - 200): m.end() + 100]
        ai = AI_WORDS.search(win)
        F.add("HIGH" if ai else "MED", f"text that steers a recommendation or purchase{label}", where,
              short(win.strip(), 260) + (" - aimed at AI shopping or research assistants" if ai else ""))
        found = True
    return found


def signals(clean, where, F, hidden=False):
    """Add findings for the patterns above. `clean` is the visible text (invisible characters already removed)."""
    t = clean[:2_000_000]
    if not steering(t, where, F, hidden=hidden):
        from .common import _fix_typos
        fixed = _fix_typos(t[:400_000])
        if fixed is not t[:400_000] and fixed != t[:400_000]:
            steering(fixed, where, F, " (misspelled)", hidden)
    for n, m in enumerate(VERIFY.finditer(t)):
        if n >= 200:
            break
        win = t[max(0, m.start() - 250): m.end() + 250]
        r = RUN_IT.search(win)
        if r:
            F.add("HIGH", "fake human check that asks to paste or run a command (ClickFix)", where,
                  short(win.strip(), 260) + " - real CAPTCHAs never ask for a keyboard shortcut, a terminal or a paste")
            break
    for n, m in enumerate(IMG_URL.finditer(t)):
        if n >= 500:
            break
        url = m.group(1) or m.group(2) or ""
        if not PLACEHOLDER.search(url):
            continue
        win = t[m.start(): m.end() + 260]
        if PRIVATE.search(win[len(m.group(0)):]) or PRIVATE.search(url):
            F.add("HIGH", "image or link URL that is to be filled with private data (exfiltration when rendered)", where,
                  short(win, 260) + " - rendering the image sends whatever is put into the URL to that server")
            break
    m = FORMULA_RUN.search(t)
    if m:
        F.add("HIGH", "spreadsheet formula that starts a program when the file is opened (DDE / cmd|)", where, short(t[m.start(): m.end() + 80], 200))
    else:
        m = FORMULA_FETCH.search(t)
        if m:
            F.add("MED", "spreadsheet formula that fetches a URL when the file is opened", where,
                  short(t[m.start(): m.end() + 120], 220) + " - formulas in a CSV run in the reader's spreadsheet program")
    m = DISGUISED.search(t)
    if m:
        F.add("MED", "file name with a disguised extension (looks like a document, runs as a program)", where, short(m.group(0).strip(), 160))
