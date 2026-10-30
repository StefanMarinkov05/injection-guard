"""LaTeX / BibTeX source (.tex .sty .cls .bib ...): what never reaches the PDF, and what runs at compile time.

The output is the source itself (an agent edits source), but every span that a reader of the compiled PDF never sees
is checked as hidden text: comments, \\iffalse / comment environments, white or phantom text, zero-size boxes,
PDF metadata, ActualText, hidden layers, attachments, glyph-to-Unicode remaps. Compile-time code execution and file
writes are reported separately - they matter for downloaded templates even without any prompt injection.
"""
import re
from .common import DIRECTIVE, IMPERSONATION, KEYWORDS, STRONG, check_text, hidden_task_signal, short, whitespace_stego

LATEX_EXT = {".tex", ".sty", ".cls", ".bib", ".ltx", ".dtx", ".ins", ".bbx", ".cbx", ".def", ".cfg", ".bst", ".clo", ".lbx"}


def looks_like_latex(text):
    return bool(re.search(r"\\(documentclass|begin\{document\}|usepackage|NeedsTeXFormat|ProvidesPackage|ProvidesClass)\b|^\s*@\w+\s*\{", text[:20000], re.M))


def _braced(s, i):
    """s[i] == '{' -> (content, index after the closing brace)."""
    depth, j = 0, i
    while j < len(s):
        c = s[j]
        if c == "\\":
            j += 2
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return s[i + 1:j], j + 1
        j += 1
    return s[i + 1:], len(s)


def _args(s, pos, n):
    """Read n braced arguments (skipping optional [..] and spaces) starting at pos."""
    out = []
    while len(out) < n and pos < len(s):
        while pos < len(s) and s[pos] in " \t\n":
            pos += 1
        if pos < len(s) and s[pos] == "[":
            k = s.find("]", pos)
            pos = k + 1 if k > 0 else pos + 1
            continue
        if pos < len(s) and s[pos] == "{":
            a, pos = _braced(s, pos)
            out.append(a)
        else:
            break
    return out, pos


def _line(src, i):
    return src.count("\n", 0, i) + 1


PACKAGE_EXT = (".sty", ".cls", ".dtx", ".def", ".clo", ".cfg", ".ins", ".bbx", ".cbx", ".lbx", ".bst")
_CODE = [False]  # set per file: package code (macros) rather than a document


def _hidden(F, kind, where, text, sev_plain="INFO", wordy_sev="MED", source_visible=False):
    if _CODE[0]:
        sev_plain = wordy_sev = "INFO"  # macro code legitimately uses phantoms, specials, dead branches
    """source_visible: the span is not printed, but whoever edits the source sees it (comments, \\iffalse)."""
    t = " ".join(text.split())
    if not t:
        return
    if STRONG.search(t) or KEYWORDS.search(t) or IMPERSONATION.search(t):
        F.add("HIGH", kind + " with AI-directed text", where, short(t, 300))
        check_text(t, where, F, hidden=True)
    elif DIRECTIVE.search(t):
        F.add("INFO" if source_visible else "MED", kind + " with a naming/notation/answer directive", where, short(t, 300))
    elif not source_visible and not _CODE[0] and hidden_task_signal(t):
        F.add("HIGH", kind + " that looks like part of the task (exercise words or formula symbols)", where, short(t, 300))
    elif len(re.findall(r"[A-Za-z]{3,}", t)) >= 4:
        F.add(wordy_sev, kind, where, short(t, 200))
    else:
        F.add(sev_plain, kind, where, short(t, 120))


WHITE = r"(white|White|bg|background|\[gray\]\{1\}|\[rgb\]\{1,\s*1,\s*1\}|\[RGB\]\{255,\s*255,\s*255\}|\[HTML\]\{FFFFFF\}|\[cmyk\]\{0,\s*0,\s*0,\s*0\})"


def scan_latex(src, F, name="tex"):
    _CODE[0] = name.lower().endswith(PACKAGE_EXT)
    # 1 comments (unescaped %), comment environments, \iffalse / \if0 blocks
    comments = []
    for m in re.finditer(r"(?<!\\)%(.*)", src):
        comments.append((m.start(), m.group(1)))
    ctext = "\n".join(c for _, c in comments)
    if comments:
        hits = [(i, c) for i, c in comments if STRONG.search(c) or KEYWORDS.search(c)]
        for i, c in hits[:10]:
            F.add("HIGH", "LaTeX comment with AI-directed text (never printed)", f"{name}:{_line(src, i)}", short(c, 300))
        joined = " ".join(c.strip() for _, c in comments)
        if not hits and STRONG.search(joined):
            F.add("HIGH", "LaTeX comments that together form an instruction to an AI", name, short(joined, 300))
        dirs = [(i, c) for i, c in comments if DIRECTIVE.search(c)]
        if dirs:  # author guidance is normal in templates; the source editor sees it - listed, not flagged
            F.add("INFO", "LaTeX comments with naming/notation directives (author guidance? check)", f"{name}:{_line(src, dirs[0][0])}",
                  short(" / ".join(c.strip() for _, c in dirs[:3]), 200))
        check_text(ctext, name + " comments", F, keywords=False)
        F.add("INFO", "LaTeX comments (not printed)", name, f"{len(comments)} comment(s)")
    for rx, kind in ((r"\\iffalse(.*?)\\fi\b", "\\iffalse block (never compiled)"),
                     (r"\\begin\{comment\}(.*?)\\end\{comment\}", "comment environment (never compiled)")):
        for m in re.finditer(rx, src, re.S):
            _hidden(F, kind, f"{name}:{_line(src, m.start())}", m.group(1), source_visible=True)
    # 2 invisible typesetting
    for m in re.finditer(r"\\textcolor\s*" + r"(\[[^\]]*\])?\{([^}]*)\}", src):
        col = (m.group(1) or "") + "{" + m.group(2) + "}"
        if re.fullmatch(r"(white|White)", m.group(2)) or re.search(r"\[gray\]\{1\}|\{1,\s*1,\s*1\}|\{255,\s*255,\s*255\}|\{FFFFFF\}|\{ffffff\}", col):
            a, _ = _args(src, m.end(), 1)
            _hidden(F, "white text (\\textcolor)", f"{name}:{_line(src, m.start())}", a[0] if a else "", "MED", "HIGH")
    for m in re.finditer(r"\{\s*\\color\s*(\{(white|White)\}|\[gray\]\{1\}|\[rgb\]\{1,\s*1,\s*1\}|\[RGB\]\{255,\s*255,\s*255\}|\[HTML\]\{[Ff]{6}\})", src):
        start = src.rfind("{", 0, m.start() + 1)
        body, _ = _braced(src, start)
        _hidden(F, "white text (\\color group)", f"{name}:{_line(src, m.start())}", re.sub(r"^\s*\\color\s*(\[[^\]]*\])?\{[^}]*\}", "", body), "MED", "HIGH")
    for m in re.finditer(r"\\(phantom|hphantom|vphantom)\s*\{", src):
        a, _ = _args(src, m.end() - 1, 1)
        _hidden(F, f"\\{m.group(1)} (takes space, prints nothing)", f"{name}:{_line(src, m.start())}", a[0] if a else "")
    for m in re.finditer(r"\\fontsize\s*\{\s*(0?\.\d+|0)\s*(pt)?\s*\}", src):
        F.add("MED", "microscopic font size (\\fontsize below 1 pt)", f"{name}:{_line(src, m.start())}", short(src[m.end():m.end() + 160], 160))
        check_text(src[m.end():m.end() + 2000], f"{name}:{_line(src, m.start())} after \\fontsize", F, hidden=True)
    for m in re.finditer(r"\\(scalebox|resizebox)\s*\{\s*(0(\.0+)?|0pt|0cm|0mm)\s*\}", src):
        a, _ = _args(src, m.end(), 2 if m.group(1) == "resizebox" else 1)
        _hidden(F, f"\\{m.group(1)} to zero size", f"{name}:{_line(src, m.start())}", a[-1] if a else "", "MED", "HIGH")
    for m in re.finditer(r"\\(raisebox|hspace\*?|vspace\*?|put|moveleft|moveright|lower|raise)\s*[\{(]\s*-?\s*(\d{3,}|\d+\s*(cm|in)\b)", src):
        val = re.findall(r"\d+", m.group(0))
        big = int(val[0]) if val else 0
        if ("cm" in m.group(0) and big >= 30) or ("in" in m.group(0) and big >= 12) or big >= 1000:
            F.add("MED", "content moved far off the page", f"{name}:{_line(src, m.start())}", short(src[m.start():m.start() + 200], 200))
            check_text(src[m.start():m.start() + 1500], f"{name}:{_line(src, m.start())} off-page", F, hidden=True)
    # 3 PDF-level hidden channels
    for m in re.finditer(r"\\BeginAccSupp\s*\{", src):
        a, _ = _args(src, m.end() - 1, 1)
        _hidden(F, "ActualText / accessibility replacement (\\BeginAccSupp)", f"{name}:{_line(src, m.start())}", a[0] if a else "", "MED", "HIGH")
    for rx, kind in ((r"\\pdfinfo\s*\{", "PDF Info dictionary (\\pdfinfo)"), (r"\\pdfcatalog\s*\{", "PDF catalog entries"),
                     (r"\\(pdfannot|pdfcomment|pdfmarkupcomment)\b[^{]*\{", "PDF annotation"),
                     (r"\\(pdfliteral|special)\s*\{", "raw PDF code")):
        for m in re.finditer(rx, src):
            a, _ = _args(src, m.end() - 1, 1)
            _hidden(F, kind, f"{name}:{_line(src, m.start())}", a[0] if a else "", "MED", "HIGH")
    for m in re.finditer(r"\\hypersetup\s*\{", src):
        body, _ = _braced(src, m.end() - 1)
        meta = " ".join(v for _, v in re.findall(r"pdf(keywords|subject|title|author|creator|producer|lang)\s*=\s*\{?([^,}]*)", body, re.I))
        if meta.strip():
            _hidden(F, "PDF metadata set by \\hypersetup (not printed)", f"{name}:{_line(src, m.start())}", meta)
    for m in re.finditer(r"\\pdfglyphtounicode\s*\{(\w+)\}\s*\{([0-9A-Fa-f]{4})\}", src):
        g, u = m.group(1), chr(int(m.group(2), 16))
        if len(g) == 1 and g.isalnum() and u.isalnum() and g != u:
            F.add("HIGH", "\\pdfglyphtounicode remap: the PDF will draw one letter and extract another", f"{name}:{_line(src, m.start())}", f"glyph {g!r} -> {u!r}")
    for m in re.finditer(r"\\begin\{ocg\}\s*(\[[^\]]*\])?\s*\{([^}]*)\}\s*\{[^}]*\}\s*\{\s*(0|off|false)\s*\}", src):
        end = src.find("\\end{ocg}", m.end())
        _hidden(F, "PDF layer switched off by default (ocg)", f"{name}:{_line(src, m.start())}", src[m.end():end if end > 0 else m.end() + 1500], "MED", "HIGH")
    for m in re.finditer(r"\\(embedfile|attachfile|textattachfile|noattachfile)\b", src):
        F.add("MED", "file embedded into the PDF", f"{name}:{_line(src, m.start())}", short(src[m.start():m.start() + 160], 160))
    # 4 compile-time code execution / file writes / remote input
    for rx, kind in ((r"(\\immediate\s*)?\\write\s*18", "shell command at compile time (\\write18)"),
                     (r"\\ShellEscape|\\shellesc", "shell command at compile time (shellesc)"),
                     (r"\\directlua\s*\{[^}]*(os\.execute|io\.popen|os\.remove|os\.rename|io\.open)", "Lua code that runs programs or touches files"),
                     (r"\\input\s*\|\s*\"|\\input\s*\{\s*\|", "\\input from a shell pipe"),
                     (r"\\openout|\\immediate\s*\\openout", "file written at compile time (\\openout)"),
                     (r"\\usepackage(\[[^\]]*\])?\{[^}]*\b(shellesc|bashful|pythontex|minted|sagetex)\b", "package that runs external programs")):
        for m in re.finditer(rx, src):
            sev = "MED" if kind.startswith(("package", "file written")) else "HIGH"
            F.add(sev, kind, f"{name}:{_line(src, m.start())}", short(src[m.start():m.start() + 200], 200) +
                  " - compile only without -shell-escape / --shell-escape, or not at all")
    for m in re.finditer(r"\\catcode\s*`?\\?.\s*=\s*\d+", src):
        if name.endswith((".tex", ".bib")):
            F.add("MED", "\\catcode change in a document (can make text mean something else)", f"{name}:{_line(src, m.start())}", m.group(0))
            break
    # 5 BibTeX: fields that are not printed by most styles
    if name.endswith(".bib") or re.search(r"^\s*@\w+\s*\{", src, re.M):
        for m in re.finditer(r"\b(note|annote|annotation|abstract|keywords|comment|howpublished|addendum)\s*=\s*[{\"]", src, re.I):
            a, _ = _args(src, m.end() - 1, 1) if src[m.end() - 1] == "{" else ([src[m.end():src.find('"', m.end())]], 0)
            val = a[0] if a else ""
            if STRONG.search(val) or KEYWORDS.search(val) or DIRECTIVE.search(val):
                F.add("HIGH", f"BibTeX field {m.group(1)} with AI-directed text or a directive", f"{name}:{_line(src, m.start())}", short(val, 300))
    # whole file: Unicode tricks, look-alikes, encodings, visible phrases, whitespace steganography
    whitespace_stego(src, name, F)
    check_text(src, name, F)
    return src
