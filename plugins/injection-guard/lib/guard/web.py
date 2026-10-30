"""HTML / XHTML / SVG sanitiser: keeps what a human sees, reports and removes everything hidden."""
import re
from html.parser import HTMLParser
from .common import DIRECTIVE, IMPERSONATION, KEYWORDS, SENTENCE, STRONG, check_text, decoded_variants, hidden_task_signal, short, whitespace_stego

VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr",
        "keygen", "command", "basefont", "frame", "isindex"}
DROP = {"script", "style", "noscript", "template", "iframe", "object", "frameset", "svg:script"}
META_TAGS = {"desc", "metadata"}  # SVG: read by screen readers / extractors, not drawn
BLOCK = {"p", "div", "section", "article", "header", "footer", "main", "aside", "nav", "li", "ul", "ol", "table", "tr",
         "h1", "h2", "h3", "h4", "h5", "h6", "pre", "blockquote", "figure", "figcaption", "dt", "dd", "dl", "form",
         "fieldset", "details", "summary", "br", "hr", "title", "text", "tspan", "body", "html"}
HIDE_CSS = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*(hidden|collapse)|opacity\s*:\s*0(\.0+)?\s*(;|$|!)|font-size\s*:\s*0(\.\d+)?(px|pt|em|rem|%)?\s*(;|$|!)"
    r"|font-size\s*:\s*0?\.[0-4]\d*(px|pt)|(max-)?(height|width)\s*:\s*[01](px)?\s*(;|$|!)|clip\s*:\s*rect\(\s*0|clip-path\s*:\s*(inset\(\s*50%|circle\(\s*0)"
    r"|text-indent\s*:\s*-\d{3,}|(left|top|right)\s*:\s*-\d{3,}(px|em|rem)|transform\s*:\s*scale\(\s*0(\.0+)?\s*\)"
    r"|color\s*:\s*transparent", re.I)
WHITE_CSS = re.compile(r"(^|[;\s])color\s*:\s*(#fff\b|#ffffff\b|white\b|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))", re.I)
TEXT_ATTRS = ("alt", "title", "aria-label", "aria-description", "placeholder", "content", "value", "label", "summary")


def css_hidden_selectors(css):
    """Return class names and ids that a <style> block hides (simple selectors only)."""
    cls, ids = set(), set()
    for sel, body in re.findall(r"([^{}]+)\{([^{}]*)\}", css):
        if HIDE_CSS.search(body):
            for part in sel.split(","):
                last = part.strip().split()[-1] if part.strip() else ""
                cls |= set(re.findall(r"\.([\w-]+)", last))
                ids |= set(re.findall(r"#([\w-]+)", last))
    return cls, ids


class Sanitizer(HTMLParser):
    def __init__(self, F, where, hidden_cls=(), hidden_ids=(), depth=0):
        super().__init__(convert_charrefs=True)
        self.depth = depth
        self.F, self.where = F, where
        self.hcls, self.hids = set(hidden_cls), set(hidden_ids)
        self.stack = []          # (tag, hidden_reason or None, white)
        self.out = []
        self.hidden = {}         # reason -> list of text
        self.comments = []
        self.title = []
        self.links = []

    def _reason(self, tag, a):
        if tag in DROP:
            return f"<{tag}>"
        if tag in META_TAGS:
            return f"<{tag}> (not drawn)"
        if tag == "head":
            return "<head>"
        if "hidden" in a or a.get("aria-hidden", "").lower() == "true":
            return "hidden attribute / aria-hidden"
        if tag == "input" and a.get("type", "").lower() == "hidden":
            return "hidden input"
        st = a.get("style", "")
        if st and HIDE_CSS.search(st):
            return "inline CSS: " + HIDE_CSS.search(st).group(0)
        for k in ("opacity", "fill-opacity"):
            if a.get(k, "").strip() in ("0", "0.0", "0%"):
                return f"{k}=0"
        if a.get("display", "") == "none" or a.get("visibility", "") == "hidden":
            return "SVG display/visibility attribute"
        if a.get("font-size", "").strip() in ("0", "0px", "0pt"):
            return "font-size 0"
        if a.get("fill", "").lower() == "none" and tag in ("text", "tspan"):
            return "SVG text with fill none"
        classes = set(a.get("class", "").split())
        if classes & self.hcls:
            return "CSS class " + ",".join(sorted(classes & self.hcls))
        if a.get("id") in self.hids:
            return "CSS id " + a.get("id")
        return None

    def _cur(self):
        for _, r, _ in reversed(self.stack):
            if r:
                return r
        return None

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        a = {k.lower(): (v or "") for k, v in attrs}
        reason = self._reason(tag, a)
        inherited = self._cur()
        hid = inherited or reason
        white = bool(WHITE_CSS.search(a.get("style", ""))) or any(w for _, _, w in self.stack)
        for k in TEXT_ATTRS:
            v = a.get(k, "")
            if len(v) > 3 and (STRONG.search(v) or KEYWORDS.search(v)):
                self.F.add("HIGH", f"attribute {k}= with AI-directed text", f"{self.where} <{tag}>", short(v, 300))
        for k, v in a.items():
            if "data:" in v[:600].lower() and k in ("src", "href", "data", "srcset", "poster", "style", "content", "xlink:href", "srcdoc"):
                data_uri(v, self.F, f"{self.where} <{tag} {k}>", self.depth)
            if k == "srcdoc" and v:
                self.F.add("MED", "iframe srcdoc (an embedded document)", f"{self.where} <{tag}>", short(v, 120))
                sanitize_html(v, self.F, self.where + " srcdoc", self.depth + 1)
            if k.startswith("data-") and len(v) > 20 and (STRONG.search(v) or KEYWORDS.search(v)):
                self.F.add("HIGH", f"data attribute {k} with AI-directed text", f"{self.where} <{tag}>", short(v, 300))
        if tag == "meta" and a.get("content") and (a.get("name") or a.get("property")):
            self.hidden.setdefault("<meta> content", []).append(f"{a.get('name') or a.get('property')}: {a['content']}")
        if not hid and tag == "img" and a.get("alt"):
            alt = a["alt"]
            self.out.append(f" [image: {short(alt, 100)}] ")
        if not hid and tag == "a" and a.get("href", "").startswith(("http://", "https://")):
            self.links.append(a["href"])
        if tag in BLOCK and not hid:
            self.out.append("\n")
        if tag not in VOID:
            self.stack.append((tag, reason, white))

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        tag = tag.lower()
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                if tag == "a" and not self._cur() and self.links:
                    href = self.links.pop()
                    self.out.append(f" <{href}>")
                del self.stack[i:]
                break
        if tag in BLOCK and not self._cur():
            self.out.append("\n")

    def handle_data(self, data):
        if not data.strip():
            if not self._cur():
                self.out.append(" ")
            return
        r = self._cur()
        tags = [t for t, _, _ in self.stack]
        if "title" in tags and "svg" not in tags:
            self.title.append(data.strip())
            return
        if r:
            self.hidden.setdefault(r, []).append(data.strip())
            return
        if any(w for _, _, w in self.stack) and (STRONG.search(data) or KEYWORDS.search(data)):
            self.F.add("HIGH", "white text (color #fff) with AI-directed words", self.where, short(data, 300))
        self.out.append(data)

    def handle_comment(self, data):
        if data.strip():
            self.comments.append(data.strip())


DOM_WRITE = re.compile(r"document\.write|innerHTML|outerHTML|insertAdjacentHTML|textContent\s*=|innerText\s*=|createTextNode|"
                       r"\.append(Child)?\(|\.prepend\(|\.replaceWith\(|\.html\(", re.I)
DECODE = re.compile(r"\batob\s*\(|fromCharCode|crypto\.subtle|\.decrypt\s*\(|\beval\s*\(|new Function\s*\(|\bunescape\s*\(|"
                    r"decodeURIComponent\s*\(|TextDecoder|CryptoJS|AES\.decrypt|pako|inflate", re.I)
FINGERPRINT = re.compile(r"navigator\.(webdriver|userAgent|languages?|platform|plugins|hardwareConcurrency)|"
                         r"\bnew Date\b|Date\.now|Intl\.DateTimeFormat|timeZone|screen\.(width|height)|document\.referrer|"
                         r"HeadlessChrome|puppeteer|playwright|selenium|__nightmare|callPhantom", re.I)
JS_STR = re.compile(r"\"((?:[^\"\\\n]|\\.){20,})\"|'((?:[^'\\\n]|\\.){20,})'|`([^`]{20,})`")


def js_checks(js, F, where):
    """Live content: what a browser (and a browser-based agent) sees is produced at runtime."""
    w, d, fp = DOM_WRITE.search(js), DECODE.search(js), FINGERPRINT.findall(js)
    if w and d:
        F.add("HIGH" if fp else "MED", "script decodes/decrypts data and writes it into the page (obfuscated live content)", where,
              f"{w.group(0)} + {d.group(0)}" + (f" + visitor checks {sorted(set(fp))[:5]}" if fp else "") +
              " - a static scan cannot see the result; if a browser agent opens it, its snapshot is scanned by the hook")
    elif w and fp:
        F.add("MED", "page content depends on the visitor (user agent / automation / time checks) - possible cloaking", where,
              f"{w.group(0)} + {sorted(set(fp))[:6]}")
    elif w:
        F.add("INFO", "script writes page content at runtime", where, w.group(0))
    for m in JS_STR.finditer(js[:5_000_000]):
        lit = next(g for g in m.groups() if g)
        if STRONG.search(lit) or KEYWORDS.search(lit):
            F.add("HIGH", "AI-directed text in a script string", where, short(lit, 300))
        elif len(lit) >= 40:
            decoded_variants(lit, where + " script string", F)


def data_uri(v, F, where, depth):
    """data: URIs carry whole documents (SVG, HTML, text) inside an attribute - decode and scan them."""
    import base64, urllib.parse
    for m in re.finditer(r"data:([\w.+-]+/[\w.+-]+)?((?:;[\w-]+=[\w-]+)*)(;base64)?,([^\s\"')]+)", v, re.I):
        mime, b64, payload = (m.group(1) or "text/plain").lower(), m.group(3), m.group(4)
        try:
            raw = base64.b64decode(payload + "=" * (-len(payload) % 4)) if b64 else urllib.parse.unquote_to_bytes(payload)
        except Exception:
            continue
        if not any(t in mime for t in ("text", "svg", "xml", "html", "json", "javascript")):
            continue
        doc = raw[:5_000_000].decode("utf-8", "replace")
        F.add("MED", f"embedded document in a data: URI ({mime})", where, short(doc, 120))
        if depth < 3 and any(t in mime for t in ("svg", "html", "xml")):
            sanitize_html(doc, F, where + " (data URI)", depth + 1)
            text_only = re.sub(r"<[^>]+>", " ", doc)
            if STRONG.search(text_only) or KEYWORDS.search(text_only) or DIRECTIVE.search(text_only):
                F.add("HIGH", "data: URI document with AI-directed text or a directive", where, short(text_only, 300))
        else:
            check_text(doc, where + " (data URI)", F, hidden=True)


DIR_RX = re.compile(r"<(bdo)\b[^>]*>([^<]{3,})|<\w+\b[^>]*(dir\s*=\s*[\"']?rtl|direction\s*:\s*rtl|unicode-bidi\s*:\s*(bidi-override|isolate-override))[^>]*>([^<]{3,})", re.I)
MIRROR_RX = re.compile(r"transform\s*:\s*[^;\"']*(scale[XY]?\(\s*-1|rotate[XY]?\(\s*180)", re.I)


def direction_tricks(src, F, where):
    """Text whose display order or glyphs differ from its DOM order: humans read one thing, extractors another."""
    for m in DIR_RX.finditer(src[:5_000_000]):
        t = (m.group(2) or m.group(5) or "").strip()
        if re.search(r"[A-Za-z]{2,}", t):
            F.add("MED", "text direction override on Latin text (displayed reversed relative to the DOM)", where,
                  f"DOM: {short(t, 100)!r} / displayed: {short(t[::-1], 100)!r}")
            check_text(t[::-1], where + " (as displayed)", F)
    css = " ".join(re.findall(r"<style[^>]*>(.*?)</style>", src, re.S | re.I)) + " " + " ".join(re.findall(r"style\s*=\s*[\"']([^\"']*)", src))
    if re.search(r"unicode-bidi\s*:\s*(bidi-override|isolate-override)", css, re.I):
        F.add("MED", "CSS bidi override (display order differs from text order)", where, "")
    if MIRROR_RX.search(css):
        F.add("MED", "mirrored or upside-down text via CSS transform", where, MIRROR_RX.search(css).group(0)[:80])
    if re.search(r"@font-face", css, re.I):
        F.add("INFO", "custom web font (@font-face): a font can draw different letters than the text says", where, "")


def sanitize_html(src, F, where="html", depth=0):
    whitespace_stego(src, where, F)
    direction_tricks(src, F, where)
    css = " ".join(re.findall(r"<style[^>]*>(.*?)</style>", src, re.S | re.I))
    for q, txt in re.findall(r"content\s*:\s*([\"'])(.*?)\1", css, re.S):  # CSS-generated text: shown, but not in the DOM text
        if len(txt) > 3:
            check_text(txt, where + " CSS content", F, hidden=True)
    cls, ids = css_hidden_selectors(css)
    p = Sanitizer(F, where, cls, ids, depth)
    try:
        p.feed(src)
        p.close()
    except Exception as e:
        F.add("MED", "HTML parse error (output may be incomplete)", where, str(e)[:120])
    scripts = " ".join(p.hidden.get("<script>", []))
    if scripts:
        js_checks(scripts, F, where)
    total_hidden = 0
    for reason, chunks in p.hidden.items():
        text = " ".join(chunks)
        if reason in ("<script>", "<style>"):
            if STRONG.search(text):
                F.add("HIGH", f"AI-directed instruction inside {reason}", where, short(STRONG.search(text).group(0), 200))
            continue
        total_hidden += len(text)
        if STRONG.search(text) or KEYWORDS.search(text) or IMPERSONATION.search(text) or (reason not in ("<meta> content", "<head>", "<noscript>") and (DIRECTIVE.search(text) or hidden_task_signal(text))):
            F.add("HIGH", f"hidden text ({reason})", where, short(text, 400))
            check_text(text, f"{where} hidden ({reason})", F, hidden=True)
        elif (len(text) > 200 or SENTENCE.search(text)) and reason not in ("<meta> content", "<head>", "<noscript>"):
            F.add("MED", f"hidden text ({reason})", where, short(text, 200))
    if total_hidden:
        F.add("INFO", "hidden elements removed", where, f"{total_hidden} characters of hidden text, {len(p.hidden)} kind(s)")
    for c in p.comments:
        if STRONG.search(c) or KEYWORDS.search(c):
            F.add("HIGH", "HTML comment with AI-directed text", where, short(c, 400))
    if p.comments:
        F.add("INFO", "HTML comments removed", where, f"{len(p.comments)} comment(s)")
    # an instruction split over several hiding places (comment + hidden span + attribute ...)
    pooled = " ".join(" ".join(v) for k, v in p.hidden.items() if k not in ("<script>", "<style>", "<head>")) + " " + " ".join(p.comments)
    if STRONG.search(pooled) or DIRECTIVE.search(pooled):
        F.add("HIGH", "hidden fragments that together form an instruction or directive", where, short(pooled, 300))
    text = "".join(p.out)
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    text = re.sub(r" *\n *", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    title = " ".join(p.title)
    check_text(text, where, F)
    if title:
        check_text(title, where + " <title>", F)
        text = f"# {title}\n\n{text}"
    return text
