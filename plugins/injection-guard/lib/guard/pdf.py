"""PDF checks (structure, metadata, attachments, text layer, render diff, images) and visible-text extraction.

Derived from pdf_trapscan.py (TCS project). Needs poppler-utils and Pillow.
"""
import html, os, re, subprocess, tempfile, unicodedata, zlib
from PIL import Image, ImageChops, ImageFilter
from .common import hidden_instruction
from .common import DIRECTIVE, INVISIBLE, KEYWORDS, STRONG, check_text, decoded_variants, hidden_task_signal, short

CROP = ["-x", "-4000", "-y", "-4000", "-W", "12000", "-H", "12000"]  # pdftotext drops off-page text otherwise
STR = rb"(\((?:\\.|[^\\)])*\)|<[0-9A-Fa-f\s]*>)"


def run(cmd, timeout=300):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout).stdout
    except Exception:
        return ""


def _texty(b):
    sample = b[:4096]
    return bool(sample) and sum(1 for c in sample if c < 9 or 13 < c < 32 or c > 126) <= 0.1 * len(sample)


def all_streams(data):
    """The file with stream bodies blanked out (objects, dictionaries, comments), then every stream:
    decompressed, or raw if it is uncompressed text. Compressed bytes are never searched as if they were text."""
    yield re.sub(rb"(stream\r?\n).*?(endstream)", rb"\1\2", data, flags=re.S)
    for m in re.finditer(rb"stream\r?\n", data):
        start = m.end()
        end = data.find(b"endstream", start)
        if end < 0:
            continue
        raw = data[start:end]
        done = False
        for cand in (raw, raw.rstrip(b"\r\n")):
            try:
                yield zlib.decompress(cand)
                done = True
                break
            except Exception:
                try:
                    out = zlib.decompressobj().decompress(cand)
                    if out:
                        yield out
                        done = True
                        break
                except Exception:
                    pass
        if not done and _texty(raw):
            yield raw  # uncompressed content stream, XMP packet, CMap ...


def pdf_string(tok):
    if tok.startswith(b"<"):
        h = re.sub(rb"\s", b"", tok[1:-1])
        if len(h) % 2:
            h += b"0"
        b = bytes.fromhex(h.decode())
    else:
        b = tok[1:-1]
        b = re.sub(rb"\\([0-7]{1,3})", lambda m: bytes([int(m.group(1), 8) & 255]), b)
        b = re.sub(rb"\\(.)", lambda m: {b"n": b"\n", b"r": b"\r", b"t": b"\t"}.get(m.group(1), m.group(1)), b)
    if b.startswith(b"\xfe\xff"):
        return b[2:].decode("utf-16-be", "replace")
    return b.decode("latin1")


def structural(data, F, replacements, kw_strings):
    all_strings, actual = [], []
    for idx, b in enumerate(all_streams(data)):
        if idx and len(b) > 4096:
            sample = b[:4096]
            if sum(1 for c in sample if c < 9 or 13 < c < 32 or c > 126) > 0.25 * len(sample):
                for r in re.findall(rb"[\x20-\x7e]{24,}", b[:20_000_000])[:2000]:
                    t = r.decode("latin1")
                    if len(re.findall(r"[A-Za-z]{3,}", t)) >= 3 and sum(c.isalpha() or c == " " for c in t) > 0.75 * len(t):
                        all_strings.append(t)
                continue  # binary image/font data: only printable runs inside it are checked
        for key, label in ((rb"/ActualText\s*", "ActualText replacement text (what extractors read instead of the drawing)"),
                           (rb"/Alt\s*", "Alt text"), (rb"/E\s*", "/E expansion text")):
            for m in re.finditer(key + STR, b):
                s = pdf_string(m.group(1))
                if label.startswith("ActualText"):
                    actual.append(s)  # judged in scan_pdf: normal when it repeats the visible text
                    continue
                if len(s.strip()) > 3:
                    strong = KEYWORDS.search(s) or STRONG.search(s) or len(s) > 40
                    F.add("HIGH" if strong else "MED", label, "structure", short(s, 400))
                    if strong:
                        replacements.append(s)
        if re.search(rb"/ReversedChars\s+B[DM]C", b):
            F.add("MED", "ReversedChars marked content: extractors reverse this text (right-to-left handling)", "content stream", "")
        if re.search(rb"/WMode\s+1\b", b):
            F.add("MED", "vertical writing mode font (/WMode 1): reading order may differ from what is seen", "font", "")
        if re.search(rb"(^|[\s\]])[37]\s+Tr\b", b):
            F.add("HIGH", "invisible text render mode (3 Tr / 7 Tr)", "content stream", "text drawn without fill or stroke")
        for m in re.finditer(rb"([0-9]*\.?[0-9]+)\s+Tf\b", b):
            try:
                if 0 < float(m.group(1)) < 0.5:
                    F.add("MED", "microscopic font size in Tf", "content stream", m.group(0).decode())
            except ValueError:
                pass
        if b"/OCProperties" in b:
            off = re.search(rb"/OFF\s*(\[\s*[^\]\s][^\]]*\]|\d+\s+\d+\s+R)", b)
            F.add("HIGH" if off else "MED", "optional content layers (OCG)", "catalog",
                  "layer(s) switched OFF by default - hidden on screen, present in the file" if off else "layers present")
        for m in re.finditer(STR, b):
            tok = m.group(1)
            if len(tok) < 12:
                continue
            try:
                st = pdf_string(tok)
            except Exception:
                continue
            all_strings.append(st)
        for m in re.finditer(rb"/Subtype\s*/(Text|FreeText|Popup|FileAttachment|Widget|Square|Highlight|Squiggly|StrikeOut|Underline|Ink|Stamp|Caret)\b", b):
            ctx = b[max(0, m.start() - 600): m.end() + 600]
            cont = re.search(rb"/Contents\s*" + STR, ctx)
            txt = pdf_string(cont.group(1)) if cont else ""
            F.add("HIGH" if (KEYWORDS.search(txt) or STRONG.search(txt) or DIRECTIVE.search(txt)) else "MED", "annotation /" + m.group(1).decode(),
                  "annotations", short(txt) or "(no text)")
        if b"/EmbeddedFile" in b:
            F.add("MED", "embedded file(s)", "attachments", "see attachment findings")
        js = re.search(rb"/(JavaScript|JS|Launch|SubmitForm|ImportData)\b", b)
        if js:
            F.add("MED", "JavaScript / launch / form actions", "catalog", js.group(0).decode())
        for pkt in re.findall(rb"<x:xmpmeta.*?</x:xmpmeta>|<rdf:RDF.*?</rdf:RDF>", b, re.S)[:20]:
            t = re.sub(r"<[^>]+>", " ", pkt.decode("utf-8", "replace"))
            if KEYWORDS.search(t) or STRONG.search(t) or DIRECTIVE.search(t):
                F.add("HIGH", "XMP metadata with AI-directed text or directives", "metadata", short(t))
        if b"begincmap" in b:
            F._cmap_id = getattr(F, "_cmap_id", 0) + 1
            targets = {}
            for blk in re.findall(rb"beginbfchar(.*?)endbfchar", b, re.S):
                for src, dst in re.findall(rb"<([0-9A-Fa-f]{2,4})>\s*<([0-9A-Fa-f]{4,8})>", blk):
                    _tounicode(F, int(src, 16), dst, len(src) == 2)
                    if len(dst) == 4:
                        ch = chr(int(dst, 16))
                        if ch.isascii() and ch.isalnum():
                            targets.setdefault(ch, set()).add(src)
            dups = sorted(ch for ch, srcs in targets.items() if len(srcs) > 1)
            if dups:  # two different glyphs that both claim to be the same letter: one of them may draw something else
                F.add("INFO", "several glyphs extract as the same letter or digit (normal for math fonts; the OCR check tests for swaps)", "font",
                      ", ".join(f"{c!r} <- {len(targets[c])} glyphs" for c in dups[:10]) + " - compare the page image (OCR check)")
            for blk in re.findall(rb"beginbfrange(.*?)endbfrange", b, re.S):
                for a0, a1, dst in re.findall(rb"<([0-9A-Fa-f]{2,4})>\s*<([0-9A-Fa-f]{2,4})>\s*<([0-9A-Fa-f]{4})>", blk):
                    a0, a1, d0 = int(a0, 16), int(a1, 16), int(dst, 16)
                    for c in range(a0, min(a1, a0 + 512) + 1):
                        _tounicode(F, c, b"%04X" % (d0 + c - a0), a1 < 256)

    F.actualtext = actual
    # one regex pass over all string objects (thousands of separate searches are slow)
    # PDF names (/Name#20with#20spaces) and % comments: invisible to viewers, read by anything that dumps the file
    blank = re.sub(rb"(stream\r?\n).*?(endstream)", rb"\1\2", data[:60_000_000], flags=re.S)  # never compressed bytes
    for m in re.finditer(rb"/([^\s/\[\]<>(){}%]{20,})", blank):
        try:
            nm = re.sub(rb"#([0-9A-Fa-f]{2})", lambda x: bytes([int(x.group(1), 16)]), m.group(1)).decode("latin1")
        except Exception:
            continue
        sp = re.sub(r"[_\-]+", " ", nm)
        if sum(c.isascii() and (c.isalnum() or c in " .,:;'") for c in sp) < 0.9 * len(sp):
            continue
        if hidden_instruction(sp) or DIRECTIVE.search(sp):
            F.add("HIGH", "PDF name with AI-directed text or a directive", "structure", short(sp, 300))
    comments = [c.decode("latin1") for c in re.findall(rb"(?m)^%(?!PDF-|%EOF)([^\r\n]{8,})", blank)]
    comments = [c for c in comments if sum(ch.isprintable() for ch in c) > 0.9 * len(c)]
    if comments:
        ctext = "\n".join(comments)
        if hidden_instruction(ctext) or DIRECTIVE.search(ctext):
            F.add("HIGH", "PDF comment with AI-directed text or a directive (not displayed, read by raw-file readers)", "structure", short(ctext, 300))
            check_text(ctext, "PDF comments", F, hidden=True)
    # raw (not compressed) streams that are not page content: images (JPEG with EXIF/XMP), fonts, embedded files
    for m in re.finditer(rb"stream\r?\n", data):
        end = data.find(b"endstream", m.end())
        body = data[m.end(): end if end > 0 else m.end()][:20_000_000]
        if b" Tj" in body or b"TJ" in body:
            continue
        try:
            zlib.decompressobj().decompress(body[:4096])
            continue  # compressed: handled by all_streams
        except Exception:
            pass
        for r in re.findall(rb"[\x20-\x7e]{24,}", body)[:500]:
            t = r.decode("latin1")
            if len(re.findall(r"[A-Za-z]{3,}", t)) >= 3 and sum(c.isalpha() or c == " " for c in t) > 0.75 * len(t):
                all_strings.append(t)  # text-like runs only (EXIF/XMP/comments), not random bytes
    uniq = list(dict.fromkeys(x.replace("\n", " ") for x in all_strings))
    joined = "\n".join(uniq).replace("_", " ")  # same length; "name_states" must match like "name states"
    starts, pos = [], 0
    for u in uniq:
        starts.append(pos)
        pos += len(u) + 1
    import bisect
    for rx, strong in ((STRONG, True), (KEYWORDS, False), (DIRECTIVE, False)):
        hit = set()
        for m in rx.finditer(joined):
            hit.add(bisect.bisect_right(starts, m.start()) - 1)
        for i in sorted(hit):
            if strong:
                F.add("HIGH", "PDF string object with AI-directed text", "structure", short(uniq[i], 400))
            elif sum(c.isascii() and (c.isalnum() or c in " .,;:!?'-()") for c in uniq[i]) >= 0.8 * len(uniq[i]):
                kw_strings.append(uniq[i])  # decided later: HIGH unless it is part of the visible page text
    longs = [u for u in uniq if len(u) >= 40]
    if longs:
        decoded_variants("\n".join(longs)[:2_000_000], "PDF string objects", F)

def _tounicode(F, src, dst_hex, simple):
    try:
        dst = bytes.fromhex(dst_hex.decode()).decode("utf-16-be")
    except Exception:
        return
    if dst == "\u200c":
        F.add("INFO", "font maps a glyph to U+200C (pdfTeX compound-word mark, normal)", "font", "use in text is caught by the text-layer check")
    elif INVISIBLE.search(dst):
        F.add("HIGH", "font maps glyphs to invisible Unicode (zero-width / bidi / tag characters)", "font",
              "extracted text contains characters a human never sees: " + " ".join(f"U+{ord(c):04X}" for c in dst))
    if simple and len(dst) == 1 and src < 128 and chr(src).isalnum() and dst.isascii() and dst.isalnum() and chr(src) != dst:
        if not hasattr(F, "remaps"):
            F.remaps = []
        F.remaps.append((getattr(F, "_cmap_id", 0), chr(src), dst))  # judged in scan_pdf (needs the text layer)


def info_and_attachments(path, F):
    meta = run(["pdfinfo", path])
    for line in meta.splitlines():
        k, _, v = line.partition(":")
        if k.strip() in ("Title", "Subject", "Keywords", "Author", "Creator", "Producer") and (KEYWORDS.search(v) or STRONG.search(v) or DIRECTIVE.search(v)):
            F.add("HIGH", "document info field " + k.strip(), "metadata", short(v))
    lst = run(["pdfdetach", "-list", path])
    names = [l.split(":", 1)[1].strip() for l in lst.splitlines()[1:] if ":" in l]
    if names:
        F.add("MED", "attachment names", "attachments", ", ".join(names))
        spaced = re.sub(r"[_\-.]+", " ", " / ".join(names))
        if hidden_instruction(spaced) or DIRECTIVE.search(spaced) or re.search(r"\b(AI|LLM|KI)\b", spaced) \
                or re.search(r"(hidden|inject|trap|canary|decoy|llm|gpt|claude|prompt|pdftotext|fingerprint|watermark)", spaced, re.I):
            F.add("HIGH", "attachment name addressed to an AI or with a directive", "attachments", short(spaced, 200))
        with tempfile.TemporaryDirectory() as td:
            subprocess.run(["pdfdetach", "-saveall", "-o", td, path], capture_output=True, timeout=120)
            for fn in os.listdir(td):
                try:
                    t = open(os.path.join(td, fn), "rb").read(50000).decode("utf-8", "replace")
                except Exception:
                    continue
                if KEYWORDS.search(t) or STRONG.search(t) or DIRECTIVE.search(t):
                    F.add("HIGH", "attachment content with AI-directed text or directives", fn, short(t))


def page_sizes(path):
    """Page sizes as displayed: pdftotext/pdftoppm work in the rotated view, pdfinfo reports the unrotated size."""
    info = run(["pdfinfo", "-f", "1", "-l", "99999", path])
    sizes = [(float(a), float(b)) for a, b in re.findall(r"Page\s+\d+ size:\s+([\d.]+) x ([\d.]+)", info)]
    rots = [int(r) % 360 for r in re.findall(r"Page\s+\d+ rot:\s+(-?\d+)", info)]
    return [(h, w) if i < len(rots) and rots[i] in (90, 270) else (w, h) for i, (w, h) in enumerate(sizes)]


def text_layer(path, F, sizes):
    txt = run(["pdftotext", "-layout", "-cropbox"] + CROP + [path, "-"])  # CropBox = what viewers show
    for i, big in enumerate(txt.split("\f"), 1):
        if i > len(sizes):
            break
        w, h = (str(int(v) + 1) for v in sizes[i - 1])
        exact = run(["pdftotext", "-layout", "-cropbox", "-f", str(i), "-l", str(i), "-x", "0", "-y", "0", "-W", w, "-H", h, path, "-"])
        joined = "".join(exact.split())
        extra = [t for t in big.split() if t not in joined]
        if extra:
            ex = " ".join(extra)
            F.add("HIGH" if (KEYWORDS.search(ex) or STRONG.search(ex) or len(extra) > 25) else "MED",
                  "text outside the visible page (only found with an enlarged crop box)", f"p.{i}", short(ex, 400))
    for i, page in enumerate(txt.split("\f"), 1):
        check_text(page, f"p.{i} text layer", F)
        spaced = re.findall(r"\b(?:\w ){3,}\w\b", page)
        if spaced:
            F.add("MED", "spaced-out letters (spacing obfuscation?)", f"p.{i}", short(", ".join(spaced[:5])))
    return txt


WORD = re.compile(r'<word xMin="([\d.-]+)" yMin="([\d.-]+)" xMax="([\d.-]+)" yMax="([\d.-]+)">(.*?)</word>')


def render_and_visible(path, F, sizes, dpi=100, max_pages=None, image_dir=None):
    """Render pages, flag text-layer words that are blank/off-page/microscopic, return visible text only."""
    bbox = run(["pdftotext", "-bbox-layout", "-cropbox"] + ([] if not max_pages else ["-l", str(max_pages)]) + [path, "-"])
    pages = re.findall(r"<page width=\"[\d.]+\" height=\"[\d.]+\">(.*?)</page>", bbox, re.S)
    out_pages = []
    with tempfile.TemporaryDirectory() as td:
        cmd = ["pdftoppm", "-r", str(dpi), "-gray", "-png", "-cropbox"] + ([] if not max_pages else ["-l", str(max_pages)]) + [path, os.path.join(td, "p")]
        subprocess.run(cmd, capture_output=True, timeout=1800)
        imgs = sorted((f for f in os.listdir(td) if f.endswith(".png")), key=lambda f: int(re.findall(r"\d+", f)[-1]))
        for idx, body in enumerate(pages):
            pw, ph = sizes[idx] if idx < len(sizes) else (595.0, 842.0)
            p = f"p.{idx + 1}"
            im = Image.open(os.path.join(td, imgs[idx])).convert("L") if idx < len(imgs) else None
            sx, sy = (im.width / pw, im.height / ph) if im else (1, 1)
            hidden, offpage, tiny, lines_out, overlay = [], [], [], [], []
            for block in re.findall(r"<block[^>]*>(.*?)</block>", body, re.S):
                blines = []
                for line in re.findall(r"<line[^>]*>(.*?)</line>", block, re.S):
                    vis = []
                    for x0, y0, x1, y1, w in WORD.findall(line):
                        x0, y0, x1, y1 = map(float, (x0, y0, x1, y1))
                        w = html.unescape(w)
                        if not w.strip():
                            continue
                        if x1 < 0 or y1 < 0 or x0 > pw or y0 > ph:
                            offpage.append(w); continue
                        if (y1 - y0) < 1.5:
                            tiny.append(w); continue
                        if im is not None:
                            X0, Y0 = max(0, int(x0 * sx)), max(0, int(y0 * sy))
                            X1, Y1 = min(im.width, int(x1 * sx) + 1), min(im.height, int(y1 * sy) + 1)
                            lo, hi = im.crop((X0, Y0, X1, Y1)).getextrema() if (X1 > X0 and Y1 > Y0) else (255, 255)
                            if lo >= 200 or hi - lo < 40:  # no dark ink, or no contrast (same colour as the background)
                                if len(w) == 1 and (x1 - x0) < 0.5:
                                    overlay.append(w)  # zero-width single glyph: overlay symbols such as LaTeX \not
                                    vis.append(w); continue
                                if any(ch.isalnum() for ch in w):
                                    hidden.append(w); continue
                        vis.append(w)
                    if vis:
                        blines.append(" ".join(vis))
                if blines:
                    lines_out.append("\n".join(blines))
            out_pages.append(f"[page {idx + 1}]\n" + "\n\n".join(lines_out))
            if overlay:
                F.add("INFO", "zero-width single glyphs (overlay symbols such as LaTeX \\not)", p, " ".join(overlay[:20]))
            for words, kind in ((hidden, "text in text layer but blank on the rendered page"),
                                (offpage, "text outside the visible page"), (tiny, "microscopic text (< 1.5 pt high)")):
                if words:
                    joined = " ".join(words)
                    sev = "HIGH" if (len(words) >= 3 or KEYWORDS.search(joined) or STRONG.search(joined) or len(joined) > 40) else "MED"
                    F.add(sev, kind, p, short(joined, 400))
                    check_text(joined, p + " hidden text", F, hidden=True)
            if im is not None:
                # faint ink: light pixel (225-252), no dark pixel within 7x7 (not an antialiasing halo of normal text)
                # and 3-30 levels darker than its 9x9 median (uniformly light boxes do not count).
                # The cheap box-blur pre-check skips the slow rank filters on ordinary text pages.
                m1 = im.point(lambda v: 255 if 225 <= v <= 252 else 0)
                pre = im.point(lambda v: 255 if v < 225 else 0).filter(ImageFilter.BoxBlur(3)).point(lambda v: 255 if v == 0 else 0)
                faint = 0
                if ImageChops.multiply(m1, pre).histogram()[255] > 40:
                    m2 = im.filter(ImageFilter.MinFilter(7)).point(lambda v: 255 if v >= 225 else 0)
                    m3 = ImageChops.subtract(im.filter(ImageFilter.MedianFilter(9)), im).point(lambda v: 255 if 3 <= v <= 30 else 0)
                    faint = ImageChops.multiply(ImageChops.multiply(m1, m2), m3).histogram()[255]
                if faint > 40:
                    F.add("HIGH" if faint > 2500 else "MED", "faint near-white ink (low-contrast text or image)", p,
                          f"{faint} faint pixels at {dpi} dpi - view the page image with contrast enhanced")
        if len(pages) < len(sizes):
            F.add("INFO", "render checks limited", "document", f"first {len(pages)} of {len(sizes)} pages checked (--max-pages)")
    if image_dir:
        os.makedirs(image_dir, exist_ok=True)
        cmd = ["pdftoppm", "-r", "110", "-png", "-cropbox"] + ([] if not max_pages else ["-l", str(max_pages)]) + [path, os.path.join(image_dir, "page")]
        subprocess.run(cmd, capture_output=True, timeout=1800)
    return "\n\n".join(out_pages)


def images(path, F):
    with tempfile.TemporaryDirectory() as td:
        subprocess.run(["pdfimages", path, os.path.join(td, "i")], capture_output=True, timeout=600)  # raw PPM/PBM: fast
        for fn in sorted(os.listdir(td))[:400]:
            try:
                im = Image.open(os.path.join(td, fn)).convert("L")
            except Exception:
                continue
            hist = im.histogram()
            n = im.width * im.height
            bg = max(range(256), key=lambda v: hist[v])
            near = sum(hist[v] for v in range(max(0, bg - 25), min(256, bg + 26)) if v != bg)
            far = n - hist[bg] - near
            if near > 50 and far < 0.001 * n:
                F.add("MED", "embedded image with faint content close to its background (text in image?)", fn,
                      f"{near} faint pixels, background {bg}")


def _alnum(t):
    return "".join(c for c in unicodedata.normalize("NFKC", t).lower() if c.isalnum())


def _judge_actualtext(F, visible):
    # visible = text of the drawn glyphs from a reader that ignores ActualText (MuPDF); "" if unavailable -> all count
    """ActualText that repeats the visible text is accessibility markup (PowerPoint/Word exports do it for every run).
    ActualText that says something the page does not show is the Sheet 2 trick."""
    actual = list(dict.fromkeys(getattr(F, "actualtext", [])))
    vflat = _alnum(visible)
    vtok = set(re.findall(r"\w+", unicodedata.normalize("NFKC", visible).lower()))
    odd, same, repl = [], 0, []
    for st in actual:
        n = _alnum(st)
        toks = re.findall(r"\w+", unicodedata.normalize("NFKC", st).lower())
        if not n:
            continue
        if (len(n) >= 6 and n in vflat) or (toks and set(toks) <= vtok):
            same += 1
            continue
        odd.append(st)
        if len(st.strip()) > 3 or hidden_task_signal(st):
            strong = KEYWORDS.search(st) or STRONG.search(st) or DIRECTIVE.search(st) or len(st) > 40 or hidden_task_signal(st)
            F.add("HIGH" if strong else "MED", "ActualText replacement text (what extractors read instead of the drawing)", "structure", short(st, 400))
            if strong:
                repl.append(st)
    if same:
        F.add("INFO", "ActualText that repeats the visible text (accessibility markup)", "structure", f"{same} span(s)")
    if len(odd) > 1:  # an instruction split into many short fragments (one per glyph or word)
        joined = "".join(odd)
        if hidden_instruction(joined) or DIRECTIVE.search(joined) or len(joined) > 60:
            F.add("HIGH", "ActualText fragments that together form a hidden text", "structure", short(joined, 400))
            check_text(joined, "joined ActualText", F, hidden=True)
    return repl


def _judge_remaps(F, layer):
    """A code whose glyph is 'a' but extracts as 'b'. Subset fonts with their own encodings remap many codes - normal.
    Evidence of tampering: text-layer words that are misspelled but become real words when the remap is undone."""
    remaps = getattr(F, "remaps", [])
    if not remaps:
        return
    from .ocr import dictionary
    D = dictionary()
    words = set(re.findall(r"[a-z]{4,}", layer.lower()))
    blocks = {}
    for bid, src, dst in remaps:
        blocks.setdefault(bid, {})[dst] = src
    for bid, inv in blocks.items():
        pairs = ", ".join(f"code {s!r} extracts as {d!r}" for d, s in sorted(inv.items(), key=lambda x: x[1])[:8])
        tab = str.maketrans({d.lower(): s.lower() for d, s in inv.items() if d.isalpha() and s.isalpha()})
        fixed = [(w, w.translate(tab)) for w in words if D and w not in D and w.translate(tab) in D and w.translate(tab) != w]
        if len(fixed) >= 2:
            F.add("HIGH", "ToUnicode remap confirmed: misspelled text-layer words become real words when the remap is undone", "font",
                  pairs + "; e.g. " + ", ".join(f"{a}->{b}" for a, b in fixed[:5]))
        elif len(inv) > 8:
            F.add("INFO", "custom font encoding (many codes mapped to other letters) - normal for subset fonts, no misspellings found", "font",
                  f"{len(inv)} codes")
        else:
            F.add("MED", "ToUnicode remap (drawn glyph != extracted character)", "font", pairs + " - compare numbers/letters with the page image")


def _step(F, name, fn, *args, default=None, **kw):
    """Fail closed: a check that crashes makes the verdict MED instead of silently clean."""
    try:
        return fn(*args, **kw)
    except Exception as e:
        F.add("MED", f"scan step '{name}' failed - result incomplete", "scanner", f"{type(e).__name__}: {str(e)[:120]}")
        return default


def scan_pdf(path, F, max_pages=None, image_dir=None, ocr_pages=30, reference=None):
    from .polyglot import pdf_ambiguity, pdf_javascript
    data = open(path, "rb").read()
    replacements, kw_strings = [], []
    _step(F, "structure", structural, data, F, replacements, kw_strings)
    _step(F, "metadata/attachments", info_and_attachments, path, F)
    sizes = _step(F, "page sizes", page_sizes, path, default=[]) or []
    layer = _step(F, "text layer", text_layer, path, F, sizes, default="") or ""
    visible = _step(F, "render diff", render_and_visible, path, F, sizes, max_pages=max_pages, image_dir=image_dir, default="") or ""
    _step(F, "images", images, path, F)
    from .readers import differential
    _step(F, "reader comparison", differential, path, layer, F)
    from . import forensic
    _step(F, "glyph audit", forensic.trace_audit, path, F)
    _step(F, "provenance", forensic.provenance, path, F)
    _step(F, "reading order", forensic.reading_order, path, F)
    if ocr_pages:
        _step(F, "glyph OCR", forensic.glyph_ocr, path, F, max_pages=min(10, ocr_pages))
    if reference:
        _step(F, "reference diff", forensic.reference_diff, path, reference, F)
    if ocr_pages:
        from .ocr import ocr_pdf
        pages = {}
        parts = re.split(r"(?m)^\[page (\d+)\]\n", visible)
        for i in range(1, len(parts) - 1, 2):
            pages[int(parts[i])] = parts[i + 1]
        _step(F, "OCR cross-check", ocr_pdf, path, F, pages, max_pages=ocr_pages)
    _step(F, "revisions/ambiguity", pdf_ambiguity, data, F, layer)
    if re.search(rb"/(JS|JavaScript)\b", data):
        js = " ".join(re.sub(rb"\\([()\\])", rb"\1", b).decode("latin1")  # PDF strings escape ( ) and backslash
                      for b in all_streams(data) if re.search(rb"/JS|JavaScript|getField|app\.", b))
        _step(F, "javascript", pdf_javascript, js, F)
        for lit_ in re.findall(r"'([^'\n]{20,})'|\"([^\"\n]{20,})\"", js):
            st = lit_[0] or lit_[1]
            if hidden_instruction(st) or DIRECTIVE.search(st):
                F.add("HIGH", "AI-directed text in PDF JavaScript", "catalog", short(st, 300))
            else:
                decoded_variants(st, "PDF JavaScript string", F)
    if sizes and not layer.strip():
        F.add("MED", "no text could be extracted (scanned images, encrypted, or broken) - only the page images show the content",
              "document", "use --images DIR and read the PNGs")
    if not sizes:
        F.add("MED", "page structure could not be read (damaged PDF?) - readers may repair it differently", "document", "")
    flat = "".join(visible.split())
    for st in dict.fromkeys(kw_strings):
        if "".join(st.split()) not in flat:
            F.add("HIGH", "PDF string object with AI-directed words or directives (not part of the visible text)", "structure", short(st, 400))
            check_text(st, "PDF string object (not visible)", F, hidden=True)
    from .readers import mutool_text, pypdf_text
    glyph_text = None
    if getattr(F, "actualtext", None):  # the drawn glyphs: pypdf ignores ActualText (MuPDF honours it in some layouts)
        glyph_text = pypdf_text(path)
        if not glyph_text or glyph_text.startswith("__error__"):
            glyph_text = mutool_text(path)
    replacements += _judge_actualtext(F, glyph_text or "")
    _judge_remaps(F, layer)
    for s in replacements:  # ActualText that replaces *visible* glyphs survives the ink test - cut it out
        toks = s.split()
        if toks:
            visible = re.sub(r"\s+".join(map(re.escape, toks)), "[[removed: ActualText replacement - quoted in the report]]", visible)
    if any(f["kind"].startswith("ToUnicode remap") and f["sev"] != "INFO" for f in F.items):
        visible = ("[[WARNING: this PDF remaps characters - the text below may differ from the printed page. "
                   "Compare with the page images before relying on any formula, number or letter.]]\n\n" + visible)
    return visible, len(sizes)
