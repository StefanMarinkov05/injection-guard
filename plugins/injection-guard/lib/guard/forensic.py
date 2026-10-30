"""PDF forensics: glyph-level trace audit (MuPDF), provenance of content streams, diff against a reference PDF,
and per-glyph font OCR (every embedded glyph rendered and read back, compared with its Unicode mapping).

These do not look at wording. They look at how each glyph is drawn, where the drawing commands came from,
and whether a glyph's shape is the letter the text layer claims.
"""
import binascii, html, io, os, re, shutil, subprocess, tempfile, unicodedata
from collections import Counter
from .common import DIRECTIVE, IMPERSONATION, KEYWORDS, STRONG, check_text, hidden_task_signal, short


def _exe(name):
    import pwd
    p = shutil.which(name) or os.path.join(pwd.getpwuid(os.getuid()).pw_dir, ".local/bin", name)
    return p if os.path.exists(p) else None


def _severity(text):
    t = " ".join(text.split())
    if IMPERSONATION.search(t) or STRONG.search(t) or KEYWORDS.search(t) or DIRECTIVE.search(t) or hidden_task_signal(t) or len(re.findall(r"\w+", t)) >= 3:
        return "HIGH"
    return "MED"


def _norm(t):
    t = unicodedata.normalize("NFKC", t)
    for x, y in (("\u2217", "*"), ("\u22c6", "*"), ("\u00ad", "-"), ("\u2010", "-"), ("\u2011", "-"), ("\u2212", "-")):
        t = t.replace(x, y)
    # unmapped glyph pieces (U+FFFD, private use) of multi-part delimiters say nothing
    return "".join(c for c in t.lower() if not c.isspace() and c != "\ufffd" and not ("\ue000" <= c <= "\uf8ff"))


# ---------------------------------------------------------------- 1. glyph-level trace audit
WHITE = {("DeviceGray", "1"), ("DeviceRGB", "1 1 1"), ("DeviceCMYK", "0 0 0 0"), ("ICCBased", "1"), ("ICCBased", "1 1 1")}
OPEN = re.compile(r'<(fill_text|stroke_text|clip_text|clip_stroke_text|ignore_text)\b([^>]*)>')
CLOSE = re.compile(r'</(fill_text|stroke_text|clip_text|clip_stroke_text|ignore_text)>')
ATTR = re.compile(r'(\w+)="([^"]*)"')


def trace_audit(path, F, max_pages=50):
    exe = _exe("mutool")
    if not exe:
        F.add("INFO", "glyph audit skipped (mutool not installed)", "forensics", "")
        return
    try:
        out = subprocess.run([exe, "trace", path, f"1-{max_pages}"], capture_output=True, text=True, errors="replace", timeout=600).stdout
    except Exception as e:
        F.add("MED", "glyph audit failed - scan incomplete", "forensics", str(e)[:120])
        return
    page, stack, meta = 0, [], []
    per_page = {}
    same_at = 0
    cells = {}  # page -> [(char, x0, y0, x1, y1, word_id)] of glyphs that should be visible

    def bucket(kind):
        return per_page.setdefault(page, {}).setdefault(kind, [])
    for line in out[:80_000_000].splitlines():
        if "<page " in line:
            m = re.search(r'number="(\d+)"', line)
            page = int(m.group(1)) if m else page + 1
            continue
        m = OPEN.search(line)
        if m:
            a = dict(ATTR.findall(m.group(2)))
            try:
                tr = [float(v) for v in a.get("transform", "1 0 0 1 0 0").split()]
            except ValueError:
                tr = [1, 0, 0, 1, 0, 0]
            stack.append({"kind": m.group(1), "cs": a.get("colorspace", ""), "color": a.get("color", ""), "alpha": a.get("alpha", "1"),
                          "size": 99, "tr": tr, "word": 0})
            continue
        if CLOSE.search(line):
            if stack:
                stack.pop()
            continue
        if "<metatext" in line and 'type="actualtext"' in line:
            mt = re.search(r'txt="([^"]*)"', line)
            meta.append({"txt": html.unescape(mt.group(1)) if mt else "", "glyphs": [], "page": page})
            continue
        if "</metatext>" in line:
            if meta:
                m_ = meta.pop()
                drawn, said = _norm("".join(m_["glyphs"])), _norm(m_["txt"])
                if said == drawn or (not said) or (not drawn and not said.strip("-")) or (len(said) <= 2 and drawn.startswith(said)):
                    same_at += 1
                else:
                    sev = "HIGH" if (STRONG.search(m_["txt"]) or KEYWORDS.search(m_["txt"]) or DIRECTIVE.search(m_["txt"])
                                     or hidden_task_signal(m_["txt"]) or len(said) > 40) else "MED"
                    F.add(sev, "ActualText differs from the glyphs it replaces (glyph audit)", f"p.{m_['page']}",
                          f"drawn: {short(''.join(m_['glyphs']), 80)!r} / read as: {short(m_['txt'], 200)!r}")
            continue
        if "<span " in line and stack:
            tm = re.search(r'trm="([-\d.e]+) ([-\d.e]+) ([-\d.e]+) ([-\d.e]+)"', line)
            if tm:
                a_, b_, c_, d_ = map(float, tm.groups())
                stack[-1]["size"] = abs(a_ * d_ - b_ * c_) ** 0.5
            continue
        if "<g " in line:
            mu = re.search(r'unicode="([^"]*)"', line)
            ch = html.unescape(mu.group(1)) if mu else ""
            if stack and stack[-1]["kind"] in ("fill_text", "stroke_text"):
                el = stack[-1]
                if not ch.strip():
                    el["word"] += 1
                else:
                    gx, gy, adv = (re.search(r'\b%s="([-\d.e]+)"' % k, line) for k in ("x", "y", "adv"))
                    if gx and gy and adv and 5 <= el["size"] < 99 and ch.isalnum():
                        a_, b_, c_, d_, e_, f_ = el["tr"]
                        x, y = float(gx.group(1)), float(gy.group(1))
                        X, Y = a_ * x + c_ * y + e_, b_ * x + d_ * y + f_
                        w = max(1.0, float(adv.group(1)) * el["size"])
                        last = el.get("last")
                        if last and (abs(Y - last[1]) > 0.3 * el["size"] or X - last[0] > 0.25 * el["size"] or X < last[0] - 1):
                            el["word"] += 1  # gap or new line: new word (pdfTeX emits no space glyphs)
                        el["last"] = (X + w, Y)
                        cells.setdefault(page, []).append((ch, X, Y - 0.72 * el["size"], X + w, Y, (id(el), el["word"])))
            for m_ in meta:
                m_["glyphs"].append(ch)
            if not stack or not ch.strip():
                continue
            el = stack[-1]
            if el["kind"] == "ignore_text":
                bucket("invisible (render mode 3)").append(ch)
            elif el["kind"] in ("clip_text", "clip_stroke_text"):
                bucket("clipping-only text (render mode 7)").append(ch)
            elif (el["cs"], el["color"]) in WHITE:
                bucket("white glyphs").append(ch)
            try:
                if float(el["alpha"]) < 0.05:
                    bucket("transparent glyphs (alpha ~ 0)").append(ch)
            except ValueError:
                pass
            if el["size"] < 1.0:
                bucket("microscopic glyphs (< 1 pt)").append(ch)
    for p, kinds in sorted(per_page.items()):
        for kind, chars in kinds.items():
            text = "".join(chars)
            if not text.strip():
                continue
            sev = _severity(text)
            t = " ".join(text.split())
            ai = bool(IMPERSONATION.search(t) or STRONG.search(t) or KEYWORDS.search(t) or DIRECTIVE.search(t))
            if kind == "white glyphs" and not ai:
                sev = "INFO"  # white text on a dark box is normal design; the render diff and cover check decide visibility
            if len(text.strip()) <= 2 and not ai:
                sev = "INFO"  # a lone glyph (export artefact)
            F.add(sev, f"{kind} (glyph audit)", f"p.{p}", short(text, 240))
    if same_at:
        F.add("INFO", "ActualText spans that match their glyphs (glyph audit)", "document", f"{same_at} span(s)")
    _cover_check(path, cells, F)


def _cover_check(path, cells, F):
    """Per-glyph render diff: a drawn glyph whose cell has no ink is covered (white box, image, same colour).
    Catches partly covered words that the word-level check misses (e.g. the c* of a(b*c+ab)*c* hidden by a box)."""
    if not cells:
        return
    from PIL import Image
    info = subprocess.run(["pdfinfo", "-box", "-f", "1", "-l", str(max(cells)), path], capture_output=True, text=True, errors="replace").stdout
    boxes = {}
    for m in re.finditer(r"Page\s+(\d+) (MediaBox|CropBox):\s+([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)", info):
        boxes.setdefault(int(m.group(1)), {})[m.group(2)] = tuple(float(v) for v in m.groups()[2:])
    rots = {int(p): int(r) % 360 for p, r in re.findall(r"Page\s+(\d+) rot:\s+(-?\d+)", info)}
    with tempfile.TemporaryDirectory() as td:
        for p, cs in sorted(cells.items()):
            b = boxes.get(p, {})
            if rots.get(p, 0) or b.get("MediaBox") != b.get("CropBox"):
                continue  # coordinates would need the box offset / rotation; the word-level checks cover these pages
            subprocess.run(["pdftoppm", "-r", "72", "-gray", "-png", "-f", str(p), "-l", str(p), path, os.path.join(td, f"c{p}")],
                           capture_output=True, timeout=300)
            img = next((os.path.join(td, f) for f in os.listdir(td) if f.startswith(f"c{p}-")), None)
            if not img:
                continue
            im = Image.open(img).convert("L")
            hidden, words = [], {}
            for ch, x0, y0, x1, y1, wid in cs:
                # padded by 2 px so the cell always includes some background: a narrow stroke filling its own cell is
                # not "no contrast", but black text on a black box still is
                X0, Y0, X1, Y1 = max(0, int(x0) - 2), max(0, int(y0) - 2), min(im.width, int(x1) + 3), min(im.height, int(y1) + 3)
                if X1 <= X0 or Y1 <= Y0:
                    continue
                lo, hi = im.crop((X0, Y0, X1, Y1)).getextrema()
                vis = lo < 200 and hi - lo >= 40
                words.setdefault(wid, []).append((ch, vis))
            for wid, gl in words.items():
                if not all(v for _, v in gl):
                    hidden.append("".join(c if v else f"[{c}]" for c, v in gl))
            if hidden:
                covered = "".join(c for w in hidden for c in re.findall(r"\[(.)\]", w))
                sev = "HIGH" if (len(covered) >= 2 or hidden_task_signal(" ".join(hidden))) else "MED"
                F.add(sev, "covered glyphs: drawn letters with no ink in their cell (per-glyph render diff)", f"p.{p}",
                      "[x] = covered: " + short(", ".join(hidden[:12]), 240))
            os.remove(img)


# ---------------------------------------------------------------- 2. provenance
def _font_table(res):
    out = {}
    try:
        fonts = res["/Font"]
    except Exception:
        return out
    for name, ref in fonts.items():
        try:
            fd = ref.get_object()
            base = str(fd.get("/BaseFont", "?"))
            desc = fd.get("/FontDescriptor")
            if desc is None and "/DescendantFonts" in fd:
                desc = fd["/DescendantFonts"][0].get_object().get("/FontDescriptor")
            desc = desc.get_object() if desc is not None else None
            emb = bool(desc) and any(k in desc for k in ("/FontFile", "/FontFile2", "/FontFile3"))
            out[str(name).lstrip("/")] = (re.sub(r"^/?[A-Z]{6}\+", "", base.lstrip("/")), emb)
        except Exception:
            continue
    return out


def provenance(path, F, max_pages=200):
    try:
        import pypdf
        r = pypdf.PdfReader(path, strict=False)
    except Exception:
        return
    for i, page in enumerate(r.pages[:max_pages], 1):
        try:
            cont = page.get("/Contents")
            if cont is None:
                continue
            cont = cont.get_object()
            if not isinstance(cont, list) or len(cont) < 2:
                continue
            fonts = _font_table(page["/Resources"])
            uses = []
            for k, ref in enumerate(cont):
                data = ref.get_object().get_data()
                used = {n.decode("latin1") for n in re.findall(rb"/([^\s/\[\]<>()]+)\s+[\d.]+\s+Tf", data)}
                uses.append((k, used, len(data), bool(re.search(rb"(^|\s)[37]\s+Tr\b", data))))
            embedded_elsewhere = any(fonts.get(n, ("", False))[1] for k, used, _, _ in uses for n in used)
            for k, used, size, inv in uses:
                if used and all(not fonts.get(n, ("", True))[1] for n in used) and embedded_elsewhere:
                    names = ", ".join(f"{n}={fonts.get(n, ('?', False))[0]}" for n in sorted(used))
                    F.add("HIGH" if inv else "MED", "content stream added by another tool: it uses only non-embedded fonts, unlike the rest of the page",
                          f"p.{i} stream {k + 1}/{len(uses)}", f"{names}; {size} bytes" + ("; draws invisible text" if inv else ""))
        except Exception:
            continue


# ---------------------------------------------------------------- 3. diff against a reference PDF
def _features(path):
    import pypdf
    r = pypdf.PdfReader(path, strict=False)
    fonts, streams = set(), []
    for page in r.pages[:300]:
        try:
            fonts |= {v for v in _font_table(page["/Resources"]).values()}
            c = page.get("/Contents")
            c = c.get_object() if c is not None else None
            streams.append(len(c) if isinstance(c, list) else 1)
        except Exception:
            streams.append(0)
    raw = open(path, "rb").read()
    info = subprocess.run(["pdfinfo", path], capture_output=True, text=True, errors="replace").stdout
    att = subprocess.run(["pdfdetach", "-list", path], capture_output=True, text=True, errors="replace").stdout
    from .pdf import all_streams
    blob = b"\n".join(all_streams(raw))
    return {"fonts": fonts, "streams": streams, "producer": re.findall(r"(?m)^(Producer|Creator):\s*(.*)$", info),
            "attachments": {l.split(":", 1)[1].strip() for l in att.splitlines()[1:] if ":" in l},
            "actualtext": len(re.findall(rb"/ActualText", blob)), "tr3": len(re.findall(rb"(^|\s)[37]\s+Tr\b", blob)),
            "ocg": b"/OCProperties" in blob, "js": bool(re.search(rb"/(JS|JavaScript)\b", blob)), "annots": len(re.findall(rb"/Annots", blob))}


def reference_diff(path, ref, F):
    try:
        a, b = _features(path), _features(ref)
    except Exception as e:
        F.add("MED", "reference comparison failed", "reference", str(e)[:120])
        return
    where = f"vs reference {os.path.basename(ref)}"
    new_fonts = a["fonts"] - b["fonts"]
    for name, emb in sorted(new_fonts):
        F.add("INFO" if emb else "MED", f"font not used by the reference ({'embedded' if emb else 'NOT embedded'})", where, name)
    if a["streams"] and b["streams"] and max(a["streams"]) > max(b["streams"]):
        pages = [i + 1 for i, n in enumerate(a["streams"]) if n > max(b["streams"])]
        F.add("MED", "more content streams per page than the reference (content appended after generation?)", where,
              f"pages {pages[:10]}: up to {max(a['streams'])} vs {max(b['streams'])}")
    if a["actualtext"] > b["actualtext"]:
        F.add("HIGH" if b["actualtext"] == 0 else "MED", "ActualText the reference does not use", where, f"{a['actualtext']} vs {b['actualtext']}")
    if a["tr3"] > b["tr3"]:
        F.add("HIGH", "invisible text render mode the reference does not use", where, f"{a['tr3']} vs {b['tr3']}")
    for att in sorted(a["attachments"] - b["attachments"]):
        F.add("MED", "attachment the reference does not have", where, att)
    for key, label in (("ocg", "optional content layers"), ("js", "JavaScript")):
        if a[key] and not b[key]:
            F.add("MED", f"{label} the reference does not have", where, "")
    if a["producer"] != b["producer"]:
        F.add("INFO", "different producing software than the reference", where, f"{a['producer']} vs {b['producer']}")


# ---------------------------------------------------------------- 4. per-glyph font OCR
def _cmap_map(stream_data):
    m = {}
    for blk in re.findall(rb"beginbfchar(.*?)endbfchar", stream_data, re.S):
        for s, d in re.findall(rb"<([0-9A-Fa-f]{2,4})>\s*<([0-9A-Fa-f]{4,8})>", blk):
            try:
                m[int(s, 16)] = bytes.fromhex(d.decode()).decode("utf-16-be")
            except Exception:
                pass
    for blk in re.findall(rb"beginbfrange(.*?)endbfrange", stream_data, re.S):
        for a, b, d in re.findall(rb"<([0-9A-Fa-f]{2,4})>\s*<([0-9A-Fa-f]{2,4})>\s*<([0-9A-Fa-f]{4})>", blk):
            a, b, d = int(a, 16), int(b, 16), int(d, 16)
            for c in range(a, min(b, a + 512) + 1):
                m[c] = chr(d + c - a)
    return m


class _Poly:
    """fontTools pen that flattens outlines into polygons."""

    def __init__(self):
        from fontTools.pens.basePen import BasePen

        class P(BasePen):
            def __init__(s):
                super().__init__(None)
                s.contours, s.cur = [], []

            def _moveTo(s, pt):
                s.cur = [pt]

            def _lineTo(s, pt):
                s.cur.append(pt)

            def _curveToOne(s, p1, p2, p3):
                p0 = s.cur[-1] if s.cur else p1
                for k in range(1, 9):
                    t = k / 8
                    mt = 1 - t
                    s.cur.append((mt ** 3 * p0[0] + 3 * mt * mt * t * p1[0] + 3 * mt * t * t * p2[0] + t ** 3 * p3[0],
                                  mt ** 3 * p0[1] + 3 * mt * mt * t * p1[1] + 3 * mt * t * t * p2[1] + t ** 3 * p3[1]))

            def _closePath(s):
                if len(s.cur) > 2:
                    s.contours.append(s.cur)
                s.cur = []
            _endPath = _closePath
        self.pen = P()


def _render(draw_fn, upm=1000, em=80):
    """Glyph at the font's own scale on a common baseline (keeps x-height and case cues for OCR)."""
    from PIL import Image, ImageChops, ImageDraw
    p = _Poly()
    draw_fn(p.pen)
    p.pen._closePath()
    pts = [q for c in p.pen.contours for q in c]
    if not pts:
        return None
    sc = em / float(upm or 1000)
    x0 = min(q[0] for q in pts)
    W, H, base = int(em * 3), int(em * 1.6), int(em * 1.15)
    img = Image.new("1", (W, H), 0)
    for c in p.pen.contours:  # even-odd fill by XOR of contour masks
        m = Image.new("1", (W, H), 0)
        ImageDraw.Draw(m).polygon([(em + (q[0] - x0) * sc, base - q[1] * sc) for q in c], fill=1)
        img = ImageChops.logical_xor(img, m)
    return Image.eval(img.convert("L"), lambda v: 255 - v)


def _font_drawers(font_obj):
    """Return {code: (unicode, draw_fn)} for the alphanumeric ASCII characters a font claims to contain."""
    from fontTools import cffLib, t1Lib, ttLib
    from fontTools.encodings.StandardEncoding import StandardEncoding
    fd = font_obj.get_object()
    tu = fd.get("/ToUnicode")
    if tu is None:
        return {}
    umap = {c: u for c, u in _cmap_map(tu.get_object().get_data()).items() if len(u) == 1 and u.isascii() and u.isalnum()}
    if not umap:
        return {}
    sub = str(fd.get("/Subtype"))
    cid = fd["/DescendantFonts"][0].get_object() if "/DescendantFonts" in fd else None
    desc = (cid or fd).get("/FontDescriptor")
    if desc is None:
        return {}
    desc = desc.get_object()
    out = {}
    if "/FontFile3" in desc:
        ff = desc["/FontFile3"].get_object()
        data = ff.get_data()
        if str(ff.get("/Subtype")) == "/OpenType":
            tt = ttLib.TTFont(io.BytesIO(data))
            gs, order, upm = tt.getGlyphSet(), tt.getGlyphOrder(), tt["head"].unitsPerEm
            for c, u in umap.items():
                if c < len(order):
                    out[c] = (u, lambda pen, n=order[c]: gs[n].draw(pen), upm)
            return out
        cs = cffLib.CFFFontSet()
        cs.decompile(io.BytesIO(data), None)
        top = cs[cs.fontNames[0]]
        names = set(top.CharStrings.keys())
        fm = getattr(top, "FontMatrix", [0.001])
        upm = round(1 / fm[0]) if fm and fm[0] else 1000
        if hasattr(top, "ROS"):  # CID-keyed: code = CID (Identity-H)
            for c, u in umap.items():
                n = f"cid{c:05d}"
                if n in names:
                    out[c] = (u, lambda pen, n=n: top.CharStrings[n].draw(pen), upm)
        else:
            enc = _simple_encoding(fd, getattr(top, "Encoding", None), StandardEncoding)
            for c, u in umap.items():
                n = enc.get(c)
                if n in names:
                    out[c] = (u, lambda pen, n=n: top.CharStrings[n].draw(pen), upm)
    elif "/FontFile2" in desc:
        tt = ttLib.TTFont(io.BytesIO(desc["/FontFile2"].get_object().get_data()))
        gs, order, upm = tt.getGlyphSet(), tt.getGlyphOrder(), tt["head"].unitsPerEm
        if cid is not None:
            for c, u in umap.items():
                if c < len(order):
                    out[c] = (u, lambda pen, n=order[c]: gs[n].draw(pen), upm)
        else:
            cmap = {}
            for t in tt["cmap"].tables:
                cmap.update(t.cmap)
            for c, u in umap.items():
                n = cmap.get(c) or cmap.get(0xF000 + c)
                if n:
                    out[c] = (u, lambda pen, n=n: gs[n].draw(pen), upm)
    elif "/FontFile" in desc:
        ff = desc["/FontFile"].get_object()
        data = ff.get_data()
        l1, l2 = int(ff.get("/Length1", 0)), int(ff.get("/Length2", 0))
        pfa = data[:l1] + data[l1:l1 + l2] + b"\n" + (b"0" * 64 + b"\n") * 8 + b"cleartomark\n"
        with tempfile.NamedTemporaryFile(suffix=".pfa", delete=False) as t:
            t.write(pfa)
        try:
            t1 = t1Lib.T1Font(t.name)
            t1.parse()
            gs = t1.getGlyphSet()
            builtin = t1.font.get("Encoding")
        finally:
            os.unlink(t.name)
        enc = _simple_encoding(fd, builtin, StandardEncoding)
        for c, u in umap.items():
            n = enc.get(c)
            if n and n in gs:
                out[c] = (u, lambda pen, n=n: gs[n].draw(pen), 1000)
    return out


def _simple_encoding(fd, builtin, standard):
    enc = {}
    if builtin is not None and not isinstance(builtin, str):
        try:
            enc = {i: n for i, n in enumerate(builtin) if n and n != ".notdef"}
        except Exception:
            enc = {}
    if not enc:
        enc = {i: n for i, n in enumerate(standard) if n and n != ".notdef"}
    e = fd.get("/Encoding")
    try:
        e = e.get_object() if e is not None else None
        if e is not None and hasattr(e, "get") and "/Differences" in e:
            code = 0
            for item in e["/Differences"]:
                if isinstance(item, int) or str(item).lstrip("-").isdigit():
                    code = int(item)
                else:
                    enc[code] = str(item).lstrip("/")
                    code += 1
    except Exception:
        pass
    return enc


CONFUSE = {frozenset(p) for p in ("l1", "lI", "I1", "O0", "o0", "S5", "Z2", "B8", "g9", "q9", "b6", "G6", "il", "i1", "ij", "rn", "vy",
                                  "uv", "nh", "ce", "ao", "eo", "ae", "cs", "CG", "QO", "DO", "Uu", "Ww", "Vv", "Xx", "Zz", "Ss", "Oo", "Cc", "Pp", "Kk",
                                  "fl", "ft", "tf", "rt", "71", "4A", "3B", "8S", "E3", "7T", "lt", "2z", "mn")}


def glyph_ocr(path, F, max_pages=10, max_glyphs=600):
    from .ocr import tesseract
    exe = tesseract()
    if not exe:
        F.add("INFO", "glyph OCR skipped (tesseract not installed)", "forensics", "")
        return
    try:
        import pypdf
        r = pypdf.PdfReader(path, strict=False)
    except Exception:
        return
    seen, todo = set(), []
    for page in r.pages[:max_pages]:
        try:
            fonts = page["/Resources"]["/Font"]
        except Exception:
            continue
        for name, ref in fonts.items():
            key = getattr(ref, "idnum", id(ref))
            if key in seen:
                continue
            seen.add(key)
            try:
                drawers = _font_drawers(ref)
            except Exception:
                continue
            base = str(ref.get_object().get("/BaseFont", name))
            for c, (u, fn, upm) in sorted(drawers.items()):
                todo.append((base, c, u, fn, upm))
    todo = todo[:max_glyphs]
    if not todo:
        return
    results = []
    with tempfile.TemporaryDirectory() as td:
        paths = []
        for k, (base, c, u, fn, upm) in enumerate(todo):
            try:
                img = _render(fn, upm)
            except Exception:
                img = None
            if img is None:
                continue
            p = os.path.join(td, f"g{k:04d}.png")
            img.save(p)
            paths.append((p, base, c, u))
        if not paths:
            return
        lst = os.path.join(td, "list.txt")
        with open(lst, "w") as f:
            f.write("\n".join(p for p, *_ in paths) + "\n")
        wl = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        try:
            out = subprocess.run([exe, lst, "-", "--psm", "10", "-c", f"tessedit_char_whitelist={wl}", "-c", "load_system_dawg=0",
                                  "-c", "load_freq_dawg=0", "tsv"], capture_output=True, text=True, errors="replace", timeout=900).stdout
        except Exception as e:
            F.add("MED", "glyph OCR failed - scan incomplete", "forensics", str(e)[:120])
            return
        best = {}  # page_num -> (conf, text)
        for row in out.splitlines()[1:]:
            col = row.split("\t")
            if len(col) >= 12 and col[0] == "5" and col[11].strip():
                try:
                    pg, conf = int(col[1]), float(col[10])
                except ValueError:
                    continue
                if conf > best.get(pg, (-1, ""))[0]:
                    best[pg] = (conf, col[11].strip())
        for idx, (p, base, c, u) in enumerate(paths, 1):
            conf, got = best.get(idx, (0.0, ""))
            got = "".join(ch for ch in got if ch.isalnum())
            results.append((base, c, u, got if len(got) == 1 else "", conf))
    raw = [(b, u, g) for b, c, u, g, conf in results if len(g) == 1 and conf >= 85 and g.lower() != u.lower()]
    rawpairs = {(u.lower(), g.lower()) for _, u, g in raw}
    # OCR confusions are ignored - unless the same pair appears in both directions (a real swap a<->b)
    mism = [(b, u, g) for b, u, g in raw if (frozenset((u, g)) not in CONFUSE and frozenset((u.lower(), g.lower())) not in CONFUSE)
            or (g.lower(), u.lower()) in rawpairs]
    checked = sum(1 for *_, g, conf in results if len(g) == 1)
    F.add("INFO", "glyph OCR: embedded glyphs rendered and read back", "forensics", f"{checked} of {len(results)} glyphs recognised")
    if not mism:
        return
    pairs = Counter((u, g) for _, u, g in mism)
    swap = [(a, b) for (a, b) in pairs if (b, a) in pairs]
    detail = ", ".join(f"{b.split('+')[-1]}: shape '{g}' mapped to '{u}'" for b, u, g in mism[:10])
    if swap or len(mism) >= 4:
        F.add("HIGH", "glyph shapes do not match their Unicode mapping (font remapped)", "forensics", detail)
    else:
        F.add("MED", "a glyph's shape may not match its Unicode mapping (single OCR mismatch)", "forensics", detail)
