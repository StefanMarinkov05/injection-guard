"""DOCX / PPTX / XLSX / ODF / EPUB: visible text plus hidden runs, comments, notes, metadata, hidden sheets."""
import re, zipfile
import xml.etree.ElementTree as ET
from .common import hidden_instruction
from .common import DIRECTIVE, IMPERSONATION, KEYWORDS, SENTENCE, STRONG, check_text, hidden_task_signal, short
from .web import sanitize_html

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
A = "{http://schemas.openxmlformats.org/drawingml/2006/main}"
P = "{http://schemas.openxmlformats.org/presentationml/2006/main}"
MC = "{http://schemas.openxmlformats.org/markup-compatibility/2006}"
MAX_PART = 40 * 1024 * 1024


def _xml(z, name):
    info = z.getinfo(name)
    if info.file_size > MAX_PART:
        raise ValueError(f"{name} too large")
    return ET.fromstring(z.read(name))


def _flag_hidden(F, where, text, kind):
    if not text.strip():
        return
    if hidden_instruction(text) or DIRECTIVE.search(text) or hidden_task_signal(text) or IMPERSONATION.search(text):
        F.add("HIGH", kind, where, short(text, 400))
        check_text(text, where, F, hidden=True)
    else:
        F.add("MED" if (len(text) > 80 or SENTENCE.search(text)) else "INFO", kind, where, short(text, 200))


def _meta(z, F):
    for name in ("docProps/core.xml", "docProps/app.xml", "docProps/custom.xml", "meta.xml"):
        if name in z.namelist():
            t = " ".join(x.strip() for x in _xml(z, name).itertext() if x.strip())
            if hidden_instruction(t) or DIRECTIVE.search(t):
                F.add("HIGH", "document metadata with AI-directed text or directives", name, short(t, 300))
    for name in z.namelist():
        if name.startswith("customXml/") and name.endswith(".xml") and "itemProps" not in name:
            t = " ".join(x.strip() for x in _xml(z, name).itertext() if x.strip())
            if t:
                _flag_hidden(F, name, t, "custom XML part (not shown in the document)")
    emb = [n for n in z.namelist() if "/embeddings/" in n or n.startswith("word/activeX") or n.endswith("vbaProject.bin")]
    if emb:
        F.add("MED", "embedded objects / macros", "package", ", ".join(emb[:8]))


# ---------------------------------------------------------------- DOCX
def _docx_walk(el, st, vis, hid):
    tag = el.tag
    if tag in (W + "rPr", W + "pPr", W + "sectPr", W + "tblPr", W + "trPr", W + "tcPr"):
        return
    if tag == MC + "AlternateContent":  # Word shows the Choice; other readers use the Fallback - two versions of one text
        choice, fb = el.find(MC + "Choice"), el.find(MC + "Fallback")
        if choice is not None:
            _docx_walk(choice, st, vis, hid)
        if fb is not None:
            ct = "".join(choice.itertext()) if choice is not None else ""
            ft = "".join(fb.itertext())
            if ft.strip() and ft.strip() != ct.strip():
                hid.setdefault("AlternateContent fallback differs from what Word shows", []).append(ft)
        return
    if tag == W + "del":
        st = dict(st, reason="tracked deletion")
    elif tag == W + "r":
        rpr = el.find(W + "rPr")
        if rpr is not None:
            if rpr.find(W + "vanish") is not None or rpr.find(W + "specVanish") is not None:
                st = dict(st, reason="hidden text (w:vanish)")
            sz = rpr.find(W + "sz")
            if sz is not None and sz.get(W + "val", "99").isdigit() and int(sz.get(W + "val")) < 4:
                st = dict(st, reason=f"microscopic text ({int(sz.get(W + 'val')) / 2} pt)")
            col = rpr.find(W + "color")
            if col is not None and col.get(W + "val", "").upper() in ("FFFFFF", "FFFFFE", "FEFEFE"):
                st = dict(st, white=True)
    if tag in (W + "t", W + "delText"):
        t = el.text or ""
        if st.get("reason"):
            hid.setdefault(st["reason"], []).append(t)
        else:
            if st.get("white"):
                hid.setdefault("white text (may be invisible on white paper)", []).append(t)
            vis.append(t)
    elif tag == W + "instrText":
        hid.setdefault("field code", []).append(el.text or "")
    elif tag == W + "tab":
        vis.append("\t")
    elif tag in (W + "br", W + "cr"):
        vis.append("\n")
    for ch in el:
        _docx_walk(ch, st, vis, hid)
    if tag == W + "p":
        vis.append("\n")


def scan_docx(z, F):
    out = []
    raw = z.read("word/document.xml")[:MAX_PART].decode("utf-8", "replace")
    for m in re.finditer(r"<w:r>(?:(?!</w:r>).)*?<w:rtl(?: w:val=\"(?:1|true|on)\")?/>(?:(?!</w:r>).)*?<w:t[^>]*>([^<]*[A-Za-z]{2,}[^<]*)</w:t>", raw, re.S):
        F.add("MED", "right-to-left run formatting on Latin text (display order may differ)", "word/document.xml", short(m.group(1), 120))
        break
    parts = ["word/document.xml"] + sorted(n for n in z.namelist() if re.match(r"word/(header|footer|footnotes|endnotes)\d*\.xml$", n))
    for name in parts:
        if name not in z.namelist():
            continue
        vis, hid = [], {}
        root = _xml(z, name)
        _docx_walk(root, {}, vis, hid)
        text = re.sub(r"\n{3,}", "\n\n", "".join(vis)).strip()
        if text:
            out.append(text if name == "word/document.xml" else f"[{name}]\n{text}")
        for reason, chunks in hid.items():
            t = " ".join(chunks)
            if reason.startswith("white"):
                if hidden_instruction(t) or DIRECTIVE.search(t):
                    F.add("HIGH", reason + " with AI-directed words", name, short(t, 300))
                continue
            _flag_hidden(F, name, t, reason)
        for d in root.iter("{http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing}docPr"):
            alt = (d.get("descr") or "") + " " + (d.get("title") or "")
            if hidden_instruction(alt) or DIRECTIVE.search(alt):
                F.add("HIGH", "image alt text with AI-directed words", name, short(alt, 300))
    if "word/comments.xml" in z.namelist():
        t = " ".join(x for x in _xml(z, "word/comments.xml").itertext())
        _flag_hidden(F, "word/comments.xml", t, "comments (not part of the printed text)")
    if "word/settings.xml" in z.namelist():
        for v in _xml(z, "word/settings.xml").iter(W + "docVar"):
            _flag_hidden(F, "word/settings.xml", (v.get(W + "name") or "") + "=" + (v.get(W + "val") or ""), "document variable (never displayed)")
    return "\n\n".join(out)


# ---------------------------------------------------------------- PPTX
def scan_pptx(z, F):
    out = []
    sw = sh = None
    if "ppt/presentation.xml" in z.namelist():
        sz = _xml(z, "ppt/presentation.xml").find(P + "sldSz")
        if sz is not None:
            sw, sh = int(sz.get("cx", "0")), int(sz.get("cy", "0"))
    slides = sorted((n for n in z.namelist() if re.match(r"ppt/slides/slide\d+\.xml$", n)), key=lambda n: int(re.findall(r"\d+", n)[-1]))
    for name in slides:
        root = _xml(z, name)
        num = re.findall(r"\d+", name)[-1]
        hidden_slide = root.get("show") == "0"
        vis, hid = [], []
        for sp in root.iter():
            if sp.tag not in (P + "sp", P + "graphicFrame", P + "pic"):
                continue
            cnv = next((e for e in sp.iter() if e.tag == P + "cNvPr"), None)
            shape_hidden = cnv is not None and cnv.get("hidden") in ("1", "true")
            off, ext = next((e for e in sp.iter(A + "off")), None), next((e for e in sp.iter(A + "ext")), None)
            if sw and off is not None:
                x, y = int(off.get("x", "0")), int(off.get("y", "0"))
                cx, cy = (int(ext.get("cx", "0")), int(ext.get("cy", "0"))) if ext is not None else (0, 0)
                if x >= sw or y >= sh or x + cx <= 0 or y + cy <= 0:
                    shape_hidden = True  # placed outside the slide
            if cnv is not None:
                alt = (cnv.get("descr") or "") + " " + (cnv.get("title") or "")
                if hidden_instruction(alt) or DIRECTIVE.search(alt):
                    F.add("HIGH", "shape alt text with AI-directed words", f"slide {num}", short(alt, 300))
            for para in sp.iter(A + "p"):
                for r in para.iter(A + "r"):
                    t = "".join(x.text or "" for x in r.iter(A + "t"))
                    rpr = r.find(A + "rPr")
                    tiny = rpr is not None and (rpr.get("sz") or "9999").isdigit() and int(rpr.get("sz")) < 400
                    (hid if (shape_hidden or hidden_slide or tiny) else vis).append(t)
                (hid if (shape_hidden or hidden_slide) else vis).append("\n")
        if hid and "".join(hid).strip():
            _flag_hidden(F, f"slide {num}", " ".join(hid), "hidden slide" if hidden_slide else "hidden, off-slide or microscopic shape text")
        out.append(f"[slide {num}]\n" + re.sub(r"\n{2,}", "\n", "".join(vis)).strip())
    notes = [n for n in z.namelist() if re.match(r"ppt/notesSlides/notesSlide\d+\.xml$", n)]
    for name in notes:
        t = " ".join(x.text or "" for x in _xml(z, name).iter(A + "t"))
        if hidden_instruction(t) or DIRECTIVE.search(t):
            F.add("HIGH", "speaker notes with AI-directed text (not shown in the slideshow)", name, short(t, 300))
    if notes:
        F.add("INFO", "speaker notes present (excluded from output)", "ppt/notesSlides", f"{len(notes)} note page(s)")
    for name in z.namelist():
        if re.match(r"ppt/comments/.*\.xml$", name):
            _flag_hidden(F, name, " ".join(_xml(z, name).itertext()), "slide comments")
    return "\n\n".join(out)


# ---------------------------------------------------------------- XLSX
def scan_xlsx(z, F):
    S = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
    out = []
    if "xl/workbook.xml" in z.namelist():
        for sh in _xml(z, "xl/workbook.xml").iter(S + "sheet"):
            if sh.get("state") in ("hidden", "veryHidden"):
                F.add("MED", f"{sh.get('state')} worksheet", "xl/workbook.xml", sh.get("name", "?"))
    if "xl/sharedStrings.xml" in z.namelist():
        strings = ["".join(x.text or "" for x in si.iter(S + "t")) for si in _xml(z, "xl/sharedStrings.xml").iter(S + "si")]
        out.append("[shared strings - all text cells, including hidden sheets/rows]\n" + "\n".join(s for s in strings if s.strip()))
        for s in strings:
            if STRONG.search(s):
                F.add("HIGH", "cell text with an AI-directed instruction", "xl/sharedStrings.xml", short(s, 300))
    for name in z.namelist():
        if re.match(r"xl/worksheets/sheet\d+\.xml$", name):
            raw = z.read(name)[:MAX_PART]
            if re.search(rb'<row[^>]*hidden="(1|true)"', raw) or re.search(rb'<col[^>]*hidden="(1|true)"', raw):
                F.add("MED", "hidden rows/columns", name, "content not visible in the sheet")
        if re.match(r"xl/comments\d*\.xml$", name) or name.startswith("xl/threadedComments/"):
            _flag_hidden(F, name, " ".join(_xml(z, name).itertext()), "cell comments")
    return "\n\n".join(out)


# ---------------------------------------------------------------- ODF / EPUB
def scan_odf(z, F):
    root = _xml(z, "content.xml")
    hid = [" ".join(e.itertext()) for e in root.iter() if e.tag.endswith("}hidden-text") or e.tag.endswith("}hidden-paragraph")]
    if hid:
        _flag_hidden(F, "content.xml", " ".join(hid), "hidden text (ODF)")
    anns = [" ".join(e.itertext()) for e in root.iter() if e.tag.endswith("}annotation")]
    if anns:
        _flag_hidden(F, "content.xml", " ".join(anns), "annotations / comments")
    paras = []
    for e in root.iter():
        if e.tag.endswith("}p") or e.tag.endswith("}h"):
            paras.append("".join(e.itertext()))
    return "\n".join(paras)


def scan_epub(z, F):
    out = []
    for name in sorted(n for n in z.namelist() if n.lower().endswith((".xhtml", ".html", ".htm"))):
        out.append(f"[{name}]\n" + sanitize_html(z.read(name)[:MAX_PART].decode("utf-8", "replace"), F, name))
    return "\n\n".join(out)


_DEPTH = [0]


def scan_archive(z, F):
    """Generic zip: every entry is extracted (bounded) and scanned like a file of its own; nested archives up to depth 2."""
    import os, tempfile
    from .scan import scan_file
    lines = []
    infos = [i for i in z.infolist() if not i.is_dir()]
    F.add("INFO", "zip archive scanned entry by entry", "package", f"{len(infos)} file(s)")
    if _DEPTH[0] >= 2:
        F.add("MED", "nested archive too deep - inner entries not scanned", "package", "")
        return "\n".join(i.filename for i in infos)
    _DEPTH[0] += 1
    try:
        with tempfile.TemporaryDirectory() as td:
            budget = 200 * 1024 * 1024
            for n, info in enumerate(infos[:500]):
                name = info.filename
                if ".." in name.split("/") or name.startswith("/"):
                    F.add("HIGH", "zip entry with a path-traversal name", name, "would be written outside the extraction folder")
                    continue
                if info.file_size > 4 * 1024 * 1024 and info.file_size > 200 * max(1, info.compress_size):
                    F.add("MED", "compression bomb: a tiny entry unpacks to a huge file (not unpacked)", name,
                          f"{info.compress_size} bytes become {info.file_size} bytes")
                    continue
                if info.file_size > budget:
                    F.add("MED", "zip entry too large to scan", name, f"{info.file_size} bytes")
                    continue
                budget -= info.file_size
                local = os.path.join(td, f"{n}_" + os.path.basename(name))
                with open(local, "wb") as f:
                    f.write(z.read(name))
                G = type(F)()
                text, kind, _ = scan_file(local, G)
                for f_ in G.items:
                    F.add(f_["sev"], f_["kind"], f"{name} > {f_['where']}", f_["detail"])
                lines.append(f"[{name}] ({kind}, {G.verdict()})")
                if kind in ("text", "latex", "html") and text:
                    lines.append(text[:20000])
    finally:
        _DEPTH[0] -= 1
    return "\n".join(lines)


def scan_zip_doc(path, F):
    with zipfile.ZipFile(path) as z:
        names = set(z.namelist())
        total = sum(i.file_size for i in z.infolist())
        if total > 500 * 1024 * 1024:
            F.add("MED", "very large uncompressed size (zip bomb?)", "package", f"{total} bytes")
            return "", "zip"
        _meta(z, F)
        for probe, fn, kind in (("word/document.xml", scan_docx, "docx"), (None, scan_pptx, "pptx"), ("xl/workbook.xml", scan_xlsx, "xlsx"),
                                ("content.xml", scan_odf, "odf")):
            if (probe in names) if probe else any(n.startswith("ppt/slides/") for n in names):
                text = fn(z, F)
                check_text(text[:3_000_000], kind + " text", F)  # the visible text: an instruction in plain sight is still an instruction
                return text, kind
        if "META-INF/container.xml" in names:
            return scan_epub(z, F), "epub"
        return scan_archive(z, F), "zip"
