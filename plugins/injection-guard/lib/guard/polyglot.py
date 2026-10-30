"""Parser differentials - the document-level analogue of a hash collision.

A hash collision gives two different contents one identity. A polyglot or an ambiguous PDF gives one file two
contents: which one you get depends on the reader. A scanner that reads version A while the agent's reader shows
version B is fooled exactly like a hash-based allowlist fooled by a collision. These checks look for the ambiguity
itself, and scan every alternative reading they can reconstruct.
"""
import os, re, subprocess, tempfile
from .common import STRONG, KEYWORDS, check_text, short

MAGIC = [(b"\x89PNG\r\n\x1a\n", "PNG"), (b"\xff\xd8\xff", "JPEG"), (b"GIF8", "GIF"), (b"PK\x03\x04", "ZIP/Office"),
         (b"%PDF", "PDF"), (b"\x7fELF", "ELF executable"), (b"MZ", "Windows executable"), (b"{\\rtf", "RTF"),
         (b"\xd0\xcf\x11\xe0", "OLE/legacy Office"), (b"<?xml", "XML"), (b"\x1f\x8b", "gzip")]


def head_type(raw):
    for sig, name in MAGIC:
        if raw.startswith(sig):
            return name
    return None


def polyglot(path, kind, F):
    with open(path, "rb") as f:
        raw = f.read()
    first, start = raw[:1024], head_type(raw)
    pdf_at = first.find(b"%PDF")
    if pdf_at > 0:
        F.add("HIGH" if start else "MED", "polyglot: PDF header not at the start of the file", "file",
              f"{start or 'unknown data'} first, %PDF at byte {pdf_at} - readers may disagree on what this file is")
    tail = raw[-70000:]
    if kind != "zipdoc" and b"PK\x05\x06" in tail and (b"PK\x03\x04" in raw or b"PK\x01\x02" in raw):
        F.add("HIGH", f"polyglot: {kind} file also contains a ZIP archive", "file", "unzip -l the file and scan every entry")
    if kind in ("pdf", "image") and re.search(rb"<(html|script|svg|iframe|body)\b", raw[:2_000_000], re.I):
        F.add("MED", f"HTML/script markup inside a {kind} file (polyglot?)", "file", "a browser may render it as a web page")
    if kind == "image" and b"%PDF" in raw[1024:2_000_000] and b"%%EOF" in raw:
        F.add("MED", "image file contains an embedded PDF", "file", "")
    return raw


def pdf_ambiguity(raw, F, current_text):
    eofs = [m.end() for m in re.finditer(rb"%%EOF", raw)]
    if not eofs:
        F.add("MED", "PDF without %%EOF marker (damaged or truncated - readers repair it differently)", "structure", "")
        return
    trailing = raw[eofs[-1]:].strip(b"\r\n\x00 \t")
    if len(trailing) > 16:
        F.add("MED", "data after the final %%EOF", "structure", f"{len(trailing)} bytes: {short(trailing[:160].decode('latin1'), 120)!r}")
        check_text(trailing[:200000].decode("latin1"), "after %%EOF", F, hidden=True)
    objs = re.findall(rb"(?<![\d.])(\d{1,7})\s+(\d{1,5})\s+obj\b", raw)
    dup = {k for k in set(objs) if objs.count(k) > 1} if len(objs) < 200000 else set()
    if len(eofs) > 1:
        F.add("MED", f"incremental updates: {len(eofs)} revisions in one file", "structure",
              "earlier revisions are still inside; some readers or signature checkers show them")
        cur = set(current_text.split())
        with tempfile.TemporaryDirectory() as td:
            for i, cut in enumerate(eofs[:-1][:10], 1):
                p = os.path.join(td, f"rev{i}.pdf")
                with open(p, "wb") as f:
                    f.write(raw[:cut])
                try:
                    t = subprocess.run(["pdftotext", "-layout", p, "-"], capture_output=True, text=True, errors="replace", timeout=120).stdout
                except Exception:
                    continue
                only = [w for w in t.split() if w not in cur]
                if len(only) >= 3:
                    F.add("HIGH" if (STRONG.search(" ".join(only)) or KEYWORDS.search(" ".join(only))) else "MED",
                          f"earlier revision {i} shows text that the final version does not", "structure", short(" ".join(only), 300))
                    check_text(t, f"revision {i}", F, hidden=True)
    if dup:
        F.add("MED" if len(eofs) > 1 else "HIGH", "objects defined more than once (shadow-attack pattern: readers may pick different versions)",
              "structure", ", ".join(f"{a.decode()} {b.decode()} obj" for a, b in sorted(dup)[:8]))
    if raw.count(b"%PDF-") > 1:
        F.add("MED", "more than one %PDF header (concatenated or nested PDFs)", "structure", f"{raw.count(b'%PDF-')} headers")
    if b"/Encrypt" in raw:
        F.add("MED", "encrypted PDF", "structure", "content streams are only visible after decryption; check the extracted text is complete")


JS_RUNTIME = re.compile(r"this\.getField|\.value\s*=|addAnnot|addField|util\.printd|new Date|app\.setTimeOut|app\.setInterval|"
                        r"getURL|submitForm|launchURL|this\.info|app\.alert|event\.target|eval\s*\(|unescape\s*\(|String\.fromCharCode", re.I)


def pdf_javascript(blobs_text, F):
    hits = sorted(set(JS_RUNTIME.findall(blobs_text)))
    if hits:
        F.add("HIGH" if any(h.lower().startswith(("eval", "unescape", "string.fromcharcode")) for h in hits) else "MED",
              "PDF JavaScript that can change content at open time (live data: date, fields, decoded strings)", "catalog",
              ", ".join(hits[:10]) + " - a static scan cannot see what it writes")
