"""Parser differential for PDFs: read the same file with independent readers and compare.

poppler (pdftotext), MuPDF (mutool) and pypdf implement ActualText, broken xrefs, incremental updates, object
streams and font maps differently. Text that only some readers extract is text that only some agents receive -
the document-level version of a hash collision.
"""
import os, re, shutil, subprocess, unicodedata
from .common import DIRECTIVE, KEYWORDS, STRONG, check_text, short


def _words(t):
    from .ocr import dictionary
    D = dictionary()
    w = re.findall(r"[^\W\d_]{3,}", t.lower())
    return [x for x in w if x in D] if D else w  # real words only: readers differ in how they mangle math


def mutool_text(path):
    import pwd
    exe = shutil.which("mutool") or os.path.join(pwd.getpwuid(os.getuid()).pw_dir, ".local/bin/mutool")
    if not os.path.exists(exe):
        return None
    try:
        return subprocess.run([exe, "draw", "-F", "txt", "-o", "-", path], capture_output=True, text=True,
                              errors="replace", timeout=300).stdout
    except Exception:
        return None


def pypdf_text(path):
    try:
        import pypdf
    except Exception:
        return None
    try:
        r = pypdf.PdfReader(path, strict=False)
        return "\n".join((p.extract_text() or "") for p in r.pages[:500])
    except Exception as e:
        return f"__error__ {e}"


def _flat(t):
    t = unicodedata.normalize("NFKC", t).lower()
    return "".join(c for c in t if c.isalnum())


def differential(path, poppler_text, F):
    base = _words(unicodedata.normalize("NFKC", poppler_text))
    bset = set(base)
    bflat = _flat(poppler_text)
    seen = []
    for name, fn in (("MuPDF", mutool_text), ("pypdf", pypdf_text)):
        t = fn(path)
        if t is None:
            F.add("INFO", f"{name} not available for the reader comparison", "readers", "")
            continue
        if t.startswith("__error__"):
            F.add("MED", f"{name} cannot parse this PDF but poppler can (readers disagree on the structure)", "readers", t[10:130])
            continue
        other = _words(unicodedata.normalize("NFKC", t))
        oset, oflat = set(other), _flat(t)
        # spacing differs between readers ("x contains" vs "xcontains"): a word only counts if its letters are absent
        only_other = [w for w in dict.fromkeys(other) if w not in bset and w not in bflat]
        only_base = [w for w in dict.fromkeys(base) if w not in oset and w not in oflat]
        for words, who in ((only_other, f"only {name}"), (only_base, f"poppler but not {name}")):
            if len(words) >= 3:
                joined = " ".join(words)
                rawdiff = " ".join(w for w in re.findall(r"[^\W\d_]{2,}", (t if who.startswith("only") else poppler_text).lower())
                                   if w not in (bflat if who.startswith("only") else oflat))
                bad = any(rx.search(x) for rx in (STRONG, KEYWORDS, DIRECTIVE) for x in (joined, rawdiff))
                share = len(words) / max(1, len(set(base) | oset))
                if bad or share > 0.02 or len(words) >= 15:
                    F.add("HIGH" if bad else "MED", f"PDF readers disagree: text extracted by {who}", "readers", short(joined, 300))
                    if bad:
                        check_text(joined, f"readers ({who})", F, hidden=True)
        seen.append(name)
    return seen
