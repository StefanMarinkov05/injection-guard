"""OCR cross-checks (tesseract, optional): what is drawn vs what the text layer says.

- text layer swaps: a word on the page reads 'abc' but the text layer says 'acb' (ToUnicode/CID remaps,
  swapped glyph shapes, homoglyph fonts) - the "story" a machine reads differs from the printed one
- systematic character swaps: the same letter pair differs again and again -> deliberate remap
- page text missing from the text layer: drawn as paths/images (a vision model reads it, extractors do not)
- faint text: words that only appear after contrast enhancement
"""
import difflib, os, re, shutil, subprocess, tempfile, unicodedata
from collections import Counter
from PIL import Image, ImageOps
from .common import STRONG, KEYWORDS, DIRECTIVE, check_text, short

# pairs tesseract confuses on clean pages - never counted as evidence
OCR_NOISE = {("l", "i"), ("i", "l"), ("1", "l"), ("l", "1"), ("0", "o"), ("o", "0"), ("i", "1"), ("1", "i"), ("rn", "m"),
             ("m", "rn"), ("c", "e"), ("e", "c"), ("u", "n"), ("n", "u"), ("5", "s"), ("s", "5"), ("8", "b"), ("b", "8"),
             ("vv", "w"), ("w", "vv"), ("f", "t"), ("t", "f"), ("q", "g"), ("g", "q"), ("cl", "d"), ("d", "cl"), ("h", "b"), ("b", "h")}


def tesseract():
    import pwd
    exe = shutil.which("tesseract") or os.path.join(pwd.getpwuid(os.getuid()).pw_dir, ".local/bin/tesseract")
    return exe if os.path.exists(exe) else None


def ocr_image(img_path, psm="3"):
    exe = tesseract()
    if not exe:
        return None
    try:
        # dictionaries off: tesseract must not "correct" what is printed (a typo or a swapped letter is evidence)
        return subprocess.run([exe, img_path, "-", "--psm", psm, "-c", "load_system_dawg=0", "-c", "load_freq_dawg=0"],
                              capture_output=True, text=True, errors="replace", timeout=300).stdout
    except Exception:
        return None


def norm_tokens(text):
    t = unicodedata.normalize("NFKD", unicodedata.normalize("NFKC", text))
    t = "".join(c for c in t if not unicodedata.combining(c)).lower()
    return re.findall(r"[a-z0-9]+", t)


def _pairs(a, b):
    out = []
    for op, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if op == "replace":
            out.append((a[i1:i2], b[j1:j2]))
    return out


_DICT = None


def dictionary():
    global _DICT
    if _DICT is None:
        _DICT = set()
        for f in ("/usr/share/dict/american-english", "/usr/share/dict/british-english", "/usr/share/dict/words",
                  "/usr/share/dict/ngerman"):
            try:
                with open(f, errors="ignore") as fh:
                    _DICT |= {w.strip().lower() for w in fh if w.strip().isalpha()}
            except Exception:
                pass
    return _DICT


def compare(layer_text, ocr_text, where, F):
    L, O = norm_tokens(layer_text), norm_tokens(ocr_text)
    if len(L) < 5 or len(O) < 5:
        return
    D = dictionary()
    real = (lambda w: w in D) if D else (lambda w: len(w) >= 4)
    lflat = "".join(L)
    words, digits, weak, swaps = [], [], [], Counter()
    lset = set(L)
    # words: position-independent (a swap breaks any alignment) - a non-word in the text layer is paired with the
    # closest real word of the same length on the page that differs in at most a third of its letters
    oset = {w for w in O if w.isalpha() and real(w)}
    by_len = {}
    for w in oset:
        by_len.setdefault(len(w), []).append(w)
    for x in dict.fromkeys(L):
        if not x.isalpha() or len(x) < 3 or real(x) or x in oset:
            continue
        best = None
        for y in by_len.get(len(x), ()):
            diff = [(a, b) for a, b in zip(x, y) if a != b]
            if diff and len(diff) <= max(1, int(len(x) * 0.4)) and (best is None or len(diff) < len(best[1])):
                best = (y, diff)
        if best:
            ps = [p for p in best[1] if p not in OCR_NOISE]
            if ps and best[0] in lset:
                weak.append(f"text '{x}' / page '{best[0]}'")  # the page word is also in the text layer: likely a typo or a name
            elif ps:
                words.append(f"text '{x}' / page '{best[0]}'")
                swaps.update(ps * L.count(x))
    for op, i1, i2, j1, j2 in difflib.SequenceMatcher(None, L, O, autojunk=False).get_opcodes():
        if op != "replace" or (i2 - i1) != (j2 - j1):
            continue
        for k, (x, y) in enumerate(zip(L[i1:i2], O[j1:j2])):
            if x == y or len(x) != len(y):
                continue
            if x.isdigit() and y.isdigit():
                i = i1 + k
                prev = L[i - 1] if i > 0 else ""
                nxt = L[i + 1] if i + 1 < len(L) else ""
                subscript = len(prev) == 1 and prev.isalpha()  # s1, q0, x2: OCR misreads subscripts
                prev_ok = len(prev) >= 3 and prev.isalpha() and real(prev)
                next_ok = len(nxt) >= 3 and nxt.isalpha() and real(nxt)
                if (prev_ok or next_ok) and not subscript:  # a number inside a sentence, not a label or subscript
                    digits.append(f"text '{x}' / page '{y}' (near '{L[i - 1] if i else ''}')")
                    swaps.update(_pairs(x, y))
    systematic = [(a, b, n) for (a, b), n in swaps.items() if n >= 3]
    if systematic:
        F.add("HIGH", "systematic character swap between page image and text layer (remapped font?)", where,
              ", ".join(f"page '{b}' / text '{a}' x{n}" for a, b, n in systematic[:6]) + f"; {short(', '.join(words + digits), 200)}")
    if weak and not systematic:
        F.add("INFO", "OCR word mismatches that are probably typos or names (the page word also occurs in the text layer)", where,
              short(", ".join(weak[:10]), 200))
    if systematic:
        pass
    elif words or digits:
        F.add("MED", "page image and text layer disagree (OCR cross-check) - check these words/numbers on the page", where,
              short(", ".join(words + digits), 300))
    # reverse: runs of real words in the text layer that the page does not show (covered by an image, same colour, ...)
    oflat = "".join(O)
    run, runs = [], []
    for w in L:
        if w.isalpha() and len(w) >= 4 and real(w) and w not in oflat:
            run.append(w)
        elif w.isalpha() and len(w) >= 4:
            if len(run) >= 4:
                runs.append(" ".join(run))
            run = []
    if len(run) >= 4:
        runs.append(" ".join(run))
    if runs:
        joined = " / ".join(runs)
        sev = "HIGH" if (STRONG.search(layer_text) or KEYWORDS.search(joined) or DIRECTIVE.search(layer_text)) else "MED"
        F.add(sev, "text-layer words not visible on the page (covered, same colour or drawn elsewhere - OCR)", where, short(joined, 300))
    missing = [w for w in dict.fromkeys(O) if w.isalpha() and len(w) >= 4 and real(w) and w not in lflat]
    if len(missing) >= 3:
        joined = " ".join(missing)
        sev = "HIGH" if (STRONG.search(ocr_text) and not STRONG.search(layer_text)) or KEYWORDS.search(joined) or DIRECTIVE.search(joined) else "MED"
        F.add(sev, "words visible on the page but absent from the text layer (drawn as image/paths - vision models read them)",
              where, short(joined, 300))
        lines = [ln for ln in ocr_text.splitlines() if any(w in norm_tokens(ln) for w in missing)]
        check_text(ocr_norm("\n".join(lines)), where + " (OCR, not in text layer)", F)


def faint_text(img_path, base_ocr, where, F, layer_text=None):
    """Erase normal ink and its antialiasing halo, make what is left (light-grey marks) black, OCR it.
    On a clean page nothing is left; faint text becomes readable."""
    from PIL import ImageFilter
    im = Image.open(img_path).convert("L")
    halo = im.filter(ImageFilter.MinFilter(7))          # dark pixels grow by 3 px
    keep = halo.point(lambda v: 255 if v >= 200 else 0)  # 255 = far from normal ink
    faint = im.point(lambda v: 255 if 200 <= v <= 250 else 0)
    from PIL import ImageChops
    mask = ImageChops.multiply(keep, faint)
    if mask.histogram()[255] < 80:
        return
    out = ImageOps.invert(mask)                          # faint marks -> black on white
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "f.png")
        out.save(p)
        t = ocr_image(p)
    if not t:
        return
    words = [w for w in norm_tokens(t) if len(w) >= 3 and w.isalpha()]
    if layer_text is not None and words:
        lflat = "".join(norm_tokens(layer_text))
        new = [w for w in words if w not in lflat]
        if len(new) < max(2, len(words) // 4):  # light-grey text that is also in the text layer: visible design, not hidden
            F.add("INFO", "light-grey text (also present in the text layer)", where, short(" ".join(words), 120))
            return
        words = new
    if len(words) >= 2:
        joined = " ".join(words)  # only the words that are NOT in the text layer
        sev = "HIGH" if (STRONG.search(joined) or KEYWORDS.search(joined) or DIRECTIVE.search(joined) or len(words) >= 6) else "MED"
        F.add(sev, "faint text readable only after removing normal ink and boosting contrast (OCR)", where, short(joined, 300))
        check_text(ocr_norm(joined), where + " (faint text, OCR)", F, hidden=True)


def ocr_pdf(path, F, page_texts, max_pages=30):
    """page_texts: {page_number: visible text from the text layer}."""
    if not tesseract():
        F.add("INFO", "OCR cross-check skipped (tesseract not installed)", "document", "")
        return
    n = len(page_texts)
    pages = sorted(page_texts)[:max_pages]
    with tempfile.TemporaryDirectory() as td:
        for p in pages:
            subprocess.run(["pdftoppm", "-r", "300", "-gray", "-png", "-cropbox", "-f", str(p), "-l", str(p), path, os.path.join(td, f"o{p}")],
                           capture_output=True, timeout=300)
            img = next((os.path.join(td, f) for f in os.listdir(td) if f.startswith(f"o{p}-") or f.startswith(f"o{p}.")), None)
            if not img:
                continue
            t = ocr_image(img)
            if t is None:
                continue
            compare(page_texts[p], t, f"p.{p}", F)
            faint_text(img, t, f"p.{p}", F, page_texts[p])
            os.remove(img)
    if n > len(pages):
        F.add("INFO", "OCR cross-check limited", "document", f"first {len(pages)} of {n} pages (--ocr-pages)")


_AI_NOUN = (r"assistants?|agents?|models?|systems?|readers?|tools?|chatbots?|crawlers?|reviewers?|summari[sz]\w*|"
            r"bots?|screeners?|filters?|helpers?|copilots?")


def ocr_norm(t):
    """A copy of OCR text for the phrase checks only: tesseract reads the capital I of 'AI' as a lowercase l ('Al'), which
    hides every address to AI readers in rendered text (bench mail-image-visible, 2026-11-20). Names stay names."""
    t = re.sub(rf"\b[Aa][l1|](?=[\s-]+(?:{_AI_NOUN})\b)", "AI", t)
    return re.sub(r"\b([Tt]o|[Ff]or|[Dd]ear|[Hh]ey|[Aa]ttention)(\s+)[Aa][l1|](?=[\s:,.!])", r"\1\2AI", t)


def ocr_picture(path, F):
    """Text drawn in an image: transcribe it (as data) and phrase-check it."""
    if not tesseract():
        return ""
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "i.png")
        im = Image.open(path)
        im = im.convert("RGBA") if im.mode in ("P", "LA", "RGBA") else im.convert("RGB")
        if im.mode == "RGBA":
            bg = Image.new("RGBA", im.size, (255, 255, 255, 255))
            im = Image.alpha_composite(bg, im)
        g = im.convert("L")
        if g.width < 1000:
            g = g.resize((g.width * 2, g.height * 2))
        g.save(p)
        t = ocr_image(p) or ""
        if t.strip():
            n = ocr_norm(t)
            check_text(n, "image text (OCR)", F)
            if DIRECTIVE.search(n):
                F.add("MED", "image contains naming/notation/authority directives (OCR)", "image", short(DIRECTIVE.search(n).group(0)))
        faint_text(p, t, "image", F)
    return t
