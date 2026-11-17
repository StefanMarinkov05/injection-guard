"""Deep image checks: raw PNG chunks / JPEG segments, strings in the file bytes, transparent-pixel content,
dark-background-only content, LSB steganography, and image-scaling attacks (text that appears after downscaling).

None of these payloads are visible to a human looking at the picture. Some are visible to a vision model
(scaling, alpha, dark background), some only to a tool that decodes them (chunks, LSB) - which an injected
instruction may ask the agent to run.
"""
import re, struct, zlib
from PIL import Image, ImageChops
from .common import hidden_instruction
from .common import KEYWORDS, STRONG, check_text, short

KNOWN_PNG = {b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"cHRM", b"gAMA", b"iCCP", b"sBIT", b"sRGB", b"cICP", b"mDCv",
             b"cLLi", b"tEXt", b"zTXt", b"iTXt", b"bKGD", b"hIST", b"pHYs", b"sPLT", b"eXIf", b"tIME", b"acTL", b"fcTL",
             b"fdAT", b"oFFs", b"pCAL", b"sCAL", b"sTER", b"gIFg", b"gIFx", b"vpAg", b"caBX", b"iDOT"}
PRINTABLE_RUN = re.compile(rb"[\x20-\x7e\t\r\n]{12,}")


def _texty(b):
    return [m.decode("latin1") for m in PRINTABLE_RUN.findall(b)]


def png_chunks(raw, F, where):
    if not raw.startswith(b"\x89PNG\r\n\x1a\n"):
        return
    i, n = 8, 0
    while i + 8 <= len(raw) and n < 100000:
        n += 1
        ln, typ = struct.unpack(">I4s", raw[i:i + 8])
        data = raw[i + 8:i + 8 + ln]
        crc = raw[i + 8 + ln:i + 12 + ln]
        if len(crc) == 4 and struct.unpack(">I", crc)[0] != (zlib.crc32(typ + data) & 0xFFFFFFFF):
            F.add("MED", "PNG chunk with wrong checksum (edited by hand?)", where, typ.decode("latin1"))
        if typ not in KNOWN_PNG:
            payload = data
            try:
                payload = zlib.decompress(data)
            except Exception:
                pass
            texts = " ".join(_texty(payload))
            F.add("MED", f"unknown PNG chunk '{typ.decode('latin1')}' ({ln} bytes) - ignored by viewers", where, short(texts, 160))
            check_text(texts, where + f" chunk {typ.decode('latin1')}", F, hidden=True)
        if typ in (b"tEXt", b"zTXt", b"iTXt"):
            body = data
            if typ == b"zTXt":
                try:
                    body = data.split(b"\0", 1)[0] + b" " + zlib.decompress(data.split(b"\0", 1)[1][1:])
                except Exception:
                    pass
            if typ == b"iTXt":
                parts = data.split(b"\0", 5)
                if len(parts) == 6 and parts[1][:1] == b"\x01":
                    try:
                        body = parts[0] + b" " + zlib.decompress(parts[5])
                    except Exception:
                        pass
            check_text(body.decode("utf-8", "replace"), where + f" {typ.decode()} chunk", F, hidden=True)
        if typ == b"IEND":
            break
        i += 12 + ln


def jpeg_segments(raw, F, where):
    if not raw.startswith(b"\xff\xd8"):
        return
    i = 2
    while i + 4 <= len(raw):
        if raw[i] != 0xFF:
            break
        marker = raw[i + 1]
        if marker in (0xD9, 0xDA):  # end / start of scan
            break
        ln = struct.unpack(">H", raw[i + 2:i + 4])[0]
        seg = raw[i + 4:i + 2 + ln]
        if marker == 0xFE or 0xE0 <= marker <= 0xEF:
            name = "COM comment" if marker == 0xFE else f"APP{marker - 0xE0}"
            texts = " ".join(_texty(seg))
            if texts:
                check_text(texts, where + f" JPEG {name}", F, hidden=True)
                if marker == 0xFE:
                    F.add("INFO", "JPEG comment segment", where, short(texts, 120))
        i += 2 + ln


def file_strings(raw, F, where):
    """Any instruction-like string anywhere in the bytes (headers, trailers, private chunks, polyglot parts)."""
    for s in _texty(raw[:40_000_000]):
        if hidden_instruction(s):
            F.add("HIGH", "AI-directed text inside the image file bytes (not part of the picture)", where, short(s, 300))
            break


def alpha_tricks(im, F, where):
    if im.mode not in ("RGBA", "LA", "PA") and not (im.mode == "P" and "transparency" in im.info):
        return
    rgba = im.convert("RGBA")
    if rgba.width * rgba.height > 25_000_000:
        rgba = rgba.resize((rgba.width // 3, rgba.height // 3))
    a = rgba.getchannel("A")
    rgb = rgba.convert("RGB")
    white = Image.alpha_composite(Image.new("RGBA", rgba.size, (255, 255, 255, 255)), rgba).convert("L")
    black = Image.alpha_composite(Image.new("RGBA", rgba.size, (0, 0, 0, 255)), rgba).convert("L")
    dropped = rgb.convert("L")
    transparent = a.point(lambda v: 255 if v < 8 else 0)
    # content in fully transparent pixels: a pipeline that ignores alpha shows it, a human never does
    # (transparent pixels usually share one stored colour, often black - only variation among them is content)
    hist = dropped.histogram(mask=transparent)
    hidden = 0
    if sum(hist):
        dom = max(range(256), key=lambda v: hist[v])
        hidden = sum(hist[v] for v in range(256) if abs(v - dom) > 64)
    if hidden > 150:
        F.add("HIGH", "content hidden in fully transparent pixels (appears when the alpha channel is dropped)", where,
              f"{hidden} pixels")
    # content visible only on a dark background (white-ish semi-transparent text)
    semi = a.point(lambda v: 255 if v < 250 else 0)
    if semi.histogram()[255] == 0:
        return  # fully opaque: nothing can hide behind the background
    on_white_blank = white.point(lambda v: 255 if v > 245 else 0)
    on_black_ink = black.point(lambda v: 255 if v > 64 else 0)
    dark_only = ImageChops.multiply(ImageChops.multiply(on_white_blank, on_black_ink), semi).histogram()[255]
    if dark_only > 150:
        F.add("MED", "content visible only on a dark background (invisible on white)", where, f"{dark_only} pixels")


def lsb_payload(im, F, where):
    rgb = im.convert("RGB")
    if rgb.width * rgb.height > 16_000_000:
        return
    data = rgb.tobytes()[:3_000_000]
    to01 = bytes((48 + (v & 1)) for v in range(256))
    planes = {"RGB": data, "R": data[0::3], "G": data[1::3], "B": data[2::3]}
    for name, plane in planes.items():
        s = plane.translate(to01)
        s = s[: len(s) // 8 * 8]
        if not s:
            continue
        msb = int(s, 2).to_bytes(len(s) // 8, "big")
        lsb = int(s[::-1], 2).to_bytes(len(s) // 8, "big")[::-1]
        for order, b in (("MSB-first", msb), ("LSB-first", lsb)):
            runs = [r.decode("latin1") for r in re.findall(rb"[\x20-\x7e\t\n]{24,}", b[:400_000])]
            words = [r for r in runs if re.search(r"\b[A-Za-z]{3,}+ [A-Za-z]{2,}+ [A-Za-z]{3,}+", r)]
            if words:
                txt = " ".join(words)
                sev = "HIGH" if (hidden_instruction(txt)) else "MED"
                F.add(sev, f"LSB steganography: readable text in the lowest bit plane ({name}, {order})", where, short(txt, 300))
                if sev == "HIGH":
                    check_text(txt, where + " LSB payload", F, hidden=True)
                return


def scaling_attack(im, F, where):
    """Text planted so that nearest-neighbour downscaling (as some model pipelines do) reveals it."""
    g = im.convert("L")
    if min(g.size) < 256 or g.width * g.height > 40_000_000:
        return
    w, h = g.size
    raw = g.tobytes()
    worst = (0, 0, 0)
    for f in (3, 4, 5, 6, 8):  # factor-2 attacks show as visible grey dots, and ordinary bold text trips it
        avg = g.reduce(f)
        aw, ah = avg.size
        for phase in sorted({0, f // 2}):
            rows = []
            for y in range(ah):
                yy = min(h - 1, y * f + phase)
                row = raw[yy * w + phase: yy * w + w: f][:aw]
                rows.append(row.ljust(aw, b"\xff"))
            near = Image.frombytes("L", (aw, ah), b"".join(rows))
            dark_near = near.point(lambda v: 255 if v < 80 else 0)
            t = 255 * (1 - 1.5 / (f * f))  # an isolated dark sample pixel averages to about this
            light_avg = avg.point(lambda v, t=t: 255 if v > t else 0)
            n = ImageChops.multiply(dark_near, light_avg).histogram()[255]
            frac = n / (aw * ah)
            if frac > worst[0]:
                worst = (frac, f, n)
    frac, f, n = worst
    if n > 60 and frac > 0.004:
        F.add("MED" if frac < 0.02 else "HIGH", "image-scaling attack: dark content appears only after downscaling", where,
              f"factor {f}: {n} pixels ({frac:.1%}) are dark when sampled but light when averaged - view the image downscaled")


def deep_image(path, im, F):
    raw = open(path, "rb").read()
    png_chunks(raw, F, path)
    jpeg_segments(raw, F, path)
    file_strings(raw, F, path)
    for fn in (alpha_tricks, lsb_payload, scaling_attack):
        try:
            fn(im, F, path)
        except Exception as e:
            F.add("MED", f"image check {fn.__name__} failed - scan incomplete", path, str(e)[:120])
