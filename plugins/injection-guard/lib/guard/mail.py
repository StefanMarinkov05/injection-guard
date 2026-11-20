"""Email messages (.eml / MIME): decode every part and scan it like a file of its own.

Before this module, .eml files were scanned as raw text, so base64 or quoted-printable bodies, HTML parts (hidden
text) and attachments (PDF, Office, images, archives) were never decoded. Now:
  - headers that a reader sees (From, To, Subject, Date) are checked for directives and passed on;
  - text/plain parts go through the text scanner, text/html parts through the HTML renderer (hidden text removed);
  - every attachment is written to a temporary file and scanned recursively (bounded depth, size and count);
    findings carry the attachment name in their location;
  - attachment names are checked for directives, and a declared type that does not match the content is reported.
The module is named mail, not email, so it never shadows the standard library package it uses.
"""
import email, email.policy, os, re, tempfile
from .common import DIRECTIVE, KEYWORDS, STRONG, Findings, check_text, hidden_instruction, short

HEADER_RX = re.compile(rb"^(?:From|To|Subject|Date|Received|Return-Path|Message-ID|MIME-Version|Content-Type|Delivered-To|Reply-To)\s*:", re.I | re.M)
MAX_DEPTH, MAX_PARTS, MAX_BYTES = 3, 100, 100 * 1024 * 1024
_DEPTH = [0]
DECLARED = {"application/pdf": "pdf", "image/png": "image", "image/jpeg": "image", "image/gif": "image", "image/webp": "image",
            "text/html": "html", "application/zip": "zipdoc", "application/gzip": "compressed"}
OFFICE = ("application/vnd.openxmlformats", "application/vnd.oasis.opendocument", "application/epub")


def looks_like_email(head):
    """True if the first bytes are RFC 822 headers: at least two known header lines before the first blank line."""
    top = head.split(b"\n\n", 1)[0].split(b"\r\n\r\n", 1)[0]
    return len(HEADER_RX.findall(top)) >= 2 and top.lstrip()[:1].isalpha()


SECRET_FILE = re.compile(r"\.aws/credentials|\.ssh/id_[a-z0-9]+\b(?!\.pub)|\bid_(rsa|ed25519|ecdsa|dsa)\b(?!\.pub)|private (ssh )?key|"
                         r"\.netrc\b|\.kube/config|\.git-credentials|\.npmrc\b|\.pypirc\b|(?<![\w.])\.env\b", re.I)
SEND_VERB = re.compile(r"\b(reply|respond|send|paste|attach|forward|upload|share|e-?mail)\b", re.I)


def asks_for_secrets(text, where, F):
    """A sentence that names a key or credential file and asks for it to be sent: phishing aimed at whoever handles the
    mailbox, a person or an agent with file access (bench mail-body-secret-request). Plain mentions do not count."""
    for sent in re.split(r"(?<=[.!?])\s+|\n+", text):
        if SECRET_FILE.search(sent) and SEND_VERB.search(sent) and not re.search(r"\b(never|do not|don't)\b", sent, re.I):
            F.add("HIGH", "email asks for credentials or private keys", where, short(sent, 200))
            return


def directive_name(name):
    spaced = re.sub(r"[_\-.]+", " ", name)
    return bool(hidden_instruction(spaced) or DIRECTIVE.search(spaced) or STRONG.search(spaced)
                or (KEYWORDS.search(spaced) and re.search(r"\b(ignore|forward|send|run|execute|must|should)\b", spaced, re.I)))


def scan_email(path, F):
    from .scan import scan_file
    from .textdoc import scan_text
    from .web import sanitize_html
    if _DEPTH[0] >= MAX_DEPTH:
        F.add("MED", "email nested too deep - inner message not opened", "email", "")
        return ""
    _DEPTH[0] += 1
    try:
        with open(path, "rb") as f:
            m = email.message_from_binary_file(f, policy=email.policy.default)
        out = []
        for h in ("From", "To", "Cc", "Reply-To", "Subject", "Date"):
            v = m.get(h)
            if v:
                out.append(f"{h}: {v}")
        # every header, not only the visible ones: Read shows the agent the raw headers, X- headers included
        for k, v in m.items():
            if k.lower() not in ("received", "dkim-signature", "arc-seal", "arc-message-signature", "x-google-dkim-signature"):
                check_text(str(v), f"email header {k}", F)
        out.append("")
        parts = list(m.walk())
        if len(parts) > MAX_PARTS:
            F.add("MED", "email with too many parts - only the first ones scanned", "email", f"{len(parts)} parts")
        budget, html_seen = MAX_BYTES, False
        with tempfile.TemporaryDirectory() as td:
            for n, part in enumerate(parts[:MAX_PARTS]):
                if part.is_multipart():
                    continue
                ctype = part.get_content_type()
                name = part.get_filename()
                disp = (part.get_content_disposition() or "").lower()
                try:
                    data = part.get_payload(decode=True) or b""
                except Exception as e:
                    F.add("MED", "email part could not be decoded", f"part {n}", str(e)[:120])
                    continue
                budget -= len(data)
                if budget < 0:
                    F.add("MED", "email too large - remaining parts not scanned", "email", "")
                    break
                if not name and disp != "attachment" and ctype in ("text/plain", "text/html"):
                    txt = data.decode(part.get_content_charset() or "utf-8", "replace")
                    if ctype == "text/html":
                        html_seen = True
                        out.append(sanitize_html(txt, F, f"email body (html, part {n})"))
                    else:
                        out.append(scan_text(txt, F, f"email body (part {n})", markdown=False))
                    asks_for_secrets(out[-1], f"email body (part {n})", F)
                    continue
                name = name or f"part-{n}.bin"
                if directive_name(name):
                    F.add("HIGH", "attachment name addressed to an AI or with a directive", "email attachments", short(name, 200))
                local = os.path.join(td, f"{n}_" + re.sub(r"[^\w.-]", "_", os.path.basename(name))[-120:])
                with open(local, "wb") as f:
                    f.write(data)
                G = Findings()
                text, kind, _ = scan_file(local, G)
                for f_ in G.items:
                    F.add(f_["sev"], f_["kind"], f"attachment {name} > {f_['where']}", f_["detail"])
                want = DECLARED.get(ctype) or ("zipdoc" if ctype.startswith(OFFICE) else None)
                if want and kind != want and not (want == "zipdoc" and kind in ("docx", "xlsx", "pptx", "odt", "epub", "zipdoc")):
                    F.add("MED", "attachment content does not match its declared type", f"attachment {name}", f"declared {ctype}, content {kind}")
                out.append(f"[attachment {name}] ({ctype}, {kind}, {G.verdict()})")
                if text:
                    out.append(text[:20000])
        if html_seen:
            F.add("INFO", "email has an HTML part - shown as rendered, hidden text removed", "email", "")
        return "\n".join(out)
    finally:
        _DEPTH[0] -= 1
