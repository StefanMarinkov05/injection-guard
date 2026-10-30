# Architecture

## Flow of one scan
```
safe-read FILE ──► scan.main_read ──► scan.scan_file(path, F)
                                        │  detect(): magic bytes, not the extension
                                        ├─ pdf      ─► pdf.scan_pdf            (structure, metadata, text layer, render diff,
                                        │                                      images, ambiguity, readers, forensic.*, OCR)
                                        ├─ zipdoc   ─► office.scan_zip_doc     (DOCX/PPTX/XLSX/ODF/EPUB, else scan_archive)
                                        ├─ compressed ► scan.scan_compressed   (tar, tar.gz/bz2/xz, gz/bz2/xz)
                                        ├─ image    ─► textdoc.scan_image ─► stego.deep_image, ocr.ocr_picture
                                        ├─ html     ─► web.sanitize_html       (hidden CSS/attrs, comments, data: URIs, JS, direction)
                                        ├─ text     ─► latex.scan_latex | textdoc.scan_text
                                        └─ other    ─► scan.scan_binary        (strings, macOS metadata)
                                        then polyglot.polyglot() for every non-text file
                                      ► registry_put(sha256 -> verdict)   ~/.cache/injection-guard/scanned/
                                      ► emit(): report, RULES line, visible text between <<<UNTRUSTED CONTENT nonce>>> markers
```
`safe-fetch URL` downloads with a browser user agent into `~/.cache/injection-guard/fetch/`, runs the same
`scan_file`, then `cloak_check` re-fetches as AI user agents and compares the visible words.

## Modules (`plugins/injection-guard/lib/guard/`)
| Module | Owns |
|---|---|
| `common.py` | pattern families (`STRONG`, `KEYWORDS`, `DIRECTIVE`, `IMPERSONATION`, `TASK_VOCAB`/`TASK_MODIFIER`, Unicode sets, look-alikes), `check_text()` (the text-level detector every format calls), `decoded_variants()` (ciphers/encodings), `whitespace_stego()`, `Findings`, config, registry |
| `pdf.py` | raw structure (streams, strings, names, comments, CMaps, XMP, JS), metadata/attachments, text layer + crop diff, render diff + visible-text extraction, embedded images, ActualText / remap judgement |
| `forensic.py` | glyph audit (MuPDF trace), per-glyph cover check, provenance, reference diff, glyph OCR of embedded fonts, tagged reading order |
| `readers.py` | poppler vs MuPDF vs pypdf text comparison |
| `ocr.py` | tesseract wrappers, page OCR vs text layer, faint-text OCR, picture OCR |
| `polyglot.py` | polyglot signatures, revisions, duplicate objects, trailers, PDF JavaScript runtime calls |
| `web.py` | HTML/SVG sanitiser, CSS hiding rules, data: URIs, scripts, direction tricks |
| `office.py` | DOCX/PPTX/XLSX/ODF/EPUB parsers, generic zip archives |
| `latex.py` | LaTeX/BibTeX hidden spans and compile-time code |
| `textdoc.py` | Markdown/plain text, images (metadata, faint content) |
| `stego.py` | PNG chunks, JPEG segments, alpha tricks, LSB, scaling attacks |
| `scan.py` | type detection, dispatch, archives, binaries, CLI (`safe-read`, `safe-fetch`), output envelope |
| `hooks/guard_hook.py` | `pre` (read gate, WebFetch route, shell readers, self-protection), `post` (output scan, LaTeX read check), `session` |

## Findings API
```python
F = Findings()
F.add(sev, kind, where, detail)   # sev: "HIGH" | "MED" | "INFO"; duplicates (same 4-tuple) are dropped
F.verdict()                       # "HIGH" if any HIGH, else "MED" if any MED, else "clean"
```
Tests assert on `kind` substrings (`has_kind(F, "covered glyphs", "HIGH")`). **Renaming a `kind` breaks tests and the
docs mapping** - keep the wording, or update both deliberately.

## Severity rules
- **HIGH**: hidden or encoded text aimed at an AI, impersonation, a hidden directive or task modifier, a structural
  trick that only makes sense for hiding (invisible render mode with text, ToUnicode remap confirmed by spelling,
  appended stream with invisible text, earlier revision with AI text ...).
- **MED**: something a reader could see differently from a human without proof of intent (hidden text without AI
  words, off-page text, faint ink, polyglot signs, live scripts, failed scan steps). Raw reads stay blocked (`block_on: MED`).
- **INFO**: normal but worth knowing (accessibility ActualText that matches the glyphs, LaTeX author comments,
  math-font duplicate glyphs, light-grey design text).
- `check_text(text, where, F, hidden=...)`: `hidden=True` means a human never sees this text - keywords, directives and
  task vocabulary become HIGH. Visible directives are INFO (students see them too).

## Hooks and the registry
The pre-hook denies raw reads of documents whose SHA-256 has no registry entry, and of entries with verdict HIGH/MED
(strict mode). Trust is bound to the exact bytes: any change re-opens the gate. Guard files, cache and the plugin's
settings entry are protected with `ask`. Config: `~/.config/injection-guard/config.json` (`mode`, `block_on`,
`trusted_paths`, `html_in_git_is_source`), environment override `INJECTION_GUARD_MODE`.
