# injection-guard

Prompt-injection defence for Claude Code, active in every project (user-scope plugin from the local marketplace `agent-guard` at `~/Projects/injection-guard`).

## What it does
| Part | File | Effect |
|---|---|---|
| `safe-read FILE` | `bin/safe-read` | scans a local file and prints a findings report plus **only the text a human can see**, between random-nonce markers |
| `safe-fetch URL` | `bin/safe-fetch` | downloads with a browser user agent into `~/.cache/injection-guard/fetch/`, scans, re-fetches as AI agents to detect cloaking |
| hooks | `hooks/hooks.json`, `hooks/guard_hook.py` | **pre:** raw Read/`cat`/`pdftotext`/... of PDF, Office, EPUB, RTF (and HTML/SVG outside git repos) is denied until scanned; files with HIGH or MED findings stay blocked for raw reads; WebFetch is routed to safe-fetch; edits to the guard's config, cache, plugin or its settings entry ask the user. **post:** output of Bash, Read, Grep, WebFetch, WebSearch, Agent and all MCP tools is checked for invisible Unicode, encoded and AI-directed instructions; findings are added to the model's context and shown to the user. **session:** one-paragraph notice |
| skill | `skills/injection-guard/SKILL.md` | procedure and reporting rules |
| agent | `agents/quarantine-reader.md` | read-only reader that returns a fixed-format digest of a sanitised document |
| library | `lib/guard/` | `common` (phrases, impersonation, task modifiers, Unicode, decoders, registry), `pdf`, `forensic` (glyph audit, cover check, provenance, reference diff, glyph OCR), `readers` (poppler/MuPDF/pypdf), `ocr`, `web`, `office`, `latex`, `textdoc`, `stego`, `polyglot`, `scan` (incl. zip/tar/gz/bz2/xz) |
| tests | `tests/` | regression suite: `python3 -I tests/run_tests.py [-v]`; `tests/report.py` records every result for the docs; `test_redteam*.py` = attacks that once got through |
| docs | `../../docs/` | `MECHANISMS.md` and `build/mechanisms.pdf`: every mechanism with target, attack vector, behaviour and the tests that prove it (generated from the last recorded run by `docs/gen_docs.py`) |

Every scan is recorded in `~/.cache/injection-guard/scanned/<sha256>.json`. Trust is bound to the exact bytes: changing one byte (or swapping the file with one of the same name, size and time) re-opens the gate.

## Formats
PDF, DOCX/PPTX/XLSX/ODF/EPUB, HTML/XHTML/SVG, Markdown/text/JSON/code, LaTeX/BibTeX (`.tex .sty .cls .bib`, with compile-time shell-escape detection), images (PNG/JPEG/GIF/WebP/TIFF), archives (zip, tar, tar.gz/bz2/xz, gz/bz2/xz; 7z/rar flagged), macOS metadata, unknown binaries (strings).

Useful options: `--images DIR` (page PNGs), `--ocr-pages N` (default 15, 0 = off), `--reference KNOWN_GOOD.pdf` (structural diff, e.g. against last week's sheet), `--out FILE`, `--json`.

## Configuration
`~/.config/injection-guard/config.json`:
```json
{ "mode": "strict", "block_on": "MED", "trusted_paths": [], "html_in_git_is_source": true }
```
- `mode`: `strict` (block), `warn` (only warnings), `off`. Environment override for one session: `INJECTION_GUARD_MODE=warn claude`.
- `block_on`: `MED` (default, recall first) or `HIGH`.
- `trusted_paths`: folders whose documents skip the read gate (output warnings still apply). Only add folders whose files you produce yourself.

## Severity
HIGH = hidden or encoded content aimed at an AI, or a structural trick that only makes sense for hiding. MED = something a reader could see differently from a human (hidden text without AI words, off-page text, faint ink, polyglot signs, live scripts, failed scan steps). INFO = normal but worth knowing. **Design choice: false positives over misses.** An unreadable file is never clean.

## Updating
Edit the source here, run the tests, then `claude plugin marketplace update agent-guard && claude plugin update injection-guard@agent-guard` (or reinstall). The commands on PATH are symlinks into this source tree and update immediately; the hooks run from the installed copy.

When a new technique appears: add a fixture or a builder-based test first (it should fail), then extend the scanner until the whole suite passes. Never delete an old test - the suite is the memory of every trap that was ever caught.

## Extra tools (user space, no sudo)
`tesseract` (OCR, eng+deu), `mutool` (MuPDF), `qpdf`, venv with `pypdf` + `fontTools` in `~/.local/opt/`. Without them the OCR and reader-comparison checks are skipped (INFO note) and every ActualText counts as suspicious; with them installed everything runs automatically.

## Known limits
OCR (tesseract) is noisy on mathematics and runs on the first 30 pages by default (`--ocr-pages`). A visible, plausible decoy cannot be told from a real task. JavaScript- or server-generated content is flagged, not executed. Phrase lists miss novel wording; the structural, Unicode, encoding and ambiguity checks do not depend on wording. The hooks cannot rewrite built-in tool output, so they block and redirect instead.
