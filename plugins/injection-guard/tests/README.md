# Tests

Run: `python3 -I tests/run_tests.py [module.py] [-v]` from `plugins/injection-guard/` (or the paths in the root CLAUDE.md).

## Layout
| File | Covers |
|---|---|
| `test_common.py` | phrases, keywords, Unicode, homoglyphs, obfuscation, robustness |
| `test_web_text.py` | HTML/SVG hiding, Markdown, plain text |
| `test_office_images.py` | DOCX/PPTX/XLSX/ODF/EPUB, image metadata |
| `test_pdf.py` | LaTeX trap corpus (`fixtures/pdf/`, pinned in `expected.json`), synthetic PDFs, real sheets (skip if absent) |
| `test_advanced.py` | encodings/ciphers, Unicode smuggling, live content, image stego, polyglots |
| `test_directives_ocr.py` | fingerprint directives, look-alike identifiers, reader differential, OCR checks |
| `test_cli_hooks.py` | `safe-read`/`safe-fetch` CLIs, registry, hooks, cloaking (local HTTP server) |
| `test_latex.py` | LaTeX/BibTeX, archives, macOS metadata, LaTeX read hook |
| `test_redteam.py`, `test_redteam2.py`, `test_redteam3.py` | evasions that got through once (never delete), impersonation, task modifiers, forensics, direction tricks, reading order, scanner DoS |

## Writing a test
- `import helpers` **first**: it isolates `HOME` in a temp dir and sets `INJECTION_GUARD_OCR_PAGES=0`.
- Build inputs in code, not as binary fixtures: `build_pdf(path, [streams], fonts=, info=, catalog_extra=, page_extra=, extra_objs=)`,
  `text_op(text, x, y, size, pre=b"3 Tr")`, `utf16hex()`, `lit()`, `build_docx`, `build_pptx` + `slide_xml`/`shape_xml`,
  `build_xlsx`, `build_odt`, `build_epub`, `build_zip`. Object numbers in `build_pdf`: 1 catalog, 2 pages, 3 page, then
  fonts, then streams, then `extra_objs` (count them when an extra object references another).
- Shared strings: `INJ` (an instruction), `TASK` (a clean exercise), `FP` in red-team files (a fingerprint directive without AI words).
- Every attack test gets a **benign twin** that must stay quiet (e.g. `test_normal_logo_with_transparency_is_clean`).
- Assert on finding kinds with `has_kind(F, "substring", "HIGH")`; print `F.items` in the failure message.
- Tests that need a tool or a local file use `skipUnless` (`tesseract()`, mutool presence, real sheet paths), so CI and
  other machines skip them instead of failing.
- Keep each test independent of order: no reliance on registry/config left by another test.
- Slow tests are fine, but after adding them run `report.py --write-durations` so the 4 CI shards stay balanced.

## CI
`.github/workflows/tests.yml`: 4 shards (`report.py --shard K --of 4`, longest-first bin packing on `durations.json`;
classes with expensive class setup such as `SafeFetch` stay in one shard), then `merge_results.py --expect N` fails on
any failure, a duplicate, or a missing shard. apt and pip are cached.
